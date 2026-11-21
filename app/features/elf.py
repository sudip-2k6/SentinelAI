import io
import struct

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from app.core.contracts import Analysis
from app.features.common import entropy, indicators, printable


def _label(data: bytes, base: int, size: int, offset: int) -> str:
    if offset >= size:
        raise ValueError("Invalid ELF string table offset.")
    start = base + offset
    end = data.find(b"\0", start, min(start + 256, base + size))
    stop = end if end >= 0 else min(start + 256, base + size)
    return printable(data[start:stop])


def parse(data: bytes) -> Analysis:
    if len(data) < 16 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        raise ValueError("Invalid ELF identification bytes.")
    is_64 = data[4] == 2
    byteorder = "<" if data[5] == 1 else ">"
    header = struct.Struct(byteorder + ("HHIQQQIHHHHHH" if is_64 else "HHIIIIIHHHHHH"))
    section = struct.Struct(byteorder + ("IIQQQQIIQQ" if is_64 else "IIIIIIIIII"))
    segment = struct.Struct(byteorder + ("IIQQQQQQ" if is_64 else "IIIIIIII"))
    (_, _, version, entry, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, shstr) = (
        header.unpack_from(data, 16)
    )
    if version != 1 or ehsize != 16 + header.size:
        raise ValueError("Invalid ELF header version or size.")
    if (
        shoff
        and (
            shoff < ehsize
            or not 1 <= shnum <= 2048
            or shsize != section.size
            or shoff + shnum * shsize > len(data)
            or shstr >= shnum
        )
    ) or (not shoff and (shnum or shstr)):
        raise ValueError("Invalid ELF section table or unsupported extended numbering.")
    if phnum and (
        phnum > 512
        or phoff < ehsize
        or phsize != segment.size
        or phoff + phnum * phsize > len(data)
    ):
        raise ValueError("Invalid ELF program table.")
    try:
        elf = ELFFile(io.BytesIO(data[:ehsize]))
    except ELFError as exc:
        raise ValueError(str(exc)) from exc
    records = [section.unpack_from(data, shoff + index * shsize) for index in range(shnum)]
    names_base, names_size = 0, 0
    if shstr:
        _, kind, _, _, names_base, names_size, *_ = records[shstr]
        if kind != 3 or names_base + names_size > len(data):
            raise ValueError("Invalid ELF section name table.")
    sections: list[dict[str, str | int | float]] = []
    imports: list[str] = []
    total_raw = 0
    for name, kind, flags, _, start, size, link, _, _, entsize in records:
        if kind not in (0, 8):
            total_raw += size
            if start + size > len(data) or total_raw > len(data) * 2:
                raise ValueError("Invalid or excessive ELF section ranges.")
        sections.append(
            {
                "name": _label(data, names_base, names_size, name) if names_size else "",
                "size": size,
                "entropy": entropy(data[start : start + size]) if kind not in (0, 8) else 0.0,
                "executable": int(bool(flags & 4)),
                "writable": int(bool(flags & 1)),
            }
        )
        if kind != 6 or len(imports) >= 256:
            continue
        dynamic = struct.Struct(byteorder + ("qQ" if is_64 else "iI"))
        if entsize != dynamic.size or link >= len(records):
            raise ValueError("Invalid ELF dynamic table.")
        _, string_kind, _, _, str_start, str_size, *_ = records[link]
        if string_kind != 3 or str_start + str_size > len(data):
            raise ValueError("Invalid ELF dynamic string table.")
        for index in range(min(size // entsize, 4096)):
            tag, value = dynamic.unpack_from(data, start + index * entsize)
            if tag == 0 or len(imports) >= 256:
                break
            if tag == 1:
                imports.append(_label(data, str_start, str_size, value))
    headers = {
        "Machine": str(elf.header.e_machine),
        "Type": str(elf.header.e_type),
        "Architecture": elf.elfclass,
        "Byte order": "Little" if elf.little_endian else "Big",
        "Entry point": str(hex(entry)),
        "Program headers": phnum,
    }
    return Analysis("ELF", headers, sections, imports, indicators(data), entropy(data))
