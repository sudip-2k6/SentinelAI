import struct

import pefile

from app.core.contracts import Analysis
from app.features.common import entropy, indicators, printable

_MAX_IMPORTS = 256


def _string(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset, offset + 256)
    if offset < 0 or end < 0:
        raise ValueError("Invalid import string.")
    return printable(data[offset:end])


def _imports(pe: pefile.PE, data: bytes) -> list[str]:
    table = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(table) < 2 or not table[1].VirtualAddress:
        return []
    count = min(table[1].Size // 20, 128)
    base = pe.get_offset_from_rva(table[1].VirtualAddress)
    width = 8 if pe.PE_TYPE == 0x20B else 4
    ordinal_flag = 1 << (width * 8 - 1)
    output: list[str] = []
    for index in range(count):
        names, _, _, library, addresses = struct.unpack_from("<IIIII", data, base + index * 20)
        if not library:
            break
        dll = _string(data, pe.get_offset_from_rva(library))
        output.append(dll)
        if len(output) >= _MAX_IMPORTS:
            return output
        if not (names or addresses):
            continue
        offset = pe.get_offset_from_rva(names or addresses)
        for entry in range(128):
            value = struct.unpack_from("<Q" if width == 8 else "<I", data, offset + entry * width)[
                0
            ]
            if not value:
                break
            if value & ordinal_flag:
                symbol = f"ordinal {value & 0xFFFF}"
            else:
                symbol = _string(data, pe.get_offset_from_rva(value) + 2)
            output.append(f"{dll}!{symbol}")
            if len(output) >= _MAX_IMPORTS:
                return output
    return output


def parse(data: bytes) -> Analysis:
    if len(data) < 64:
        raise ValueError("Truncated DOS header.")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset < 64 or offset + 24 > len(data) or data[offset : offset + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature or header offset.")
    machine, count, timestamp, _, _, optional_size, flags = struct.unpack_from(
        "<HHIIIHH", data, offset + 4
    )
    optional = offset + 24
    sections_base = optional + optional_size
    if not 1 <= count <= 96 or optional_size < 2 or sections_base + count * 40 > len(data):
        raise ValueError("Invalid PE section table.")
    magic = struct.unpack_from("<H", data, optional)[0]
    minimum = {0x10B: 96, 0x20B: 112}.get(magic)
    if minimum is None or optional_size < minimum:
        raise ValueError("Unsupported or truncated PE optional header.")
    directory_count = struct.unpack_from("<I", data, optional + minimum - 4)[0]
    if directory_count > 16 or minimum + directory_count * 8 > optional_size:
        raise ValueError("Invalid PE data directory table.")
    sections: list[dict[str, str | int | float]] = []
    total_raw = 0
    for index in range(count):
        base = sections_base + index * 40
        size, start = struct.unpack_from("<II", data, base + 16)
        characteristics = struct.unpack_from("<I", data, base + 36)[0]
        total_raw += size
        if size and (not start or start + size > len(data) or total_raw > len(data) * 2):
            raise ValueError("Invalid or excessive PE section ranges.")
        sections.append(
            {
                "name": printable(data[base : base + 8].split(b"\0", 1)[0]),
                "size": size,
                "entropy": entropy(data[start : start + size]),
                "executable": int(bool(characteristics & 0x20000000)),
                "writable": int(bool(characteristics & 0x80000000)),
            }
        )
    try:
        pe = pefile.PE(data=data, fast_load=True)
        try:
            imports = _imports(pe, data)
            headers = {
                "Machine": f"0x{machine:04x}",
                "Architecture": "PE32+" if magic == 0x20B else "PE32",
                "Timestamp (raw)": timestamp,
                "Entry point RVA": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "Subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
                "File flags": f"0x{flags:04x}",
                "Image size": int(pe.OPTIONAL_HEADER.SizeOfImage),
            }
        finally:
            pe.close()
    except pefile.PEFormatError as exc:
        raise ValueError(str(exc)) from exc
    return Analysis("PE", headers, sections, imports, indicators(data), entropy(data))
