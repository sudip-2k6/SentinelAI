"""Versioned projections shared by the benchmark adapters and live scanner."""

import re
from collections.abc import Mapping
from functools import lru_cache
from zlib import crc32

from app.core.contracts import Analysis

_PRINTABLE = re.compile(rb"[\x20-\x7f]{5,}")
_PE_STRINGS = (
    ("paths", re.compile(rb"c:\\", re.IGNORECASE)),
    ("urls", re.compile(rb"https?://", re.IGNORECASE)),
    ("registry", re.compile(rb"HKEY_")),
    ("MZ", re.compile(rb"MZ")),
)
_ELF_PATHS = ("/dev/", "/proc/", "/bin/", "/usr/", "/tmp/")
_ELF_WORDS = (
    "access",
    "debug",
    "download",
    "environment",
    "exit",
    "file",
    "hostname",
    "install",
    "memory",
    "module",
    "password",
    "process",
    "remote",
    "resource",
    "security",
    "service",
    "shell",
    "system",
    "thread",
)
ELF_MARKERS = _ELF_PATHS + _ELF_WORDS
_ELF_PATTERNS = tuple(word.encode("ascii") for word in ELF_MARKERS)
# The ELF archive stores counts of matching printable strings, grouped by pattern.
_EXTRA_ELF = {
    **{
        word: re.compile(word.encode("ascii"), re.IGNORECASE)
        for word in (
            "base64",
            "cache",
            "certificate",
            "clipboard",
            "command",
            "connect",
            "cookie",
            "create",
            "decode",
            "delete",
            "desktop",
            "directory",
            "disk",
            "encode",
            "enum",
            "hidden",
            "html",
            "internet",
            "javascript",
            "keyboard",
            "mutex",
            "powershell",
            "privilege",
            "snapshot",
            "token",
            "wallet",
            "window",
        )
    },
    "crypt": re.compile(rb"crypt"),
    "ftp": re.compile(rb"ftp:", re.IGNORECASE),
    "get": re.compile(rb"GET /", re.IGNORECASE),
    "http": re.compile(rb"HTTP/", re.IGNORECASE),
    "http://": re.compile(rb"http://", re.IGNORECASE),
    "https://": re.compile(rb"https://", re.IGNORECASE),
    "post": re.compile(rb"POST /", re.IGNORECASE),
    "url": re.compile(rb"\b(?:http|https|ftp)://[a-zA-Z0-9._~:?#\[\]@!$&'()*+,;=\-]"),
    "useragent": re.compile(rb"User-Agent", re.IGNORECASE),
    "ipv4_addr": re.compile(
        rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    "mac_addr": re.compile(rb"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b"),
}
_DIRECTORIES = (
    "EXPORT_TABLE",
    "IMPORT_TABLE",
    "RESOURCE_TABLE",
    "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE",
    "BASE_RELOCATION_TABLE",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS_TABLE",
    "LOAD_CONFIG_TABLE",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT_DESCRIPTOR",
    "CLR_RUNTIME_HEADER",
)
_OPTIONAL = (
    ("major_image_version", "MajorImageVersion"),
    ("minor_image_version", "MinorImageVersion"),
    ("major_linker_version", "MajorLinkerVersion"),
    ("minor_linker_version", "MinorLinkerVersion"),
    ("major_operating_system_version", "MajorOperatingSystemVersion"),
    ("minor_operating_system_version", "MinorOperatingSystemVersion"),
    ("major_subsystem_version", "MajorSubsystemVersion"),
    ("minor_subsystem_version", "MinorSubsystemVersion"),
    ("sizeof_code", "SizeOfCode"),
    ("sizeof_headers", "SizeOfHeaders"),
    ("sizeof_heap_commit", "SizeOfHeapCommit"),
)
_SECTIONS = (".text", ".rdata", ".data", ".rsrc", ".reloc", ".idata", ".pdata", ".bss")
_LIBRARIES, _SYMBOLS, _MAX_IMPORTS = 64, 128, 256
_WIDE_LIBRARIES, _WIDE_SYMBOLS, _SECTION_BUCKETS = 128, 512, 32
_COFF_NAMES = (
    "RELOCS_STRIPPED",
    "EXECUTABLE_IMAGE",
    "LINE_NUMS_STRIPPED",
    "LOCAL_SYMS_STRIPPED",
    "LARGE_ADDRESS_AWARE",
    "CHARA_32BIT_MACHINE",
    "DEBUG_STRIPPED",
    "SYSTEM",
    "DLL",
)
_COFF_BITS = (0x1, 0x2, 0x4, 0x8, 0x20, 0x100, 0x200, 0x1000, 0x2000)
_MACHINES = {"I386": 0x14C, "AMD64": 0x8664, "ARM": 0x1C0, "ARMNT": 0x1C4, "ARM64": 0xAA64}
_SUBSYSTEMS = {
    "NATIVE": 1,
    "WINDOWS_GUI": 2,
    "WINDOWS_CUI": 3,
    "POSIX_CUI": 7,
    "EFI_APPLICATION": 10,
}

COMMON_NAMES = (
    *(
        f"Local entropy bin {row} and byte group {column:x}"
        for row in range(16)
        for column in range(16)
    ),
    "Printable string count",
    "Average printable string length",
    "Printable byte count",
    *(f"Printable byte frequency 0x{index:02X}" for index in range(32, 128)),
    "Printable byte entropy",
)
ELF_NAMES = tuple(f"Printable strings containing {word}" for word in ELF_MARKERS)
EXTRA_ELF_NAMES = tuple(f"Printable strings matching {word}" for word in _EXTRA_ELF)
EXTRA_COMMON_NAMES = (
    "Printable fraction",
    "Printable string density",
    *(f"Fraction at local entropy level {index}" for index in range(16)),
)
PE_NAMES = (
    *(f"Byte marker count {key}" for key, _ in _PE_STRINGS),
    "PE section count",
    "Executable sections",
    "Writable sections",
    "Unnamed sections",
    *(f"{name} {field}" for name in _SECTIONS for field in ("size", "virtual size", "entropy")),
    *(f"{name} {field}" for name in _DIRECTORIES for field in ("size", "address")),
    *(name for name, _ in _OPTIONAL),
    "Imported libraries",
    "Named imports",
    *(f"Library group {index}" for index in range(_LIBRARIES)),
    *(f"Imported symbol group {index}" for index in range(_SYMBOLS)),
)
PE_WIDE_NAMES = (
    PE_NAMES[: -(_LIBRARIES + _SYMBOLS)]
    + tuple(f"Wide library group {index}" for index in range(_WIDE_LIBRARIES))
    + tuple(f"Wide imported symbol group {index}" for index in range(_WIDE_SYMBOLS))
    + tuple(
        f"Section group {index} {field}"
        for field in ("size", "vsize", "entropy")
        for index in range(_SECTION_BUCKETS)
    )
    + (
        "Zero-size sections",
        "Largest section",
        "Highest section entropy",
        "Executable writable sections",
        "PE machine",
        "PE subsystem",
        "PE image size",
    )
    + tuple(f"COFF {name}" for name in _COFF_NAMES)
)


def _distribution(counts: list[int]) -> list[float]:
    total = max(1, sum(counts))
    return [count / total for count in counts]


def _string_vector(strings: Mapping) -> list[float]:
    counts = strings["printabledist"]
    if len(counts) != 96:
        raise ValueError("Expected 96 printable character counts.")
    return [
        strings["numstrings"],
        strings["avlength"],
        strings["printables"],
        *_distribution(counts),
        strings["entropy"],
    ]


@lru_cache(maxsize=8192)
def _bucket(value: str, width: int) -> int:
    return crc32(value.encode("utf-8", errors="replace")) % width


def _pe_vector(
    sections: list[dict],
    directories: list[dict],
    header: Mapping,
    imports: Mapping,
    *,
    wide: bool,
) -> list[float]:
    by_name = {item["name"].lower(): item for item in sections}
    by_directory = {item["name"]: item for item in directories}
    library_width, symbol_width = (
        (_WIDE_LIBRARIES, _WIDE_SYMBOLS) if wide else (_LIBRARIES, _SYMBOLS)
    )
    libs: list[float] = [0.0] * library_width
    symbols: list[float] = [0.0] * symbol_width
    count = named = libraries = 0
    for library, functions in imports.items():
        if count >= _MAX_IMPORTS:
            break
        name = library.lower()
        libs[_bucket(name, library_width)] = 1
        libraries += 1
        count += 1
        for function in functions[: min(128, _MAX_IMPORTS - count)]:
            if function.lower().startswith(("ordinal", "ord")) and any(
                c.isdigit() for c in function
            ):
                continue
            symbols[_bucket(f"{name}:{function.lower()}", symbol_width)] = 1
            named += 1
        count += min(128, len(functions), _MAX_IMPORTS - count)
    return [
        len(sections),
        sum("MEM_EXECUTE" in item["props"] for item in sections),
        sum("MEM_WRITE" in item["props"] for item in sections),
        sum(not item["name"] for item in sections),
        *(
            by_name.get(name, {}).get(key, 0)
            for name in _SECTIONS
            for key in ("size", "vsize", "entropy")
        ),
        *(
            by_directory.get(name, {}).get(key, 0)
            for name in _DIRECTORIES
            for key in ("size", "virtual_address")
        ),
        *(header.get(key, 0) for key, _ in _OPTIONAL),
        libraries,
        named,
        *libs,
        *symbols,
    ]


def _wide_pe(
    sections: list[dict],
    machine: int,
    subsystem: int,
    image_size: int,
    flags: int,
) -> list[float]:
    groups = [[0.0] * _SECTION_BUCKETS for _ in range(3)]
    for item in sections:
        index = _bucket(item["name"].lower(), _SECTION_BUCKETS)
        for group, field in zip(groups, ("size", "vsize", "entropy"), strict=True):
            group[index] += item[field]
    return [
        *groups[0],
        *groups[1],
        *groups[2],
        sum(item["size"] == 0 for item in sections),
        max((item["size"] for item in sections), default=0),
        max((item["entropy"] for item in sections), default=0),
        sum("MEM_WRITE" in item["props"] and "MEM_EXECUTE" in item["props"] for item in sections),
        machine,
        subsystem,
        image_size,
        *(int(bool(flags & bit)) for bit in _COFF_BITS),
    ]


def _extra_common(common: list[float], size: int) -> list[float]:
    string_count, _, printable_bytes = common[256:259]
    return [
        printable_bytes / size,
        string_count * 1024 / size,
        *(sum(common[index : index + 16]) for index in range(0, 256, 16)),
    ]


def archive_vector(raw: dict, kind: str, *, enhanced: bool = False) -> list[float]:
    byteentropy = raw["byteentropy"]
    if len(byteentropy) != 256:
        raise ValueError("Expected 256 local byte entropy counts.")
    strings = raw["strings"]
    common = [*_distribution(byteentropy), *_string_vector(strings)]
    extra = _extra_common(common, raw["general"]["size"]) if enhanced else []
    if kind == "ELF":
        keys = (*ELF_MARKERS, *_EXTRA_ELF) if enhanced else ELF_MARKERS
        return [*common, *extra, *(strings["string_counts"].get(key, 0) for key in keys)]
    sections = raw["section"].get("sections", [])
    optional = raw["header"].get("optional", {})
    pe = _pe_vector(sections, raw["datadirectories"], optional, raw["imports"], wide=enhanced)
    if enhanced:
        coff = raw["header"].get("coff", {})
        attributes = coff.get("characteristics", [])
        pe.extend(
            _wide_pe(
                sections,
                _MACHINES.get(coff.get("machine", ""), 0),
                _SUBSYSTEMS.get(optional.get("subsystem", ""), 0),
                raw["general"]["vsize"],
                sum(
                    bit
                    for name, bit in zip(_COFF_NAMES, _COFF_BITS, strict=True)
                    if name in attributes
                ),
            )
        )
    return [*common, *extra, *(strings[key] for key, _ in _PE_STRINGS), *pe]


def _live_pe(data: bytes, analysis: Analysis, *, enhanced: bool) -> list[float]:
    import pefile

    with pefile.PE(data=data, fast_load=True) as executable:
        header = {
            key: getattr(executable.OPTIONAL_HEADER, attribute, 0) for key, attribute in _OPTIONAL
        }
        directories = [
            {"name": name, "size": entry.Size, "virtual_address": entry.VirtualAddress}
            for name, entry in zip(_DIRECTORIES, executable.OPTIONAL_HEADER.DATA_DIRECTORY)
        ]
        sections = [
            {
                "name": parsed["name"],
                "size": parsed["size"],
                "vsize": section.Misc_VirtualSize,
                "entropy": parsed["entropy"],
                "props": [
                    flag
                    for key, flag in (("executable", "MEM_EXECUTE"), ("writable", "MEM_WRITE"))
                    if parsed[key]
                ],
            }
            for parsed, section in zip(analysis.sections, executable.sections)
        ]
        wide = (
            _wide_pe(
                sections,
                executable.FILE_HEADER.Machine
                if executable.FILE_HEADER.Machine in _MACHINES.values()
                else 0,
                executable.OPTIONAL_HEADER.Subsystem
                if executable.OPTIONAL_HEADER.Subsystem in _SUBSYSTEMS.values()
                else 0,
                executable.OPTIONAL_HEADER.SizeOfImage,
                executable.FILE_HEADER.Characteristics,
            )
            if enhanced
            else []
        )
    imports: dict[str, list[str]] = {}
    for entry in analysis.imports:
        library, separator, symbol = entry.partition("!")
        names = imports.setdefault(library, [])
        if separator:
            names.append(symbol)
    return [
        *(sum(1 for _ in pattern.finditer(data)) for _, pattern in _PE_STRINGS),
        *_pe_vector(sections, directories, header, imports, wide=enhanced),
        *wide,
    ]


def live_vector(data: bytes, analysis: Analysis, *, enhanced: bool = False) -> list[float]:
    import numpy as np

    # EMBER uses overlapping 2 KiB windows with a 1 KiB stride and 16 byte groups.
    payload = np.frombuffer(data, dtype=np.uint8)
    joint = np.zeros((16, 16), dtype=np.int64)
    for offset in range(0, max(1, len(payload) - 2047), 1024):
        count = np.bincount(payload[offset : offset + 2048] >> 4, minlength=16)
        probabilities = count[count != 0].astype(np.float32) / 2048
        h = -np.sum(probabilities * np.log2(probabilities))
        joint[min(15, int(h * 4))] += count
    chars = np.zeros(128, dtype=np.int64)
    batch = bytearray()
    string_count = total = 0
    markers = [0] * len(ELF_MARKERS)
    extra_markers = [0] * len(_EXTRA_ELF)
    for match in _PRINTABLE.finditer(data):
        item = match.group()
        string_count += 1
        total += len(item)
        if analysis.format == "ELF":
            lowered = item.lower()
            for index, needle in enumerate(_ELF_PATTERNS):
                markers[index] += needle in (item if index < len(_ELF_PATHS) else lowered)
            if enhanced:
                for index, pattern in enumerate(_EXTRA_ELF.values()):
                    extra_markers[index] += pattern.search(item) is not None
        if len(item) < 1024 * 1024:
            batch.extend(item)
        else:
            for offset in range(0, len(item), 1024 * 1024):
                chunk = np.frombuffer(item[offset : offset + 1024 * 1024], dtype=np.uint8)
                chars += np.bincount(chunk, minlength=128)
        if len(batch) >= 1024 * 1024:
            chars += np.bincount(np.frombuffer(batch, dtype=np.uint8), minlength=128)
            batch.clear()
    chars += np.bincount(np.frombuffer(batch, dtype=np.uint8), minlength=128)
    frequencies = _distribution(chars[32:].tolist())
    nonzero = np.asarray([p for p in frequencies if p], dtype=np.float32)
    common = [
        *_distribution(joint.ravel().tolist()),
        string_count,
        total / max(1, string_count),
        total,
        *frequencies,
        float(-np.sum(nonzero * np.log2(nonzero))),
    ]
    extra = _extra_common(common, len(data)) if enhanced else []
    if analysis.format == "PE":
        return [*common, *extra, *_live_pe(data, analysis, enhanced=enhanced)]
    return [*common, *extra, *markers, *(extra_markers if enhanced else [])]
