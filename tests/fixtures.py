"""Generated inert headers. These byte strings are not detector validation data."""

import struct


def pe_fixture() -> bytes:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = 152
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<IIII", data, optional + 32, 0x1000, 512, 0, 0)
    struct.pack_into("<II", data, optional + 56, 8192, 512)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 108, 16)
    data[392:400] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", data, 400, 32, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    data[512:530] = b"fixture text bytes"
    return bytes(data)


def elf_fixture() -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    return ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
