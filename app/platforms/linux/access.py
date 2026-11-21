import ctypes
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def current_uid() -> int:
    return int(getattr(os, "getuid")())


@contextmanager
def directory_handle(path: Path) -> Iterator[int]:
    if not path.is_absolute():
        raise ValueError("An absolute directory path is required.")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY") | getattr(os, "O_NOFOLLOW")
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor
    finally:
        os.close(descriptor)


def move_no_replace(source: Path, destination: Path) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renameat2
    except AttributeError as exc:
        raise OSError("Atomic non-overwriting moves are unavailable on this system.") from exc
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    with directory_handle(source.parent) as src, directory_handle(destination.parent) as dest:
        if rename(src, os.fsencode(source.name), dest, os.fsencode(destination.name), 1):
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), str(destination))
