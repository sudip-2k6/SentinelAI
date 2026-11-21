import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE)


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def local_path(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if os.name == "nt":
        from app.platforms.windows.access import local_volume

        if str(path).startswith("\\\\") or not local_volume(path):
            raise OSError("Only regular paths on fixed local Windows volumes are supported.")
        if any(":" in part or part.endswith((".", " ")) for part in path.parts[1:]):
            raise OSError("Alternate streams and ambiguous Windows paths are unsupported.")
        if path.is_reserved():
            raise OSError("Reserved device paths are unsupported.")
    return path


def check_chain(path: Path, *, include_leaf: bool = True) -> None:
    parts = [*reversed(path.parents)]
    if include_leaf:
        parts.append(path)
    for part in parts:
        if is_link(part.lstat()):
            raise OSError(f"Symbolic links and reparse points are unsupported: {part}")


@contextmanager
def open_regular(path: Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    path = local_path(path)
    check_chain(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise OSError("The target is not a regular file.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if os.name == "nt":
        fd = os.open(path, flags)
    else:
        from app.platforms.linux.access import directory_handle

        with directory_handle(path.parent) as parent:
            fd = os.open(path.name, flags, dir_fd=parent)
    with os.fdopen(fd, "rb") as stream:
        current = os.fstat(stream.fileno())
        if not stat.S_ISREG(current.st_mode) or identity(before) != identity(current):
            raise OSError("The file changed while it was being opened.")
        yield stream, current
        if identity(os.fstat(stream.fileno())) != identity(current):
            raise OSError("The file changed while it was being read.")


def beneath(path: Path, root: Path) -> bool:
    return path == root or root in path.parents
