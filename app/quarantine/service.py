import errno
import hashlib
import os
import re
import stat
from pathlib import Path
from threading import Lock
from uuid import uuid4

from sqlalchemy import text

from app.core.contracts import utc_now
from app.core.files import beneath, check_chain, identity, local_path, open_regular
from app.database.history import History
from app.platforms.linux.access import current_uid

_IDENTIFIER = re.compile(r"[0-9a-f]{32}")
_HASH = re.compile(r"[0-9a-f]{64}")
_MAX_SIZE = 128 * 1024 * 1024
_PROTECTED = {"appdata", "application data", "local settings", "start menu", "startup"}


def _move(source: Path, target: Path) -> None:
    try:
        if os.name == "nt":
            check_chain(source)
            check_chain(target, include_leaf=False)
            source.rename(target)  # Windows rename refuses to replace an existing destination
        else:
            from app.platforms.linux.access import move_no_replace

            move_no_replace(source, target)
    except OSError as exc:
        if exc.errno == errno.EXDEV or getattr(exc, "winerror", None) == 17:
            raise OSError("Quarantine and restore require the same filesystem.") from exc
        raise


def _fingerprint(path: Path) -> tuple[str, os.stat_result]:
    with open_regular(path) as (file, info):
        if info.st_size > _MAX_SIZE or info.st_nlink != 1:
            raise OSError("Quarantine supports a single-link file up to 128 MiB.")
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            chunk = file.read(min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("The file changed during quarantine verification.")
            remaining -= len(chunk)
            digest.update(chunk)
        if file.read(1):
            raise OSError("The file changed during quarantine verification.")
        return digest.hexdigest(), info


class Quarantine:
    def __init__(self, root: Path, history: History, *, home: Path | None = None) -> None:
        self.home = local_path(home or Path.home())
        self.root = local_path(root)
        self.history = history
        self.lock = Lock()
        self.storage = self.root / "quarantine"
        check_chain(self.root)
        self.storage.mkdir(mode=0o700, exist_ok=True)
        check_chain(self.storage)
        if os.name == "nt":
            from app.platforms.windows.access import set_private

            set_private(self.storage, directory=True)
        else:
            info = self.storage.stat()
            if info.st_uid != current_uid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise OSError("Quarantine storage must be owned by you and mode 0700.")

    def _allowed(self, path: Path) -> Path:
        path = local_path(path)
        if not beneath(path, self.home) or path == self.home or beneath(path, self.root):
            raise ValueError("Choose a file within your home folder outside SentinelAI storage.")
        relative = path.relative_to(self.home)
        if any(part.startswith(".") or part.casefold() in _PROTECTED for part in relative.parts):
            raise ValueError("Hidden and protected profile locations are excluded from quarantine.")
        check_chain(path, include_leaf=False)
        return path

    def _payload(self, entry: str) -> Path:
        if not _IDENTIFIER.fullmatch(entry):
            raise ValueError("Invalid quarantine item identifier.")
        return self.storage / f"{entry}.blob"

    def _state(
        self, entry: str, state: str, *, note: str = "", destination: str | None = None
    ) -> None:
        with self.history.engine.begin() as db:
            db.execute(
                text("""
                UPDATE quarantine SET state=:state, note=:note, destination=:target WHERE id=:id
            """),
                {"id": entry, "state": state, "note": note, "target": destination},
            )

    def _private(self, payload: Path) -> None:
        check_chain(payload)
        if os.name == "nt":
            from app.platforms.windows.access import set_private

            set_private(payload)
        else:
            with open_regular(payload) as (stream, _):
                getattr(os, "fchmod")(stream.fileno(), 0o600)

    def _restore_permissions(self, payload: Path, item: dict) -> None:
        check_chain(payload)
        if os.name == "nt":
            from app.platforms.windows.access import restore_security

            restore_security(payload, item["security"])
        else:
            with open_regular(payload) as (stream, _):
                getattr(os, "fchmod")(stream.fileno(), item["mode"])

    def items(self) -> list[dict]:
        with self.history.engine.connect() as db:
            items = db.execute(
                text("SELECT * FROM quarantine ORDER BY timestamp DESC, id DESC LIMIT 500")
            )
            return [dict(row) for row in items.mappings()]

    def _item(self, entry: str) -> dict:
        with self.history.engine.connect() as db:
            data = db.execute(text("SELECT * FROM quarantine WHERE id=:id"), {"id": entry})
            match = data.mappings().one_or_none()
        if match is None:
            raise ValueError("The quarantine item does not exist.")
        return dict(match)

    def store(self, path: Path, expected: str, *, confirmed: bool = False) -> str:
        if not confirmed or not _HASH.fullmatch(expected):
            raise ValueError(
                "Quarantine requires explicit approval and a SHA-256 from scan history."
            )
        with self.lock:
            path = self._allowed(path)
            digest, info = _fingerprint(path)
            if digest != expected:
                raise OSError("The file has changed since it was scanned. Scan it again.")
            snapshot = None
            if os.name == "nt":
                from app.platforms.windows.access import is_owner, security_snapshot

                if not is_owner(path):
                    raise PermissionError("Only files owned by your account can be quarantined.")
                snapshot = security_snapshot(path)
            elif info.st_uid != current_uid() or info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise PermissionError(
                    "Only regular, user-owned files without set-ID bits are supported."
                )
            if identity(path.lstat()) != identity(info):
                raise OSError("The file changed before quarantine.")
            entry = uuid4().hex
            payload = self._payload(entry)
            with self.history.engine.begin() as db:
                db.execute(
                    text("""
                    INSERT INTO quarantine(id, original, sha256, size, timestamp, state, mode, security)
                    VALUES(:id,:original,:sha,:size,:time,'Staging',:mode,:security)
                """),
                    {
                        "id": entry,
                        "original": str(path),
                        "sha": digest,
                        "size": info.st_size,
                        "time": utc_now(),
                        "mode": info.st_mode & 0o777,
                        "security": snapshot,
                    },
                )
            moved = False
            try:
                _move(path, payload)
                moved = True
                check, moved_info = _fingerprint(payload)
                if check != digest or identity(info) != identity(moved_info):
                    self._state(
                        entry, "Recovery required", note="File identity changed during the move."
                    )
                    try:
                        _move(payload, path)
                    except OSError:
                        pass
                    raise OSError("File changed during quarantine. Review the manifest.")
                self._private(payload)
                self._state(entry, "Isolated")
            except OSError as exc:
                if not moved:
                    self._state(entry, "Failed", note=str(exc))
                elif self._item(entry)["state"] == "Staging":
                    self._state(entry, "Recovery required", note=str(exc))
                raise
            return entry

    def restore(
        self,
        entry: str,
        destination: Path | None = None,
        *,
        confirmed: bool = False,
    ) -> Path:
        if not confirmed:
            raise ValueError("Restoration requires explicit approval.")
        with self.lock:
            payload, item = self._payload(entry), self._item(entry)
            if item["state"] not in ("Isolated", "Recovery required"):
                raise ValueError("This item has no restorable quarantine payload.")
            original = self._allowed(Path(item["original"]))
            target = local_path(destination or original)
            if target.parent != original.parent:
                raise ValueError(
                    "Restore to the original directory using the original name or a new name."
                )
            target = self._allowed(target)
            if os.path.lexists(target):
                raise FileExistsError(
                    "The destination already exists. Choose a different file name."
                )
            digest, info = _fingerprint(payload)
            if digest != item["sha256"] or info.st_size != item["size"]:
                self._state(entry, "Recovery required", note="Payload integrity check failed.")
                raise OSError("Payload integrity check failed. The file was left in quarantine.")
            self._state(entry, "Restoring", destination=str(target))
            moved = False
            try:
                _move(payload, target)
                moved = True
                restored, restored_info = _fingerprint(target)
                if restored != digest or identity(info) != identity(restored_info):
                    raise OSError("Restore destination failed its integrity check.")
                self._restore_permissions(target, item)
                self._state(entry, "Restored", destination=str(target))
            except OSError as exc:
                if moved:
                    self._state(entry, "Recovery required", note=str(exc), destination=str(target))
                else:
                    self._state(entry, "Isolated", note=str(exc))
                raise
            return target

    def recover(self) -> None:
        with self.lock:
            with self.history.engine.connect() as db:
                records = (
                    db.execute(
                        text("""
                    SELECT * FROM quarantine WHERE state IN ('Staging', 'Restoring')
                """)
                    )
                    .mappings()
                    .all()
                )
            for item in records:
                entry = item["id"]
                try:
                    payload = self._payload(entry)
                    if os.path.lexists(payload):
                        digest, info = _fingerprint(payload)
                        if digest != item["sha256"] or info.st_size != item["size"]:
                            raise OSError("Payload integrity check failed.")
                        self._private(payload)
                        self._state(
                            entry, "Isolated", note="Recovered after interrupted operation."
                        )
                    elif item["state"] == "Restoring" and item["destination"]:
                        destination = self._allowed(Path(item["destination"]))
                        digest, info = _fingerprint(destination)
                        if digest != item["sha256"] or info.st_size != item["size"]:
                            raise OSError("Destination integrity check failed.")
                        self._restore_permissions(destination, dict(item))
                        self._state(
                            entry,
                            "Restored",
                            destination=str(destination),
                            note="Recovered after interrupted restoration.",
                        )
                    else:
                        self._state(entry, "Failed", note="No quarantine payload was created.")
                except (OSError, ValueError) as exc:
                    self._state(
                        entry, "Recovery required", note=str(exc), destination=item["destination"]
                    )
