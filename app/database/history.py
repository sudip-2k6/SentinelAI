import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from sqlite3 import SQLITE_INTERRUPT, Connection
from threading import Event
from typing import Any, cast

from sqlalchemy import URL, create_engine, event, text
from sqlalchemy.exc import OperationalError

from app.core.contracts import ScanResult


class History:
    def __init__(self, root: Path) -> None:
        self.engine = create_engine(
            URL.create("sqlite", database=str(root / "sentinel.sqlite3")),
            connect_args={"timeout": 15},
        )

        @event.listens_for(self.engine, "connect")
        def enable_wal(connection: Any, _record: Any) -> None:
            connection.execute("PRAGMA busy_timeout=15000")

        with self.engine.begin() as db:
            db.exec_driver_sql("PRAGMA journal_mode=WAL")
            db.exec_driver_sql("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, origin TEXT NOT NULL,
                    path TEXT NOT NULL, sha256 TEXT, format TEXT NOT NULL, status TEXT NOT NULL,
                    probability REAL, review TEXT NOT NULL, model_version TEXT, payload TEXT NOT NULL
                )
            """)
            db.exec_driver_sql("CREATE INDEX IF NOT EXISTS scans_hash ON scans(sha256, id)")
            db.exec_driver_sql("CREATE INDEX IF NOT EXISTS scans_date ON scans(timestamp)")
            db.exec_driver_sql("""
                CREATE TABLE IF NOT EXISTS quarantine (
                    id TEXT PRIMARY KEY, original TEXT NOT NULL, sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL, timestamp TEXT NOT NULL, state TEXT NOT NULL,
                    destination TEXT, note TEXT NOT NULL DEFAULT '',
                    mode INTEGER, security TEXT
                )
            """)
            columns = {column[1] for column in db.exec_driver_sql("PRAGMA table_info(quarantine)")}
            if "mode" not in columns:
                db.exec_driver_sql("ALTER TABLE quarantine ADD COLUMN mode INTEGER")
            if "security" not in columns:
                db.exec_driver_sql("ALTER TABLE quarantine ADD COLUMN security TEXT")

    def record(self, result: ScanResult, origin: str) -> None:
        with self.engine.begin() as db:
            db.execute(
                text("""
                INSERT INTO scans(timestamp, origin, path, sha256, format, status, probability,
                                  review, model_version, payload)
                VALUES(:timestamp, :origin, :path, :sha, :format, :status, :probability,
                       :review, :version, :payload)
            """),
                {
                    "timestamp": result.timestamp,
                    "origin": origin,
                    "path": result.path,
                    "sha": result.sha256,
                    "format": result.format,
                    "status": result.status,
                    "probability": result.assessment.probability,
                    "review": result.assessment.review,
                    "version": result.assessment.model_version,
                    "payload": json.dumps(result.to_dict(), allow_nan=False),
                },
            )

    def recent(
        self,
        query: str = "",
        status: str = "",
        sha256: str = "",
        *,
        limit: int = 250,
        cancel: Event | None = None,
    ) -> list[dict]:
        conditions = []
        params: dict[str, str | int] = {"limit": limit}
        if query:
            conditions.append("path LIKE :pattern ESCAPE '!'")
            params["pattern"] = (
                "%" + query.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
            )
        if status:
            conditions.append("status = :status")
            params["status"] = status
        if sha256:
            conditions.append("sha256 = :sha")
            params["sha"] = sha256
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        statement = text(
            "SELECT id, timestamp, origin, path, sha256, format, status, probability, review "
            f"FROM scans{where} ORDER BY id DESC LIMIT :limit"
        )
        if cancel is not None and cancel.is_set():
            return []
        with self.engine.connect() as db:
            connection = cast(Connection, db.connection.driver_connection)
            if cancel is not None:
                connection.set_progress_handler(cancel.is_set, 1000)
            try:
                return [dict(row) for row in db.execute(statement, params).mappings()]
            except OperationalError as exc:
                if (
                    cancel is not None
                    and cancel.is_set()
                    and (getattr(exc.orig, "sqlite_errorcode", None) == SQLITE_INTERRUPT)
                ):
                    return []
                raise
            finally:
                if cancel is not None:
                    connection.set_progress_handler(None, 0)

    def detail(self, scan_id: int) -> dict:
        with self.engine.connect() as db:
            row = db.execute(text("SELECT payload FROM scans WHERE id=:id"), {"id": scan_id})
            payload = row.scalar_one_or_none()
        return json.loads(payload) if payload is not None else {}

    def dashboard(self) -> tuple[dict, list[dict]]:
        with self.engine.connect() as db:
            totals = (
                db.execute(
                    text("""
                SELECT COUNT(*) AS scans, SUM(status='Analyzed') AS analyzed,
                       SUM(review='Elevated model score') AS elevated,
                       COUNT(DISTINCT sha256) AS unique_files
                FROM scans
            """)
                )
                .mappings()
                .one()
            )
            days = db.execute(
                text("""
                SELECT substr(timestamp,1,10) AS day, COUNT(*) AS scans,
                       SUM(review='Elevated model score') AS elevated
                FROM scans WHERE timestamp >= :start
                GROUP BY day ORDER BY day
            """),
                {"start": (datetime.now(UTC) - timedelta(days=6)).date().isoformat()},
            ).mappings()
            return dict(totals), [dict(day) for day in days]

    def prune(self, days: int) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self.engine.begin() as db:
            db.execute(text("DELETE FROM scans WHERE timestamp < :cutoff"), {"cutoff": cutoff})
