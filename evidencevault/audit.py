"""Store run results and file actions in a local SQLite database."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .core import FileResult, RunResult, VaultError, output_writer, reject_symlinks, utc_now


class AuditStore:
    """Keep one database connection in the command thread."""

    def __init__(self, path: Path):
        self.path = path.absolute()
        reject_symlinks(self.path)
        if not self.path.exists():
            with output_writer(self.path):
                pass
        if not self.path.is_file():
            raise VaultError("The database path is not a regular file.")
        self.connection = sqlite3.connect(self.path, timeout=10)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA synchronous = FULL")
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            self.connection.close()
            raise VaultError("The database uses an unsupported format version.")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                case_name TEXT NOT NULL,
                operator TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL DEFAULT '',
                exit_code INTEGER,
                result_json TEXT
            );
            CREATE TABLE IF NOT EXISTS files (
                run_id TEXT NOT NULL REFERENCES runs(id),
                item_number INTEGER NOT NULL,
                path TEXT NOT NULL,
                destination TEXT NOT NULL,
                status TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                algorithm TEXT NOT NULL,
                digest TEXT NOT NULL,
                PRIMARY KEY (run_id, item_number)
            );
            CREATE INDEX IF NOT EXISTS files_digest ON files(algorithm, digest);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(id),
                time_utc TEXT NOT NULL,
                action TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            PRAGMA user_version = 1;
        """)

    def start(self, result: RunResult) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO runs(id, action, case_name, operator, started_utc) VALUES (?, ?, ?, ?, ?)",
                (result.run_id, result.action, result.case, result.operator, result.started_utc),
            )

    def event(self, result: RunResult, action: str, source: str, destination: str, detail: str = "") -> None:
        # Save each event before the next file action starts.
        with self.connection:
            self.connection.execute(
                "INSERT INTO events(run_id, time_utc, action, source, destination, detail) VALUES (?, ?, ?, ?, ?, ?)",
                (result.run_id, utc_now(), action, source, destination, detail),
            )

    def finish(self, result: RunResult) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE runs SET finished_utc = ?, exit_code = ?, result_json = ? WHERE id = ?",
                (result.finished_utc, result.exit_code, json.dumps(result.to_dict()), result.run_id),
            )
            self.connection.execute("DELETE FROM files WHERE run_id = ?", (result.run_id,))
            self.connection.executemany(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (result.run_id, number, row.path, row.destination, row.status,
                     row.size, row.algorithm, row.digest)
                    for number, row in enumerate(result.files)
                ],
            )

    def close(self) -> None:
        self.connection.close()


def load_run(path: Path, run_id: str = "") -> RunResult:
    """Read a stored result without a database write."""
    path = path.absolute()
    reject_symlinks(path)
    if not path.is_file():
        raise VaultError("The database file does not exist.")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        if run_id:
            row = connection.execute("SELECT result_json FROM runs WHERE id = ?", (run_id,)).fetchone()
        else:
            row = connection.execute(
                "SELECT result_json FROM runs WHERE result_json IS NOT NULL ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
        if row is None or row[0] is None:
            raise VaultError("No completed run was found in the database.")
        value = json.loads(row[0])
        files = [FileResult(**item) for item in value.pop("files")]
        return RunResult(files=files, **value)
    finally:
        connection.close()
