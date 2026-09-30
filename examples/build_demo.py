"""Create sample files and run each main operation with those files."""

from __future__ import annotations

import argparse
import io
import json
import struct
import zlib
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from evidencevault.audit import load_run
from evidencevault.cli import main


def build_demo(output: Path) -> None:
    """Use a new folder. Store only synthetic case data."""
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    (source / "logs").mkdir(parents=True)
    (source / "screenshots").mkdir()
    note = b"School training case. All files and events are synthetic.\n"
    (source / "notes.txt").write_bytes(note)
    (source / "notes-copy.txt").write_bytes(note)
    (source / "logs/access.log").write_text(
        "2026-09-30T08:10:00Z 192.0.2.10 GET /login 200\n"
        "2026-09-30T08:11:00Z 192.0.2.10 GET /dashboard 200\n", encoding="utf-8",
    )
    (source / "events.csv").write_text("time,event\n08:10,Sample login\n08:11,Sample page visit\n", encoding="utf-8")
    def png_chunk(name, data):
        return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))
    image = (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">2I5B", 1, 1, 8, 2, 0, 0, 0))
             + png_chunk(b"IDAT", zlib.compress(b"\x00\x20\x80\xb0")) + png_chunk(b"IEND", b""))
    (source / "screenshots/sample.png").write_bytes(image)
    records = output / "records"
    records.mkdir()
    case = output / "case"
    archive = case / "case.vault.zip"
    jobs = (
        ("collect", ["collect", source, "-o", case, "--case", "SCHOOL-DEMO-01", "--operator", "Student"], case / "audit.sqlite3"),
        ("bundle", ["bundle", source, "-r", "--format", "json", "--compress", "-o", output / "sample.vault.json"], None),
        ("verify", ["verify", archive, "--db", records / "verify.sqlite3"], records / "verify.sqlite3"),
        ("extract", ["extract", archive, "-o", output / "restored", "--db", records / "extract.sqlite3"], records / "extract.sqlite3"),
        ("hash", ["hash", source, "-r", "--md5", "-o", output / "inventory.json", "--db", records / "hash.sqlite3"], records / "hash.sqlite3"),
        ("encode", ["encode", source, "-r", "--compress", "-o", output / "encoded", "--db", records / "encode.sqlite3"], records / "encode.sqlite3"),
        ("decode", ["decode", output / "encoded", "-r", "--decompress", "-o", output / "decoded", "--db", records / "decode.sqlite3"], records / "decode.sqlite3"),
        ("rename", ["rename", source, "-r", "--pattern", "EVID_{n:04d}_{hash}{ext}", "-o", output / "renamed"], output / "renamed/audit.sqlite3"),
        ("sort", ["sort", source, "-r", "-o", output / "sorted"], output / "sorted/audit.sqlite3"),
        ("report", ["report", "--db", case / "audit.sqlite3", "-o", records / "saved-report.html"], case / "audit.sqlite3"),
    )
    results = {}
    for action, arguments, database in jobs:
        arguments = [str(value) for value in arguments]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments)
        if code:
            raise RuntimeError(action + ": " + stderr.getvalue())
        rows = load_run(database).to_dict()["files"] if database else []
        if action == "bundle":
            manifest = json.loads((output / "sample.vault.json").read_text(encoding="utf-8"))
            rows = [{"path": item["path"], "size": item["size"], "digest": item["hash"],
                     "status": "ok", "kind": "stored", "destination": "demo/sample.vault.json"}
                    for item in manifest["files"]]
        results[action] = {
            "command": [value.replace(str(output), "demo") for value in arguments],
            "output": stdout.getvalue().replace(str(output), "demo"),
            "exit_code": code,
            "files": rows,
        }
        for row in rows:
            row["destination"] = row["destination"].replace(str(output), "demo")
    results["report_html"] = (case / "report.html").read_text(encoding="utf-8").replace(str(output), "demo")
    (output / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("Sample results: " + str(output / "results.json"))
    print("Sample report: " + str(case / "report.html"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", type=Path, required=True, help="New sample output folder.")
    build_demo(parser.parse_args().output.absolute())
