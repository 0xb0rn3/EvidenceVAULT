"""Check complete operator workflows with temporary files."""

import base64
import hashlib
import io
import json
import os
import sqlite3
import struct
import tempfile
import unittest
import zipfile
import zlib
import warnings
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from evidencevault.audit import load_run
from evidencevault.cli import main
from evidencevault.core import CHUNK_SIZE, CODECS, FileResult, RunResult, open_source, output_writer
from evidencevault.report import create_report


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "note.txt").write_bytes(b"case note\n")
        (self.source / "sub").mkdir()
        (self.source / "sub" / "image.png").write_bytes(b"\x89PNG\r\n\x1a\nsample bytes")

    def tearDown(self):
        self.directory.cleanup()

    def command(self, *arguments):
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main([str(argument) for argument in arguments])
        return code, output.getvalue(), errors.getvalue()

    def json_archive(self, paths=("note.txt",), payload=b"test", **changes):
        entries = [{
            "path": name, "encoding": "base64", "compressed": False,
            "hash": hashlib.sha256(payload).hexdigest(), "size": len(payload),
            "mtime": "2026-09-29T12:00:00Z", "data": base64.b64encode(payload).decode("ascii"),
        } for name in paths]
        value = {
            "vault_format": "1.1", "container": "json", "hash_algo": "sha256",
            "file_count": len(entries), "total_raw_bytes": len(payload) * len(entries),
            "files": entries,
        }
        value.update(changes)
        path = self.root / "manual.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path, value

    def test_case_package_and_saved_report(self):
        output = self.root / "case"
        code, _, errors = self.command("collect", self.source, "-o", output, "--case", "CASE-01", "--operator", "Student")
        self.assertEqual(code, 0, errors)
        self.assertEqual(
            {path.name for path in output.iterdir()},
            {"case.vault.zip", "manifest.json", "audit.sqlite3", "report.html"},
        )
        run = load_run(output / "audit.sqlite3")
        self.assertEqual((run.case, run.operator, run.exit_code), ("CASE-01", "Student", 0))
        self.assertEqual(len(run.files), 2)
        regenerated = self.root / "saved-report.html"
        self.assertEqual(self.command("report", "--db", output / "audit.sqlite3", "-o", regenerated)[0], 0)
        self.assertIn("CASE-01", regenerated.read_text())
        connection = sqlite3.connect(output / "audit.sqlite3")
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM files").fetchone()[0], 2)
        finally:
            connection.close()

    def test_roundtrip_zip_and_json(self):
        for container in ("zip", "json"):
            with self.subTest(container=container):
                archive = self.root / ("case." + container)
                args = ["bundle", self.source, "-r", "--format", container, "-o", archive]
                if container == "json":
                    args.append("--compress")
                code, _, errors = self.command(*args)
                self.assertEqual(code, 0, errors)
                self.assertEqual(self.command("verify", archive, "--workers", 2)[0], 0)
                output = self.root / ("restore-" + container)
                self.assertEqual(self.command("extract", archive, "-o", output)[0], 0)
                for source in self.source.rglob("*"):
                    if source.is_file():
                        self.assertEqual(source.read_bytes(), (output / source.relative_to(self.source)).read_bytes())

    def test_multiple_roots_preserve_file_identity(self):
        other = self.root / "other"
        other.mkdir()
        (other / "note.txt").write_bytes(b"different case note")
        archive = self.root / "roots.zip"
        self.assertEqual(self.command("bundle", self.source, other, "-r", "-o", archive)[0], 0)
        with zipfile.ZipFile(archive) as reader:
            self.assertIn("files/source/note.txt", reader.namelist())
            self.assertIn("files/other/note.txt", reader.namelist())
        self.assertEqual(self.command("verify", archive)[0], 0)

    def test_legacy_json_archive(self):
        archive, value = self.json_archive()
        value["vault_format"] = "1.0"
        value.pop("hash_algo")
        value["files"][0]["sha256"] = value["files"][0].pop("hash")
        archive.write_text(json.dumps(value))
        self.assertEqual(self.command("verify", archive)[0], 0)

    def test_all_hash_algorithms(self):
        for algorithm in ("sha256", "blake2b", "blake2s", "sha1", "md5"):
            with self.subTest(algorithm=algorithm):
                archive = self.root / (algorithm + ".zip")
                self.assertEqual(self.command("bundle", self.source, "-o", archive, "--hash-algo", algorithm)[0], 0)
                self.assertEqual(self.command("verify", archive)[0], 0)

    def test_md5_only_inventory_keeps_the_digest(self):
        output = self.root / "md5.json"
        self.assertEqual(self.command("hash", self.source, "--algo", "md5", "-o", output)[0], 0)
        rows = json.loads(output.read_text())["files"]
        self.assertEqual(rows[0]["hash"], hashlib.md5(b"case note\n").hexdigest())

    def test_second_hash_is_recorded(self):
        output = self.root / "both.json"
        self.assertEqual(self.command("hash", self.source, "--md5", "-o", output)[0], 0)
        row = json.loads(output.read_text())["files"][0]
        self.assertEqual(row["hash"], hashlib.sha256(b"case note\n").hexdigest())
        self.assertEqual(row["md5"], hashlib.md5(b"case note\n").hexdigest())

    def test_stream_codec_boundaries(self):
        payload = bytes(range(256)) * (CHUNK_SIZE // 256 + 1) + b"end"
        source = self.root / "bytes.bin"
        source.write_bytes(payload)
        for codec in CODECS:
            for compress in (False, True):
                with self.subTest(codec=codec, compress=compress):
                    encoded = self.root / ("encoded-" + codec + str(compress))
                    args = ["encode", source, "-e", codec, "-o", encoded]
                    if compress:
                        args.append("--compress")
                    code, _, errors = self.command(*args)
                    self.assertEqual(code, 0, errors)
                    restored = self.root / ("decoded-" + codec + str(compress))
                    args = ["decode", encoded, "-o", restored]
                    if compress:
                        args.append("--decompress")
                    code, _, errors = self.command(*args)
                    self.assertEqual(code, 0, errors)
                    self.assertEqual((restored / "bytes.bin").read_bytes(), payload)

    def test_empty_file_roundtrip(self):
        source = self.root / "empty.bin"
        source.write_bytes(b"")
        archive = self.root / "empty.zip"
        self.assertEqual(self.command("bundle", source, "-o", archive)[0], 0)
        self.assertEqual(self.command("verify", archive)[0], 0)
        output = self.root / "empty-out"
        self.assertEqual(self.command("extract", archive, "-o", output)[0], 0)
        self.assertEqual((output / "empty.bin").read_bytes(), b"")

    def test_sort_and_rename_keep_sources(self):
        original = {str(path): path.read_bytes() for path in self.source.rglob("*") if path.is_file()}
        sorted_output = self.root / "sorted"
        self.assertEqual(self.command("sort", self.source, "-r", "-o", sorted_output)[0], 0)
        self.assertTrue((sorted_output / "image/sub/image.png").is_file())
        renamed = self.root / "renamed"
        self.assertEqual(self.command("rename", self.source, "-r", "-o", renamed, "--pattern", "EVID_{n:04d}{ext}")[0], 0)
        for name, contents in original.items():
            self.assertEqual(Path(name).read_bytes(), contents)
        connection = sqlite3.connect(renamed / "audit.sqlite3")
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM events WHERE action = 'complete'").fetchone()[0], 2)
        finally:
            connection.close()

    def test_folder_names_change_only_in_the_copy(self):
        output = self.root / "folders"
        code, _, errors = self.command("rename", self.source, "-r", "--folders", "-o", output, "--pattern", "EVID_{n:04d}{ext}")
        self.assertEqual(code, 0, errors)
        self.assertTrue((output / "EVID_0001/EVID_0002.png").is_file())
        self.assertTrue((self.source / "sub/image.png").is_file())

    def test_dry_run_has_no_output_files(self):
        before = set(self.root.rglob("*"))
        code, _, errors = self.command("rename", self.source, "-r", "-o", self.root / "preview", "--dry-run")
        self.assertEqual(code, 0, errors)
        self.assertEqual(set(self.root.rglob("*")), before)

    def test_in_place_rename_has_a_saved_event(self):
        database = self.root / "audit.sqlite3"
        code, _, errors = self.command(
            "rename", self.source, "--in-place", "--db", database,
            "--pattern", "EVID_{n:04d}{ext}",
        )
        self.assertEqual(code, 0, errors)
        self.assertFalse((self.source / "note.txt").exists())
        self.assertEqual((self.source / "EVID_0001.txt").read_bytes(), b"case note\n")
        self.assertEqual(load_run(database).exit_code, 0)

    def test_signature_has_priority_over_extension(self):
        source = self.root / "capture.txt"
        source.write_bytes(b"%PDF-1.7\nexample")
        output = self.root / "types"
        self.assertEqual(self.command("sort", source, "-o", output)[0], 0)
        self.assertTrue((output / "document/capture.txt").is_file())

    def test_duplicate_contents_are_reported(self):
        (self.source / "copy.txt").write_bytes(b"case note\n")
        output = self.root / "case"
        self.assertEqual(self.command("collect", self.source, "-o", output)[0], 0)
        text = (output / "report.html").read_text()
        self.assertIn("Same contents as another listed file.", text)

    def test_report_escapes_untrusted_text(self):
        result = RunResult("verify", case="<script>alert(1)</script>", operator='" onload="bad')
        result.files.append(FileResult(path="<img src=x onerror=bad>", note="<script>bad</script>"))
        result.finish()
        output = self.root / "escaped.html"
        create_report(result, output)
        text = output.read_text()
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn("<img src=x", text)
        self.assertIn("Content-Security-Policy", text)

    def test_guided_case_workflow(self):
        output = self.root / "guided"
        values = iter(["1", str(self.source), str(output), "SCHOOL-01", "Student", ""])
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=lambda _: next(values)):
            code, _, errors = self.command("wizard")
        self.assertEqual(code, 0, errors)
        self.assertTrue((output / "report.html").is_file())

    def test_noninteractive_start_does_not_wait_for_input(self):
        with patch("sys.stdin.isatty", return_value=False), patch("builtins.input", side_effect=AssertionError("Unexpected input request")):
            self.assertEqual(self.command()[0], 0)
            self.assertEqual(self.command("wizard")[0], 1)

    def test_json_paths_cannot_escape(self):
        for name in ("../outside.txt", "/tmp/outside.txt", "C:/outside.txt", "sub\\outside.txt", "sub/../outside.txt", "CON.txt"):
            with self.subTest(name=name):
                archive, _ = self.json_archive(paths=(name,))
                output = self.root / "restore"
                self.assertNotEqual(self.command("extract", archive, "-o", output)[0], 0)
                self.assertFalse(output.exists())
        self.assertFalse((self.root / "outside.txt").exists())

    def test_zip_paths_cannot_escape(self):
        _, manifest = self.json_archive(paths=("../outside.txt",))
        manifest["container"] = "zip"
        archive = self.root / "unsafe.zip"
        with zipfile.ZipFile(archive, "w") as writer:
            writer.writestr("manifest.json", json.dumps(manifest))
            writer.writestr("files/../outside.txt", b"test")
        self.assertNotEqual(self.command("extract", archive, "-o", self.root / "restore")[0], 0)
        self.assertFalse((self.root / "outside.txt").exists())

    def test_existing_file_is_not_replaced(self):
        archive, _ = self.json_archive()
        output = self.root / "restore"
        output.mkdir()
        (output / "note.txt").write_bytes(b"previous evidence")
        self.assertNotEqual(self.command("extract", archive, "-o", output)[0], 0)
        self.assertEqual((output / "note.txt").read_bytes(), b"previous evidence")

    def test_rename_collision_does_not_change_sources(self):
        (self.source / "second.txt").write_bytes(b"second")
        code, _, _ = self.command("rename", self.source, "-o", self.root / "renamed", "--pattern", "same{ext}")
        self.assertNotEqual(code, 0)
        self.assertEqual((self.source / "note.txt").read_bytes(), b"case note\n")
        self.assertEqual((self.source / "second.txt").read_bytes(), b"second")
        self.assertFalse((self.root / "renamed/same.txt").exists())

    def test_case_collision_is_rejected(self):
        archive, _ = self.json_archive(paths=("FILE.txt", "file.txt"))
        self.assertNotEqual(self.command("extract", archive, "-o", self.root / "restore")[0], 0)
        self.assertFalse((self.root / "restore").exists())

    def test_file_parent_collision_is_rejected(self):
        archive, _ = self.json_archive(paths=("file.txt", "file.txt/child"))
        self.assertNotEqual(self.command("verify", archive)[0], 0)

    def test_contradictory_empty_manifest_fails(self):
        archive, _ = self.json_archive(paths=(), file_count=99, total_raw_bytes=12345)
        self.assertNotEqual(self.command("verify", archive)[0], 0)

    def test_invalid_encoding_fails_without_a_write(self):
        archive, value = self.json_archive()
        value["files"][0]["encoding"] = "unknown"
        archive.write_text(json.dumps(value))
        self.assertNotEqual(self.command("extract", archive, "-o", self.root / "restore")[0], 0)
        self.assertFalse((self.root / "restore").exists())

    def test_mismatch_has_exit_three_and_no_file(self):
        archive, value = self.json_archive()
        value["files"][0]["hash"] = "0" * 64
        archive.write_text(json.dumps(value))
        output = self.root / "restore"
        self.assertEqual(self.command("verify", archive)[0], 3)
        self.assertEqual(self.command("extract", archive, "-o", output)[0], 3)
        self.assertFalse((output / "note.txt").exists())

    def test_declared_size_is_checked(self):
        archive, value = self.json_archive()
        value["files"][0]["size"] = 1
        value["total_raw_bytes"] = 1
        archive.write_text(json.dumps(value))
        self.assertEqual(self.command("extract", archive, "-o", self.root / "restore")[0], 3)
        self.assertFalse((self.root / "restore/note.txt").exists())

    def test_decompression_output_is_bounded(self):
        archive, value = self.json_archive(payload=b"a")
        value["files"][0]["compressed"] = True
        value["files"][0]["data"] = base64.b64encode(zlib.compress(b"a" * (CHUNK_SIZE * 3))).decode()
        archive.write_text(json.dumps(value))
        self.assertEqual(self.command("extract", archive, "-o", self.root / "restore")[0], 3)
        self.assertFalse((self.root / "restore/note.txt").exists())

    def test_size_limit_is_checked_before_extraction(self):
        archive, _ = self.json_archive()
        output = self.root / "restore"
        self.assertNotEqual(self.command("extract", archive, "-o", output, "--max-file-bytes", 1)[0], 0)
        self.assertFalse(output.exists())

    def test_missing_source_does_not_produce_an_archive(self):
        output = self.root / "case.zip"
        self.assertNotEqual(self.command("bundle", self.source, self.root / "missing", "-o", output)[0], 0)
        self.assertFalse(output.exists())

    def test_output_inside_source_is_rejected(self):
        output = self.source / "case"
        self.assertNotEqual(self.command("collect", self.source, "-o", output)[0], 0)
        self.assertFalse(output.exists())

    def test_case_rerun_does_not_replace_outputs(self):
        output = self.root / "case"
        self.assertEqual(self.command("collect", self.source, "-o", output)[0], 0)
        original = (output / "case.vault.zip").read_bytes()
        self.assertNotEqual(self.command("collect", self.source, "-o", output)[0], 0)
        self.assertEqual((output / "case.vault.zip").read_bytes(), original)

    def test_changed_source_does_not_publish_a_copy(self):
        source = self.root / "changing.bin"
        source.write_bytes(b"original")
        def changing_blocks(stream):
            yield stream.read()
            source.write_bytes(b"changed contents")
        with patch("evidencevault.operations.raw_blocks", changing_blocks):
            self.assertNotEqual(self.command("sort", source, "-o", self.root / "sorted")[0], 0)
        self.assertFalse((self.root / "sorted/other/changing.bin").exists())

    def test_invalid_base64_does_not_publish_a_file(self):
        source = self.root / "bad.b64"
        source.write_bytes(b"aGVsbG8=JUNK")
        self.assertNotEqual(self.command("decode", source, "-o", self.root / "decoded")[0], 0)
        self.assertFalse((self.root / "decoded/bad").exists())

    def test_csv_file_names_cannot_start_a_formula(self):
        source = self.root / "=formula.txt"
        source.write_bytes(b"safe")
        output = self.root / "manifest.csv"
        self.assertEqual(self.command("hash", source, "-o", output)[0], 0)
        self.assertIn("'=formula.txt", output.read_text())

    @unittest.skipUnless(hasattr(os, "symlink"), "The system has no symbolic links.")
    def test_input_and_output_links_are_rejected(self):
        target = self.root / "real"
        target.mkdir()
        link = self.root / "link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("The account cannot create symbolic links.")
        archive, _ = self.json_archive()
        self.assertNotEqual(self.command("extract", archive, "-o", link)[0], 0)
        self.assertFalse((target / "note.txt").exists())
        (self.source / "link.txt").symlink_to(self.source / "note.txt")
        self.assertNotEqual(self.command("bundle", self.source, "-o", self.root / "links.zip")[0], 0)

    def test_failed_write_removes_the_temporary_file(self):
        output = self.root / "failed.bin"
        with self.assertRaises(RuntimeError):
            with output_writer(output) as stream:
                stream.write(b"incomplete")
                raise RuntimeError("Stop the write.")
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".evidencevault-*.tmp")), [])

    def test_zip_duplicate_and_extra_entries_fail(self):
        _, manifest = self.json_archive()
        manifest["container"] = "zip"
        for extra in ("files/note.txt", "unexpected.txt"):
            with self.subTest(extra=extra):
                archive = self.root / "bad-entries.zip"
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(archive, "w") as writer:
                        writer.writestr("manifest.json", json.dumps(manifest))
                        writer.writestr("files/note.txt", b"test")
                        writer.writestr(extra, b"extra")
                self.assertNotEqual(self.command("verify", archive)[0], 0)

    def test_zip_directory_limit_precedes_directory_allocation(self):
        archive = self.root / "directory.zip"
        self.assertEqual(self.command("bundle", self.source, "-o", archive)[0], 0)
        data = bytearray(archive.read_bytes())
        position = data.rfind(b"PK\x05\x06")
        struct.pack_into("<L", data, position + 12, 64 * 1024 * 1024 + 1)
        archive.write_bytes(data)
        code, _, errors = self.command("verify", archive)
        self.assertNotEqual(code, 0)
        self.assertIn("memory limit", errors)

    def test_zip_readers_are_reused(self):
        for index in range(20):
            (self.source / ("file-" + str(index) + ".txt")).write_text(str(index))
        archive = self.root / "many.zip"
        self.assertEqual(self.command("bundle", self.source, "-o", archive)[0], 0)
        original = zipfile.ZipFile
        with patch("evidencevault.vault.zipfile.ZipFile", wraps=original) as constructor:
            self.assertEqual(self.command("verify", archive, "--workers", 2)[0], 0)
            self.assertLessEqual(constructor.call_count, 3)

    def test_output_dot_components_cannot_bypass_source_separation(self):
        (self.root / "other").mkdir()
        output = self.root / "other" / ".." / "source" / "case"
        self.assertNotEqual(self.command("collect", self.source, "-o", output)[0], 0)
        self.assertFalse((self.source / "case").exists())

    def test_failed_report_is_recorded_in_the_database(self):
        output = self.root / "case"
        with patch("evidencevault.cli.create_report", side_effect=OSError("Report write failed.")):
            self.assertEqual(self.command("collect", self.source, "-o", output)[0], 2)
        self.assertEqual(load_run(output / "audit.sqlite3").exit_code, 2)
        self.assertFalse((output / "report.html").exists())

    def test_changed_source_does_not_publish_an_archive(self):
        @contextmanager
        def changing_source(path):
            with open_source(path) as pair:
                yield pair
                path.write_bytes(b"changed after the read")
        archive = self.root / "changing.zip"
        with patch("evidencevault.vault.open_source", changing_source):
            self.assertNotEqual(self.command("bundle", self.source, "-o", archive)[0], 0)
        self.assertFalse(archive.exists())
        self.assertEqual(list(self.root.glob(".evidencevault-*.tmp")), [])

    def test_in_place_sort_is_stable_on_a_second_run(self):
        for _ in range(2):
            code, _, errors = self.command("sort", self.source, "-r", "--in-place", "--db", self.root / "audit.sqlite3")
            self.assertEqual(code, 0, errors)
        self.assertTrue((self.source / "document/note.txt").is_file())
        self.assertFalse((self.source / "document/document").exists())

    def test_database_hard_link_cannot_change_a_source(self):
        source = self.source / "note.txt"
        database = self.root / "linked.sqlite3"
        try:
            os.link(source, database)
        except OSError:
            self.skipTest("The file system does not support hard links.")
        original = source.read_bytes()
        self.assertNotEqual(self.command("hash", self.source, "--db", database)[0], 0)
        self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
