"""Create case archives and check their file contents."""

from __future__ import annotations

import hashlib
import json
import stat
import struct
import threading
import zipfile
import zlib
from contextlib import ExitStack
from pathlib import Path

from . import VERSION
from .core import (
    CHUNK_SIZE, CODECS, HASH_ALGOS, FileResult, IntegrityError, RunResult, Source,
    VaultError, bounded_map, check_unique, detect_kind, open_source,
    output_writer, portable_path, read_blocks, utc_mtime, utc_now, write_json,
)

MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSON_RAW_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 2 * 1024 ** 3
DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 ** 3
MAX_FILES = 100000


def manifest_for(entries: list[dict], result: RunResult, container: str, algorithm: str) -> dict:
    return {
        "vault_format": "1.1",
        "container": container,
        "tool": "EvidenceVault",
        "tool_version": VERSION,
        "created_utc": utc_now(),
        "case_name": result.case,
        "operator": result.operator,
        "hash_algo": algorithm,
        "file_count": len(entries),
        "total_raw_bytes": sum(entry["size"] for entry in entries),
        "files": sorted(entries, key=lambda entry: entry["path"]),
    }


def json_entry(source: Source, encoding: str, compress: bool, algorithm: str) -> tuple[dict, FileResult]:
    with open_source(source.path) as (stream, details):
        if details.st_size > MAX_JSON_RAW_BYTES:
            raise VaultError("Use the ZIP format for files larger than 16 MiB.")
        raw = stream.read(MAX_JSON_RAW_BYTES + 1)
        if len(raw) > MAX_JSON_RAW_BYTES:
            raise VaultError("The source exceeds the JSON file limit.")
    digest = hashlib.new(algorithm, raw).hexdigest()
    payload = zlib.compress(raw, 6) if compress else raw
    entry = {
        "path": source.relative,
        "encoding": encoding,
        "compressed": compress,
        "hash": digest,
        "size": len(raw),
        "mtime": utc_mtime(details),
        "data": CODECS[encoding][1](payload).decode("ascii"),
    }
    row = FileResult(
        path=source.relative, size=len(raw), digest=digest, algorithm=algorithm,
        modified_utc=entry["mtime"], kind=detect_kind(raw[:64], source.path.name),
    )
    return entry, row


def create_vault(
    sources: list[Source], destination: Path, result: RunResult, container: str = "zip",
    algorithm: str = "sha256", encoding: str = "base64", compress: bool = False,
    workers: int = 4, compression: int = 6, compact: bool = False,
) -> None:
    """Publish an archive only after all source files pass their read checks."""
    entries = []
    if len(sources) > MAX_FILES:
        raise VaultError("A case archive can contain at most 100000 files.")
    if destination.exists():
        raise VaultError("The archive already exists. Select a new output path.")
    if container == "json":
        total = sum(source.path.stat().st_size for source in sources)
        if total > MAX_JSON_RAW_BYTES:
            raise VaultError("Use ZIP when the source files exceed 16 MiB in total.")
        def worker(source):
            return json_entry(source, encoding, compress, algorithm)
        for entry, row in bounded_map(worker, sources, workers):
            row.destination = str(destination)
            entries.append(entry)
            result.files.append(row)
        write_json(destination, manifest_for(entries, result, "json", algorithm), compact)
        return

    with output_writer(destination) as stream:
        with zipfile.ZipFile(
            stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=compression,
        ) as archive:
            for source in sources:
                digest = hashlib.new(algorithm)
                header = b""
                # Hash the same bytes that enter the archive.
                with open_source(source.path) as (reader, details):
                    with archive.open("files/" + source.relative, "w", force_zip64=True) as target:
                        for block in read_blocks(reader, details.st_size):
                            if not header:
                                header = bytes(block[:64])
                            digest.update(block)
                            target.write(block)
                value = digest.hexdigest()
                entries.append({
                    "path": source.relative, "hash": value, "size": details.st_size,
                    "mtime": utc_mtime(details),
                })
                result.files.append(FileResult(
                    path=source.relative, destination=str(destination), size=details.st_size,
                    digest=value, algorithm=algorithm, modified_utc=utc_mtime(details),
                    kind=detect_kind(header, source.path.name),
                ))
            manifest = json.dumps(manifest_for(entries, result, "zip", algorithm), ensure_ascii=True)
            if len(manifest.encode("utf-8")) > MAX_MANIFEST_BYTES:
                raise VaultError("The file manifest exceeds 16 MiB.")
            archive.writestr("manifest.json", manifest)


def check_zip_directory(stream, size: int) -> None:
    """Limit ZIP directory memory before the archive library reads it."""
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        raise VaultError("The ZIP end record is invalid.")
    record = struct.unpack("<4s4H2LH", tail[position:position + 22])
    if position + 22 + record[7] != len(tail):
        raise VaultError("The ZIP end record has an invalid comment length.")
    count, directory_size = record[4], record[5]
    if count == 65535 or directory_size == 0xFFFFFFFF:
        end_position = max(0, size - 65557) + position
        if end_position < 20:
            raise VaultError("The ZIP64 locator is missing.")
        stream.seek(end_position - 20)
        locator = struct.unpack("<4sLQL", stream.read(20))
        if locator[0] != b"PK\x06\x07" or locator[2] > size - 56:
            raise VaultError("The ZIP64 locator is invalid.")
        stream.seek(locator[2])
        large = struct.unpack("<4sQ2H2L4Q", stream.read(56))
        if large[0] != b"PK\x06\x06":
            raise VaultError("The ZIP64 end record is invalid.")
        count, directory_size = large[7], large[8]
    if count > MAX_FILES + 1 or directory_size > 64 * 1024 * 1024:
        raise VaultError("The ZIP directory exceeds its entry count or memory limit.")
    stream.seek(0)


def validate_manifest(value: dict, container: str, max_file: int, max_total: int) -> list[dict]:
    """Check the manifest before a file read or an extraction write."""
    if not isinstance(value, dict):
        raise VaultError("The manifest must be a JSON object.")
    if value.get("vault_format") not in ("1.0", "1.1"):
        raise VaultError("The archive format version is missing or unsupported.")
    if value.get("container", container) != container:
        raise VaultError("The manifest container does not match the archive.")
    algorithm = value.get("hash_algo", "sha256")
    if algorithm not in HASH_ALGOS:
        raise VaultError("The manifest uses an unsupported hash algorithm.")
    entries = value.get("files")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES:
        raise VaultError("The manifest must list from 1 to 100000 files.")
    if type(value.get("file_count")) is not int or value["file_count"] != len(entries):
        raise VaultError("The manifest file count does not match the file list.")
    paths = []
    total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise VaultError("Each manifest entry must be an object.")
        paths.append(portable_path(entry.get("path")))
        size = entry.get("size")
        if type(size) is not int or not 0 <= size <= max_file:
            raise VaultError("A file size is invalid or exceeds the file limit.")
        total += size
        expected = entry.get("hash", entry.get("sha256"))
        length = hashlib.new(algorithm).digest_size * 2
        if not isinstance(expected, str) or len(expected) != length:
            raise VaultError("A file hash has the wrong length.")
        if any(character not in "0123456789abcdef" for character in expected):
            raise VaultError("A file hash must contain lowercase hexadecimal characters.")
        if container == "json":
            if entry.get("encoding") not in CODECS or not isinstance(entry.get("data"), str):
                raise VaultError("A JSON file entry has an invalid encoding or payload.")
            if type(entry.get("compressed", False)) is not bool:
                raise VaultError("The compression flag must be true or false.")
        if not isinstance(entry.get("mtime", ""), str):
            raise VaultError("A file time must be a string.")
    check_unique(paths)
    if total > max_total:
        raise VaultError("The archive exceeds the total output size limit.")
    if type(value.get("total_raw_bytes")) is not int or value["total_raw_bytes"] != total:
        raise VaultError("The manifest total size does not match the listed file sizes.")
    for field in ("case_name", "operator"):
        if value.get(field) is not None and not isinstance(value.get(field), str):
            raise VaultError("The case name and operator must be text.")
    return entries


def decompress_blocks(payload: bytes):
    """Limit each decompression step to one memory block."""
    decoder = zlib.decompressobj()
    for position in range(0, len(payload), CHUNK_SIZE):
        pending = payload[position:position + CHUNK_SIZE]
        while pending:
            block = decoder.decompress(pending, CHUNK_SIZE)
            pending = decoder.unconsumed_tail
            if block:
                yield block
    if not decoder.eof or decoder.unused_data:
        raise IntegrityError("The compressed payload is incomplete or contains extra data.")


class VaultReader:
    """Validate one archive and keep its source file open."""

    def __init__(self, path: Path, max_file: int = DEFAULT_MAX_FILE_BYTES, max_total: int = DEFAULT_MAX_TOTAL_BYTES):
        self.path = path
        self.max_file = max_file
        self.max_total = max_total
        self.stack = ExitStack()
        self.manifest = {}
        self.container = ""
        self.entries = []
        self.local = threading.local()
        self.lock = threading.Lock()

    def __enter__(self):
        try:
            stream, details = self.stack.enter_context(open_source(self.path))
            if zipfile.is_zipfile(stream):
                self.container = "zip"
                check_zip_directory(stream, details.st_size)
                archive = self.stack.enter_context(zipfile.ZipFile(stream))
                members = archive.infolist()
                if len(members) > MAX_FILES + 1:
                    raise VaultError("The ZIP archive contains too many entries.")
                check_unique(member.filename for member in members)
                info = archive.getinfo("manifest.json")
                if info.file_size > MAX_MANIFEST_BYTES:
                    raise VaultError("The ZIP manifest exceeds 16 MiB.")
                self.manifest = json.loads(archive.read(info))
                self.entries = validate_manifest(self.manifest, "zip", self.max_file, self.max_total)
                expected = {"manifest.json"} | {"files/" + entry["path"] for entry in self.entries}
                if set(member.filename for member in members) != expected:
                    raise VaultError("The ZIP entries do not match the manifest.")
                sizes = {entry["path"]: entry["size"] for entry in self.entries}
                for member in members:
                    if stat.S_ISLNK(member.external_attr >> 16) or member.is_dir():
                        raise VaultError("ZIP links and folder entries are not supported.")
                    if member.filename != "manifest.json" and member.file_size != sizes[member.filename[6:]]:
                        raise IntegrityError("A ZIP file size differs from the manifest.")
            else:
                self.container = "json"
                stream.seek(0)
                if details.st_size > MAX_JSON_BYTES:
                    raise VaultError("The JSON archive exceeds 64 MiB. Use ZIP.")
                self.manifest = json.load(stream)
                self.entries = validate_manifest(self.manifest, "json", self.max_file, self.max_total)
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *arguments):
        return self.stack.__exit__(*arguments)

    def worker_archive(self):
        """Read the ZIP directory once per worker, rather than once per file."""
        if not hasattr(self.local, "archive"):
            stack = ExitStack()
            try:
                stream, _ = stack.enter_context(open_source(self.path))
                self.local.archive = stack.enter_context(zipfile.ZipFile(stream))
                with self.lock:
                    self.stack.callback(stack.close)
            except BaseException:
                stack.close()
                raise
        return self.local.archive

    def blocks(self, entry: dict):
        if self.container == "zip":
            with self.worker_archive().open("files/" + entry["path"]) as member:
                for block in iter(lambda: member.read(CHUNK_SIZE), b""):
                    yield block
        else:
            payload = CODECS[entry["encoding"]][2](entry["data"].encode("ascii"))
            if entry.get("compressed"):
                yield from decompress_blocks(payload)
            else:
                for position in range(0, len(payload), CHUNK_SIZE):
                    yield payload[position:position + CHUNK_SIZE]

    def check_entry(self, entry: dict, output=None) -> FileResult:
        algorithm = self.manifest.get("hash_algo", "sha256")
        digest = hashlib.new(algorithm)
        total = 0
        header = b""
        for block in self.blocks(entry):
            total += len(block)
            if total > entry["size"] or total > self.max_file:
                raise IntegrityError("The file payload exceeds its declared size.")
            if not header:
                header = block[:64]
            digest.update(block)
            if output is not None:
                output.write(block)
        if total != entry["size"]:
            raise IntegrityError("The file payload size does not match the manifest.")
        expected = entry.get("hash", entry.get("sha256"))
        if digest.hexdigest() != expected:
            raise IntegrityError("The file hash does not match the manifest.")
        return FileResult(
            path=entry["path"], size=total, digest=digest.hexdigest(), algorithm=algorithm,
            modified_utc=entry.get("mtime", ""), kind=detect_kind(header, entry["path"]),
        )


def check_vault(path: Path, result: RunResult, workers: int, max_file: int, max_total: int) -> None:
    with VaultReader(path, max_file, max_total) as reader:
        result.case = result.case or reader.manifest.get("case_name") or ""
        def worker(entry):
            try:
                return reader.check_entry(entry)
            except Exception as error:
                status = "mismatch" if isinstance(error, IntegrityError) else "error"
                return FileResult(path=entry["path"], status=status, note=str(error))
        result.files.extend(bounded_map(worker, reader.entries, workers))
        result.notes.append("Hashes and sizes were checked. The supplied manifest is not authenticated.")


def extract_vault(
    path: Path, output: Path, result: RunResult, max_file: int, max_total: int,
) -> None:
    with VaultReader(path, max_file, max_total) as reader:
        result.case = result.case or reader.manifest.get("case_name") or ""
        destinations = [(entry, output / entry["path"]) for entry in reader.entries]
        # Check every destination before the first output file is created.
        from .core import reject_symlinks
        for _, destination in destinations:
            reject_symlinks(destination)
            if destination.exists():
                raise VaultError("An extraction destination already exists: " + str(destination))
        for entry, destination in destinations:
            try:
                with output_writer(destination) as stream:
                    row = reader.check_entry(entry, stream)
                row.destination = str(destination)
                result.files.append(row)
            except Exception as error:
                status = "mismatch" if isinstance(error, IntegrityError) else "error"
                result.files.append(FileResult(
                    path=entry["path"], destination=str(destination), status=status, note=str(error),
                ))
        result.notes.append("A failed file was not published. Existing files were not replaced.")
