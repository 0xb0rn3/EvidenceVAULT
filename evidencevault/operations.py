"""Hash, encode, and organize working copies of files."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import string
import zlib
from datetime import datetime, timezone
from pathlib import Path

from .core import (
    CHUNK_SIZE, CODECS, EXT_TO_CODEC, FileResult, RunResult, Source, VaultError,
    bounded_map, check_unique, detect_kind, hash_source, open_source,
    output_writer, portable_path, reject_symlinks, utc_mtime, write_json,
)
from .vault import MAX_JSON_RAW_BYTES


def check_destinations(destinations: list[Path]) -> None:
    keys = set()
    for destination in destinations:
        reject_symlinks(destination)
        key = str(destination.absolute()).casefold()
        if key in keys:
            raise VaultError("Two files have the same output path.")
        keys.add(key)
        if destination.exists():
            raise VaultError("An output file already exists: " + str(destination))


def save_manifest(destination: Path, result: RunResult, extra_hashes: dict | None = None) -> None:
    """Write a file inventory as JSON or CSV."""
    extra_hashes = extra_hashes or {}
    rows = []
    for row in result.files:
        item = {
            "path": row.path, "size_bytes": row.size, "modified_utc": row.modified_utc,
            "algorithm": row.algorithm, "hash": row.digest, "status": row.status, "note": row.note,
        }
        if extra_hashes:
            item["md5"] = extra_hashes.get(row.path, "")
        rows.append(item)
    if destination.suffix.lower() == ".json":
        write_json(destination, {
            "tool": "EvidenceVault", "tool_version": result.version,
            "generated_utc": result.finished_utc or result.started_utc,
            "case_name": result.case, "operator": result.operator,
            "file_count": len(rows), "files": rows,
        })
    else:
        buffer = io.StringIO(newline="")
        fields = list(rows[0]) if rows else ["path", "size_bytes", "algorithm", "hash", "status"]
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            # Prevent a spreadsheet from treating a file name as a formula.
            writer.writerow({
                key: "'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@")) else value
                for key, value in row.items()
            })
        with output_writer(destination) as stream:
            stream.write(buffer.getvalue().encode("utf-8"))


def hash_files(sources: list[Source], result: RunResult, algorithm: str, md5: bool, workers: int) -> dict:
    def worker(source):
        try:
            return hash_source(source, algorithm, md5)
        except Exception as error:
            return FileResult(path=source.relative, status="error", note=str(error)), ""
    extra = {}
    for row, value in bounded_map(worker, sources, workers):
        result.files.append(row)
        if md5:
            extra[row.path] = value
    return extra


def raw_blocks(stream):
    yield from iter(lambda: stream.read(CHUNK_SIZE), b"")


def compressed_blocks(blocks):
    compressor = zlib.compressobj(6)
    for block in blocks:
        value = compressor.compress(block)
        if value:
            yield value
    yield compressor.flush()


def encode_blocks(blocks, encoding: str):
    unit = {"base64": 3, "base64url": 3, "base32": 5, "base85": 4, "ascii85": 4}.get(encoding, 1)
    pending = b""
    for block in blocks:
        pending += block
        length = len(pending) - len(pending) % unit
        if length:
            yield CODECS[encoding][1](pending[:length])
            pending = pending[length:]
    if pending:
        yield CODECS[encoding][1](pending)


def decode_blocks(stream, encoding: str):
    if encoding in ("ascii85", "urlenc"):
        raw = stream.read(MAX_JSON_RAW_BYTES + 1)
        if len(raw) > MAX_JSON_RAW_BYTES:
            raise VaultError("ASCII85 and URL decoding are limited to 16 MiB.")
        if encoding == "urlenc" and re.search(rb"%(?![0-9A-Fa-f]{2})", raw):
            raise VaultError("The URL payload contains an invalid percent sequence.")
        yield CODECS[encoding][2](raw)
        return
    unit = {"base64": 4, "base64url": 4, "base32": 8, "base16": 2, "base85": 5}[encoding]
    pending = b""
    ended = False
    for block in raw_blocks(stream):
        if ended:
            raise VaultError("The encoded payload contains data after its padding.")
        pending += block
        length = len(pending) - len(pending) % unit
        if length:
            value = pending[:length]
            if b"=" in value and encoding in ("base64", "base64url", "base32"):
                ended = True
            yield CODECS[encoding][2](value)
            pending = pending[length:]
            if ended and pending:
                raise VaultError("The encoded payload contains data after its padding.")
    if pending:
        yield CODECS[encoding][2](pending)


def inflate_blocks(blocks):
    decoder = zlib.decompressobj()
    for value in blocks:
        pending = value
        while pending:
            block = decoder.decompress(pending, CHUNK_SIZE)
            pending = decoder.unconsumed_tail
            if block:
                yield block
    if not decoder.eof or decoder.unused_data:
        raise VaultError("The compressed payload is incomplete or contains extra data.")


def transform_files(sources: list[Source], output: Path, result: RunResult, args, decode: bool = False) -> None:
    tasks = []
    for source in sources:
        encoding = args.encoding
        if decode:
            encoding = encoding or EXT_TO_CODEC.get(source.path.suffix.lstrip("."))
            if not encoding:
                raise VaultError("Select an encoding for: " + source.relative)
            suffix = "." + CODECS[encoding][0]
            name = source.path.name[:-len(suffix)] if source.path.name.endswith(suffix) else source.path.name + ".decoded"
        else:
            name = source.path.name + "." + CODECS[encoding][0]
        relative = (Path(source.relative).parent / name).as_posix()
        portable_path(relative)
        tasks.append((source, output / relative, encoding))
    check_destinations([task[1] for task in tasks])

    def worker(task):
        source, destination, encoding = task
        try:
            digest = hashlib.sha256()
            total = 0
            with output_writer(destination) as target:
                with open_source(source.path) as (stream, details):
                    blocks = decode_blocks(stream, encoding) if decode else raw_blocks(stream)
                    if decode:
                        if args.decompress:
                            blocks = inflate_blocks(blocks)
                    else:
                        if args.compress:
                            blocks = compressed_blocks(blocks)
                        blocks = encode_blocks(blocks, encoding)
                    for block in blocks:
                        total += len(block)
                        if decode and total > args.max_file_bytes:
                            raise VaultError("The decoded file exceeds the output size limit.")
                        digest.update(block)
                        target.write(block)
            return FileResult(
                path=source.relative, destination=str(destination), size=total, digest=digest.hexdigest(),
                modified_utc=utc_mtime(details), kind="decoded" if decode else "encoded",
                note="The hash describes the output contents.",
            )
        except Exception as error:
            return FileResult(
                path=source.relative, destination=str(destination), status="error", note=str(error),
            )
    result.files.extend(bounded_map(worker, tasks, args.workers))


def new_name(source: Source, index: int, pattern: str, case: str, hash_length: int, stamp: datetime, folder: bool = False) -> str:
    fields = {
        "name": source.path.name if folder else source.path.stem,
        "ext": "" if folder else source.path.suffix, "n": index,
        "hash": "", "date": stamp.strftime("%Y%m%d"), "time": stamp.strftime("%H%M%S"),
        "parent": source.path.parent.name,
    }
    for _, field, spec, conversion in string.Formatter().parse(pattern):
        if field is not None and (field not in fields or conversion):
            raise VaultError("The rename template contains an unsupported token.")
        if field is not None and spec and (field != "n" or not re.fullmatch(r"0?\d{0,3}d", spec)):
            raise VaultError("Only the file number supports a format such as n:04d.")
    if "{hash}" in pattern and not folder:
        fields["hash"] = hash_source(source)[0].digest[:hash_length]
    name = pattern.format(**fields)
    if not folder and "{ext}" not in pattern and not Path(name).suffix:
        name += source.path.suffix
    if case != "none":
        name = {"lower": str.lower, "upper": str.upper, "title": str.title}[case](name)
    if "/" in name:
        raise VaultError("The rename template must produce a file name.")
    return portable_path(name)


def copy_source(source: Source, destination: Path) -> FileResult:
    digest = hashlib.sha256()
    header = b""
    with output_writer(destination) as target:
        with open_source(source.path) as (stream, details):
            for block in raw_blocks(stream):
                if not header:
                    header = block[:64]
                digest.update(block)
                target.write(block)
    return FileResult(
        path=source.relative, destination=str(destination), size=details.st_size,
        digest=digest.hexdigest(), modified_utc=utc_mtime(details),
        kind=detect_kind(header, source.path.name),
    )


def organize_files(sources: list[Source], output: Path, result: RunResult, args, audit) -> None:
    """Plan the full operation before a copy or an explicit file rename."""
    stamp = datetime.now(timezone.utc)
    plan = []
    folder_names = {}
    if result.action == "rename" and args.folders:
        parents = sorted({
            parent.as_posix()
            for source in sources
            for parent in Path(source.relative).parents
            if parent != Path(".")
        })
        root = Path(args.path).absolute()
        for index, parent in enumerate(parents, start=args.start):
            directory = root / parent
            folder_names[parent] = new_name(
                Source(directory, parent), index, args.pattern, args.case_style,
                args.hash_length, stamp, folder=True,
            )
    for index, source in enumerate(sources, start=getattr(args, "start", 1)):
        if result.action == "rename":
            name = new_name(source, index, args.pattern, args.case_style, args.hash_length, stamp)
            parent = Path(source.relative).parent
            components = [
                folder_names.get(Path(*parent.parts[:number + 1]).as_posix(), part)
                for number, part in enumerate(parent.parts)
            ]
            relative = Path(*components, name).as_posix()
        else:
            with open_source(source.path) as (stream, details):
                kind = detect_kind(stream.read(64), source.path.name)
            if args.by == "ext":
                bucket = source.path.suffix.lower().lstrip(".") or "no_extension"
            elif args.by == "date":
                bucket = datetime.fromtimestamp(details.st_mtime, timezone.utc).strftime("%Y-%m")
            elif args.by == "encoding":
                bucket = EXT_TO_CODEC.get(source.path.suffix.lstrip("."), "unencoded")
            else:
                bucket = kind
            relative = source.relative if source.relative.startswith(bucket + "/") else bucket + "/" + source.relative
        relative = portable_path(relative)
        destination = source.path.with_name(Path(relative).name) if args.in_place else output / relative
        if args.in_place and result.action == "sort":
            destination = output / relative
        plan.append((source, destination, relative))
    check_unique(item[2] for item in plan)
    check_destinations([destination for source, destination, relative in plan if destination != source.path])
    if not args.in_place and not args.dry_run:
        def jobs():
            for source, destination, relative in plan:
                if audit:
                    audit.event(result, "planned", str(source.path), str(destination))
                yield source, destination
        def worker(job):
            source, destination = job
            try:
                return source, copy_source(source, destination)
            except Exception as error:
                return source, FileResult(
                    path=source.relative, destination=str(destination),
                    status="error", note=str(error),
                )
        for source, row in bounded_map(worker, jobs(), args.workers):
            result.files.append(row)
            if audit:
                audit.event(result, "complete" if row.status == "ok" else "error",
                            str(source.path), row.destination, row.digest or row.note)
        result.notes.append("The operation created working copies. The source paths did not change.")
        return
    for source, destination, _ in plan:
        if destination == source.path:
            result.files.append(FileResult(path=source.relative, destination=str(destination), note="The file name did not change."))
            continue
        if args.dry_run:
            result.files.append(FileResult(path=source.relative, destination=str(destination), status="planned"))
            continue
        try:
            if audit:
                audit.event(result, "planned", str(source.path), str(destination))
            if args.in_place:
                row = hash_source(source)[0]
                reject_symlinks(destination)
                destination.parent.mkdir(parents=True, exist_ok=True)
                reject_symlinks(destination)
                # A hard link cannot replace an existing destination.
                os.link(source.path, destination, follow_symlinks=False)
                try:
                    source.path.unlink()
                except BaseException:
                    destination.unlink()
                    raise
                row.destination = str(destination)
            result.files.append(row)
            if audit:
                audit.event(result, "complete", str(source.path), str(destination), row.digest)
        except Exception as error:
            result.files.append(FileResult(
                path=source.relative, destination=str(destination), status="error", note=str(error),
            ))
            if audit:
                audit.event(result, "error", str(source.path), str(destination), str(error))
    result.notes.append(
        "The source files were changed by an explicit in-place operation."
        if args.in_place else "The operation created working copies. The source paths did not change."
    )
