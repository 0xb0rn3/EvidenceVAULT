"""Read source files, plan file paths, and write results safely."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import tempfile
import unicodedata
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable, Iterable, Iterator
from urllib.parse import quote_from_bytes, unquote_to_bytes

from . import VERSION

CHUNK_SIZE = 1024 * 1024
HASH_ALGOS = ("sha256", "blake2b", "blake2s", "sha1", "md5")
DEFAULT_WORKERS = min(4, os.cpu_count() or 1)
CODECS = {
    "base64": ("b64", base64.b64encode, lambda data: base64.b64decode(data, validate=True)),
    "base64url": (
        "b64u", base64.urlsafe_b64encode,
        lambda data: base64.b64decode(data, altchars=b"-_", validate=True),
    ),
    "base32": ("b32", base64.b32encode, base64.b32decode),
    "base16": ("hex", base64.b16encode, base64.b16decode),
    "base85": ("b85", base64.b85encode, base64.b85decode),
    "ascii85": ("a85", base64.a85encode, base64.a85decode),
    "urlenc": (
        "urlenc", lambda data: quote_from_bytes(data, safe="").encode("ascii"),
        lambda data: unquote_to_bytes(data.decode("ascii")),
    ),
}
EXT_TO_CODEC = {value[0]: name for name, value in CODECS.items()}
WINDOWS_NAMES = {"CON", "PRN", "AUX", "NUL"} | {
    prefix + str(index) for prefix in ("COM", "LPT") for index in range(1, 10)
}


class VaultError(ValueError):
    """Describe an input or file safety problem."""


class IntegrityError(VaultError):
    """Describe a file hash or size mismatch."""


def utc_now() -> str:
    """Return a UTC time with an explicit time zone."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def utc_mtime(value: os.stat_result) -> str:
    return datetime.fromtimestamp(value.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Source:
    path: Path
    relative: str


@dataclass
class FileResult:
    path: str
    destination: str = ""
    status: str = "ok"
    size: int = 0
    digest: str = ""
    algorithm: str = "sha256"
    modified_utc: str = ""
    kind: str = ""
    note: str = ""


@dataclass
class RunResult:
    action: str
    case: str = ""
    operator: str = ""
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started_utc: str = field(default_factory=utc_now)
    finished_utc: str = ""
    version: str = VERSION
    files: list[FileResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    exit_code: int = 0

    def finish(self) -> "RunResult":
        self.finished_utc = utc_now()
        if self.exit_code == 130:
            return self
        if any(row.status == "mismatch" for row in self.files):
            self.exit_code = 3
        elif any(row.status == "error" for row in self.files):
            self.exit_code = 2
        return self

    def to_dict(self) -> dict:
        return asdict(self)


def portable_path(value: str) -> str:
    """Accept only a relative path that is safe on all supported systems."""
    if not isinstance(value, str) or not value or "\\" in value:
        raise VaultError("Use a nonempty relative path with forward slashes.")
    if value.startswith("/") or re.search(r'[<>:"|?*\x00-\x1f]', value):
        raise VaultError("The path contains an absolute path or an invalid character.")
    parts = value.split("/")
    for part in parts:
        if part in ("", ".", "..") or part.endswith((".", " ")):
            raise VaultError("The path contains an unsafe component: " + value)
        if part.split(".")[0].upper() in WINDOWS_NAMES:
            raise VaultError("The path contains a reserved file name: " + value)
        if len(part.encode("utf-8")) > 240:
            raise VaultError("A path component exceeds 240 bytes.")
    return PurePosixPath(value).as_posix()


def path_key(value: str) -> str:
    """Compare paths without a case or Unicode normalization difference."""
    return unicodedata.normalize("NFC", value).casefold()


def check_unique(paths: Iterable[str]) -> None:
    keys = set()
    for value in paths:
        key = path_key(portable_path(value))
        if key in keys:
            raise VaultError("Two files have the same destination path: " + value)
        keys.add(key)
    for key in keys:
        parts = key.split("/")
        if any("/".join(parts[:index]) in keys for index in range(1, len(parts))):
            raise VaultError("A file path is also a parent folder: " + key)


def reject_symlinks(path: Path) -> None:
    """Reject symbolic links in a path and its parent folders."""
    for current in (path.absolute(), *path.absolute().parents):
        if current.is_symlink():
            raise VaultError("Symbolic links are not allowed: " + str(current))


def check_output_separate(paths: list[str], output: Path) -> None:
    """Keep output files outside the source folders."""
    reject_symlinks(output)
    target = Path(os.path.abspath(output))
    for raw in paths:
        source = Path(os.path.abspath(raw))
        if source.is_dir():
            try:
                target.relative_to(source)
            except ValueError:
                continue
            raise VaultError("Choose an output path outside the source folder.")
        if target == source:
            raise VaultError("The output path is also a source file.")


def collect_sources(paths: list[str], recursive: bool) -> list[Source]:
    """Build the full file list before an operation starts."""
    if not paths:
        raise VaultError("Select at least one source path.")
    sources = []
    seen = set()
    multiple = len(paths) > 1
    for raw in paths:
        root = Path(raw).absolute()
        reject_symlinks(root)
        root = Path(os.path.abspath(root))
        if not root.exists():
            raise VaultError("The source path does not exist: " + str(root))
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = []
            for folder, directories, names in os.walk(root, followlinks=False):
                for name in directories:
                    if (Path(folder) / name).is_symlink():
                        raise VaultError("A source folder contains a symbolic link.")
                for name in names:
                    candidates.append(Path(folder) / name)
                if not recursive:
                    break
        else:
            raise VaultError("Select regular files or folders.")
        for path in sorted(candidates):
            reject_symlinks(path)
            if not stat.S_ISREG(path.stat().st_mode):
                raise VaultError("A source is not a regular file: " + str(path))
            if path in seen:
                raise VaultError("A source file was selected twice: " + str(path))
            seen.add(path)
            relative = path.relative_to(root).as_posix() if root.is_dir() else path.name
            if multiple and root.is_dir():
                relative = root.name + "/" + relative
            sources.append(Source(path, portable_path(relative)))
    if not sources:
        raise VaultError("No regular source files were found.")
    check_unique(source.relative for source in sources)
    return sources


@contextmanager
def open_source(path: Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Check that the same regular file stays in place during a read."""
    reject_symlinks(path)
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise VaultError("The source is not a regular file.")
        yield stream, before
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            raise VaultError("The source file changed during the read: " + str(path))
        reject_symlinks(path)
        # Windows can return different time values for stat and fstat.
        # Compare two file handles with the same metadata method.
        current_descriptor = os.open(path, flags)
        try:
            current = os.fstat(current_descriptor)
        finally:
            os.close(current_descriptor)
        if any(getattr(before, key) != getattr(current, key) for key in fields):
            raise VaultError("The source path changed during the read: " + str(path))


@contextmanager
def output_writer(destination: Path) -> Iterator[BinaryIO]:
    """Write a temporary file. Publish it without replacing an existing file."""
    reject_symlinks(destination)
    destination = Path(os.path.abspath(destination))
    reject_symlinks(destination)
    parent_fd = None
    temporary = ".evidencevault-" + uuid.uuid4().hex + ".tmp"
    published = False
    # Linux uses folder descriptors to block a symbolic link race.
    secure = os.name == "posix" and os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
    try:
        if secure:
            parent_fd = os.open(destination.anchor, os.O_RDONLY | os.O_DIRECTORY)
            for component in destination.parent.parts[1:]:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd,
                )
                os.close(parent_fd)
                parent_fd = next_fd
            descriptor = os.open(
                temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=parent_fd,
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            reject_symlinks(destination)
            descriptor, name = tempfile.mkstemp(prefix=".evidencevault-", dir=destination.parent)
            temporary = Path(name).name
        with os.fdopen(descriptor, "w+b") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        if secure:
            os.link(temporary, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        elif os.name == "nt":
            # Windows rejects an existing destination for this file rename.
            reject_symlinks(destination)
            os.rename(destination.parent / temporary, destination)
        else:
            # Exclusive creation also works on file systems without hard links.
            with open(destination.parent / temporary, "rb") as source:
                with open(destination, "xb") as target:
                    published = True
                    for block in iter(lambda: source.read(CHUNK_SIZE), b""):
                        target.write(block)
                    target.flush()
                    os.fsync(target.fileno())
        published = True
    except BaseException:
        if published and not secure:
            destination.unlink(missing_ok=True)
        raise
    finally:
        if parent_fd is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)
        else:
            (destination.parent / temporary).unlink(missing_ok=True)


def write_json(destination: Path, value: dict, compact: bool = False) -> None:
    import json
    with output_writer(destination) as stream:
        stream.write(json.dumps(value, indent=None if compact else 2, ensure_ascii=True).encode("utf-8"))


def read_blocks(stream: BinaryIO, size: int = CHUNK_SIZE) -> Iterator[memoryview]:
    """Reuse one buffer. Consume each block before the next read."""
    if size >= 8 * CHUNK_SIZE and hasattr(os, "posix_fadvise"):
        try:
            os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_SEQUENTIAL)
        except OSError:
            # A read hint is optional. It must not stop a file operation.
            pass
    buffer = bytearray(max(1, min(size, CHUNK_SIZE)))
    view = memoryview(buffer)
    while True:
        count = stream.readinto(buffer)
        if not count:
            return
        yield view[:count]


def bounded_map(function: Callable, values: Iterable, workers: int) -> Iterator:
    """Keep at most two jobs per worker in the queue."""
    if not 1 <= workers <= 32:
        raise VaultError("Use a worker count from 1 to 32.")
    pending = deque()
    iterator = iter(values)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for _ in range(workers * 2):
            try:
                pending.append(pool.submit(function, next(iterator)))
            except StopIteration:
                break
        while pending:
            yield pending.popleft().result()
            try:
                pending.append(pool.submit(function, next(iterator)))
            except StopIteration:
                pass


def detect_kind(header: bytes, name: str) -> str:
    """Use file signatures first. Use a file extension as a fallback."""
    signatures = (
        (b"\x89PNG\r\n\x1a\n", "image"), (b"\xff\xd8\xff", "image"),
        (b"GIF8", "image"), (b"%PDF-", "document"), (b"PK\x03\x04", "archive"),
        (b"\x1f\x8b", "archive"), (b"SQLite format 3\x00", "database"),
        (b"\x7fELF", "executable"), (b"MZ", "executable"),
    )
    for signature, kind in signatures:
        if header.startswith(signature):
            return kind
    suffix = Path(name).suffix.lower()
    groups = {
        "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".tif", ".bmp", ".heic"},
        "document": {".txt", ".log", ".csv", ".pdf", ".docx", ".xlsx", ".json", ".xml"},
        "archive": {".zip", ".gz", ".tar", ".7z", ".rar", ".xz"},
        "audio": {".mp3", ".wav", ".ogg", ".flac"},
        "video": {".mp4", ".mkv", ".avi", ".mov"},
        "capture": {".pcap", ".pcapng"},
        "encoded": {"." + item for item in EXT_TO_CODEC},
    }
    return next((kind for kind, suffixes in groups.items() if suffix in suffixes), "other")


def hash_source(source: Source, algorithm: str = "sha256", also_md5: bool = False) -> tuple[FileResult, str]:
    digest = hashlib.new(algorithm)
    extra = hashlib.md5() if also_md5 and algorithm != "md5" else None
    header = b""
    with open_source(source.path) as (stream, details):
        for block in read_blocks(stream, details.st_size):
            if not header:
                header = bytes(block[:64])
            digest.update(block)
            if extra is not None:
                extra.update(block)
    row = FileResult(
        path=source.relative, size=details.st_size, digest=digest.hexdigest(),
        algorithm=algorithm, modified_utc=utc_mtime(details),
        kind=detect_kind(header, source.path.name),
    )
    return row, extra.hexdigest() if extra else (row.digest if algorithm == "md5" else "")
