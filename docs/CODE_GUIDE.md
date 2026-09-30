# Explain the code

EvidenceVault uses Python and its standard library.
Each module has one main responsibility.

| File | Responsibility |
|---|---|
| Evidencevault.py | Start the program with the original file name. |
| evidencevault.py | Start the program with a lowercase file name. |
| evidencevault/cli.py | Read command options and show the guided menu. |
| evidencevault/core.py | Read files, check paths, and publish output files. |
| evidencevault/vault.py | Create archives and check their contents. |
| evidencevault/operations.py | Hash, encode, copy, rename, and sort files. |
| evidencevault/audit.py | Store run results and action records in SQLite. |
| evidencevault/report.py | Convert a run result to safe HTML. |
| evidencevault/report.css | Set the report layout and print style. |
| tests/test_workflows.py | Check complete file operations with temporary data. |

## Follow one case operation

1. The command interface reads the source and output paths.
2. The file planner checks source paths and output separation.
3. The database records the start of the run.
4. The archive writer reads each source file.
5. The writer calculates a hash from the same bytes that enter the ZIP archive.
6. The writer adds the file manifest.
7. The output writer publishes the finished archive.
8. File workers check the archive hashes and sizes.
9. The program writes the inventory and saves the run result.
10. The report module writes the local HTML report.

## Explain the safety checks

A manifest path must be relative.
It cannot contain a parent path component or a Windows drive name.
The program also rejects symbolic links and destination collisions.

The output writer first writes a temporary file.
On supported POSIX systems, it uses folder descriptors and an exclusive hard link.
These checks prevent a symbolic link race and an existing file replacement.

Windows uses a file rename that rejects an existing destination.
Other systems use exclusive file creation.
If a write fails, the program removes its incomplete output file.

The source reader checks file identity, size, and change times after each read.
It rejects a source that changes during the read.

## Explain concurrency

Hash, encode, decode, verify, and working copy tasks use a thread pool.
The queue holds at most two tasks per worker.
The default worker count is at most four.
The operator can select from one to 32 workers.

Each ZIP reader thread has its own archive handle.
It reads the archive directory once.
This avoids a full directory read for every listed file.

The ZIP writer uses one thread.
The ZIP format has one shared output stream.
The writer hashes and compresses each source in one read.

Database writes stay in the command thread.
This avoids a shared database connection between workers.
In-place path changes run in sequence.

## Explain the file type result

The program checks a small set of known file signatures.
It uses the extension if it does not find a known signature.
The result is a category, not a full file analysis.

The report also groups repeated hashes.
This can help an operator find duplicate file contents.
The result is less reliable when the operator selects a legacy hash.

## Explain the limits

The program does not acquire a disk image or recover deleted files.
It does not authenticate a collector or sign a manifest.
It does not encrypt an archive, report, or database.

The recorded modification time remains in the manifest.
Restored files have new file system times and permissions.
Empty folders, access controls, and extended attributes are not collected.

Use separate collection records and preserve the original evidence.
