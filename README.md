<p align="center">
  <img src="logo.svg" alt="EvidenceVault logo" width="240">
</p>

# EvidenceVault

**Version 1.1.1**

EvidenceVault helps an operator package, check, and organize local case files.
It uses Python and the standard library.
It has no runtime package dependencies or network features.

Use it for working copies of incident response files, investigation notes, screenshots, and other collected material.
Keep the original evidence and separate collection records.

## Start with the guided menu

Get the full repository.
The program now uses small modules. Do not copy only the launcher file.

~~~bash
git clone https://github.com/0xb0rn3/EvidenceVAULT.git
cd EvidenceVAULT
python3 Evidencevault.py
~~~

On Windows, use python instead of python3.
On Termux, install Python with pkg install python.

The menu asks for the source, output, case name, and operator name.
You do not need to remember the command sequence.
Rename and sort actions show their file plan before you start.

You can also use either launcher:

~~~bash
python3 evidencevault.py
python3 -m evidencevault
~~~

If input is not a terminal, the program shows help instead of an input prompt.

## Prepare a case in one command

A hash is a value calculated from file contents.
A manifest lists file paths, sizes, hashes, and recorded times.

~~~bash
python3 Evidencevault.py collect ./case_files \
  -o ./case_output --case CASE-2026-0091 --operator "Your name"
~~~

This command includes subfolders.
It creates these files:

| File | Purpose |
|---|---|
| case.vault.zip | Source file contents and their hash manifest. |
| manifest.json | A separate file inventory. |
| audit.sqlite3 | Run details, file results, and operation records. |
| report.html | A local HTML report with file results and repeated hash groups. |

The command checks the finished archive before it records a successful case.
Select a new output folder for each case package.

## Check and restore a case

~~~bash
python3 Evidencevault.py verify ./case_output/case.vault.zip
python3 Evidencevault.py extract ./case_output/case.vault.zip -o ./restored_files
~~~

The program checks manifest paths, file counts, sizes, and hashes.
It rejects an unsafe path or a destination collision before it writes a restored file.
It never replaces an existing output file.

A file with a wrong hash or size does not become a finished output file.
Other valid files can complete. A partial result has a nonzero exit code.

## Main commands

| Command | Result |
|---|---|
| collect | A checked ZIP case package, inventory, audit database, and HTML report. |
| bundle | A ZIP or JSON case archive. |
| verify | A check of archive structure, file hashes, and file sizes. |
| extract | Checked files in new output paths. |
| hash | A file inventory in JSON or CSV, or hash lines in the terminal. |
| encode | Encoded working copies. |
| decode | Decoded working copies. |
| rename | Working copies with consistent names. |
| sort | Working copies in category, extension, date, or encoding folders. |
| report | An HTML report from an archive or a saved database run. |
| wizard | The guided operator menu. |

Use command help for all options:

~~~bash
python3 Evidencevault.py --help
python3 Evidencevault.py collect --help
python3 Evidencevault.py rename --help
~~~

## Use archives and file inventories

ZIP is the default archive format.
It stores raw file bytes with compression.
The writer hashes the same bytes that enter the archive.

JSON is available for small, text-based transfers.
Its encoded payloads use more space.

~~~bash
python3 Evidencevault.py bundle ./case_files -r -o ./case.vault.zip
python3 Evidencevault.py bundle ./case_files -r --format json --compress -o ./case.vault.json
python3 Evidencevault.py hash ./case_files -r --md5 -o ./manifest.json
~~~

SHA-256 is the default hash.
BLAKE2b and BLAKE2s are also available.
MD5 and SHA-1 remain available for legacy use.
Use SHA-256 for a new case.

The hash command calculates an optional MD5 value in the same file read.
CSV exports protect file names that a spreadsheet could treat as formulas.
These displayed names have an apostrophe prefix.
JSON keeps the exact file names.

If you select several source folders, the archive keeps each folder name.
If two source paths still have the same logical destination, the program stops.
Source roots must have distinct names.

## Encode and decode working copies

A codec converts bytes to an encoded form and back.
Supported codecs are Base64, URL-safe Base64, Base32, Base16, Base85, ASCII85, and URL encoding.

~~~bash
python3 Evidencevault.py encode ./case_files -r -o ./encoded_files
python3 Evidencevault.py decode ./encoded_files -r -o ./decoded_files
~~~

Use --compress for zlib compression before encoding.
Use --decompress to reverse that compression.
Decode can select a codec from the encoded file extension.

Encoding is not encryption.
Anyone with the encoded data can decode it.

## Organize working copies

Rename and sort create copies by default.
They keep the source paths unchanged.
They also create an audit database in the output folder.

~~~bash
python3 Evidencevault.py rename ./case_files -r -o ./renamed_files \
  --pattern "EVID_{n:04d}_{hash}{ext}" --dry-run

python3 Evidencevault.py rename ./case_files -r -o ./renamed_files \
  --pattern "EVID_{n:04d}_{hash}{ext}"

python3 Evidencevault.py sort ./case_files -r -o ./sorted_files --by category
~~~

Rename tokens are {name}, {ext}, {n}, {hash}, {date}, {time}, and {parent}.
The number token supports a format such as {n:04d}.
Date and time tokens use UTC.
Use --folders to rename parent folders in the working copy too.

A dry run does not write files, a database, a report, or a log.
Do not combine --dry-run with an output record option.

An in-place action changes source paths.
Use it only on a working copy.
It requires a database outside the source folder.

~~~bash
python3 Evidencevault.py rename ./working_copy --in-place \
  --db ./records/audit.sqlite3 --pattern "EVID_{n:04d}{ext}"
~~~

In-place actions require hard link support and stay on one file system.
Folder renames require an output folder.
They are not available in place.

## Reports and audit records

Use --db to save a run.
Use --report to write its HTML report.

~~~bash
python3 Evidencevault.py verify ./case.vault.zip \
  --db ./records/audit.sqlite3 --report ./records/check.html

python3 Evidencevault.py report --db ./records/audit.sqlite3 -o ./saved_report.html
python3 Evidencevault.py report ./case.vault.zip -o ./fresh_report.html
~~~

A saved report uses the latest completed database run.
Use --run-id to select a specific run.
A fresh report checks the supplied archive.

Reports include the case name, operator name, UTC run times, hashes, file results, and repeated hash groups.
They use local CSS.
They have no scripts, remote fonts, or network resources.
The report escapes all supplied text.
It has a print layout and a narrow-screen layout.

The file type result uses a small set of known file signatures.
It falls back to the extension.
It does not identify malware or prove the real file format.

The database stores run results and file actions.
Rename and sort save a planned action before each file change.
They save a complete or error action afterward.

These records are not signed or protected against database edits.
A hash manifest alone is not a full chain-of-custody record.

## Safety and resource limits

- Output paths must stay outside source folders, except for an explicit in-place action.
- The program rejects symbolic links and nonregular source files.
- Archive paths must be safe relative paths on Linux, Windows, and macOS.
- The program rejects duplicate paths, case collisions, and file-versus-folder collisions.
- Source files must keep the same identity, size, and change times during each read.
- Most file operations use 1 MiB memory blocks.
- An archive can list at most 100000 files.
- A ZIP manifest can use at most 16 MiB.
- A ZIP directory can use at most 64 MiB.
- A JSON archive can use at most 64 MiB.
- New JSON archives can contain at most 16 MiB of raw file data in total.
- ASCII85 and URL decoding accept at most 16 MiB of encoded input.
- Restored files have a default limit of 2 GiB each and 20 GiB in total.

Use --max-file-bytes and --max-total-bytes to change archive check limits.
These options accept whole byte counts.
Collect accepts the same limits.
Decode accepts --max-file-bytes.

Use --workers to select from one to 32 file workers.
The default is at most four workers.
The task queue holds at most two tasks per worker.
ZIP reads reuse one archive handle per worker.
ZIP creation and in-place path changes run in sequence.
The default ZIP compression level is six.
Use --compression to select a level from one to nine.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The requested operation completed. A dry-run plan can also return zero. |
| 1 | A report input or guided menu request failed. |
| 2 | An input, file operation, or output record failed. Command option errors also use two. |
| 3 | A file hash or payload size did not match. |
| 130 | The operator stopped the command. |

## Scope

EvidenceVault handles existing regular files.
It does not acquire a forensic disk image or recover deleted files.
It does not encrypt files, authenticate an operator, or sign a manifest.

Original modification times remain in the manifest.
Restored files have new file system times and permissions.
The package does not preserve empty folders, access controls, or extended attributes.

A completed case can contain a partial result if a later output record fails.
Check the exit code and report before you hand over a case.

## Tests and code guide

Python 3.8 or a newer version is required.
The target systems are Linux, Windows, macOS, and Termux.
The CI workflow checks Linux, Windows, and macOS with several Python versions.

~~~bash
python3 -m compileall -q evidencevault Evidencevault.py evidencevault.py tests
python3 -m unittest discover -s tests -v
~~~

Read [the code guide](docs/CODE_GUIDE.md) for a module map and a school presentation walkthrough.
Read [the contribution guide](CONTRIBUTING.md) for the code and writing rules.

## Version history

### 1.1.1

- Fixed unsafe extraction paths, output replacement, rename collisions, and false success results.
- Added strict manifest checks and bounded decompression.
- Fixed MD5-only file inventories and source folder identity.
- Added the guided menu and the collect workflow.
- Added SQLite audit records and offline HTML reports.
- Added file signature categories and repeated hash groups.
- Added bounded file workers, streaming codecs, and one-pass ZIP hashing.
- Changed rename and sort to create working copies by default.
- Added modules, file safety tests, and a CI workflow.
- Added a lowercase launcher and a student code guide.

### 1.1.0

Added ZIP archives and more hash algorithm options.

### 1.0.0

Added encoding, JSON archives, hashing, renaming, and sorting.

## Upgrade from 1.1.0

Get the full repository. The launcher now imports the package modules.
Bundle uses ZIP by default. Select --format json for the old container choice.
Encode and decode require an output folder.
Rename and sort require an output folder or an explicit audited in-place action.
Extraction does not support --force.
The unused --timeout option and animated banner were removed.
The old --audit-log option is replaced by the SQLite audit database.

Versions 1.0 and 1.1 JSON archives remain readable when their manifests pass the safety checks.

## Contributors and license

Original project: [DezTheJackal](https://github.com/DezTheJackal).
Version 1.1.1 updates: [0xb0rn3](https://github.com/0xb0rn3), also known as oxbv1.

Apache License 2.0. See [LICENSE](LICENSE).
