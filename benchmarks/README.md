# Measure file planning and reads

Run this command from the repository:

~~~bash
python benchmarks/benchmark_io.py --output ./benchmark-result.json
~~~

The command creates temporary sample files and removes them afterward.
It uses warm file caches and records five timed runs after one warm-up run.
The output file must be new.
Use --workers to change the worker count.
Use --project-root to measure a different checkout with the same script.

## Recorded local result

This result uses Linux, Python 3.12.14, and four workers.
The before checkout has the original version 1.1.1 I/O code.
The after checkout adds the shared read buffer and parallel hash-name planning.
It also removes source content reads from extension, month, and encoding plans.

| Operation | Sample | Before median | After median |
|---|---|---:|---:|
| Extension sort plan | 1500 small files | 120.1 ms | 52.3 ms |
| Category sort plan | 1500 small files | 124.6 ms | 121.7 ms |
| Rename plan with hashes | 32 files of about 4 MiB | 113.6 ms | 32.1 ms |
| One file hash | About 4 MiB | 3.01 ms | 3.08 ms |

The plan measurements exclude source discovery and file copies.
The category plan and single hash result do not show a clear speed change.
These results do not measure physical disk latency or predict all hardware.

Read the complete samples in [the before result](results/linux-python3.12-before.json)
and [the after result](results/linux-python3.12-after.json).

## Native code and Python

The Python interface calls compiled file I/O, hash, and compression routines.
Hash workers can run native hash work at the same time.
Full source reads reuse one memory buffer per active task.
Linux can receive an optional sequential read hint for files of at least 8 MiB.
The hint is ignored if the file system does not support it.

The project does not require a separate compiler or extension build.
Keep source checks, bounded workers, and safe output publication in each measured change.
