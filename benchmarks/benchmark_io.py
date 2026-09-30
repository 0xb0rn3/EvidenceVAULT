"""Measure file planning, native hash workers, and file reads with sample data."""

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path


def measure(function, repeat):
    samples = []
    function()
    for _ in range(repeat):
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter() - start)
    return {"median_seconds": statistics.median(samples), "samples_seconds": samples}


def benchmark(project: Path, workers: int, repeat: int) -> dict:
    sys.path.insert(0, str(project))
    from evidencevault.cli import build_parser
    from evidencevault.core import RunResult, collect_sources, hash_source
    from evidencevault.operations import organize_files
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        small = root / "small"
        large = root / "large"
        small.mkdir()
        large.mkdir()
        for index in range(1500):
            (small / ("note-%04d.txt" % index)).write_bytes(b"sample note\n" * 64)
        block = b"sample bytes\n" * 80660
        for index in range(32):
            with (large / ("file-%02d.bin" % index)).open("wb") as stream:
                for _ in range(4):
                    stream.write(block)
        small_files = collect_sources([str(small)], True)
        large_files = collect_sources([str(large)], True)
        def plan(action, source, files, options):
            args = build_parser().parse_args([action, str(source), "-r", "-o", str(root / "output"),
                                             "--dry-run", "--workers", str(workers)] + options)
            organize_files(files, root / "output", RunResult(action), args, None)
        return {
            "python": platform.python_version(), "system": platform.system(), "workers": workers,
            "repeat": repeat, "cache": "warm", "small_files": 1500, "large_files": 32,
            "large_bytes_per_file": len(block) * 4,
            "extension_plan": measure(lambda: plan("sort", small, small_files, ["--by", "ext"]), repeat),
            "category_plan": measure(lambda: plan("sort", small, small_files, ["--by", "category"]), repeat),
            "hash_name_plan": measure(lambda: plan("rename", large, large_files, ["--pattern", "{n:04d}_{hash}{ext}"]), repeat),
            "single_hash": measure(lambda: hash_source(large_files[0]), repeat),
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--workers", type=int, choices=range(1, 33), default=4)
    parser.add_argument("--repeat", type=int, choices=range(1, 21), default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = benchmark(args.project_root, args.workers, args.repeat)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))
