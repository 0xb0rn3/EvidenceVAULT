"""Check the demo with a separate Python process and a local source tree."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / "student project"
        self.examples = self.root / "examples"
        self.examples.mkdir(parents=True)
        project = Path(__file__).resolve().parents[1]
        shutil.copytree(project / "evidencevault", self.root / "evidencevault",
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy2(project / "examples/build_demo.py", self.examples / "build_demo.py")

    def tearDown(self):
        self.directory.cleanup()

    def command(self, arguments, folder):
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        return subprocess.run([sys.executable] + arguments, cwd=str(folder),
                              env=environment, capture_output=True, text=True, timeout=30)

    def check_results(self, output):
        results = json.loads((output / "results.json").read_text(encoding="utf-8"))
        operations = {"collect", "bundle", "verify", "extract", "hash", "encode",
                      "decode", "rename", "sort", "report"}
        self.assertEqual(set(results), operations | {"report_html"})
        for operation in operations:
            self.assertEqual(results[operation]["exit_code"], 0, operation)
            self.assertEqual(len(results[operation]["files"]), 5, operation)
        report = output / "case/report.html"
        self.assertIn("SCHOOL-DEMO-01", report.read_text(encoding="utf-8"))
        for source in (output / "source").rglob("*"):
            if source.is_file():
                relative = source.relative_to(output / "source")
                for folder in ("restored", "decoded"):
                    self.assertEqual(source.read_bytes(), (output / folder / relative).read_bytes())

    def test_direct_start_uses_the_default_output(self):
        result = self.command(["build_demo.py"], self.examples)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.check_results(self.examples / "demo_output")

    def test_module_start_uses_a_selected_output(self):
        result = self.command(["-m", "examples.build_demo", "-o", "selected output"], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.check_results(self.root / "selected output")

    def test_existing_output_is_not_changed(self):
        output = self.examples / "saved files"
        output.mkdir()
        sentinel = output / "keep.txt"
        sentinel.write_bytes(b"Keep this file.\n")
        result = self.command(["build_demo.py", "-o", "saved files"], self.examples)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output folder already exists", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(list(output.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"Keep this file.\n")


if __name__ == "__main__":
    unittest.main()
