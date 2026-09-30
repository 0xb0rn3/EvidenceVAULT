"""Create an offline HTML report from a run result."""

from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path

from .core import RunResult, output_writer


def create_report(result: RunResult, destination: Path) -> None:
    """Escape all case text and file names before they enter the HTML."""
    def text(value) -> str:
        return escape(str(value), quote=True)

    counts = Counter(row.status for row in result.files)
    hashes = Counter((row.algorithm, row.digest) for row in result.files if row.digest and row.status == "ok")
    duplicate_groups = sum(count > 1 for count in hashes.values())
    rows = []
    for row in result.files:
        duplicate = hashes[(row.algorithm, row.digest)] > 1 if row.digest else False
        detail = row.note or ("Same contents as another listed file." if duplicate else "")
        css_class = row.status if row.status in ("ok", "error", "mismatch", "planned") else "error"
        rows.append(
            '<tr><td><span class="status ' + css_class + '">' + text(row.status) + "</span></td>"
            "<td><strong>" + text(row.path) + "</strong>"
            + ("<small>Output: " + text(row.destination) + "</small>" if row.destination else "")
            + ("<small>Recorded modification time: " + text(row.modified_utc) + "</small>" if row.modified_utc else "")
            + "</td><td>" + text(row.kind or "Not checked") + "</td>"
            "<td class=\"number\">" + text(f"{row.size:,}") + "</td>"
            "<td><small>" + text(row.algorithm) + "</small><code>" + text(row.digest or "Not recorded")
            + "</code></td><td>" + text(detail) + "</td></tr>"
        )
    notes = "".join("<li>" + text(note) + "</li>" for note in result.notes)
    status = "Complete" if result.exit_code == 0 else "Needs review"
    css = Path(__file__).with_name("report.css").read_text(encoding="utf-8")
    document = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>EvidenceVault report</title>
<style>""" + css + """</style>
</head>
<body>
<header><div class="shell"><p class="label">EvidenceVault """ + text(result.version) + """</p>
<h1>Case file report</h1><p class="subtitle">""" + text(result.case or "No case name") + """</p></div></header>
<main class="shell">
<section class="summary" aria-label="Run summary">
<article><span>Run status</span><strong>""" + status + """</strong></article>
<article><span>Files complete</span><strong>""" + str(counts["ok"]) + """</strong></article>
<article><span>Errors or mismatches</span><strong>""" + str(counts["error"] + counts["mismatch"]) + """</strong></article>
<article><span>Duplicate content groups</span><strong>""" + str(duplicate_groups) + """</strong></article>
</section>
<section class="panel"><h2>Run details</h2><dl>
<div><dt>Action</dt><dd>""" + text(result.action) + """</dd></div>
<div><dt>Operator</dt><dd>""" + text(result.operator or "Not set") + """</dd></div>
<div><dt>Start time (UTC)</dt><dd>""" + text(result.started_utc) + """</dd></div>
<div><dt>End time (UTC)</dt><dd>""" + text(result.finished_utc or "Not set") + """</dd></div>
<div><dt>Run ID</dt><dd><code>""" + text(result.run_id) + """</code></dd></div>
<div><dt>Exit code</dt><dd>""" + str(result.exit_code) + """</dd></div>
</dl></section>
<section class="panel"><h2>File results</h2>
<p>The file hash describes the file contents. The file type is a limited classification.</p>
<div class="table-wrap"><table>
<caption>Results for this run</caption>
<thead><tr><th scope="col">Status</th><th scope="col">File</th><th scope="col">Type</th>
<th scope="col">Bytes</th><th scope="col">Hash</th><th scope="col">Note</th></tr></thead>
<tbody>""" + "".join(rows) + """</tbody></table></div></section>
""" + ('<section class="panel"><h2>Operator notes</h2><ul>' + notes + "</ul></section>" if notes else "") + """
<aside class="notice"><h2>Report limits</h2>
<p>A successful check confirms that listed contents match the supplied hashes and sizes.
It does not prove the source, collector identity, or collection time.</p>
<p>The archive, report, and database are not encrypted or signed.
Keep the original evidence and separate collection records.</p></aside>
</main><footer class="shell">Local report. No network resources or scripts.</footer>
</body></html>
"""
    with output_writer(destination) as stream:
        stream.write(document.encode("utf-8"))
