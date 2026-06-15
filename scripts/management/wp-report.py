#!/usr/bin/env python3
"""
wp-report.py — Generate HTML audit reports from WP-Arsenal JSON output
=======================================================================
Reads JSON output from any wp-arsenal script (pass --json flag when running)
and produces a self-contained HTML report: one file, no external dependencies,
opens in any browser, safe to email.

Usage:
  # Generate report from a single scan
  python scripts/security/wp-scan.py --config config/config.yaml --json > logs/scan.json
  python scripts/management/wp-report.py --input logs/scan.json --output reports/scan.html

  # Combine multiple script runs into one report
  python scripts/management/wp-report.py \
      --input logs/scan.json logs/deep-audit.json logs/db-audit.json \
      --output reports/full-audit.html \
      --site-label "example.com — 2026-06-16"

  # Process all JSON files in a directory
  python scripts/management/wp-report.py \
      --input-dir logs/weekly/ \
      --output reports/weekly-summary.html

  # Text format (for terminal or plain email)
  python scripts/management/wp-report.py --input logs/scan.json --format text
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime
from html import escape


# ── Severity config ────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLORS = {
    "CRITICAL": ("#7b1313", "#ffd5d5"),
    "HIGH":     ("#7a3300", "#ffe8d0"),
    "MEDIUM":   ("#5a4500", "#fff3c8"),
    "LOW":      ("#1a3a00", "#e6f4d7"),
    "INFO":     ("#1a2e4a", "#ddeeff"),
}
SEV_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


# ── HTML template ──────────────────────────────────────────────────────────────

HTML_STYLE = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f4f6f9; color: #1a1a2e; padding: 24px; }
  h1 { font-size: 1.6rem; margin-bottom: 4px; color: #0d1b2a; }
  .meta { color: #556; font-size: 0.85rem; margin-bottom: 24px; }
  .summary-grid { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }
  .sev-card { border-radius: 8px; padding: 12px 20px; min-width: 120px; text-align: center; }
  .sev-card .count { font-size: 2rem; font-weight: 700; }
  .sev-card .label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .section { background: #fff; border-radius: 10px; margin-bottom: 20px;
             box-shadow: 0 1px 4px rgba(0,0,0,.08); overflow: hidden; }
  .section-header { padding: 12px 18px; font-weight: 600; font-size: 0.95rem;
                    border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 8px; }
  .section-header .script-name { font-family: monospace; font-size: 0.85rem;
                                  background: #f0f0f0; padding: 2px 8px; border-radius: 4px; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #f8f9fa; text-align: left; padding: 8px 14px;
       font-size: 0.8rem; text-transform: uppercase; color: #666; border-bottom: 1px solid #eee; }
  td { padding: 8px 14px; border-bottom: 1px solid #f0f0f0; font-size: 0.875rem; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .sev-badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
               font-size: 0.75rem; font-weight: 600; white-space: nowrap; }
  .path { font-family: monospace; font-size: 0.78rem; color: #556; word-break: break-all; }
  .stats-table td:first-child { color: #666; width: 200px; }
  .stats-table td:last-child { font-family: monospace; }
  .no-findings { padding: 18px; color: #3a7d44; font-weight: 500; }
  .footer { text-align: center; color: #999; font-size: 0.78rem; margin-top: 32px; }
  @media (max-width: 600px) { body { padding: 12px; } .summary-grid { gap: 8px; } }
</style>
"""


def sev_badge(sev: str) -> str:
    fg, bg = SEV_COLORS.get(sev, ("#333", "#eee"))
    icon = SEV_ICONS.get(sev, "")
    return (f'<span class="sev-badge" style="color:{fg};background:{bg}">'
            f'{icon} {escape(sev)}</span>')


def sev_card(sev: str, count: int) -> str:
    fg, bg = SEV_COLORS.get(sev, ("#333", "#eee"))
    icon = SEV_ICONS.get(sev, "")
    return (f'<div class="sev-card" style="color:{fg};background:{bg}">'
            f'<div class="count">{count}</div>'
            f'<div class="label">{icon} {sev}</div>'
            f'</div>')


def render_html(runs: list[dict], site_label: str, generated_at: str) -> str:
    """Render full HTML report from a list of run dicts."""
    # Aggregate severity counts across all runs
    totals: dict[str, int] = {s: 0 for s in SEV_ORDER}
    for run in runs:
        for f in run.get("findings", []):
            sev = f.get("severity", "INFO")
            if sev in totals:
                totals[sev] += 1

    # Summary grid
    grid = "".join(
        sev_card(sev, totals[sev])
        for sev in SEV_ORDER
        if totals[sev] > 0 or sev in ("CRITICAL", "HIGH")
    )

    # Build sections per run
    sections_html = ""
    for run in runs:
        script = escape(run.get("script", "unknown"))
        findings = sorted(
            run.get("findings", []),
            key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99)
        )
        stats = run.get("stats", {})

        # Findings table
        if findings:
            rows = ""
            for f in findings:
                sev = f.get("severity", "INFO")
                cat = escape(f.get("category", ""))
                detail = escape(f.get("detail", ""))
                path = escape(f.get("path", ""))
                path_cell = f'<div class="path">{path}</div>' if path else ""
                rows += (
                    f"<tr><td>{sev_badge(sev)}</td>"
                    f"<td>{cat}</td>"
                    f"<td>{detail}{path_cell}</td></tr>"
                )
            findings_html = (
                '<table><thead><tr>'
                '<th style="width:110px">Severity</th>'
                '<th style="width:160px">Category</th>'
                '<th>Detail</th>'
                '</tr></thead><tbody>' + rows + '</tbody></table>'
            )
        else:
            findings_html = '<div class="no-findings">✅ No findings — clean</div>'

        # Stats table
        stats_html = ""
        if stats:
            rows = "".join(
                f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>"
                for k, v in stats.items()
            )
            stats_html = (
                '<div style="padding:0 0 0 0">'
                '<table class="stats-table" style="width:auto;min-width:340px">'
                '<thead><tr><th>Stat</th><th>Value</th></tr></thead>'
                '<tbody>' + rows + '</tbody></table></div>'
            )

        sections_html += f"""
        <div class="section">
          <div class="section-header">
            <span class="script-name">{script}</span>
            <span style="color:#888;font-size:.82rem;font-weight:400">
              {len(findings)} finding(s)
            </span>
          </div>
          {findings_html}
          {stats_html}
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP-Arsenal Report — {escape(site_label)}</title>
{HTML_STYLE}
</head>
<body>
<h1>WP-Arsenal Security Report</h1>
<div class="meta">
  <strong>{escape(site_label)}</strong> &nbsp;·&nbsp; Generated {escape(generated_at)}
</div>
<div class="summary-grid">
  {grid}
</div>
{sections_html}
<div class="footer">
  Generated by <strong>WP-Arsenal</strong> &mdash;
  <a href="https://github.com/rahlplx/wp-arsenal">github.com/rahlplx/wp-arsenal</a>
</div>
</body>
</html>"""


def render_text(runs: list[dict], site_label: str, generated_at: str) -> str:
    """Render plain-text report."""
    lines = [
        "=" * 60,
        "WP-ARSENAL SECURITY REPORT",
        f"Site:      {site_label}",
        f"Generated: {generated_at}",
        "=" * 60,
    ]
    for run in runs:
        script = run.get("script", "unknown")
        findings = sorted(
            run.get("findings", []),
            key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99)
        )
        lines.append(f"\n── {script} ──")
        if not findings:
            lines.append("  ✓ No findings")
        for f in findings:
            sev = f.get("severity", "INFO")
            cat = f.get("category", "")
            detail = f.get("detail", "")
            path = f.get("path", "")
            path_str = f"\n      {path}" if path else ""
            lines.append(f"  [{sev:8}] {cat}: {detail}{path_str}")
        stats = run.get("stats", {})
        if stats:
            lines.append("  Stats: " + ", ".join(f"{k}={v}" for k, v in stats.items()))
    lines += ["", "=" * 60]
    return "\n".join(lines)


def load_json_file(path: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as exc:
        print(f"Warning: could not read {path}: {exc}", file=sys.stderr)
        return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Generate HTML or text reports from JSON audit output"
    )
    parser.add_argument("--input", nargs="+", default=[],
                        help="One or more JSON output files from wp-arsenal scripts")
    parser.add_argument("--input-dir", dest="input_dir", default="",
                        help="Directory — load all *.json files from it")
    parser.add_argument("--output", default="",
                        help="Output file path (default: print to stdout)")
    parser.add_argument("--format", choices=["html", "text"], default="html",
                        help="Output format (default: html)")
    parser.add_argument("--site-label", dest="site_label", default="",
                        help="Label shown in report header (e.g. 'example.com')")
    args = parser.parse_args()

    # Collect input files
    input_files = list(args.input)
    if args.input_dir:
        input_files += sorted(glob.glob(os.path.join(args.input_dir, "*.json")))

    if not input_files:
        print("Error: provide --input FILE or --input-dir DIR", file=sys.stderr)
        sys.exit(1)

    runs = []
    for path in input_files:
        data = load_json_file(path)
        if data:
            if "script" not in data:
                data["script"] = os.path.basename(path).replace(".json", "")
            runs.append(data)

    if not runs:
        print("Error: no valid JSON files loaded", file=sys.stderr)
        sys.exit(1)

    site_label = args.site_label or os.path.basename(input_files[0]).replace(".json", "")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if args.format == "html":
        content = render_html(runs, site_label, generated_at)
    else:
        content = render_text(runs, site_label, generated_at)

    if args.output:
        os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Report written to: {args.output}")
    else:
        print(content)


if __name__ == "__main__":
    main()
