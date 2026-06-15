#!/usr/bin/env python3
"""
wp-digest.py — Weekly multi-site security digest emailer
=========================================================
Reads all JSON logs from a directory, aggregates findings per site,
and sends (or prints) a digest summary. Designed to run weekly after
the wp-multisite.py sweep so you get one consolidated email covering
all managed sites.

Usage:
  # Print digest to terminal (no email sent)
  python scripts/management/wp-digest.py --logs-dir logs/weekly/ --print-only

  # Send email digest via SMTP
  python scripts/management/wp-digest.py \
      --logs-dir logs/weekly/ \
      --to you@example.com \
      --smtp-host mail.example.com \
      --smtp-user you@example.com \
      --smtp-password SECRET

  # Send via config file (reads alerts.email + smtp.* section)
  python scripts/management/wp-digest.py \
      --logs-dir logs/weekly/ \
      --config config/config.yaml

  # Filter to only CRITICAL/HIGH findings
  python scripts/management/wp-digest.py \
      --logs-dir logs/weekly/ \
      --min-severity HIGH --print-only

  # Include only logs from the last N hours (default: 168 = 7 days)
  python scripts/management/wp-digest.py \
      --logs-dir logs/ --hours 24 --print-only
"""

import argparse
import glob
import json
import os
import smtplib
import sys
import time
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
SEV_COLORS = {
    "CRITICAL": ("#7b1313", "#ffd5d5"),
    "HIGH":     ("#7a3300", "#ffe8d0"),
    "MEDIUM":   ("#5a4500", "#fff3c8"),
    "LOW":      ("#1a3a00", "#e6f4d7"),
    "INFO":     ("#1a2e4a", "#ddeeff"),
}


def parse_site_from_filename(path: str) -> str:
    """Extract site label from filename like 20260616-030012-wp-scan-client-site1.json."""
    base = os.path.basename(path).replace(".json", "")
    # Remove timestamp prefix (YYYYMMDD-HHMMSS-) and script name
    parts = base.split("-")
    if len(parts) > 3 and parts[0].isdigit() and parts[1].isdigit():
        # Skip timestamp (parts[0,1]) + script name (parts[2])
        return "-".join(parts[3:]) or base
    return base


def load_logs(logs_dir: str, hours: int, min_severity: str) -> list[dict]:
    """Load JSON log files from dir, filter by age and minimum severity."""
    cutoff = time.time() - hours * 3600
    min_sev_rank = SEV_ORDER.get(min_severity, 99)
    runs = []

    for path in sorted(glob.glob(os.path.join(logs_dir, "*.json"))):
        if os.path.getmtime(path) < cutoff:
            continue
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue

        # Apply min severity filter
        findings = [
            f for f in data.get("findings", [])
            if SEV_ORDER.get(f.get("severity", "INFO"), 99) <= min_sev_rank
        ]
        data["findings"] = findings
        data["_source_file"] = path
        data["_site"] = parse_site_from_filename(path)
        runs.append(data)

    return runs


def group_by_site(runs: list[dict]) -> dict[str, list[dict]]:
    """Group run dicts by site label."""
    grouped: dict[str, list[dict]] = {}
    for run in runs:
        site = run.get("_site", "unknown")
        grouped.setdefault(site, []).append(run)
    return grouped


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts


def render_text_digest(
    grouped: dict[str, list[dict]],
    period_label: str,
    min_severity: str,
) -> str:
    lines = [
        "=" * 62,
        "  WP-ARSENAL WEEKLY SECURITY DIGEST",
        f"  Period: {period_label}",
        f"  Min severity shown: {min_severity}",
        "=" * 62,
    ]

    critical_sites = []
    clean_sites = []

    for site, runs in sorted(grouped.items()):
        all_findings = [f for r in runs for f in r.get("findings", [])]
        counts = count_by_severity(all_findings)
        has_critical = counts["CRITICAL"] > 0 or counts["HIGH"] > 0

        if not all_findings:
            clean_sites.append(site)
            continue

        if has_critical:
            critical_sites.append(site)

        sev_str = "  ".join(
            f"{SEV_EMOJI.get(s, '')} {s}: {n}"
            for s, n in counts.items()
            if n > 0
        )
        lines += [
            "",
            f"── {site} {'⚠️ ACTION NEEDED' if has_critical else ''}",
            f"   {sev_str}",
        ]
        for run in runs:
            script = run.get("script", "?")
            findings = sorted(
                run.get("findings", []),
                key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99)
            )
            if findings:
                lines.append(f"   [{script}]")
                for f in findings[:10]:  # cap at 10 per script
                    sev = f.get("severity", "INFO")
                    cat = f.get("category", "")
                    detail = f.get("detail", "")
                    lines.append(f"     {SEV_EMOJI.get(sev, '')} {cat}: {detail}")
                if len(findings) > 10:
                    lines.append(f"     ... and {len(findings) - 10} more")

    if clean_sites:
        lines += ["", "── Clean sites (no findings)"]
        for s in clean_sites:
            lines.append(f"   ✅ {s}")

    lines += [
        "",
        "=" * 62,
        f"Total sites: {len(grouped)}  |  "
        f"Needs attention: {len(critical_sites)}  |  "
        f"Clean: {len(clean_sites)}",
        "=" * 62,
        "Generated by WP-Arsenal — https://github.com/rahlplx/wp-arsenal",
    ]

    if critical_sites:
        lines.insert(3, f"  ⚠️  SITES NEEDING ATTENTION: {', '.join(critical_sites)}")

    return "\n".join(lines)


def render_html_digest(
    grouped: dict[str, list[dict]],
    period_label: str,
    min_severity: str,
) -> str:
    critical_sites = [
        site for site, runs in grouped.items()
        if any(
            f.get("severity") in ("CRITICAL", "HIGH")
            for r in runs for f in r.get("findings", [])
        )
    ]

    alert_banner = ""
    if critical_sites:
        site_list = ", ".join(f"<strong>{escape(s)}</strong>" for s in critical_sites)
        alert_banner = f"""
        <div style="background:#ffd5d5;border-left:4px solid #c00;padding:12px 16px;
                    border-radius:6px;margin-bottom:20px;color:#7b1313">
          ⚠️ Sites needing immediate attention: {site_list}
        </div>"""

    site_blocks = ""
    for site, runs in sorted(grouped.items()):
        all_findings = [f for r in runs for f in r.get("findings", [])]
        counts = count_by_severity(all_findings)
        has_critical = counts["CRITICAL"] > 0 or counts["HIGH"] > 0
        header_bg = "#ffeaea" if has_critical else "#f0fff4"
        header_color = "#7b1313" if has_critical else "#1a3a00"

        count_pills = " ".join(
            f'<span style="background:{SEV_COLORS[s][1]};color:{SEV_COLORS[s][0]};'
            f'padding:2px 8px;border-radius:4px;font-size:.78rem;font-weight:600">'
            f'{SEV_EMOJI.get(s,"")} {s} {n}</span>'
            for s, n in counts.items() if n > 0
        )
        if not count_pills:
            count_pills = '<span style="color:#3a7d44;font-weight:500">✅ Clean</span>'

        finding_rows = ""
        for run in runs:
            script = run.get("script", "?")
            findings = sorted(
                run.get("findings", []),
                key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99)
            )
            for f in findings[:15]:
                sev = f.get("severity", "INFO")
                fg, bg = SEV_COLORS.get(sev, ("#333", "#eee"))
                cat = escape(f.get("category", ""))
                detail = escape(f.get("detail", ""))
                path = escape(f.get("path", ""))
                finding_rows += (
                    f'<tr><td style="color:#666;font-size:.78rem;white-space:nowrap">'
                    f'{escape(script)}</td>'
                    f'<td><span style="background:{bg};color:{fg};padding:1px 6px;'
                    f'border-radius:3px;font-size:.75rem;font-weight:600">'
                    f'{SEV_EMOJI.get(sev,"")} {sev}</span></td>'
                    f'<td style="font-size:.82rem">{cat}</td>'
                    f'<td style="font-size:.82rem">{detail}'
                    f'{"<br><span style=\\'font-family:monospace;font-size:.75rem;color:#556\\'>" + path + "</span>" if path else ""}'
                    f'</td></tr>'
                )

        table = ""
        if finding_rows:
            table = f"""
            <table style="width:100%;border-collapse:collapse;margin-top:10px">
              <thead>
                <tr style="background:#f8f9fa">
                  <th style="padding:6px 10px;text-align:left;font-size:.78rem;color:#666;width:130px">Script</th>
                  <th style="padding:6px 10px;text-align:left;font-size:.78rem;color:#666;width:110px">Severity</th>
                  <th style="padding:6px 10px;text-align:left;font-size:.78rem;color:#666;width:140px">Category</th>
                  <th style="padding:6px 10px;text-align:left;font-size:.78rem;color:#666">Detail</th>
                </tr>
              </thead>
              <tbody>{finding_rows}</tbody>
            </table>"""

        site_blocks += f"""
        <div style="background:#fff;border-radius:8px;margin-bottom:16px;
                    box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden">
          <div style="background:{header_bg};color:{header_color};padding:10px 16px;
                      font-weight:600;display:flex;align-items:center;gap:12px">
            {escape(site)}
            <span style="font-weight:400;font-size:.82rem">{count_pills}</span>
          </div>
          {table if table else '<div style="padding:10px 16px;color:#3a7d44;font-size:.875rem">✅ No findings</div>'}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP-Arsenal Weekly Digest</title>
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
             background:#f4f6f9;color:#1a1a2e;padding:20px;max-width:860px;margin:0 auto">
  <div style="background:#fff;border-radius:10px;padding:20px 24px;margin-bottom:20px;
              box-shadow:0 1px 4px rgba(0,0,0,.08)">
    <h1 style="font-size:1.4rem;margin-bottom:4px">WP-Arsenal Weekly Security Digest</h1>
    <div style="color:#556;font-size:.85rem">
      Period: {escape(period_label)} &nbsp;·&nbsp; {len(grouped)} sites &nbsp;·&nbsp;
      Min severity: {escape(min_severity)}
    </div>
  </div>
  {alert_banner}
  {site_blocks}
  <div style="text-align:center;color:#999;font-size:.78rem;margin-top:24px">
    Generated by <strong>WP-Arsenal</strong> —
    <a href="https://github.com/rahlplx/wp-arsenal">github.com/rahlplx/wp-arsenal</a>
  </div>
</body>
</html>"""


def load_config_smtp(config_path: str) -> dict:
    """Load SMTP settings from config.yaml if present."""
    if not config_path or not os.path.exists(config_path):
        return {}
    try:
        import yaml
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("smtp", {})
    except Exception:
        return {}


def send_email(
    html_body: str,
    text_body: str,
    subject: str,
    to: str,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_from: str,
    use_tls: bool,
) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from or smtp_user
    msg["To"] = to
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as srv:
        srv.ehlo()
        if use_tls:
            srv.starttls()
            srv.ehlo()
        if smtp_user and smtp_password:
            srv.login(smtp_user, smtp_password)
        srv.sendmail(smtp_from or smtp_user, [to], msg.as_string())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Weekly multi-site security digest"
    )
    parser.add_argument("--logs-dir", dest="logs_dir", required=True,
                        help="Directory containing JSON log files from wp-arsenal scripts")
    parser.add_argument("--hours", type=int, default=168,
                        help="Include logs from last N hours (default: 168 = 7 days)")
    parser.add_argument("--min-severity", dest="min_severity", default="LOW",
                        choices=list(SEV_ORDER),
                        help="Minimum severity to include (default: LOW)")
    parser.add_argument("--print-only", action="store_true",
                        help="Print digest to terminal, do not send email")
    parser.add_argument("--to", default="",
                        help="Recipient email address")
    parser.add_argument("--smtp-host", dest="smtp_host", default="",
                        help="SMTP server hostname")
    parser.add_argument("--smtp-port", dest="smtp_port", type=int, default=587,
                        help="SMTP port (default: 587)")
    parser.add_argument("--smtp-user", dest="smtp_user", default="",
                        help="SMTP username")
    parser.add_argument("--smtp-password", dest="smtp_password", default="",
                        help="SMTP password")
    parser.add_argument("--smtp-from", dest="smtp_from", default="",
                        help="From address (default: smtp-user)")
    parser.add_argument("--no-tls", action="store_true",
                        help="Disable STARTTLS (not recommended)")
    parser.add_argument("--config", default="",
                        help="Config YAML — reads alerts.email and smtp.* section")
    parser.add_argument("--subject", default="",
                        help="Email subject (auto-generated if omitted)")
    args = parser.parse_args()

    # Load SMTP from config if provided
    smtp_cfg = load_config_smtp(args.config)
    smtp_host = args.smtp_host or smtp_cfg.get("host", "")
    smtp_port = args.smtp_port or smtp_cfg.get("port", 587)
    smtp_user = args.smtp_user or smtp_cfg.get("user", "")
    smtp_password = args.smtp_password or smtp_cfg.get("password", "")
    smtp_from = args.smtp_from or smtp_cfg.get("from_addr", "")
    to_addr = args.to

    if not to_addr and args.config:
        try:
            import yaml
            with open(args.config) as f:
                cfg = yaml.safe_load(f) or {}
            to_addr = cfg.get("alerts", {}).get("email", "")
        except Exception:
            pass

    # Load logs
    runs = load_logs(args.logs_dir, args.hours, args.min_severity)
    if not runs:
        print(f"No JSON logs found in {args.logs_dir} (within last {args.hours}h)")
        sys.exit(0)

    grouped = group_by_site(runs)
    now = datetime.now()
    period_label = (
        f"{(now - timedelta(hours=args.hours)).strftime('%Y-%m-%d')} "
        f"to {now.strftime('%Y-%m-%d')}"
    )

    text_digest = render_text_digest(grouped, period_label, args.min_severity)
    html_digest = render_html_digest(grouped, period_label, args.min_severity)

    if args.print_only:
        print(text_digest)
        return

    if not to_addr:
        print("No recipient address — use --to or set alerts.email in config.yaml")
        print("Use --print-only to print digest without sending.")
        print()
        print(text_digest)
        return

    if not smtp_host:
        print("Error: --smtp-host required to send email (or use --print-only)")
        sys.exit(1)

    critical_count = sum(
        1 for runs_list in grouped.values()
        for r in runs_list
        for f in r.get("findings", [])
        if f.get("severity") in ("CRITICAL", "HIGH")
    )
    subject = args.subject or (
        f"[WP-Arsenal] Weekly Digest — {len(grouped)} sites — "
        f"{'⚠️ ACTION NEEDED' if critical_count else '✅ All Clear'} — {now.strftime('%Y-%m-%d')}"
    )

    print(f"Sending digest to {to_addr} via {smtp_host}:{smtp_port}...")
    try:
        send_email(
            html_body=html_digest,
            text_body=text_digest,
            subject=subject,
            to=to_addr,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            smtp_from=smtp_from,
            use_tls=not args.no_tls,
        )
        print(f"Digest sent to {to_addr}")
    except Exception as exc:
        print(f"Error sending email: {exc}", file=sys.stderr)
        print("\nFalling back to terminal output:\n")
        print(text_digest)
        sys.exit(1)


if __name__ == "__main__":
    main()
