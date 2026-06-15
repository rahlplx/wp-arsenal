#!/usr/bin/env python3
"""
wp-multisite.py — Run any WP-Arsenal script across multiple sites
==================================================================
Reads all site config files from config/sites/*.yaml and runs a
specified script against each one in sequence.

Outputs a summary table showing pass/fail per site per script.

Use cases:
  - Weekly security scan across all client sites
  - Mass plugin update sweep
  - Post-incident sweep to find lateral movement across sites

Usage:
  python wp-multisite.py --script wp-scan --sites-dir config/sites/
  python wp-multisite.py --script wp-deep-audit --output-dir logs/
  python wp-multisite.py --script wp-update --args "--all --check-only"
  python wp-multisite.py --script wp-backup --args "--keep 5"
  python wp-multisite.py --sites site1.yaml,site2.yaml --script wp-scan
"""

import argparse
import glob
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import ok, warn, err, info, section, BOLD, GREEN, RED, YELLOW, DIM

SCRIPT_PATHS = {
    "wp-scan":           "scripts/security/wp-scan.py",
    "wp-deep-audit":     "scripts/security/wp-deep-audit.py",
    "wp-shell-nuke":     "scripts/security/wp-shell-nuke.py",
    "wp-chmod-fix":      "scripts/security/wp-chmod-fix.py",
    "wp-harden":         "scripts/hardening/wp-harden.py",
    "wp-firewall":       "scripts/hardening/wp-firewall.py",
    "wp-backup":         "scripts/management/wp-backup.py",
    "wp-update":         "scripts/management/wp-update.py",
    "wp-user-audit":     "scripts/management/wp-user-audit.py",
    "wp-restore-core":   "scripts/restoration/wp-restore-core.py",
    "wp-elementor-fix":  "scripts/restoration/wp-elementor-fix.py",
    "wp-plugin-restore": "scripts/restoration/wp-plugin-restore.py",
    "wp-forensics":      "scripts/forensics/wp-forensics.py",
    "wp-db-audit":       "scripts/forensics/wp-db-audit.py",
    "wp-attacker-profile": "scripts/forensics/wp-attacker-profile.py",
}


def find_repo_root() -> str:
    """Walk up from this script to find the wp-arsenal repo root."""
    d = os.path.dirname(os.path.abspath(__file__))
    while d != os.path.dirname(d):
        if os.path.exists(os.path.join(d, "CLAUDE.md")):
            return d
        d = os.path.dirname(d)
    return os.getcwd()


def run_script_against_site(
    repo_root: str,
    script_name: str,
    config_path: str,
    extra_args: str,
    dry_run: bool,
    output_dir: str,
) -> tuple[str, int, str]:
    """Run script against one site config. Returns (site_label, exit_code, log_path)."""
    site_label = os.path.basename(config_path).replace(".yaml", "").replace(".yml", "")

    rel_path = SCRIPT_PATHS.get(script_name)
    if not rel_path:
        err(f"Unknown script: {script_name}")
        return site_label, 1, ""

    script_abs = os.path.join(repo_root, rel_path)
    if not os.path.exists(script_abs):
        err(f"Script not found: {script_abs}")
        return site_label, 1, ""

    cmd = [sys.executable, script_abs, "--config", config_path]
    if dry_run:
        cmd.append("--dry-run")
    if extra_args:
        cmd.extend(extra_args.split())
    cmd.extend(["--json"])

    log_path = ""
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        log_path = os.path.join(output_dir, f"{ts}-{script_name}-{site_label}.json")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if log_path:
            with open(log_path, "w") as f:
                f.write(proc.stdout)
                if proc.stderr:
                    f.write("\n--- STDERR ---\n")
                    f.write(proc.stderr)
        return site_label, proc.returncode, log_path
    except subprocess.TimeoutExpired:
        return site_label, 124, log_path
    except Exception as exc:
        err(f"  {site_label}: Exception: {exc}")
        return site_label, 1, log_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Run a script across multiple WordPress sites"
    )
    parser.add_argument("--script", required=True,
                        help=f"Script to run. One of: {', '.join(SCRIPT_PATHS)}")
    parser.add_argument("--sites-dir", dest="sites_dir", default="config/sites",
                        help="Directory containing site YAML config files (default: config/sites)")
    parser.add_argument("--sites", default="",
                        help="Comma-separated specific YAML file paths (overrides --sites-dir)")
    parser.add_argument("--args", dest="extra_args", default="",
                        help="Extra arguments to pass to the target script")
    parser.add_argument("--output-dir", dest="output_dir", default="",
                        help="Directory to save JSON output logs per site")
    parser.add_argument("--dry-run", action="store_true",
                        help="Pass --dry-run to each script")
    parser.add_argument("--stop-on-fail", action="store_true",
                        help="Stop the sweep if any site fails")
    args = parser.parse_args()

    repo_root = find_repo_root()

    print(f"\n{BOLD}WP-MULTISITE — {args.script} sweep{DIM}{' [DRY-RUN]' if args.dry_run else ''}\n")

    # Collect site configs
    if args.sites:
        configs = [p.strip() for p in args.sites.split(",") if p.strip()]
    else:
        sites_dir = args.sites_dir
        if not os.path.isabs(sites_dir):
            sites_dir = os.path.join(repo_root, sites_dir)
        configs = sorted(glob.glob(os.path.join(sites_dir, "*.yaml")) +
                         glob.glob(os.path.join(sites_dir, "*.yml")))

    if not configs:
        err(f"No site configs found in {args.sites_dir}")
        sys.exit(1)

    info(f"Running {args.script} against {len(configs)} site(s)...\n")

    results: list[tuple[str, int, str]] = []
    for config_path in configs:
        section(f"Site: {os.path.basename(config_path)}")
        label, code, log_path = run_script_against_site(
            repo_root, args.script, config_path,
            args.extra_args, args.dry_run, args.output_dir,
        )
        results.append((label, code, log_path))
        if code == 0:
            ok(f"  {label}: PASSED (exit 0)")
        else:
            err(f"  {label}: FAILED (exit {code})")
            if args.stop_on_fail:
                warn("Stopping sweep (--stop-on-fail)")
                break

    # Summary table
    print(f"\n{BOLD}{'─'*60}")
    print(f"SWEEP RESULTS — {args.script}")
    print(f"{'─'*60}")
    passed = sum(1 for _, c, _ in results if c == 0)
    failed = sum(1 for _, c, _ in results if c != 0)
    for label, code, log_path in results:
        status = f"{GREEN}PASS{DIM}" if code == 0 else f"{RED}FAIL{DIM}"
        log_note = f"  → {log_path}" if log_path else ""
        print(f"  {status}  {label}{log_note}")
    print(f"{'─'*60}")
    print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
    print(f"{'─'*60}\n")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
