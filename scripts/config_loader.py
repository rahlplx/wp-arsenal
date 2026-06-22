"""
config_loader.py — YAML config loader for WP-Arsenal scripts
=============================================================
Loads config/config.yaml and merges values into argparse Namespace,
with CLI flags always taking priority over the config file.

Usage in any script:
    from config_loader import load_config
    args = load_config(parser.parse_args())
"""

import os
import sys
from argparse import Namespace
from typing import Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# Hosting-provider-specific suppression CIDRs (auto-populated when hosting.provider is set)
_PROVIDER_TRUSTED_CIDRS = {
    "ionos":       ["82.165."],
    "siteground":  ["193.203."],
    "wpengine":    ["104.18.", "195.234."],
    "kinsta":      ["35.227.", "34."],
    "bluehost":    ["162.241."],
    "godaddy":     ["208.109."],
    "namecheap":   ["198.54."],
    "hostgator":   ["174.36."],
    "dreamhost":   ["205.196."],
}


def find_config_file() -> Optional[str]:
    """Walk up directories looking for config/config.yaml."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Look in: script dir, parent, parent/config
    candidates = [
        os.path.join(script_dir, "..", "config", "config.yaml"),
        os.path.join(script_dir, "config", "config.yaml"),
        os.path.join(script_dir, "..", "..", "config", "config.yaml"),
        os.path.join(os.getcwd(), "config", "config.yaml"),
        os.path.join(os.getcwd(), "config.yaml"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.abspath(path)
    return None


def load_config(args: Namespace, config_path: Optional[str] = None) -> Namespace:
    """
    Load YAML config and merge into args.
    CLI args always override config file values.
    Returns the updated Namespace.
    """
    # Honour explicit --config flag if present
    if config_path is None:
        config_path = getattr(args, "config", None)
    if config_path is None:
        config_path = find_config_file()

    if config_path is None:
        return args  # No config file — use CLI args only

    if not _HAS_YAML:
        # Silently skip if PyYAML not installed — user must use CLI flags
        return args

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"  [config] Warning: cannot read {config_path}: {exc}", file=sys.stderr)
        return args

    # ── SSH ────────────────────────────────────────────────────────────
    ssh = cfg.get("ssh", {})
    _set_if_default(args, "host",     ssh.get("host", ""))
    _set_if_default(args, "user",     ssh.get("user", ""))
    _set_if_default(args, "password", ssh.get("password", ""))
    _set_if_default(args, "port",     ssh.get("port", 22))
    _set_if_default(args, "key_file", ssh.get("key_file", ""))

    # ── WordPress ──────────────────────────────────────────────────────
    wp = cfg.get("wordpress", {})
    _set_if_default(args, "wp_path",  wp.get("path", ""))
    _set_if_default(args, "site_url", wp.get("site_url", ""))

    # ── Database ───────────────────────────────────────────────────────
    db = cfg.get("database", {})
    _set_if_default(args, "db_host",   db.get("host", ""))
    _set_if_default(args, "db_user",   db.get("user", ""))
    _set_if_default(args, "db_pass",   db.get("password", ""))
    _set_if_default(args, "db_name",   db.get("name", ""))
    _set_if_default(args, "db_prefix", db.get("prefix", "wp_"))

    # ── Alerts ─────────────────────────────────────────────────────────
    alerts = cfg.get("alerts", {})
    if not getattr(args, "alert_email", ""):
        args.alert_email = alerts.get("email", "")
    if not getattr(args, "alert_bcc", ""):
        args.alert_bcc = alerts.get("bcc", "")

    # ── Trusted / blocked CIDRs ────────────────────────────────────────
    trusted = _normalize_cidr_list(cfg.get("trusted_cidrs", []))
    # Auto-add provider-specific trusted CIDRs
    provider = (cfg.get("hosting", {}) or {}).get("provider", "").lower()
    if provider in _PROVIDER_TRUSTED_CIDRS:
        for cidr in _PROVIDER_TRUSTED_CIDRS[provider]:
            if cidr not in trusted:
                trusted.append(cidr)

    # Normalize: CLI delivers --trusted-cidrs as a raw comma string; config delivers a list.
    # _normalize_cidr_list converts either form to a list of prefix strings.
    existing_trusted = _normalize_cidr_list(getattr(args, "trusted_cidrs", None))
    args.trusted_cidrs = existing_trusted if existing_trusted else trusted

    existing_blocked = _normalize_cidr_list(getattr(args, "blocked_cidrs", None))
    cfg_blocked = _normalize_cidr_list(cfg.get("blocked_cidrs", []))
    args.blocked_cidrs = existing_blocked if existing_blocked else cfg_blocked
    args.hosting_provider = getattr(args, "hosting_provider", "") or provider

    # ── Sibling sites ──────────────────────────────────────────────────
    args.sibling_sites = getattr(args, "sibling_sites", []) or (cfg.get("sibling_sites", []) or [])

    return args


def _normalize_cidr_list(raw) -> list:
    """Convert a CLI comma-string or a config list to a list of CIDR prefix strings."""
    if isinstance(raw, str):
        return [v.strip() for v in raw.split(",") if v.strip()]
    if isinstance(raw, list):
        return [str(v).strip() for v in raw if v]
    return []


def _set_if_default(args: Namespace, attr: str, value) -> None:
    """Set args.attr = value only if the current value is the default (empty/None, or 22 for port)."""
    current = getattr(args, attr, None)
    is_default = current in (None, "", 22) if attr == "port" else current in (None, "")
    if is_default and value not in (None, ""):
        setattr(args, attr, value)


def add_config_arg(parser) -> None:
    """Add --config flag to any argparse parser."""
    parser.add_argument(
        "--config",
        metavar="FILE",
        default=None,
        help="Path to config.yaml (default: auto-detect config/config.yaml)",
    )
