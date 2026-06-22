#!/usr/bin/env python3
"""
wp-woo-audit.py — WooCommerce security & integrity audit
==========================================================
Checks WooCommerce-specific attack surface: REST API keys, payment gateway
config exposure, webhook secrets, suspicious orders/coupons, exposed logs
containing PII/payment data, and outdated core/extension versions.

Usage:
  python wp-woo-audit.py --config config/config.yaml
  python wp-woo-audit.py --config config/config.yaml --json
"""

import argparse
import json
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wp_connect import (
    WPConnection, add_connection_args, connect_from_args, print_banner,
    AuditResult, ok, warn, err, info, section, RED, GREEN, YELLOW, CYAN, BOLD
)

# Permission levels that should never be paired with a key that has no
# IP restriction and full read/write access on a public-facing site.
RISKY_PERMISSIONS = {"read_write", "write"}


def run_audit(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-woo-audit")
    prefix = wp.db_prefix

    # ── A. Is WooCommerce installed/active? ─────────────────────────────
    section("A. WooCommerce presence")
    active_plugins = wp.db(f"SELECT option_value FROM {prefix}options WHERE option_name='active_plugins';")
    if "woocommerce/woocommerce.php" not in active_plugins:
        warn("WooCommerce plugin not found in active_plugins — skipping Woo-specific checks")
        result.stat("woocommerce_active", False)
        return result
    result.stat("woocommerce_active", True)
    ok("WooCommerce is active")

    woo_version = wp.db(
        f"SELECT option_value FROM {prefix}options WHERE option_name='woocommerce_version';"
    ).strip()
    result.stat("woocommerce_version", woo_version)
    info(f"WooCommerce version: {woo_version or 'unknown'}")

    # ── B. REST API keys ─────────────────────────────────────────────────
    section("B. REST API keys")
    if wp.wp_exists("wp-content"):
        keys_raw = wp.db(
            f"SELECT key_id, user_id, description, permissions, truncated_key, "
            f"last_access FROM {prefix}woocommerce_api_keys;"
        )
        lines = keys_raw.splitlines()[1:] if keys_raw else []
        result.stat("api_key_count", len(lines))
        for line in lines:
            cols = line.split("\t")
            if len(cols) < 6:
                continue
            key_id, user_id, desc, perms, trunc, last_access = cols[:6]
            if perms in RISKY_PERMISSIONS:
                result.add(
                    "MEDIUM", "woo-api-key",
                    f"API key '{desc}' (id={key_id}, user={user_id}) has '{perms}' "
                    f"permission — verify this key is still needed and scoped correctly",
                )
            if last_access in ("NULL", "", "0000-00-00 00:00:00"):
                result.add(
                    "LOW", "woo-api-key",
                    f"API key '{desc}' (id={key_id}) has never been used — "
                    f"consider revoking unused keys",
                )
        if not lines:
            ok("No WooCommerce REST API keys configured")
        else:
            ok(f"Found {len(lines)} API key(s) — see findings for risky permissions")

    # ── C. Payment gateway configuration exposure ───────────────────────
    section("C. Payment gateway settings")
    gateway_options = wp.db(
        f"SELECT option_name, option_value FROM {prefix}options "
        f"WHERE option_name LIKE 'woocommerce_%_settings' LIMIT 50;"
    )
    test_mode_live_keys = 0
    for line in gateway_options.splitlines()[1:] if gateway_options else []:
        if "testmode" in line and ("\"testmode\";s:3:\"yes\"" in line or "'testmode'" in line and "yes" in line):
            # test mode enabled — informational, not a finding by itself
            continue
        if re.search(r"sk_live_|pk_live_", line):
            result.add(
                "INFO", "woo-payment",
                "Live Stripe API key detected in gateway settings (expected if site is live; "
                "verify this matches the intended Stripe account)",
            )
    ok("Payment gateway settings scanned")

    # ── D. Webhook secrets ────────────────────────────────────────────────
    section("D. Webhooks")
    webhooks = wp.db(
        f"SELECT webhook_id, name, status, delivery_url FROM {prefix}wc_webhooks;"
    )
    wh_lines = webhooks.splitlines()[1:] if webhooks else []
    result.stat("webhook_count", len(wh_lines))
    for line in wh_lines:
        cols = line.split("\t")
        if len(cols) < 4:
            continue
        wh_id, name, status, url = cols[:4]
        if status == "active" and not url.startswith("https://"):
            result.add(
                "HIGH", "woo-webhook",
                f"Webhook '{name}' (id={wh_id}) delivers to a non-HTTPS URL ({url}) — "
                f"order data is sent unencrypted",
            )
    if wh_lines:
        ok(f"Found {len(wh_lines)} webhook(s)")
    else:
        ok("No webhooks configured")

    # ── E. Suspicious orders ─────────────────────────────────────────────
    section("E. Order anomalies")
    zero_total_orders = wp.db(
        f"SELECT COUNT(*) FROM {prefix}posts p "
        f"JOIN {prefix}postmeta pm ON p.ID = pm.post_id "
        f"WHERE p.post_type IN ('shop_order','shop_order_placehold') "
        f"AND pm.meta_key = '_order_total' AND pm.meta_value = '0' "
        f"AND p.post_status NOT IN ('wc-cancelled','wc-failed');"
    )
    zero_count_match = re.search(r"\d+", zero_total_orders.splitlines()[-1] if zero_total_orders else "0")
    zero_count = int(zero_count_match.group()) if zero_count_match else 0
    result.stat("zero_total_completed_orders", zero_count)
    if zero_count > 0:
        result.add(
            "MEDIUM", "woo-order",
            f"{zero_count} non-cancelled order(s) found with $0 total — "
            f"check for coupon abuse, price manipulation, or checkout exploits",
        )
    else:
        ok("No suspicious $0 orders found")

    # ── F. Exposed logs (PII / payment data) ────────────────────────────
    section("F. WooCommerce logs")
    log_dir = wp.wp("wp-content/uploads/wc-logs")
    if wp.wp_exists("wp-content/uploads/wc-logs"):
        listing = wp.ssh(f"ls -la {shlex.quote(log_dir)} 2>/dev/null | head -20")
        log_count = len([l for l in listing.splitlines() if l.endswith(".log")])
        result.stat("wc_log_files", log_count)
        index_exists = wp.wp_exists("wp-content/uploads/wc-logs/.htaccess") or \
            wp.wp_exists("wp-content/uploads/wc-logs/index.php")
        if not index_exists:
            result.add(
                "HIGH", "woo-logs",
                "wc-logs directory has no index.php/.htaccess protection — "
                "logs may be directly browsable and can contain customer PII / "
                "gateway request payloads",
                path="wp-content/uploads/wc-logs",
            )
        else:
            ok("wc-logs directory has directory-listing protection")
    else:
        ok("No wc-logs directory found")

    # ── G. Coupon abuse check ────────────────────────────────────────────
    section("G. Coupons")
    high_usage_coupons = wp.db(
        f"SELECT p.post_title, pm.meta_value FROM {prefix}posts p "
        f"JOIN {prefix}postmeta pm ON p.ID = pm.post_id "
        f"WHERE p.post_type = 'shop_coupon' AND pm.meta_key = 'usage_count' "
        f"AND CAST(pm.meta_value AS UNSIGNED) > 100 ORDER BY CAST(pm.meta_value AS UNSIGNED) DESC LIMIT 10;"
    )
    coupon_lines = high_usage_coupons.splitlines()[1:] if high_usage_coupons else []
    if coupon_lines:
        for line in coupon_lines:
            cols = line.split("\t")
            if len(cols) >= 2:
                result.add(
                    "LOW", "woo-coupon",
                    f"Coupon '{cols[0]}' has been used {cols[1]} times — verify this is expected",
                )
    else:
        ok("No abnormally high coupon usage detected")

    return result


def main():
    parser = argparse.ArgumentParser(description="WooCommerce security & integrity audit")
    add_connection_args(parser)
    args = parser.parse_args()

    print_banner("WP-ARSENAL — WooCommerce Audit", dry_run=args.dry_run)
    wp = connect_from_args(args)
    try:
        result = run_audit(wp, args)
    finally:
        wp.close()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        result.print_summary()


if __name__ == "__main__":
    main()
