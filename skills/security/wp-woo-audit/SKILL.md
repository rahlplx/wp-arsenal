---
name: wp-woo-audit
description: >
  Security and integrity audit for WooCommerce stores. Checks REST API key
  scope, payment gateway exposure, webhook HTTPS enforcement, suspicious
  $0 orders, exposed wc-logs (PII/payment data), and coupon abuse.
triggers:
  - WooCommerce audit
  - WooCommerce security
  - store security check
  - check WooCommerce
  - webhook security
  - order anomaly
---

# Skill: wp-woo-audit

Audits a WooCommerce store for the attack surface unique to e-commerce —
beyond what `wp-scan.py` already covers for WordPress core.

## Usage

```bash
# Standard audit
python scripts/security/wp-woo-audit.py --config config/config.yaml

# JSON output (for wp-report.py / wp-digest.py pipelines)
python scripts/security/wp-woo-audit.py --config config/config.yaml --json > logs/woo-audit.json
```

If WooCommerce is not active on the site, the script detects this and exits
cleanly with `woocommerce_active: false` — safe to run unconditionally
across a mixed fleet of WooCommerce and non-WooCommerce sites (see
`wp-multisite.py` / `wp-network-audit.py`).

## What is checked

| Area | Check |
|------|-------|
| **REST API keys** | Flags `read_write`/`write` permission keys (verify still needed); flags never-used keys |
| **Payment gateways** | Scans gateway settings for live API keys, surfaces for manual verification |
| **Webhooks** | Flags any active webhook delivering to a non-HTTPS URL (order data sent in clear) |
| **Orders** | Flags non-cancelled orders with `$0` total — common signature of coupon abuse or checkout exploits |
| **wc-logs** | Flags missing directory-listing protection on `wp-content/uploads/wc-logs/` — these logs can contain customer PII and raw gateway request/response payloads |
| **Coupons** | Flags coupons with unusually high usage counts (>100) for manual review |

## When to run

- After any security incident on a store site — payment data exposure has
  legal/compliance implications (PCI-DSS) beyond a typical WP hack
- Quarterly, as part of routine `wp-network-audit.py` / maintenance cycles
- Before/after a WooCommerce or payment gateway plugin update
- Immediately if you suspect coupon or checkout abuse (sudden revenue drop,
  customer complaints about pricing)

## Common findings and what they mean

**`read_write` API key with no recent use**: Either dead and should be
revoked, or actively used by an integration you've lost track of (a former
employee's automation, a discontinued app). Check `description` field to
identify the owner before revoking.

**Non-HTTPS webhook**: Order data — names, addresses, sometimes partial
payment info — is sent in cleartext over the wire. Update the webhook
delivery URL to HTTPS or disable it.

**Unprotected wc-logs**: If `wc-logs` has no `index.php`/`.htaccess` and
is web-accessible, anyone who guesses/finds the log filename (often
predictable, like `gateway_name-hash.log`) can read raw request payloads.
Fix by adding an `index.php` (empty `<?php // Silence is golden.`) or
`.htaccess` with `Deny from all` — or relocate logs outside the webroot
via WooCommerce → Settings → Advanced.

**$0 orders**: Either legitimate (100%-off coupon, manual order, free
product) or a sign of coupon stacking abuse / a checkout calculation bug
being exploited. Cross-reference with the coupon usage findings.

## Related scripts

- `wp-scan.py` / `wp-deep-audit.py` — general WordPress core/plugin audit (run first)
- `wp-user-audit.py` — checks for rogue admin accounts that could be used to create fraudulent orders/coupons
- `wp-report.py` / `wp-digest.py` — aggregate this script's JSON output into reports/alerts
