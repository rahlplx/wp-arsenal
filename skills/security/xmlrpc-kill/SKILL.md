---
name: xmlrpc-kill
description: >
  MU-plugin that completely disables WordPress XML-RPC at the PHP level.
  Belt-and-suspenders alongside .htaccess blocking. Also removes pingback headers
  and self-pingbacks. Do not use if you run Jetpack.
triggers:
  - disable xmlrpc
  - xmlrpc attack
  - pingback attack
  - xmlrpc brute force
  - disable pingbacks
---

# Skill: xmlrpc-kill (MU-plugin)

Disables WordPress XML-RPC completely — the `xmlrpc_enabled` filter, the
`xmlrpc_call` action hook, pingback headers, and self-pingback functionality.

## Deploy

```bash
cp scripts/hardening/mu-plugins/xmlrpc-kill.php \
   /path/to/wp-content/mu-plugins/
```

No configuration required — deploys and works immediately.

## When to use

- Site is receiving XML-RPC brute-force amplification attacks (`system.multicall`)
- Site is being used as a pingback DDoS reflector
- You don't use Jetpack, WooCommerce API, or any XML-RPC-dependent service
- As part of standard hardening for any new or post-attack site

## When NOT to use

**Jetpack requires XML-RPC.** If you run Jetpack, do not deploy this plugin.
Instead, use `wp-firewall.py` to restrict `xmlrpc.php` to Automattic's IP ranges:

```bash
python scripts/hardening/wp-firewall.py \
    --config config/config.yaml \
    --allow-xmlrpc-ip "192.0.64.0/18,192.0.80.0/20"
```

Other services that use XML-RPC:
- Some older mobile apps
- BlogDesk, MarsEdit, and other desktop blogging clients
- IFTTT (older integrations)

## What it disables

| Feature | How |
|---------|-----|
| XML-RPC API | `xmlrpc_enabled` filter → false |
| Any XML-RPC call | `xmlrpc_call` action → wp_die(403) |
| RSD link in `<head>` | `rsd_link` removed |
| WLW manifest in `<head>` | `wlwmanifest_link` removed |
| `X-Pingback` header | `wp_headers` filter |
| Self-pingbacks | `pre_ping` hook |

## Verify it's working

```bash
curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://yoursite.com/xmlrpc.php \
    -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
# Should return 403
```
