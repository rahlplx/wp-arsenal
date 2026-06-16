<?php
/**
 * WP-Arsenal Admin Guard MU-Plugin
 *
 * Restricts wp-login.php and wp-admin/ to trusted IP ranges at PHP level.
 * Belt-and-suspenders alongside the .htaccess login whitelist from wp-firewall.py.
 *
 * Allows:
 *   - Trusted CIDRs (WP_ARSENAL_TRUSTED_CIDRS) — full admin access
 *   - wp-admin/admin-ajax.php — allowed from any IP (public themes use it)
 *   - wp-admin/admin-post.php — allowed from any IP (form submissions)
 *   - REST API (/wp-json/) — allowed from any IP (headless/API clients)
 *
 * Blocks:
 *   - wp-login.php from untrusted IPs → 403
 *   - wp-admin/*.php (except ajax/post) from untrusted IPs → 403
 *
 * Requires: wp-arsenal-config.php (for WP_ARSENAL_TRUSTED_CIDRS)
 *
 * Deploy:
 *   cp admin-guard.php /path/to/wp-content/mu-plugins/
 */

if (!defined('ABSPATH')) exit;

// Run at priority 1 on init, before anything else loads
add_action('init', 'wp_arsenal_admin_guard', 1);
function wp_arsenal_admin_guard(): void {
    // Only act on admin requests
    if (!is_admin() && !wp_arsenal_ag_is_login_page()) return;

    // Always allow AJAX and admin-post (needed for public site functionality)
    $script = $_SERVER['SCRIPT_FILENAME'] ?? '';
    if (
        str_ends_with($script, '/admin-ajax.php') ||
        str_ends_with($script, '/admin-post.php')
    ) {
        return;
    }

    // REST API — always allow
    $request_uri = $_SERVER['REQUEST_URI'] ?? '';
    if (str_contains($request_uri, '/wp-json/')) return;

    // Check IP
    $ip = wp_arsenal_ag_client_ip();
    if (wp_arsenal_ag_is_trusted($ip)) return;

    // Not trusted — block
    error_log(sprintf(
        '[WP-Arsenal] admin-guard: blocked %s from accessing %s',
        $ip,
        $request_uri
    ));

    status_header(403);
    nocache_headers();
    wp_die(
        '<h2>Access Restricted</h2>'
        . '<p>Administration access from your IP address is not permitted.</p>'
        . '<p>If you are the site owner, add your IP to <code>WP_ARSENAL_TRUSTED_CIDRS</code> '
        . 'in <code>wp-content/mu-plugins/wp-arsenal-config.php</code>.</p>',
        'Access Restricted — 403',
        ['response' => 403, 'back_link' => false]
    );
}


// ── Helpers ────────────────────────────────────────────────────────────────

function wp_arsenal_ag_is_login_page(): bool {
    $script = $_SERVER['SCRIPT_FILENAME'] ?? '';
    return str_ends_with($script, '/wp-login.php');
}

function wp_arsenal_ag_client_ip(): string {
    // Proxy headers (CF-Connecting-IP, X-Forwarded-For) are attacker-controlled
    // unless the connection genuinely passed through a trusted proxy/CDN — trusting
    // them unconditionally lets anyone spoof their way past the IP allowlist below.
    // Only consult them if the site owner has confirmed a trusted proxy is in front
    // by defining WP_ARSENAL_TRUST_PROXY_HEADERS = true in wp-arsenal-config.php.
    if (defined('WP_ARSENAL_TRUST_PROXY_HEADERS') && WP_ARSENAL_TRUST_PROXY_HEADERS) {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $h) {
            $val = $_SERVER[$h] ?? '';
            if ($val) return trim(explode(',', $val)[0]);
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function wp_arsenal_ag_is_trusted(string $ip): bool {
    if (!defined('WP_ARSENAL_TRUSTED_CIDRS') || empty(WP_ARSENAL_TRUSTED_CIDRS)) {
        // Safety valve: if no trusted CIDRs configured, allow all (so admin isn't locked out)
        return true;
    }
    foreach ((array) WP_ARSENAL_TRUSTED_CIDRS as $cidr) {
        if ($cidr && str_starts_with($ip, $cidr)) return true;
    }
    return false;
}
