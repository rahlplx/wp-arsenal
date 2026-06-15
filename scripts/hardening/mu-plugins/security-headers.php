<?php
/**
 * WP-Arsenal Security Headers MU-Plugin
 *
 * Adds HTTP security headers to every WordPress response.
 * Headers are sent before any output — compatible with all themes and plugins.
 *
 * Headers added:
 *   X-Frame-Options: SAMEORIGIN          (clickjacking protection)
 *   X-Content-Type-Options: nosniff      (MIME sniffing protection)
 *   X-XSS-Protection: 1; mode=block     (legacy XSS filter — belt-and-suspenders)
 *   Referrer-Policy: strict-origin-when-cross-origin
 *   Permissions-Policy: camera=(), microphone=(), geolocation=()
 *   Strict-Transport-Security: ...       (HTTPS only — only if HTTPS detected)
 *   Content-Security-Policy: ...         (opt-in via constant — off by default)
 *
 * Override defaults in wp-arsenal-config.php:
 *   define('WP_ARSENAL_HSTS_MAX_AGE',  31536000); // 1 year (default)
 *   define('WP_ARSENAL_CSP_ENABLED',   true);      // enable CSP header
 *   define('WP_ARSENAL_CSP_POLICY',    "default-src 'self'; script-src 'self' 'unsafe-inline'");
 *   define('WP_ARSENAL_X_FRAME',       'DENY');    // or 'SAMEORIGIN' (default)
 *
 * Deploy:
 *   cp security-headers.php /path/to/wp-content/mu-plugins/
 */

if (!defined('ABSPATH')) exit;

// Default constants — override in wp-arsenal-config.php before this file loads
if (!defined('WP_ARSENAL_HSTS_MAX_AGE'))  define('WP_ARSENAL_HSTS_MAX_AGE',  31536000);
if (!defined('WP_ARSENAL_CSP_ENABLED'))   define('WP_ARSENAL_CSP_ENABLED',   false);
if (!defined('WP_ARSENAL_X_FRAME'))       define('WP_ARSENAL_X_FRAME',       'SAMEORIGIN');
if (!defined('WP_ARSENAL_CSP_POLICY'))    define('WP_ARSENAL_CSP_POLICY',
    "default-src 'self'; "
    . "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "   // inline scripts common in WP
    . "style-src 'self' 'unsafe-inline'; "                  // inline styles common in WP
    . "img-src 'self' data: https:; "
    . "font-src 'self' data: https:; "
    . "connect-src 'self' https:; "
    . "frame-ancestors 'self';"
);

add_action('send_headers', 'wp_arsenal_send_security_headers', 1);
function wp_arsenal_send_security_headers(): void {
    // Already sent (e.g. redirect happened)
    if (headers_sent()) return;

    // ── Clickjacking protection ──────────────────────────────────────────
    header('X-Frame-Options: ' . WP_ARSENAL_X_FRAME);

    // ── MIME sniffing protection ─────────────────────────────────────────
    header('X-Content-Type-Options: nosniff');

    // ── Legacy XSS filter (belt-and-suspenders for old browsers) ─────────
    header('X-XSS-Protection: 1; mode=block');

    // ── Referrer policy ───────────────────────────────────────────────────
    header('Referrer-Policy: strict-origin-when-cross-origin');

    // ── Permissions policy ────────────────────────────────────────────────
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');

    // ── HSTS (HTTPS only, only when connection is actually HTTPS) ─────────
    $is_https = (
        (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
        (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
        (isset($_SERVER['HTTP_CF_VISITOR']) && str_contains($_SERVER['HTTP_CF_VISITOR'], '"https"'))
    );
    if ($is_https && WP_ARSENAL_HSTS_MAX_AGE > 0) {
        header('Strict-Transport-Security: max-age=' . (int) WP_ARSENAL_HSTS_MAX_AGE . '; includeSubDomains');
    }

    // ── Content Security Policy (opt-in) ──────────────────────────────────
    if (WP_ARSENAL_CSP_ENABLED) {
        header('Content-Security-Policy: ' . WP_ARSENAL_CSP_POLICY);
    }

    // ── Remove server fingerprinting headers ──────────────────────────────
    header_remove('X-Powered-By');
    header_remove('Server');
}

// Also apply on wp-login.php (which doesn't fire send_headers)
add_action('login_init', 'wp_arsenal_send_security_headers', 1);

// Remove WordPress version from head and feeds
add_filter('the_generator', '__return_empty_string');
remove_action('wp_head', 'wp_generator');
