<?php
/**
 * WP-Arsenal Rate Limiter MU-Plugin
 *
 * Tracks failed login attempts per IP using WP transients.
 * After N failures within a rolling window, blocks further attempts.
 * No database tables required — uses existing transient infrastructure.
 *
 * Thresholds (override in wp-arsenal-config.php):
 *   WP_ARSENAL_RATE_LIMIT_MAX     — max failures before lockout (default: 5)
 *   WP_ARSENAL_RATE_LIMIT_WINDOW  — rolling window in seconds (default: 300 = 5 min)
 *   WP_ARSENAL_RATE_LIMIT_LOCKOUT — lockout duration in seconds (default: 1800 = 30 min)
 *
 * Requires: wp-arsenal-config.php (for WP_ARSENAL_TRUSTED_CIDRS)
 *
 * Deploy:
 *   cp rate-limiter.php /path/to/wp-content/mu-plugins/
 */

if (!defined('ABSPATH')) exit;

// Defaults — override in wp-arsenal-config.php
if (!defined('WP_ARSENAL_RATE_LIMIT_MAX'))     define('WP_ARSENAL_RATE_LIMIT_MAX',     5);
if (!defined('WP_ARSENAL_RATE_LIMIT_WINDOW'))  define('WP_ARSENAL_RATE_LIMIT_WINDOW',  300);
if (!defined('WP_ARSENAL_RATE_LIMIT_LOCKOUT')) define('WP_ARSENAL_RATE_LIMIT_LOCKOUT', 1800);


// ── Helpers ────────────────────────────────────────────────────────────────

function wp_arsenal_rl_client_ip(): string {
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $h) {
        $val = $_SERVER[$h] ?? '';
        if ($val) return trim(explode(',', $val)[0]);
    }
    return '0.0.0.0';
}

function wp_arsenal_rl_is_trusted(string $ip): bool {
    if (!defined('WP_ARSENAL_TRUSTED_CIDRS')) return false;
    foreach ((array) WP_ARSENAL_TRUSTED_CIDRS as $cidr) {
        if (str_starts_with($ip, $cidr)) return true;
    }
    return false;
}

function wp_arsenal_rl_transient_key(string $ip): string {
    return 'wp_arsenal_rl_' . md5($ip);
}

function wp_arsenal_rl_lockout_key(string $ip): string {
    return 'wp_arsenal_lk_' . md5($ip);
}


// ── Block on login page if locked out ────────────────────────────────────

add_action('login_init', 'wp_arsenal_rl_check_lockout', 1);
function wp_arsenal_rl_check_lockout(): void {
    $ip = wp_arsenal_rl_client_ip();
    if (wp_arsenal_rl_is_trusted($ip)) return;

    if (get_transient(wp_arsenal_rl_lockout_key($ip))) {
        $mins = (int) round(WP_ARSENAL_RATE_LIMIT_LOCKOUT / 60);
        wp_die(
            '<h2>Too Many Failed Attempts</h2>'
            . "<p>Your IP has been temporarily blocked due to too many failed login attempts.</p>"
            . "<p>Please try again in approximately {$mins} minutes.</p>",
            'Access Temporarily Blocked',
            ['response' => 429, 'back_link' => false]
        );
    }
}


// ── Record failure ─────────────────────────────────────────────────────────

add_action('wp_login_failed', 'wp_arsenal_rl_record_failure');
function wp_arsenal_rl_record_failure(string $username): void {
    $ip = wp_arsenal_rl_client_ip();
    if (wp_arsenal_rl_is_trusted($ip)) return;

    $key     = wp_arsenal_rl_transient_key($ip);
    $current = (int) get_transient($key);
    $current++;
    set_transient($key, $current, WP_ARSENAL_RATE_LIMIT_WINDOW);

    error_log(sprintf(
        '[WP-Arsenal] rate-limiter: failed login #%d from %s (user: %s)',
        $current, $ip, $username
    ));

    if ($current >= WP_ARSENAL_RATE_LIMIT_MAX) {
        // Set lockout — separate transient so window reset doesn't lift lockout early
        set_transient(wp_arsenal_rl_lockout_key($ip), 1, WP_ARSENAL_RATE_LIMIT_LOCKOUT);
        delete_transient($key);

        error_log(sprintf(
            '[WP-Arsenal] rate-limiter: LOCKED OUT %s for %d seconds after %d failures (user: %s)',
            $ip, WP_ARSENAL_RATE_LIMIT_LOCKOUT, WP_ARSENAL_RATE_LIMIT_MAX, $username
        ));

        // Alert email (if configured)
        if (defined('WP_ARSENAL_ALERT_EMAIL') && WP_ARSENAL_ALERT_EMAIL) {
            $site    = get_option('siteurl', 'unknown');
            $subject = "[WP-Arsenal] Brute-force lockout — {$ip} — {$site}";
            $body    = "IP {$ip} has been locked out after {$current} failed login attempts.\n"
                     . "Last attempted username: {$username}\n"
                     . "Site: {$site}\n"
                     . "Lockout duration: " . round(WP_ARSENAL_RATE_LIMIT_LOCKOUT / 60) . " minutes\n"
                     . "Time: " . date('Y-m-d H:i:s T');
            $headers = ['Content-Type: text/plain; charset=UTF-8'];
            if (defined('WP_ARSENAL_ALERT_BCC') && WP_ARSENAL_ALERT_BCC) {
                $headers[] = 'Bcc: ' . WP_ARSENAL_ALERT_BCC;
            }
            wp_mail(WP_ARSENAL_ALERT_EMAIL, $subject, $body, $headers);
        }

        wp_die(
            '<h2>Too Many Failed Attempts</h2>'
            . '<p>Your IP has been temporarily blocked. Please try again later.</p>',
            'Access Temporarily Blocked',
            ['response' => 429, 'back_link' => false]
        );
    }
}


// ── Clear failure count on successful login ────────────────────────────────

add_action('wp_login', 'wp_arsenal_rl_clear_on_success', 10, 2);
function wp_arsenal_rl_clear_on_success(string $user_login, \WP_User $user): void {
    $ip = wp_arsenal_rl_client_ip();
    delete_transient(wp_arsenal_rl_transient_key($ip));
    // Note: intentionally do NOT clear lockout on success — lockout stands for full duration
}
