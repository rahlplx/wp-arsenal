<?php
/**
 * WP-Arsenal File Monitor MU-Plugin
 *
 * Detects unexpected changes to critical WordPress files and alerts
 * by email. Runs on a scheduled WP-Cron event (not on every request).
 *
 * Files monitored:
 *   - wp-config.php
 *   - .htaccess
 *   - wp-login.php
 *   - wp-admin/admin.php
 *   - wp-includes/functions.php
 *   - wp-includes/pluggable.php
 *   - wp-content/themes/ (active theme PHP files)
 *
 * Requires: wp-arsenal-config.php to be loaded first (sets constants).
 *
 * Deploy:
 *   cp file-monitor.php /path/to/wp-content/mu-plugins/
 */

if (!defined('ABSPATH')) exit;

// Bail if central config not loaded
if (!defined('WP_ARSENAL_ALERT_EMAIL') || !WP_ARSENAL_ALERT_EMAIL) return;

define('WP_ARSENAL_FILE_MONITOR_OPTION',   'wp_arsenal_file_hashes');
define('WP_ARSENAL_FILE_MONITOR_SCHEDULE', 'wp_arsenal_file_monitor_run');

// ── Register cron event ────────────────────────────────────────────────────

add_action('wp', 'wp_arsenal_file_monitor_schedule_cron');
function wp_arsenal_file_monitor_schedule_cron(): void {
    if (!wp_next_scheduled(WP_ARSENAL_FILE_MONITOR_SCHEDULE)) {
        wp_schedule_event(time(), 'hourly', WP_ARSENAL_FILE_MONITOR_SCHEDULE);
    }
}

add_action(WP_ARSENAL_FILE_MONITOR_SCHEDULE, 'wp_arsenal_file_monitor_run');

// ── Core monitoring logic ──────────────────────────────────────────────────

function wp_arsenal_file_monitor_get_targets(): array {
    $root = ABSPATH;
    $targets = [
        $root . 'wp-config.php',
        $root . '.htaccess',
        $root . 'wp-login.php',
        $root . 'wp-admin/admin.php',
        $root . 'wp-includes/functions.php',
        $root . 'wp-includes/pluggable.php',
        $root . 'wp-includes/class-wp-hook.php',
    ];

    // Add active theme PHP files (1 level deep)
    $theme_dir = get_template_directory();
    if ($theme_dir && is_dir($theme_dir)) {
        foreach (glob($theme_dir . '/*.php') ?: [] as $f) {
            $targets[] = $f;
        }
    }

    return array_filter($targets, 'file_exists');
}

function wp_arsenal_file_monitor_hash_files(array $paths): array {
    $hashes = [];
    foreach ($paths as $path) {
        if (is_readable($path)) {
            $hashes[$path] = hash_file('sha256', $path);
        }
    }
    return $hashes;
}

function wp_arsenal_file_monitor_run(): void {
    $targets = wp_arsenal_file_monitor_get_targets();
    $current = wp_arsenal_file_monitor_hash_files($targets);
    $stored  = get_option(WP_ARSENAL_FILE_MONITOR_OPTION, []);

    $changed = [];
    $added   = [];

    foreach ($current as $path => $hash) {
        if (!isset($stored[$path])) {
            $added[] = $path;
        } elseif ($stored[$path] !== $hash) {
            $changed[] = $path;
        }
    }

    if (empty($changed) && empty($added)) {
        // No changes — save current hashes as baseline if first run
        if (empty($stored)) {
            update_option(WP_ARSENAL_FILE_MONITOR_OPTION, $current, false);
        }
        return;
    }

    // Alert
    $site = get_option('siteurl', 'unknown site');
    $lines = ["[WP-Arsenal] File change detected on {$site}\n"];

    if (!empty($changed)) {
        $lines[] = "MODIFIED files:";
        foreach ($changed as $f) {
            $lines[] = "  {$f}";
        }
    }
    if (!empty($added)) {
        $lines[] = "NEW (unrecognised) files:";
        foreach ($added as $f) {
            $lines[] = "  {$f}";
        }
    }

    $lines[] = "\nTime: " . date('Y-m-d H:i:s T');
    $lines[] = "If this was not you, run wp-deep-audit.py and wp-shell-nuke.py immediately.";

    $body    = implode("\n", $lines);
    $subject = "[WP-Arsenal] File change alert — {$site}";
    $to      = WP_ARSENAL_ALERT_EMAIL;
    $headers = ['Content-Type: text/plain; charset=UTF-8'];

    if (defined('WP_ARSENAL_ALERT_BCC') && WP_ARSENAL_ALERT_BCC) {
        $headers[] = 'Bcc: ' . WP_ARSENAL_ALERT_BCC;
    }
    if (defined('WP_ARSENAL_ALERT_FROM') && WP_ARSENAL_ALERT_FROM) {
        $headers[] = 'From: ' . WP_ARSENAL_ALERT_FROM;
    }

    wp_mail($to, $subject, $body, $headers);
    error_log("[WP-Arsenal] file-monitor: " . count($changed) . " changed, " . count($added) . " new — alert sent to {$to}");

    // Update stored hashes to current (so we don't re-alert on same change)
    update_option(WP_ARSENAL_FILE_MONITOR_OPTION, $current, false);
}

// ── Admin action: reset baseline ───────────────────────────────────────────

add_action('wp_arsenal_reset_file_baseline', 'wp_arsenal_reset_file_baseline');
function wp_arsenal_reset_file_baseline(): void {
    $targets = wp_arsenal_file_monitor_get_targets();
    $hashes  = wp_arsenal_file_monitor_hash_files($targets);
    update_option(WP_ARSENAL_FILE_MONITOR_OPTION, $hashes, false);
    error_log('[WP-Arsenal] file-monitor: baseline reset (' . count($hashes) . ' files)');
}

// Run baseline reset on deactivation (so re-activation starts fresh)
register_deactivation_hook(__FILE__, function () {
    delete_option(WP_ARSENAL_FILE_MONITOR_OPTION);
    wp_clear_scheduled_hook(WP_ARSENAL_FILE_MONITOR_SCHEDULE);
});
