<?php
/**
 * WP-Arsenal XML-RPC Kill MU-Plugin
 *
 * Completely disables WordPress XML-RPC at the PHP level.
 * Belt-and-suspenders alongside .htaccess blocking — if .htaccess
 * is bypassed or reset, this ensures xmlrpc.php still returns nothing.
 *
 * Why disable XML-RPC?
 *   - Used in brute-force amplification attacks (multicall method)
 *   - Used as a pingback DDoS reflector
 *   - Rarely needed in modern WordPress (REST API replaced its use cases)
 *   - Jetpack and some plugins need it — see note below
 *
 * Jetpack users: XML-RPC is required by Jetpack. If you use Jetpack,
 * do NOT deploy this plugin. Use wp-firewall.py to restrict xmlrpc.php
 * to Automattic IPs only instead.
 *
 * Deploy:
 *   cp xmlrpc-kill.php /path/to/wp-content/mu-plugins/
 */

if (!defined('ABSPATH')) exit;

// Disable XML-RPC via filter (cleanest method)
add_filter('xmlrpc_enabled', '__return_false', 1);

// Belt-and-suspenders: die before any XML-RPC call executes
add_action('xmlrpc_call', 'wp_arsenal_xmlrpc_kill', 1);
function wp_arsenal_xmlrpc_kill(): void {
    error_log('[WP-Arsenal] xmlrpc-kill: blocked XML-RPC call from ' . ($_SERVER['REMOTE_ADDR'] ?? '?'));
    wp_die(
        'XML-RPC is disabled on this site.',
        'XML-RPC Disabled',
        ['response' => 403]
    );
}

// Belt-and-suspenders: remove xmlrpc pingback link from head
add_action('wp_head', 'wp_arsenal_remove_xmlrpc_pingback', 1);
function wp_arsenal_remove_xmlrpc_pingback(): void {
    remove_action('wp_head', 'rsd_link');
    remove_action('wp_head', 'wlwmanifest_link');
}

// Suppress pingback from HTTP headers
add_filter('wp_headers', 'wp_arsenal_remove_pingback_header');
function wp_arsenal_remove_pingback_header(array $headers): array {
    unset($headers['X-Pingback']);
    return $headers;
}

// Disable self-pingbacks
add_action('pre_ping', 'wp_arsenal_disable_self_pingback');
function wp_arsenal_disable_self_pingback(array &$links): void {
    $home = get_option('home');
    foreach ($links as $key => $link) {
        if (str_starts_with($link, $home)) {
            unset($links[$key]);
        }
    }
}
