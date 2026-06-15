<?php
/**
 * Plugin Name: WP-Arsenal IP Blocker
 * Description: PHP-level IP block list enforced before WordPress fully loads.
 *              Reads blocked/trusted CIDRs from wp-arsenal-config.php.
 *              For high-traffic sites, prefer .htaccess blocks via wp-firewall.py
 *              (runs before PHP, much faster) — this is belt-and-suspenders.
 *
 * Deploy to: wp-content/mu-plugins/ip-blocker.php
 * Requires:  wp-content/mu-plugins/wp-arsenal-config.php (with your settings)
 */

defined( 'ABSPATH' ) || exit;

// Load config
$_wp_arsenal_config = __DIR__ . '/wp-arsenal-config.php';
if ( file_exists( $_wp_arsenal_config ) ) {
    require_once $_wp_arsenal_config;
}

// Nothing to block if no config
if ( ! defined( 'WP_ARSENAL_BLOCKED_CIDRS' ) || empty( WP_ARSENAL_BLOCKED_CIDRS ) ) {
    return;
}


add_action( 'init', function() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if ( ! $ip ) {
        return;
    }

    // Never block trusted IPs
    $trusted = defined( 'WP_ARSENAL_TRUSTED_CIDRS' ) ? WP_ARSENAL_TRUSTED_CIDRS : [];
    foreach ( $trusted as $prefix ) {
        if ( str_starts_with( $ip, $prefix ) ) {
            return;
        }
    }

    // Check blocked list
    foreach ( WP_ARSENAL_BLOCKED_CIDRS as $cidr ) {
        if ( str_starts_with( $ip, $cidr ) ) {
            error_log( "[WP-ARSENAL] ip-blocker: blocked {$ip} {$_SERVER['REQUEST_URI']}" );
            http_response_code( 403 );
            nocache_headers();
            echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head>'
               . '<body><h1>Forbidden</h1><p>Your IP has been blocked.</p></body></html>';
            exit;
        }
    }
}, 1 );
