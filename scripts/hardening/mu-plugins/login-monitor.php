<?php
/**
 * Plugin Name: WP-Arsenal Login Monitor
 * Description: Sends email alert on admin login from an IP not in your trusted list.
 *              Configure via wp-arsenal-config.php (WP_ARSENAL_ALERT_EMAIL and
 *              WP_ARSENAL_TRUSTED_CIDRS). Works on any host, any WP install.
 *
 * Deploy to: wp-content/mu-plugins/login-monitor.php
 * Requires:  wp-content/mu-plugins/wp-arsenal-config.php (with your settings)
 */

defined( 'ABSPATH' ) || exit;

// Load config
$_wp_arsenal_config = __DIR__ . '/wp-arsenal-config.php';
if ( file_exists( $_wp_arsenal_config ) ) {
    require_once $_wp_arsenal_config;
}

// Bail if not configured
if ( ! defined( 'WP_ARSENAL_ALERT_EMAIL' ) || ! WP_ARSENAL_ALERT_EMAIL ) {
    return;
}

if ( defined( 'WP_ARSENAL_LOGIN_MONITOR_ENABLED' ) && ! WP_ARSENAL_LOGIN_MONITOR_ENABLED ) {
    return;
}


/**
 * Check if an IP matches any of the trusted CIDR prefixes.
 * Simple prefix-match works for /8, /16, /24 CIDRs and exact IPs.
 * For full CIDR notation (e.g. 192.0.2.0/24) use wp-firewall.py .htaccess blocks instead.
 */
function wp_arsenal_is_trusted_ip( string $ip ): bool {
    $trusted = defined( 'WP_ARSENAL_TRUSTED_CIDRS' ) ? WP_ARSENAL_TRUSTED_CIDRS : [ '127.0.0.1', '::1' ];
    foreach ( $trusted as $cidr ) {
        if ( str_starts_with( $ip, $cidr ) ) {
            return true;
        }
    }
    return false;
}


add_action( 'wp_login', function( string $user_login, WP_User $user ) {
    // Only alert for admins
    if ( ! user_can( $user, 'manage_options' ) ) {
        return;
    }

    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    if ( wp_arsenal_is_trusted_ip( $ip ) ) {
        return;
    }

    $site    = get_bloginfo( 'name' );
    $siteurl = get_option( 'siteurl' );
    $time    = gmdate( 'Y-m-d H:i:s T' );
    $ua      = substr( $_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 250 );
    $email   = WP_ARSENAL_ALERT_EMAIL;

    $from_domain = parse_url( $siteurl, PHP_URL_HOST ) ?: 'wordpress';
    $from_header = defined( 'WP_ARSENAL_ALERT_FROM' ) && WP_ARSENAL_ALERT_FROM
                 ? WP_ARSENAL_ALERT_FROM
                 : "security@{$from_domain}";
    $from_header = str_replace( [ "\r", "\n" ], '', $from_header );

    $subject = "[WP-ARSENAL] Admin login: {$user_login} on {$site} from {$ip}";

    $body = "WordPress Admin Login Alert\n"
          . str_repeat( '=', 56 ) . "\n\n"
          . "Site:      {$siteurl}\n"
          . "User:      {$user_login}\n"
          . "IP:        {$ip}\n"
          . "Time:      {$time}\n"
          . "Agent:     {$ua}\n\n"
          . "If this was NOT you:\n"
          . "  1. Change your WP admin password immediately\n"
          . "  2. Go to Users → your profile → Sessions → Log out all\n"
          . "  3. Run wp-scan.py to check for malware\n";

    $headers = [ "From: WP-Arsenal Security <{$from_header}>" ];
    if ( defined( 'WP_ARSENAL_ALERT_BCC' ) && WP_ARSENAL_ALERT_BCC ) {
        $headers[] = 'BCC: ' . WP_ARSENAL_ALERT_BCC;
    }

    // Use wp_mail if available, fall back to PHP mail() to bypass mail-kill
    if ( function_exists( 'wp_mail' ) ) {
        add_filter( 'wp_mail_from', fn() => $from_header );
        wp_mail( $email, $subject, $body, $headers );
    } else {
        mail( $email, $subject, $body, implode( "\r\n", $headers ) );
    }

    error_log( "[WP-ARSENAL] login-monitor: admin {$user_login} from {$ip}" );
}, 10, 2 );
