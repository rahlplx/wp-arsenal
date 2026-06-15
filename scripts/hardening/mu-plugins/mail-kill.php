<?php
/**
 * Plugin Name: WP-Arsenal Mail Kill
 * Description: Suppresses all outbound WordPress emails when WP_ARSENAL_MAIL_KILL is true.
 *              Use during malware cleanup to stop spam from injected mail() calls.
 *              Set WP_ARSENAL_MAIL_KILL = false to re-enable email normally.
 *
 * Deploy to: wp-content/mu-plugins/mail-kill.php
 * Requires:  wp-content/mu-plugins/wp-arsenal-config.php
 */

defined( 'ABSPATH' ) || exit;

// Load config if not already loaded
$_wp_arsenal_config = ABSPATH . '../mu-plugins/wp-arsenal-config.php';
if ( file_exists( $_wp_arsenal_config ) ) {
    require_once $_wp_arsenal_config;
}

// Only suppress if explicitly enabled in config
if ( ! defined( 'WP_ARSENAL_MAIL_KILL' ) || ! WP_ARSENAL_MAIL_KILL ) {
    return;
}

add_filter( 'pre_wp_mail', function( $null, $atts ) {
    $to = is_array( $atts['to'] ) ? implode( ', ', $atts['to'] ) : $atts['to'];
    error_log( '[WP-ARSENAL] mail-kill suppressed to: ' . $to . ' | subject: ' . ( $atts['subject'] ?? '' ) );
    return false;
}, 1, 2 );
