<?php
/**
 * Plugin Name: WP-Arsenal Honeypot
 * Description: Hidden trap link + JavaScript fingerprinting. When a bot or attacker
 *              follows the hidden link, captures: IP, User-Agent, Referer, and (for
 *              real browsers) WebRTC real IP, canvas fingerprint, timezone, screen size.
 *              Sends alert to WP_ARSENAL_ALERT_EMAIL. Skips trusted IPs.
 *
 * Deploy to: wp-content/mu-plugins/honeypot.php
 * Requires:  wp-content/mu-plugins/wp-arsenal-config.php (with your settings)
 *
 * To place manually on a page/post: [wp_arsenal_honeypot]
 */

defined( 'ABSPATH' ) || exit;

// Load config
$_wp_arsenal_config = __DIR__ . '/wp-arsenal-config.php';
if ( file_exists( $_wp_arsenal_config ) ) {
    require_once $_wp_arsenal_config;
}

if ( ! defined( 'WP_ARSENAL_ALERT_EMAIL' ) || ! WP_ARSENAL_ALERT_EMAIL ) {
    return;
}

if ( ! defined( 'WP_ARSENAL_HONEYPOT_SECRET' ) || WP_ARSENAL_HONEYPOT_SECRET === 'change-me-to-random-string-per-site' ) {
    // Force admin to configure a unique secret before activating
    error_log( '[WP-ARSENAL] honeypot: WP_ARSENAL_HONEYPOT_SECRET not configured — honeypot disabled' );
    return;
}


// ── Trap endpoint ─────────────────────────────────────────────────────────
add_action( 'init', function() {
    if ( isset( $_GET['_wpa_hp'] ) ) {
        $expected = hash_hmac( 'sha256', (string) floor( time() / 3600 ), WP_ARSENAL_HONEYPOT_SECRET );
        if ( hash_equals( $expected, $_GET['_wpa_hp'] ) ) {
            _wp_arsenal_honeypot_triggered();
            exit;
        }
    }
} );


function _wp_arsenal_honeypot_triggered(): void {
    $ip  = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ua  = substr( $_SERVER['HTTP_USER_AGENT'] ?? '', 0, 300 );
    $ref = substr( $_SERVER['HTTP_REFERER'] ?? '', 0, 200 );
    $fp  = substr( $_GET['fp'] ?? '', 0, 800 );       // JS fingerprint payload
    $uri = $_SERVER['REQUEST_URI'] ?? '';

    // Skip trusted IPs silently
    $trusted = defined( 'WP_ARSENAL_TRUSTED_CIDRS' ) ? WP_ARSENAL_TRUSTED_CIDRS : [];
    foreach ( $trusted as $prefix ) {
        if ( str_starts_with( $ip, $prefix ) ) {
            http_response_code( 404 );
            exit;
        }
    }

    $siteurl = get_option( 'siteurl' );
    $time    = gmdate( 'Y-m-d H:i:s T' );
    $domain  = parse_url( $siteurl, PHP_URL_HOST ) ?: 'wordpress';
    $from    = defined( 'WP_ARSENAL_ALERT_FROM' ) && WP_ARSENAL_ALERT_FROM
               ? WP_ARSENAL_ALERT_FROM
               : "security@{$domain}";

    $body = "HONEYPOT TRIGGERED\n"
          . str_repeat( '=', 56 ) . "\n\n"
          . "Site:      {$siteurl}\n"
          . "IP:        {$ip}\n"
          . "Time:      {$time}\n"
          . "UserAgent: {$ua}\n"
          . "Referer:   {$ref}\n"
          . "URI:       {$uri}\n";

    if ( $fp ) {
        // Decode JS fingerprint JSON if present
        $fp_data = @json_decode( $fp, true );
        if ( $fp_data ) {
            $body .= "\nJS Fingerprint:\n";
            foreach ( $fp_data as $k => $v ) {
                $body .= "  {$k}: {$v}\n";
            }
        } else {
            $body .= "\nFingerprint (raw): {$fp}\n";
        }
    }

    $body .= "\nRecommended action: run wp-attacker-profile.py to cross-reference this IP.\n";

    $headers = [ "From: WP-Arsenal Security <{$from}>" ];
    if ( defined( 'WP_ARSENAL_ALERT_BCC' ) && WP_ARSENAL_ALERT_BCC ) {
        $headers[] = 'BCC: ' . WP_ARSENAL_ALERT_BCC;
    }

    $subject = "[WP-ARSENAL] Honeypot triggered on {$domain} — IP: {$ip}";
    mail( WP_ARSENAL_ALERT_EMAIL, $subject, $body, implode( "\r\n", $headers ) );
    error_log( "[WP-ARSENAL] honeypot triggered: {$ip} UA={$ua}" );

    http_response_code( 404 );
    echo '<!DOCTYPE html><html><body>Not Found</body></html>';
}


// ── Footer injection — hidden trap link + JS fingerprinter ────────────────
add_action( 'wp_footer', function() {
    $token = hash_hmac( 'sha256', (string) floor( time() / 3600 ), WP_ARSENAL_HONEYPOT_SECRET );
    $trap = esc_url( add_query_arg( '_wpa_hp', $token, home_url( '/' ) ) );
    echo "\n";
    // Hidden link only automated tools follow
    echo '<a href="' . $trap . '" style="display:none;visibility:hidden;'
       . 'position:absolute;left:-9999px;width:0;height:0" '
       . 'tabindex="-1" aria-hidden="true"></a>' . "\n";

    // JS fingerprinter — only fires on wp-admin and wp-login pages
    // (real users on those pages are candidates for monitoring)
    ?>
    <script>
    (function() {
        if ( ! /wp-login|wp-admin/.test( window.location.href ) ) return;
        var trap = <?php echo json_encode( add_query_arg( '_wpa_hp', $token, home_url( '/' ) ) ); ?>;
        var fp = { ua: navigator.userAgent.substr(0, 100) };
        fp.tz  = Intl.DateTimeFormat().resolvedOptions().timeZone;
        fp.lang = navigator.language;
        fp.scr  = screen.width + 'x' + screen.height;
        try {
            var c = document.createElement('canvas');
            c.getContext('2d').fillText('wpa',2,10);
            fp.cv = c.toDataURL().slice(-20);
        } catch(e){}
        // WebRTC real-IP probe (bypasses proxy/VPN)
        try {
            var pc = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
            pc.createDataChannel('');
            pc.createOffer().then(function(o){pc.setLocalDescription(o);});
            pc.onicecandidate = function(e){
                if(e.candidate){
                    fp.rtc = e.candidate.candidate.substr(0,80);
                    new Image().src = trap + '&fp=' + encodeURIComponent(JSON.stringify(fp));
                }
            };
        } catch(e){
            new Image().src = trap + '&fp=' + encodeURIComponent(JSON.stringify(fp));
        }
    })();
    </script>
    <?php
} );


// ── Shortcode [wp_arsenal_honeypot] for manual placement ─────────────────
add_shortcode( 'wp_arsenal_honeypot', function() {
    $token = hash_hmac( 'sha256', (string) floor( time() / 3600 ), WP_ARSENAL_HONEYPOT_SECRET );
    $trap = esc_url( add_query_arg( '_wpa_hp', $token, home_url( '/' ) ) );
    return '<a href="' . $trap . '" style="display:none" tabindex="-1" aria-hidden="true"></a>';
} );
