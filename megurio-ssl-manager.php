<?php
/**
 * Plugin Name: Megurio SSL Manager
 * Description: Let's Encrypt SSL certificate manager — multi-domain SAN support
 * Version:     1.4.1
 * Author:      megurio
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: megurio-ssl-manager
 * Domain Path: /languages
 */

defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/acme-client.php';

define( 'MEGURIO_CERT_GEN_OPTION', 'megurio_cert_gen_data' );


register_activation_hook( __FILE__, 'megurio_cert_gen_activate' );

function megurio_cert_gen_activate() {
    add_option( MEGURIO_CERT_GEN_OPTION, [], '', false );
}

/* ------------------------------------------------------------------ */
/*  Admin menu + scripts                                                */
/* ------------------------------------------------------------------ */

add_action( 'admin_menu', function () {
    add_menu_page(
        __( 'Megurio SSL Manager', 'megurio-ssl-manager' ),
        __( 'Megurio SSL Manager', 'megurio-ssl-manager' ),
        'manage_options', 'megurio-ssl-manager', 'megurio_cert_gen_admin_page', 'dashicons-lock'
    );
    add_submenu_page(
        'megurio-ssl-manager',
        __( 'Certificate Settings', 'megurio-ssl-manager' ),
        __( 'Settings', 'megurio-ssl-manager' ),
        'manage_options', 'megurio-ssl-manager-settings', 'megurio_cert_gen_settings_page'
    );
} );

add_action( 'admin_enqueue_scripts', function ( $hook ) {
    if ( ! in_array( $hook, [ 'toplevel_page_megurio-ssl-manager', 'megurio-ssl-manager_page_megurio-ssl-manager-settings' ], true ) ) return;
    wp_enqueue_script( 'megurio-cert-gen-js', plugin_dir_url( __FILE__ ) . 'megurio-ssl-manager.js', [ 'jquery' ], filemtime( __DIR__ . '/megurio-ssl-manager.js' ), true );
    wp_localize_script( 'megurio-cert-gen-js', 'megurio_cert_gen', [
        'ajax_url' => admin_url( 'admin-ajax.php' ),
        'nonce'    => wp_create_nonce( 'megurio_cert_gen_prepare' ),
        'i18n'     => [
            'loading_token'  => __( 'Requesting verification token from Let\'s Encrypt…', 'megurio-ssl-manager' ),
            'loading_verify' => __( 'Verifying and issuing certificate, please wait (30–60 seconds)…', 'megurio-ssl-manager' ),
            'request_failed' => __( 'Request failed', 'megurio-ssl-manager' ),
            'network_error'  => __( 'Network error, please retry', 'megurio-ssl-manager' ),
            'file_dir'       => __( 'Place file under', 'megurio-ssl-manager' ),
            'filename'       => __( 'Filename', 'megurio-ssl-manager' ),
            'file_content'   => __( 'File content', 'megurio-ssl-manager' ),
            'access_verify'  => __( 'Access to verify', 'megurio-ssl-manager' ),
            'host_record'    => __( 'Host record', 'megurio-ssl-manager' ),
            'record_type'    => __( 'Record type', 'megurio-ssl-manager' ),
            'record_value'   => __( 'Record value', 'megurio-ssl-manager' ),
            'domain'         => __( 'Domain', 'megurio-ssl-manager' ),
            'reused_challenge' => __( 'Using the existing pending challenge. No new challenge was requested from Let\'s Encrypt.', 'megurio-ssl-manager' ),
        ],
    ] );
} );

/* ------------------------------------------------------------------ */
/*  AJAX: prepare http-01                                               */
/* ------------------------------------------------------------------ */

add_action( 'wp_ajax_megurio_cert_gen_prepare_http', function () {
    check_ajax_referer( 'megurio_cert_gen_prepare' );

    $id      = intval( $_POST['id'] ?? 0 );
    $staging = ! empty( $_POST['staging'] );
    $email   = megurio_cert_gen_email();

    [ $row ] = megurio_cert_gen_find_row( $id );
    if ( ! $row ) wp_send_json_error( __( 'Record not found', 'megurio-ssl-manager' ) );
    if ( megurio_cert_gen_verify_method( $row ) !== 'http-01' ) {
        wp_send_json_error( __( 'This order uses DNS verification', 'megurio-ssl-manager' ) );
    }

    $pending = megurio_cert_gen_pending_challenge( $row, 'http-01' );
    if ( $pending ) {
        megurio_cert_gen_send_challenge_success( $id, $pending, true );
    }

    try {
        $acme = megurio_cert_gen_make_client( $staging, $email );
        $pc   = $acme->megurio_prepare_http01( $row['domains'] );
        $pc   = array_merge( $pc, [ 'staging' => $staging, 'email' => $email, 'webroot' => get_home_path() ] );
        megurio_cert_gen_save_pending( $id, $pc );

        megurio_cert_gen_send_challenge_success( $id, $pc );
    } catch ( Exception $e ) {
        wp_send_json_error( $e->getMessage() );
    }
} );

/* ------------------------------------------------------------------ */
/*  AJAX: prepare dns-01                                                */
/* ------------------------------------------------------------------ */

add_action( 'wp_ajax_megurio_cert_gen_prepare_dns', function () {
    check_ajax_referer( 'megurio_cert_gen_prepare' );

    $id      = intval( $_POST['id'] ?? 0 );
    $staging = ! empty( $_POST['staging'] );
    $email   = megurio_cert_gen_email();

    [ $row ] = megurio_cert_gen_find_row( $id );
    if ( ! $row ) wp_send_json_error( __( 'Record not found', 'megurio-ssl-manager' ) );
    if ( megurio_cert_gen_verify_method( $row ) !== 'dns-01' ) {
        wp_send_json_error( __( 'This order uses file verification', 'megurio-ssl-manager' ) );
    }

    $pending = megurio_cert_gen_pending_challenge( $row, 'dns-01' );
    if ( $pending ) {
        megurio_cert_gen_send_challenge_success( $id, $pending, true );
    }

    try {
        $acme = megurio_cert_gen_make_client( $staging, $email );
        $pc   = $acme->megurio_prepare_dns01( $row['domains'] );
        $pc   = array_merge( $pc, [ 'staging' => $staging, 'email' => $email ] );
        megurio_cert_gen_save_pending( $id, $pc );

        megurio_cert_gen_send_challenge_success( $id, $pc );
    } catch ( Exception $e ) {
        wp_send_json_error( $e->getMessage() );
    }
} );

/* ------------------------------------------------------------------ */
/*  POST: verify                                                        */
/* ------------------------------------------------------------------ */

add_action( 'admin_post_megurio_cert_gen_verify', 'megurio_cert_gen_handle_verify' );

function megurio_cert_gen_handle_verify() {
    $id = intval( $_POST['id'] ?? 0 );
    check_admin_referer( 'megurio_cert_gen_verify_' . $id );

    $data = get_option( MEGURIO_CERT_GEN_OPTION, [] );
    $row  = null;
    foreach ( $data as &$r ) {
        if ( $r['id'] === $id ) { $row = &$r; break; }
    }
    if ( ! $row || empty( $row['pending_challenge'] ) ) {
        wp_safe_redirect( admin_url( 'admin.php?page=megurio-ssl-manager&error=' . urlencode(
            __( 'Please click File Verify or DNS Verify first', 'megurio-ssl-manager' )
        ) ) );
        exit;
    }

    $pc = $row['pending_challenge'];

    try {
        $acme   = megurio_cert_gen_make_client( $pc['staging'], $pc['email'] );
        $result = ( $pc['type'] === 'dns-01' )
            ? $acme->megurio_complete_dns01( $pc )
            : $acme->megurio_complete_http01( $pc, $pc['webroot'] ?? get_home_path() );

        $row['status']            = 'issued';
        $row['issued']            = current_time( 'mysql' );
        $row['certificate']       = [
            'fullchain.pem' => $result['fullchain_pem'],
            'cert.pem'      => $result['cert_pem'],
            'chain.pem'     => $result['chain_pem'],
            'privkey.pem'   => $result['private_key_pem'],
        ];
        $row['pending_challenge'] = null;
        update_option( MEGURIO_CERT_GEN_OPTION, $data, false );

        wp_safe_redirect( admin_url( 'admin.php?page=megurio-ssl-manager&success=issued' ) );

    } catch ( Exception $e ) {
        $row['status']            = 'error';
        $row['error_detail']      = $e->getMessage();
        if ( megurio_cert_gen_should_reset_challenge( $e->getMessage() ) ) {
            $row['pending_challenge'] = null;
        }
        update_option( MEGURIO_CERT_GEN_OPTION, $data, false );
        $challenge_id = empty( $row['pending_challenge'] ) ? 0 : $id;
        wp_safe_redirect( admin_url( 'admin.php?page=megurio-ssl-manager&challenge_id=' . $challenge_id . '&error=' . urlencode( $e->getMessage() ) ) );
    }
    exit;
}

/* ------------------------------------------------------------------ */
/*  GET: download certificate as ZIP                                   */
/* ------------------------------------------------------------------ */

add_action( 'admin_post_megurio_cert_gen_download', function () {
    $id = intval( $_GET['id'] ?? 0 );
    check_admin_referer( 'megurio_cert_gen_download_' . $id );

    [ $row ] = megurio_cert_gen_find_row( $id );
    if ( ! $row || $row['status'] !== 'issued' ) {
        wp_die( esc_html( __( 'Certificate not found or not yet issued', 'megurio-ssl-manager' ) ) );
    }

    $files   = [ 'fullchain.pem', 'cert.pem', 'chain.pem', 'privkey.pem' ];
    $certs   = megurio_cert_gen_certificate_files( $row );
    $missing = array_filter( $files, fn($f) => empty( $certs[ $f ] ) );
    if ( $missing ) {
        wp_die( esc_html( __( 'Certificate files missing: ', 'megurio-ssl-manager' ) ) . esc_html( implode( ', ', $missing ) ) );
    }

    if ( ! class_exists( 'ZipArchive' ) ) {
        wp_die( esc_html( __( 'ZipArchive extension is not enabled.', 'megurio-ssl-manager' ) ) );
    }

    $domains     = $row['domains'] ?? [ 'cert' ];
    $base_domain = ltrim( $domains[0], '*.' );
    $zip_name    = sanitize_file_name( $base_domain . '_' . gmdate( 'Ymd' ) . '.zip' );
    require_once ABSPATH . 'wp-admin/includes/file.php';
    $zip_tmp     = wp_tempnam( $zip_name );
    if ( ! $zip_tmp ) {
        wp_die( esc_html( __( 'Failed to create temporary ZIP file', 'megurio-ssl-manager' ) ) );
    }

    $zip = new ZipArchive();
    if ( $zip->open( $zip_tmp, ZipArchive::CREATE | ZipArchive::OVERWRITE ) !== true ) {
        wp_die( esc_html( __( 'Failed to create ZIP', 'megurio-ssl-manager' ) ) );
    }

    foreach ( $files as $f ) {
        $zip->addFromString( $f, $certs[ $f ] );
    }

    $san    = implode( ' ', $domains );
    $readme = "Certificate Files\n";
    $readme .= "=================\n\n";
    $readme .= "Domains : $san\n";
    $readme .= "Issued  : " . ( $row['issued'] ?? '-' ) . "\n\n";
    $readme .= "Files:\n";
    $readme .= "  fullchain.pem  Full chain (cert + intermediate CA). Use this for nginx/Apache.\n";
    $readme .= "  cert.pem       Certificate only\n";
    $readme .= "  chain.pem      Intermediate CA only\n";
    $readme .= "  privkey.pem    Private key (keep secure, do not share)\n\n";
    $readme .= "--- Nginx ---\n\n";
    $readme .= "ssl_certificate     /path/to/fullchain.pem;\n";
    $readme .= "ssl_certificate_key /path/to/privkey.pem;\n\n";
    $readme .= "--- Apache ---\n\n";
    $readme .= "SSLCertificateFile    /path/to/cert.pem\n";
    $readme .= "SSLCertificateKeyFile /path/to/privkey.pem\n";
    $readme .= "SSLCACertificateFile  /path/to/chain.pem\n";

    $zip->addFromString( 'README.txt', $readme );
    $zip->close();

    WP_Filesystem();
    global $wp_filesystem;
    if ( ! $wp_filesystem ) {
        wp_die( esc_html( __( 'WordPress filesystem is not available.', 'megurio-ssl-manager' ) ) );
    }
    $zip_data = $wp_filesystem->get_contents( $zip_tmp );
    wp_delete_file( $zip_tmp );
    if ( false === $zip_data ) {
        wp_die( esc_html( __( 'Failed to read ZIP file', 'megurio-ssl-manager' ) ) );
    }

    header( 'Content-Type: application/zip' );
    header( 'Content-Disposition: attachment; filename="' . $zip_name . '"' );
    header( 'Content-Length: ' . strlen( $zip_data ) );
    header( 'Pragma: no-cache' );
    // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    echo $zip_data;
    exit;
} );

/* ------------------------------------------------------------------ */
/*  POST: add / delete                                                  */
/* ------------------------------------------------------------------ */

add_action( 'admin_post_megurio_cert_gen_add', function () {
    check_admin_referer( 'megurio_cert_gen_add' );

    $raw     = sanitize_textarea_field( wp_unslash( $_POST['domains'] ?? '' ) );
    $domains = array_values( array_unique( array_filter(
        array_map( 'trim', preg_split( '/[\n,]+/', $raw ) )
    ) ) );

    if ( empty( $domains ) ) {
        wp_safe_redirect( admin_url( 'admin.php?page=megurio-ssl-manager&error=' . urlencode(
            __( 'Please enter at least one domain', 'megurio-ssl-manager' )
        ) ) );
        exit;
    }

    $has_wildcard  = megurio_cert_gen_has_wildcard( $domains );
    $verify_method = sanitize_key( wp_unslash( $_POST['verify_method'] ?? 'http-01' ) );
    if ( ! in_array( $verify_method, [ 'http-01', 'dns-01' ], true ) ) {
        $verify_method = 'http-01';
    }
    if ( $has_wildcard ) {
        $verify_method = 'dns-01';
    }

    $data   = get_option( MEGURIO_CERT_GEN_OPTION, [] );
    $data[] = [
        'id'            => time(),
        'domains'       => $domains,
        'verify_method' => $verify_method,
        'status'        => 'pending',
        'created'       => current_time( 'mysql' ),
    ];
    update_option( MEGURIO_CERT_GEN_OPTION, $data, false );
    wp_safe_redirect( admin_url( 'admin.php?page=megurio-ssl-manager' ) );
    exit;
} );

add_action( 'admin_post_megurio_cert_gen_delete', function () {
    check_admin_referer( 'megurio_cert_gen_delete' );
    $id   = intval( $_POST['id'] ?? 0 );
    $data = array_values( array_filter( get_option( MEGURIO_CERT_GEN_OPTION, [] ), fn($r) => $r['id'] !== $id ) );
    update_option( MEGURIO_CERT_GEN_OPTION, $data, false );
    wp_safe_redirect( admin_url( 'admin.php?page=megurio-ssl-manager' ) );
    exit;
} );

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

function megurio_cert_gen_days_remaining( $row ) {
    $certs = megurio_cert_gen_certificate_files( $row );
    if ( empty( $certs['cert.pem'] ) ) return null;

    $parsed = openssl_x509_parse( $certs['cert.pem'] );
    if ( ! $parsed || empty( $parsed['validTo_time_t'] ) ) return null;

    return max( (int) ceil( ( $parsed['validTo_time_t'] - time() ) / 86400 ), 0 );
}

function megurio_cert_gen_has_wildcard( $domains ) {
    return count( array_filter( $domains, fn($domain) => strpos( $domain, '*' ) !== false ) ) > 0;
}

function megurio_cert_gen_verify_method( $row ) {
    $method = $row['verify_method'] ?? '';
    if ( in_array( $method, [ 'http-01', 'dns-01' ], true ) ) {
        return $method;
    }

    return 'http-01';
}

function megurio_cert_gen_email() {
    $saved = get_option( 'megurio_cert_gen_email', '' );
    return $saved ?: get_option( 'admin_email' );
}

function megurio_cert_gen_certificate_files( $row ) {
    $certs = $row['certificate'] ?? [];
    return is_array( $certs ) ? $certs : [];
}

function megurio_cert_gen_make_client( $staging, $email ) {
    $acme   = new megurio_AcmeClient( $staging );
    $suffix = $staging ? 'staging' : 'prod';
    $key    = get_option( 'megurio_cert_gen_account_key_' . $suffix );
    $url    = get_option( 'megurio_cert_gen_account_url_' . $suffix );
    if ( $key && $url ) {
        $acme->megurio_load_account( $key, $url );
    } else {
        $acct = $acme->megurio_register_account( $email );
        update_option( 'megurio_cert_gen_account_key_' . $suffix, $acct['private_key_pem'], false );
        update_option( 'megurio_cert_gen_account_url_' . $suffix, $acct['account_url'], false );
    }
    return $acme;
}

function megurio_cert_gen_find_row( $id ) {
    $data = get_option( MEGURIO_CERT_GEN_OPTION, [] );
    foreach ( $data as $r ) {
        if ( $r['id'] === $id ) return [ $r, $data ];
    }
    return [ null, $data ];
}

function megurio_cert_gen_pending_challenge( $row, $type ) {
    $pc = $row['pending_challenge'] ?? null;
    if (
        ! is_array( $pc )
        || ( $pc['type'] ?? '' ) !== $type
        || empty( $pc['challenges'] )
        || empty( $pc['order_url'] )
        || empty( $pc['finalize_url'] )
        || empty( $pc['domain_key_pem'] )
    ) {
        return null;
    }

    return $pc;
}

function megurio_cert_gen_send_challenge_success( $id, $pc, $reused = false ) {
    wp_send_json_success( [
        'id'           => $id,
        'challenges'   => $pc['challenges'],
        'reused'       => $reused,
        'verify_nonce' => wp_create_nonce( 'megurio_cert_gen_verify_' . $id ),
    ] );
}

function megurio_cert_gen_should_reset_challenge( $message ) {
    return strpos( $message, 'Validation failed for ' ) === 0
        || strpos( $message, "Order 'invalid'" ) !== false;
}

function megurio_cert_gen_save_pending( $id, $pc ) {
    $data = get_option( MEGURIO_CERT_GEN_OPTION, [] );
    foreach ( $data as &$r ) {
        if ( $r['id'] === $id ) { $r['pending_challenge'] = $pc; $r['status'] = 'pending'; break; }
    }
    update_option( MEGURIO_CERT_GEN_OPTION, $data, false );
}

/* ------------------------------------------------------------------ */
/*  Admin page UI                                                       */
/* ------------------------------------------------------------------ */

function megurio_cert_gen_admin_page() {
    $data    = get_option( MEGURIO_CERT_GEN_OPTION, [] );
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $error   = sanitize_text_field( wp_unslash( $_GET['error']  ?? '' ) );
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $success = sanitize_text_field( wp_unslash( $_GET['success'] ?? '' ) );
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $challenge_id = intval( $_GET['challenge_id'] ?? 0 );
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Megurio SSL Manager', 'megurio-ssl-manager' ); ?> <small style="font-size:13px;color:#888">Let's Encrypt</small></h1>

        <?php if ( $error ) : ?>
            <div class="notice notice-error is-dismissible"><p><?php echo esc_html( __( 'Error: ', 'megurio-ssl-manager' ) . $error ); ?></p></div>
        <?php endif; ?>
        <?php
        if ( $error && $challenge_id ) {
            [ $challenge_row ] = megurio_cert_gen_find_row( $challenge_id );
            if ( ! empty( $challenge_row['pending_challenge'] ) ) {
                megurio_cert_gen_render_challenge_notice( $challenge_row['pending_challenge'] );
            }
        }
        ?>
        <?php if ( $success === 'issued' ) : ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Certificate issued successfully', 'megurio-ssl-manager' ); ?></p></div>
        <?php endif; ?>

        <p style="margin:16px 0">
            <button type="button" class="button button-primary" id="megurio-cg-open-add">
                <?php esc_html_e( 'Add Certificate Order', 'megurio-ssl-manager' ); ?>
            </button>
        </p>

        <table class="wp-list-table widefat fixed striped">
            <thead><tr>
                <th width="80"><?php esc_html_e( 'ID', 'megurio-ssl-manager' ); ?></th>
                <th width="160"><?php esc_html_e( 'Bound Domains', 'megurio-ssl-manager' ); ?></th>
                <th width="60"><?php esc_html_e( 'Count', 'megurio-ssl-manager' ); ?></th>
                <th width="120"><?php esc_html_e( 'Verification Method', 'megurio-ssl-manager' ); ?></th>
                <th><?php esc_html_e( 'Status', 'megurio-ssl-manager' ); ?></th>
                <th width="140"><?php esc_html_e( 'Created', 'megurio-ssl-manager' ); ?></th>
                <th width="140"><?php esc_html_e( 'Issued', 'megurio-ssl-manager' ); ?></th>
                <th><?php esc_html_e( 'Actions', 'megurio-ssl-manager' ); ?></th>
            </tr></thead>
            <tbody>
            <?php if ( empty( $data ) ) : ?>
                <tr><td colspan="8"><?php esc_html_e( 'No records', 'megurio-ssl-manager' ); ?></td></tr>
            <?php else : foreach ( $data as $row ) :
                $labels = [
                    'pending' => __( 'Pending', 'megurio-ssl-manager' ),
                    'issued'  => __( 'Issued', 'megurio-ssl-manager' ),
                    'error'   => __( 'Failed', 'megurio-ssl-manager' ),
                ];
                $domains      = $row['domains'] ?? [];
                $verify_method = megurio_cert_gen_verify_method( $row );
                $days_left    = megurio_cert_gen_days_remaining( $row );
                $can_renew    = $row['status'] === 'issued' && $days_left !== null && $days_left <= 30;
            ?>
                <tr>
                    <td><?php echo esc_html( $row['id'] ); ?></td>
                    <td>
                        <?php foreach ( $domains as $d ) : ?>
                            <span><?php echo esc_html( $d ); ?></span><br>
                        <?php endforeach; ?>
                    </td>
                    <td><?php echo count( $domains ); ?></td>
                    <td><?php echo esc_html( $verify_method === 'dns-01' ? __( 'DNS Verify', 'megurio-ssl-manager' ) : __( 'File Verify', 'megurio-ssl-manager' ) ); ?></td>
                    <td>
                        <?php echo esc_html( $labels[ $row['status'] ] ?? $row['status'] ); ?>
                        <?php if ( $days_left !== null ) : ?>
                            <br><small style="color:<?php echo $days_left <= 30 ? '#d63638' : '#666'; ?>">
                                <?php
                                echo esc_html( sprintf(
                                    /* translators: %d: number of days */
                                    __( '%d days remaining', 'megurio-ssl-manager' ),
                                    $days_left
                                ) ); ?>
                            </small>
                        <?php endif; ?>
                        <?php if ( ! empty( $row['error_detail'] ) ) : ?>
                            <br><small style="color:red"><?php echo esc_html( $row['error_detail'] ); ?></small>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html( $row['created'] ?? '-' ); ?></td>
                    <td><?php echo esc_html( $row['issued'] ?? '-' ); ?></td>
                    <td>
                        <?php if ( $can_renew ) : ?>
                            <span style="color:#d63638;font-size:12px;font-weight:600;display:block;margin-bottom:4px">
                                ⚠ <?php esc_html_e( 'Expiring soon — please renew', 'megurio-ssl-manager' ); ?>
                            </span>
                        <?php endif; ?>

                        <?php if ( $verify_method === 'http-01' ) : ?>
                        <button type="button"
                                class="button <?php echo $can_renew ? 'button-primary' : ''; ?> megurio-cert-btn-http"
                                data-id="<?php echo esc_attr( $row['id'] ); ?>">
                            <?php echo esc_html( $can_renew
                                ? __( 'Renew (File Verify)', 'megurio-ssl-manager' )
                                : __( 'File Verify', 'megurio-ssl-manager' ) ); ?>
                        </button>
                        <?php else : ?>
                        <button type="button"
                                class="button <?php echo $can_renew ? 'button-primary' : ''; ?> megurio-cert-btn-dns"
                                data-id="<?php echo esc_attr( $row['id'] ); ?>">
                            <?php echo esc_html( $can_renew
                                ? __( 'Renew (DNS Verify)', 'megurio-ssl-manager' )
                                : __( 'DNS Verify', 'megurio-ssl-manager' ) ); ?>
                        </button>
                        <?php endif; ?>

                        <?php if ( $row['status'] === 'issued' && megurio_cert_gen_certificate_files( $row ) ) : ?>
                        <a class="button" href="<?php echo esc_url( wp_nonce_url(
                            admin_url( 'admin-post.php?action=megurio_cert_gen_download&id=' . $row['id'] ),
                            'megurio_cert_gen_download_' . $row['id']
                        ) ); ?>">
                            <?php esc_html_e( 'Download', 'megurio-ssl-manager' ); ?>
                        </a>
                        <?php endif; ?>

                        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
                              style="display:inline;margin-left:6px"
                              onsubmit="return confirm('<?php esc_attr_e( 'Confirm delete?', 'megurio-ssl-manager' ); ?>')">
                            <?php wp_nonce_field( 'megurio_cert_gen_delete' ); ?>
                            <input type="hidden" name="action" value="megurio_cert_gen_delete">
                            <input type="hidden" name="id" value="<?php echo esc_attr( $row['id'] ); ?>">
                            <button type="submit" class="button button-link-delete">
                                <?php esc_html_e( 'Delete', 'megurio-ssl-manager' ); ?>
                            </button>
                        </form>

                    </td>
                </tr>
            <?php endforeach; endif; ?>
            </tbody>
        </table>
        <p style="color:#888;font-size:12px;margin-top:8px">
            <?php esc_html_e( 'Issued certificate data is stored in the WordPress database.', 'megurio-ssl-manager' ); ?>
        </p>
    </div>

    <div id="megurio-cg-overlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:99998"></div>

    <div id="megurio-cg-modal" style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
         background:#fff;border-radius:8px;padding:36px 40px;width:600px;max-width:95vw;max-height:90vh;
         overflow-y:auto;z-index:99999;box-shadow:0 8px 32px rgba(0,0,0,.22)">

        <div id="megurio-cg-loading" style="text-align:center;padding:40px 0">
            <span class="spinner is-active" style="float:none;margin:0 auto 12px;display:block"></span>
            <p id="megurio-cg-loading-msg"></p>
        </div>

        <div id="megurio-cg-add-info" style="display:none">
            <?php // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo megurio_cert_gen_modal_header( __( 'New Certificate', 'megurio-ssl-manager' ) ); ?>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <?php wp_nonce_field( 'megurio_cert_gen_add' ); ?>
                <input type="hidden" name="action" value="megurio_cert_gen_add">
                <p style="margin:0 0 6px;color:#666;font-size:13px">
                    <?php esc_html_e( 'One certificate can bind multiple domains (SAN). One domain per line. Wildcards (*.example.com) are supported.', 'megurio-ssl-manager' ); ?><br>
                    <?php esc_html_e( 'Wildcard domains must also include the base domain (example.com) as a separate entry.', 'megurio-ssl-manager' ); ?>
                </p>
                <textarea name="domains" rows="5" style="width:100%;font-family:monospace"
                          placeholder="example.com&#10;*.example.com&#10;sub.example.com" required></textarea>
                <fieldset style="margin-top:14px">
                    <legend style="font-weight:600;margin-bottom:6px"><?php esc_html_e( 'Verification Method', 'megurio-ssl-manager' ); ?></legend>
                    <label style="margin-right:16px">
                        <input type="radio" name="verify_method" value="http-01" checked>
                        <?php esc_html_e( 'File Verify', 'megurio-ssl-manager' ); ?>
                    </label>
                    <label>
                        <input type="radio" name="verify_method" value="dns-01">
                        <?php esc_html_e( 'DNS Verify', 'megurio-ssl-manager' ); ?>
                    </label>
                    <p style="margin:6px 0 0;color:#666;font-size:12px">
                        <?php esc_html_e( 'Wildcard domains always use DNS verification.', 'megurio-ssl-manager' ); ?>
                    </p>
                </fieldset>
                <div style="text-align:center;margin-top:24px">
                    <button type="submit" class="button button-primary">
                        <?php esc_html_e( 'Add Certificate Order', 'megurio-ssl-manager' ); ?>
                    </button>
                    <button type="button" class="button megurio-cg-close" style="margin-left:8px">
                        <?php esc_html_e( 'Cancel', 'megurio-ssl-manager' ); ?>
                    </button>
                </div>
            </form>
        </div>

        <div id="megurio-cg-http-info" style="display:none">
            <?php // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo megurio_cert_gen_modal_header( __( 'File Verification', 'megurio-ssl-manager' ) ); ?>
            <p style="color:#666;font-size:13px">
                <?php esc_html_e( 'If this is the current site domain, clicking Verify will create the file automatically.', 'megurio-ssl-manager' ); ?>
            </p>
            <div id="megurio-cg-http-list"></div>
            <p style="color:#666;font-size:13px;margin-top:12px">
                <?php esc_html_e( 'If auto-renewal is enabled, do not delete the challenge file or directory.', 'megurio-ssl-manager' ); ?>
            </p>
        </div>

        <div id="megurio-cg-dns-info" style="display:none">
            <?php // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo megurio_cert_gen_modal_header( __( 'DNS Verification', 'megurio-ssl-manager' ) ); ?>
            <p style="color:#666;font-size:13px">
                <?php esc_html_e( 'After adding the DNS TXT record, wait for propagation before clicking Verify.', 'megurio-ssl-manager' ); ?>
            </p>
            <div id="megurio-cg-dns-list"></div>
            <p style="color:#666;font-size:13px;margin-top:12px">
                <?php esc_html_e( 'If auto-renewal is enabled, do not delete the DNS TXT record.', 'megurio-ssl-manager' ); ?>
            </p>
        </div>

        <div id="megurio-cg-error" style="display:none;text-align:center;padding:20px 0">
            <p style="color:#d63638;font-size:14px" id="megurio-cg-error-msg"></p>
            <button type="button" class="megurio-cg-close" style="<?php echo esc_attr( megurio_cert_gen_btn_style( '#555' ) ); ?>">
                <?php esc_html_e( 'Close', 'megurio-ssl-manager' ); ?>
            </button>
        </div>

        <form id="megurio-cg-verify-form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
            <input type="hidden" name="action"   value="megurio_cert_gen_verify">
            <input type="hidden" name="id"       id="megurio-cg-form-id"    value="">
            <input type="hidden" name="_wpnonce" id="megurio-cg-form-nonce" value="">
        </form>

        <div id="megurio-cg-modal-footer" style="display:none;text-align:center;margin-top:24px">
            <button type="button" id="megurio-cg-do-verify" style="<?php echo esc_attr( megurio_cert_gen_btn_style( '#6c5ce7' ) ); ?>">
                <?php esc_html_e( 'Verify', 'megurio-ssl-manager' ); ?>
            </button>
            <button type="button" class="megurio-cg-close" style="<?php echo esc_attr( megurio_cert_gen_btn_style( '#555' ) ); ?>;margin-left:12px">
                <?php esc_html_e( 'Cancel', 'megurio-ssl-manager' ); ?>
            </button>
        </div>
    </div>
    <?php
}

function megurio_cert_gen_modal_header( $title ) {
    return '<div style="text-align:center;margin-bottom:20px">
        <div style="width:56px;height:56px;border-radius:50%;border:3px solid #00a0d2;
             display:flex;align-items:center;justify-content:center;margin:0 auto 12px">
            <span style="font-size:24px;color:#00a0d2;font-weight:bold">i</span>
        </div>
        <h2 style="margin:0;font-size:20px">' . esc_html( $title ) . '</h2>
    </div>';
}

function megurio_cert_gen_btn_style( $bg ) {
    return "background:$bg;color:#fff;border:none;padding:10px 32px;border-radius:5px;font-size:15px;cursor:pointer";
}

function megurio_cert_gen_render_challenge_notice( $pc ) {
    if ( empty( $pc['challenges'] ) ) return;

    ?>
    <div class="notice notice-warning">
        <p><strong><?php esc_html_e( 'Use the existing verification challenge below, then open File/DNS Verify and click Verify again.', 'megurio-ssl-manager' ); ?></strong></p>
        <?php foreach ( $pc['challenges'] as $challenge ) : ?>
            <div style="margin:8px 0 12px;padding:10px 12px;background:#fff;border:1px solid #dcdcde">
                <p style="margin:0 0 6px"><strong><?php esc_html_e( 'Domain', 'megurio-ssl-manager' ); ?>:</strong> <?php echo esc_html( $challenge['domain'] ?? '' ); ?></p>
                <?php if ( ( $pc['type'] ?? '' ) === 'http-01' ) : ?>
                    <p style="margin:4px 0"><strong><?php esc_html_e( 'Place file under', 'megurio-ssl-manager' ); ?>:</strong> <code>/.well-known/acme-challenge/</code></p>
                    <p style="margin:4px 0"><strong><?php esc_html_e( 'Filename', 'megurio-ssl-manager' ); ?>:</strong> <code><?php echo esc_html( $challenge['token'] ?? '' ); ?></code></p>
                    <p style="margin:4px 0"><strong><?php esc_html_e( 'File content', 'megurio-ssl-manager' ); ?>:</strong> <code style="word-break:break-all"><?php echo esc_html( $challenge['key_auth'] ?? '' ); ?></code></p>
                <?php else : ?>
                    <p style="margin:4px 0"><strong><?php esc_html_e( 'Host record', 'megurio-ssl-manager' ); ?>:</strong> <code><?php echo esc_html( $challenge['dns_host'] ?? '' ); ?></code></p>
                    <p style="margin:4px 0"><strong><?php esc_html_e( 'Record type', 'megurio-ssl-manager' ); ?>:</strong> <code>TXT</code></p>
                    <p style="margin:4px 0"><strong><?php esc_html_e( 'Record value', 'megurio-ssl-manager' ); ?>:</strong> <code style="word-break:break-all"><?php echo esc_html( $challenge['txt_value'] ?? '' ); ?></code></p>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>
    <?php
}

/* ------------------------------------------------------------------ */
/*  Settings page                                                       */
/* ------------------------------------------------------------------ */

add_action( 'admin_post_megurio_cert_gen_save_settings', function () {
    check_admin_referer( 'megurio_cert_gen_settings' );
    $email = sanitize_email( wp_unslash( $_POST['megurio_cert_gen_email'] ?? '' ) );
    if ( $email ) {
        update_option( 'megurio_cert_gen_email', $email );
    } else {
        delete_option( 'megurio_cert_gen_email' );
    }
    wp_safe_redirect( admin_url( 'admin.php?page=megurio-ssl-manager-settings&saved=1' ) );
    exit;
} );

function megurio_cert_gen_settings_page() {
    $current = get_option( 'megurio_cert_gen_email', '' );
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $saved   = ! empty( $_GET['saved'] );
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Certificate Settings', 'megurio-ssl-manager' ); ?></h1>

        <?php if ( $saved ) : ?>
            <div class="notice notice-success is-dismissible">
                <p><?php esc_html_e( 'Settings saved.', 'megurio-ssl-manager' ); ?></p>
            </div>
        <?php endif; ?>

        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
              style="max-width:480px;margin-top:20px">
            <?php wp_nonce_field( 'megurio_cert_gen_settings' ); ?>
            <input type="hidden" name="action" value="megurio_cert_gen_save_settings">

            <table class="form-table">
                <tr>
                    <th><label for="megurio_cert_gen_email"><?php esc_html_e( 'Certificate Email', 'megurio-ssl-manager' ); ?></label></th>
                    <td>
                        <input type="email" id="megurio_cert_gen_email" name="megurio_cert_gen_email"
                               value="<?php echo esc_attr( $current ); ?>"
                               placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>"
                               class="regular-text">
                        <p class="description">
                            <?php esc_html_e( "Used for Let's Encrypt expiry notifications.", 'megurio-ssl-manager' ); ?><br>
                            <?php
                            echo esc_html( sprintf(
                                /* translators: %s: admin email address */
                                __( 'Leave blank to use the WordPress admin email (%s).', 'megurio-ssl-manager' ),
                                get_option( 'admin_email' )
                            ) ); ?>
                        </p>
                    </td>
                </tr>
            </table>

            <p class="submit">
                <button type="submit" class="button button-primary">
                    <?php esc_html_e( 'Save Settings', 'megurio-ssl-manager' ); ?>
                </button>
            </p>
        </form>
    </div>
    <?php
}
