<?php
/**
 * ACME v2 client (Let's Encrypt) — no external libraries
 * Supports multi-domain (SAN) certificates.
 */

class megurio_AcmeClient {

    const MEGURIO_LE_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';
    const MEGURIO_LE_PROD    = 'https://acme-v02.api.letsencrypt.org/directory';

    private $directory   = [];
    private $nonce       = '';
    private $account_url = '';
    private $key_data    = [];
    private $staging;

    public function __construct( $staging = false ) {
        $this->staging = $staging;
    }

    /* ------------------------------------------------------------------ */
    /*  Account                                                             */
    /* ------------------------------------------------------------------ */

    public function megurio_register_account( $email, $key_pem = null ) {
        $this->load_directory();

        $pk = $key_pem
            ? openssl_pkey_get_private( $key_pem )
            : openssl_pkey_new( [ 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ] );

        if ( ! $pk ) throw new Exception( 'Key error: ' . esc_html( openssl_error_string() ) );
        $this->init_key( $pk );

        $resp = $this->signed_request( $this->directory['newAccount'], [
            'termsOfServiceAgreed' => true,
            'contact'              => [ 'mailto:' . $email ],
        ] );

        $this->account_url     = $resp['headers']['location'] ?? '';
        $this->key_data['kid'] = $this->account_url;

        openssl_pkey_export( $pk, $pem_out );
        return [ 'account_url' => $this->account_url, 'private_key_pem' => $pem_out ];
    }

    public function megurio_load_account( $key_pem, $account_url ) {
        $this->load_directory();
        $pk = openssl_pkey_get_private( $key_pem );
        if ( ! $pk ) throw new Exception( 'Invalid key PEM' );
        $this->init_key( $pk );
        $this->account_url     = $account_url;
        $this->key_data['kid'] = $account_url;
    }

    /* ------------------------------------------------------------------ */
    /*  Step 1: prepare — create order, collect all challenges             */
    /* ------------------------------------------------------------------ */

    /**
     * http-01: returns one challenge entry per domain.
     * Wildcard domains are silently skipped (http-01 cannot validate them).
     *
     * Returns [
     *   'order_url'      => string,
     *   'finalize_url'   => string,
     *   'domain_key_pem' => string,
     *   'domains'        => string[],
     *   'challenges'     => [
     *     [ 'domain' => ..., 'auth_url' => ..., 'challenge_url' => ...,
     *       'token'  => ..., 'key_auth' => ... ],
     *     ...
     *   ],
     * ]
     */
    public function megurio_prepare_http01( array $domains ) {
        $this->assert_account();
        [ $order, $order_url ] = $this->new_order( $domains );

        $challenges = [];
        foreach ( $order['authorizations'] as $auth_url ) {
            $auth = $this->signed_request( $auth_url, null )['body'];
            if ( $auth['status'] === 'valid' ) continue;

            $domain = $auth['identifier']['value'];
            if ( strpos( $domain, '*' ) !== false ) continue;  // skip wildcards

            $c = $this->find_challenge( $auth, 'http-01' );
            if ( ! $c ) throw new Exception( 'No http-01 challenge for ' . esc_html( $domain ) );

            $token    = $c['token'];
            $key_auth = $token . '.' . $this->jwk_thumbprint();

            $challenges[] = [
                'domain'        => $domain,
                'auth_url'      => $auth_url,
                'challenge_url' => $c['url'],
                'token'         => $token,
                'key_auth'      => $key_auth,
            ];
        }

        openssl_pkey_export( $this->new_domain_key(), $dk_pem );

        return [
            'type'           => 'http-01',
            'order_url'      => $order_url,
            'finalize_url'   => $order['finalize'],
            'domain_key_pem' => $dk_pem,
            'domains'        => $domains,
            'challenges'     => $challenges,
        ];
    }

    /**
     * dns-01: returns one TXT record entry per domain.
     * Wildcards are supported (and required to use dns-01).
     *
     * Returns same structure as megurio_prepare_http01 but challenges have:
     *   [ 'domain', 'auth_url', 'challenge_url', 'token', 'dns_host', 'txt_value' ]
     */
    public function megurio_prepare_dns01( array $domains ) {
        $this->assert_account();
        [ $order, $order_url ] = $this->new_order( $domains );

        $challenges = [];
        foreach ( $order['authorizations'] as $auth_url ) {
            $auth = $this->signed_request( $auth_url, null )['body'];
            if ( $auth['status'] === 'valid' ) continue;

            $domain = $auth['identifier']['value'];
            $c      = $this->find_challenge( $auth, 'dns-01' );
            if ( ! $c ) throw new Exception( 'No dns-01 challenge for ' . esc_html( $domain ) );

            $token     = $c['token'];
            $key_auth  = $token . '.' . $this->jwk_thumbprint();
            $txt_value = $this->b64u( hash( 'sha256', $key_auth, true ) );
            $base      = ltrim( $domain, '*.' );

            $challenges[] = [
                'domain'        => $domain,
                'auth_url'      => $auth_url,
                'challenge_url' => $c['url'],
                'token'         => $token,
                'dns_host'      => '_acme-challenge.' . $base,
                'txt_value'     => $txt_value,
            ];
        }

        openssl_pkey_export( $this->new_domain_key(), $dk_pem );

        return [
            'type'           => 'dns-01',
            'order_url'      => $order_url,
            'finalize_url'   => $order['finalize'],
            'domain_key_pem' => $dk_pem,
            'domains'        => $domains,
            'challenges'     => $challenges,
        ];
    }

    /* ------------------------------------------------------------------ */
    /*  Step 2: complete — validate all challenges, finalize, download     */
    /* ------------------------------------------------------------------ */

    public function megurio_complete_http01( array $pc, $webroot ) {
        $this->assert_account();

        $files = [];
        try {
            // Write all token files first
            foreach ( $pc['challenges'] as $ch ) {
                $dir  = rtrim( $webroot, '/' ) . '/.well-known/acme-challenge';
                $file = $dir . '/' . $ch['token'];
                if ( ! is_dir( $dir ) ) wp_mkdir_p( $dir );
                $this->write_file( $file, $ch['key_auth'] );
                $files[] = $file;
            }

            // Trigger + poll each authorization
            foreach ( $pc['challenges'] as $ch ) {
                $this->trigger_and_poll( $ch['challenge_url'], $ch['auth_url'] );
            }

            return $this->finalize_and_download( $pc );
        } finally {
            foreach ( $files as $f ) wp_delete_file( $f );
        }
    }

    public function megurio_complete_dns01( array $pc ) {
        $this->assert_account();

        foreach ( $pc['challenges'] as $ch ) {
            $this->trigger_and_poll( $ch['challenge_url'], $ch['auth_url'] );
        }

        return $this->finalize_and_download( $pc );
    }

    /* ------------------------------------------------------------------ */
    /*  Shared finalize + download                                          */
    /* ------------------------------------------------------------------ */

    private function finalize_and_download( array $pc ) {
        $this->poll_order( $pc['order_url'], 'ready', 15, 2 );

        $dk      = openssl_pkey_get_private( $pc['domain_key_pem'] );
        $csr_pem = $this->generate_csr( $pc['domains'], $dk );
        $csr_der = $this->pem_to_der( $csr_pem, 'CERTIFICATE REQUEST' );

        $this->signed_request( $pc['finalize_url'], [ 'csr' => $this->b64u( $csr_der ) ] );

        $order = $this->poll_order( $pc['order_url'], 'valid', 20, 3 );

        $full_chain = $this->signed_request( $order['certificate'], null )['raw_body'];
        preg_match_all( '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $full_chain, $m );

        return [
            'cert_pem'        => $m[0][0] ?? '',
            'chain_pem'       => implode( "\n", array_slice( $m[0], 1 ) ),
            'fullchain_pem'   => $full_chain,
            'private_key_pem' => $pc['domain_key_pem'],
        ];
    }

    private function trigger_and_poll( $challenge_url, $auth_url ) {
        $this->signed_request( $challenge_url, (object) [] );

        $tries = 0;
        do {
            sleep( 3 );
            $auth = $this->signed_request( $auth_url, null )['body'];
        } while ( in_array( $auth['status'], [ 'pending', 'processing' ] ) && ++$tries < 20 );

        if ( $auth['status'] !== 'valid' ) {
            $detail = '';
            foreach ( $auth['challenges'] as $c ) {
                if ( isset( $c['error']['detail'] ) ) { $detail = $c['error']['detail']; break; }
            }
            throw new Exception( 'Validation failed for ' . esc_html( $auth['identifier']['value'] ?? '' ) . ': ' . esc_html( $detail ?: $auth['status'] ) );
        }
    }

    /* ------------------------------------------------------------------ */
    /*  ACME helpers                                                        */
    /* ------------------------------------------------------------------ */

    private function new_order( array $domains ) {
        $identifiers = array_map( fn($d) => [ 'type' => 'dns', 'value' => $d ], $domains );
        $resp        = $this->signed_request( $this->directory['newOrder'], [ 'identifiers' => $identifiers ] );
        return [ $resp['body'], $resp['headers']['location'] ?? '' ];
    }

    private function find_challenge( array $auth, string $type ) {
        foreach ( $auth['challenges'] as $c ) {
            if ( $c['type'] === $type ) return $c;
        }
        return null;
    }

    private function poll_order( $url, $target, $max, $interval ) {
        $tries = 0; $body = [];
        do {
            sleep( $interval );
            $body = $this->signed_request( $url, null )['body'];
        } while ( $body['status'] !== $target && ++$tries < $max );

        if ( $body['status'] !== $target ) {
            throw new Exception( "Order '" . esc_html( $body['status'] ) . "', expected '" . esc_html( $target ) . "'" );
        }
        return $body;
    }

    /* ------------------------------------------------------------------ */
    /*  Crypto helpers                                                      */
    /* ------------------------------------------------------------------ */

    private function load_directory() {
        if ( $this->directory ) return;
        $url = $this->staging ? self::MEGURIO_LE_STAGING : self::MEGURIO_LE_PROD;
        $r   = wp_remote_get( $url, [ 'timeout' => 30 ] );
        if ( is_wp_error( $r ) ) throw new Exception( 'Directory: ' . esc_html( $r->get_error_message() ) );
        $this->directory = json_decode( wp_remote_retrieve_body( $r ), true );
        $this->nonce     = wp_remote_retrieve_header( $r, 'replay-nonce' );
    }

    private function fresh_nonce() {
        $r = wp_remote_head( $this->directory['newNonce'], [ 'timeout' => 15 ] );
        if ( is_wp_error( $r ) ) throw new Exception( 'Nonce: ' . esc_html( $r->get_error_message() ) );
        $this->nonce = wp_remote_retrieve_header( $r, 'replay-nonce' );
    }

    private function init_key( $pk ) {
        $d = openssl_pkey_get_details( $pk );
        $this->key_data = [
            'private_key' => $pk,
            'jwk'         => [ 'kty' => 'RSA', 'n' => $this->b64u( $d['rsa']['n'] ), 'e' => $this->b64u( $d['rsa']['e'] ) ],
            'kid'         => '',
        ];
    }

    private function new_domain_key() {
        return openssl_pkey_new( [ 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ] );
    }

    private function assert_account() {
        if ( ! $this->account_url ) throw new Exception( 'Call megurio_load_account() first' );
    }

    private function signed_request( $url, $payload ) {
        if ( ! $this->nonce ) $this->fresh_nonce();

        $header = [ 'alg' => 'RS256', 'nonce' => $this->nonce, 'url' => $url ];
        $header[ $this->key_data['kid'] ? 'kid' : 'jwk' ] =
            $this->key_data['kid'] ?: $this->key_data['jwk'];

        $protected   = $this->b64u( json_encode( $header ) );
        $payload_enc = $payload === null ? '' : $this->b64u( $payload instanceof stdClass ? '{}' : json_encode( $payload ) );

        openssl_sign( "$protected.$payload_enc", $sig, $this->key_data['private_key'], OPENSSL_ALGO_SHA256 );

        $r = wp_remote_post( $url, [
            'timeout' => 60,
            'headers' => [ 'Content-Type' => 'application/jose+json' ],
            'body'    => json_encode( [ 'protected' => $protected, 'payload' => $payload_enc, 'signature' => $this->b64u( $sig ) ] ),
        ] );

        if ( is_wp_error( $r ) ) throw new Exception( 'HTTP: ' . esc_html( $r->get_error_message() ) );

        $this->nonce = wp_remote_retrieve_header( $r, 'replay-nonce' );
        $status      = wp_remote_retrieve_response_code( $r );
        $raw_body    = wp_remote_retrieve_body( $r );
        $parsed      = json_decode( $raw_body, true );

        $headers = [];
        foreach ( wp_remote_retrieve_headers( $r ) as $k => $v ) {
            $headers[ strtolower($k) ] = is_array($v) ? end($v) : $v;
        }

        if ( $status >= 400 ) throw new Exception( 'ACME ' . esc_html( (string) $status ) . ': ' . esc_html( $parsed['detail'] ?? $raw_body ) );

        return [ 'status' => $status, 'headers' => $headers, 'body' => $parsed, 'raw_body' => $raw_body ];
    }

    private function generate_csr( array $domains, $key ) {
        $san     = implode( ',', array_map( fn($d) => 'DNS:' . $d, $domains ) );
        require_once ABSPATH . 'wp-admin/includes/file.php';
        $tmp_cnf = wp_tempnam( 'acme-csr.cnf' );
        if ( ! $tmp_cnf ) {
            throw new Exception( 'CSR: failed to create temporary config file' );
        }
        $this->write_file( $tmp_cnf, "[req]\ndistinguished_name=req\n[SAN]\nsubjectAltName=$san\n" );
        $csr = openssl_csr_new( [ 'CN' => $domains[0] ], $key, [ 'config' => $tmp_cnf, 'req_extensions' => 'SAN', 'digest_alg' => 'sha256' ] );
        wp_delete_file( $tmp_cnf );
        if ( ! $csr ) throw new Exception( 'CSR: ' . esc_html( openssl_error_string() ) );
        openssl_csr_export( $csr, $pem );
        return $pem;
    }

    private function write_file( $path, $contents ) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        WP_Filesystem();
        global $wp_filesystem;

        if ( ! $wp_filesystem || ! $wp_filesystem->put_contents( $path, $contents, FS_CHMOD_FILE ) ) {
            throw new Exception( 'Failed to write temporary file: ' . esc_html( basename( $path ) ) );
        }
    }

    private function pem_to_der( $pem, $type ) {
        return base64_decode( preg_replace( '/-----[^-]+-----|[\r\n\s]/', '', $pem ) );
    }

    private function b64u( $data ) {
        return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
    }

    private function jwk_thumbprint() {
        $j = $this->key_data['jwk'];
        return $this->b64u( hash( 'sha256', json_encode( [ 'e' => $j['e'], 'kty' => $j['kty'], 'n' => $j['n'] ] ), true ) );
    }
}
