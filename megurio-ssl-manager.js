jQuery(function ($) {
    var overlay = $('#megurio-cg-overlay');
    var t = megurio_cert_gen.i18n;

    function openModal()  { overlay.show(); $('#megurio-cg-modal').show(); }
    function closeModal() {
        overlay.hide(); $('#megurio-cg-modal').hide();
        $('#megurio-cg-loading,#megurio-cg-add-info,#megurio-cg-http-info,#megurio-cg-dns-info,#megurio-cg-error,#megurio-cg-modal-footer').hide();
    }
    function showLoading( msg ) {
        $('#megurio-cg-loading-msg').text( msg || t.loading_token );
        $('#megurio-cg-loading').show();
        $('#megurio-cg-add-info,#megurio-cg-http-info,#megurio-cg-dns-info,#megurio-cg-error,#megurio-cg-modal-footer').hide();
    }
    function showError( msg ) {
        $('#megurio-cg-loading,#megurio-cg-add-info,#megurio-cg-http-info,#megurio-cg-dns-info,#megurio-cg-modal-footer').hide();
        $('#megurio-cg-error-msg').text( msg );
        $('#megurio-cg-error').show();
    }
    function showPanel( selector ) {
        $('#megurio-cg-loading,#megurio-cg-add-info,#megurio-cg-http-info,#megurio-cg-dns-info,#megurio-cg-error').hide();
        $( selector ).show();
        $('#megurio-cg-modal-footer').show();
    }
    function showAddPanel() {
        openModal();
        $('#megurio-cg-loading,#megurio-cg-http-info,#megurio-cg-dns-info,#megurio-cg-error,#megurio-cg-modal-footer').hide();
        $('#megurio-cg-add-info').show();
    }

    function codeBlock( label, value ) {
        return '<div style="margin:8px 0"><strong style="display:block;margin-bottom:3px">' + label + ':</strong>'
             + '<code style="background:#f0f0f0;padding:6px 8px;border-radius:3px;word-break:break-all;display:block;line-height:1.5">'
             + $('<span>').text( value ).html()
             + '</code></div>';
    }

    function reusedNotice( d ) {
        if ( ! d.reused ) {
            return '';
        }

        return '<div style="border-left:4px solid #00a32a;background:#f0f6ef;padding:8px 10px;margin:0 0 12px;color:#1d5f2a">'
             + $('<span>').text( t.reused_challenge ).html()
             + '</div>';
    }

    function ajaxPrepare( action, id, onSuccess ) {
        openModal();
        showLoading( t.loading_token );
        $.post( megurio_cert_gen.ajax_url, {
            action:      action,
            id:          id,
            _ajax_nonce: megurio_cert_gen.nonce,
        }, function ( res ) {
            if ( !res.success ) { showError( res.data || t.request_failed ); return; }
            onSuccess( res.data );
        }).fail(function () { showError( t.network_error ); });
    }

    $(document).on( 'click', '#megurio-cg-open-add', showAddPanel );

    /* ---- File Verify ---- */
    $(document).on( 'click', '.megurio-cert-btn-http', function () {
        var id = $(this).data('id');
        ajaxPrepare( 'megurio_cert_gen_prepare_http', id, function ( d ) {
            var html = reusedNotice( d );
            $.each( d.challenges, function ( i, ch ) {
                html += '<div style="border:1px solid #ddd;border-radius:4px;padding:12px 14px;margin-bottom:12px">';
                html += '<p style="font-weight:600;margin:0 0 8px">' + t.domain + ': ' + $('<span>').text(ch.domain).html() + '</p>';
                html += codeBlock( t.file_dir,     '/.well-known/acme-challenge/' );
                html += codeBlock( t.filename,     ch.token );
                html += codeBlock( t.file_content, ch.key_auth );
                html += '<p style="margin:6px 0;font-size:12px;color:#666">' + t.access_verify + ': '
                     + '<a href="#" target="_blank" style="color:#d63638;word-break:break-all">'
                     + 'http(s)://' + $('<span>').text(ch.domain).html()
                     + '/.well-known/acme-challenge/' + $('<span>').text(ch.token).html()
                     + '</a></p>';
                html += '</div>';
            });
            $('#megurio-cg-http-list').html( html );
            $('#megurio-cg-form-id').val( d.id );
            $('#megurio-cg-form-nonce').val( d.verify_nonce );
            showPanel( '#megurio-cg-http-info' );
        });
    });

    /* ---- DNS Verify ---- */
    $(document).on( 'click', '.megurio-cert-btn-dns', function () {
        var id = $(this).data('id');
        ajaxPrepare( 'megurio_cert_gen_prepare_dns', id, function ( d ) {
            var html = reusedNotice( d );
            $.each( d.challenges, function ( i, ch ) {
                html += '<div style="border:1px solid #ddd;border-radius:4px;padding:12px 14px;margin-bottom:12px">';
                html += '<p style="font-weight:600;margin:0 0 8px">' + t.domain + ': ' + $('<span>').text(ch.domain).html() + '</p>';
                html += codeBlock( t.host_record,  ch.dns_host );
                html += codeBlock( t.record_type,  'TXT' );
                html += codeBlock( t.record_value, ch.txt_value );
                html += '</div>';
            });
            $('#megurio-cg-dns-list').html( html );
            $('#megurio-cg-form-id').val( d.id );
            $('#megurio-cg-form-nonce').val( d.verify_nonce );
            showPanel( '#megurio-cg-dns-info' );
        });
    });

    /* ---- Verify button ---- */
    $('#megurio-cg-do-verify').on( 'click', function () {
        showLoading( t.loading_verify );
        setTimeout(function () { $('#megurio-cg-verify-form').submit(); }, 100);
    });

    /* ---- Close ---- */
    $(document).on( 'click', '.megurio-cg-close', closeModal );
    overlay.on( 'click', closeModal );
});
