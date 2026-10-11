/**
 * Loyal Security — uninstall confirmation prompt.
 *
 * Loaded only on plugins.php. Intercepts the "Delete" action for this plugin and shows
 * a modal that lets the admin choose whether to also wipe all security data. The choice
 * is saved via wp-ajax before WordPress's own deletion flow continues.
 */
( function () {
	'use strict';

	var cfg = window.LoyalSecUninstall || {};

	document.addEventListener( 'DOMContentLoaded', function () {
		var row = document.querySelector( '[data-plugin="' + cfg.plugin + '"]' );
		if ( ! row ) {
			return;
		}

		// Intercept "Deactivate" — the plugin is still running at this point so our
		// script is loaded. "Delete" only appears after deactivation, at which point
		// the plugin no longer runs and cannot inject anything into the page.
		var link = row.querySelector( '.deactivate a' );
		if ( ! link ) {
			return;
		}

		link.addEventListener( 'click', function ( e ) {
			e.preventDefault();
			showModal( link.href );
		} );
	} );

	function showModal( deleteHref ) {
		var overlay = document.createElement( 'div' );
		overlay.id = 'loyalsec-del-overlay';
		overlay.style.cssText =
			'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100000;' +
			'display:flex;align-items:center;justify-content:center';

		overlay.innerHTML =
			'<div style="background:#fff;border-radius:6px;padding:28px 32px;' +
			'max-width:480px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.28)">' +

			'<h2 style="margin-top:0;font-size:18px;color:#1d2327">Deactivate Loyal Security</h2>' +
			'<p style="color:#50575e;margin-bottom:16px">' +
			'Before you deactivate, choose what should happen if you also uninstall the plugin.' +
			'</p>' +

			'<label style="display:flex;align-items:flex-start;gap:10px;padding:14px;' +
			'border:1px solid #dcdcde;border-radius:4px;background:#fafafa;cursor:pointer">' +
			'<input type="checkbox" id="loyalsec-del-chk"' +
			( cfg.deleteOnUninstall ? ' checked' : '' ) +
			' style="margin-top:2px;width:16px;height:16px;flex-shrink:0">' +
			'<span>' +
			'<strong>Delete all data on uninstall</strong><br>' +
			'<span style="font-size:13px;color:#646970">' +
			'If you later delete the plugin, all settings, firewall rules, security logs, scan history, ' +
			'and backups will be permanently erased. Leave unchecked to keep data for a possible re-install.' +
			'</span>' +
			'</span>' +
			'</label>' +

			'<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:20px">' +
			'<button id="loyalsec-del-cancel" type="button" ' +
			'style="padding:6px 14px;border:1px solid #dcdcde;border-radius:3px;' +
			'background:#fff;cursor:pointer;font-size:13px">Cancel</button>' +
			'<button id="loyalsec-del-confirm" type="button" ' +
			'style="padding:6px 16px;border:none;border-radius:3px;' +
			'background:#2271b1;color:#fff;cursor:pointer;font-size:13px;font-weight:600">' +
			'Save &amp; Deactivate</button>' +
			'</div>' +

			'</div>';

		document.body.appendChild( overlay );

		document.getElementById( 'loyalsec-del-cancel' ).addEventListener( 'click', function () {
			overlay.remove();
		} );

		overlay.addEventListener( 'click', function ( e ) {
			if ( e.target === overlay ) {
				overlay.remove();
			}
		} );

		document.getElementById( 'loyalsec-del-confirm' ).addEventListener( 'click', function () {
			var deleteData = document.getElementById( 'loyalsec-del-chk' ).checked;
			var btn = this;
			btn.disabled = true;
			btn.textContent = 'Saving…';

			var body = new FormData();
			body.append( 'action', 'loyalsec_set_delete_flag' );
			body.append( 'nonce', cfg.nonce );
			body.append( 'delete_data', deleteData ? 'true' : 'false' );

			fetch( cfg.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' } )
				.then( function () {
					window.location.href = deleteHref;
				} )
				.catch( function () {
					// Proceed even if the AJAX call fails — the existing default (false) is safe.
					window.location.href = deleteHref;
				} );
		} );
	}
} )();
