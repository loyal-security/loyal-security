/**
 * Loyal Security — two-factor enrollment / management popup.
 *
 * Loaded on every wp-admin screen (via admin_enqueue_scripts, not the React dashboard) so it
 * works regardless of capability — a role like Editor (a default force_2fa_roles member) can
 * be enforced without ever having the manage_total_security_wp capability the plugin's own
 * admin page requires, so linking out to that page would just trade one wall for another.
 * Enrollment and disabling both happen entirely inside this popup instead.
 *
 * Two ways this script is enqueued (window.TotalSecWP2faPrompt.autoShow tells them apart):
 *   - Reminder (autoShow: true, from TwoFactorEnrollPrompt) — shows itself automatically for a
 *     non-enrolled user in an enforced role. Two states driven by cfg.enforced: within the
 *     grace period it's dismissible ("Remind me tomorrow" / the close button both snooze it a
 *     day via wp-ajax); once the grace period ends there's no close/snooze affordance at all.
 *   - Manage (autoShow: false, from TwoFactorProfileSection on profile.php) — sits inert until
 *     window.totalsecwp2faOpen() is called from a button click. Always dismissible. Opens
 *     straight to enrollment if the user has no 2FA yet, or a status+disable view if they do —
 *     this is the only self-service way to remove 2FA for a user who can't open the plugin's
 *     own admin page at all.
 */
( function () {
	'use strict';

	var cfg = window.TotalSecWP2faPrompt || {};
	var overlayEl = null;

	document.addEventListener( 'DOMContentLoaded', function () {
		if ( cfg.autoShow ) {
			render( 'intro' );
		}
		// The "Set up / Manage two-factor authentication" button on profile.php.
		var openers = document.querySelectorAll( '[data-totalsecwp-2fa-open]' );
		for ( var i = 0; i < openers.length; i++ ) {
			openers[ i ].addEventListener( 'click', function () {
				window.totalsecwp2faOpen();
			} );
		}
	} );

	// Manage-mode entry point — wired to the "Manage two-factor authentication" button
	// TwoFactorProfileSection renders on profile.php.
	window.totalsecwp2faOpen = function () {
		render( cfg.alreadyEnabled ? 'manage' : 'intro' );
	};

	function snoozeThenClose() {
		var body = new FormData();
		body.append( 'action', 'totalsecwp_2fa_snooze' );
		body.append( 'nonce', cfg.nonce );
		fetch( cfg.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' } )
			.then( function ( res ) {
				return res.text().then( function ( text ) {
					// wp_die(1) on success, wp_die(-1) (or any non-2xx) on failure — WordPress's
					// standard AJAX success/failure convention, not a custom envelope.
					if ( ! res.ok || '1' !== text.trim() ) {
						throw new Error( 'Snooze request failed' );
					}
				} );
			} )
			.then( close )
			.catch( function () {
				// Genuinely failed server-side (expired session, nonce lifetime, etc.) — leave
				// the popup open rather than closing it while the state didn't actually change,
				// which is exactly the bug this replaces (looked like it worked, silently didn't).
				var btn = document.getElementById( 'totalsecwp-2fa-snooze' ) || document.getElementById( 'totalsecwp-2fa-close' );
				if ( btn ) {
					btn.disabled = false;
					if ( btn.textContent ) btn.textContent = 'Remind me tomorrow';
				}
				window.alert( 'Could not save — please try again.' );
			} );
	}

	function close() {
		if ( overlayEl ) {
			overlayEl.remove();
			overlayEl = null;
		}
	}

	function restFetch( path, body ) {
		return fetch( cfg.restRoot.replace( /\/$/, '' ) + path, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': cfg.restNonce },
			body: JSON.stringify( body || {} ),
		} ).then( function ( res ) {
			return res.json().then( function ( json ) {
				if ( ! res.ok ) {
					throw new Error( ( json && json.message ) || 'Request failed.' );
				}
				return json && json.data;
			} );
		} );
	}

	/**
	 * Rebuilds the modal body for a given view. Keeping this as one function that swaps the
	 * whole inner HTML per state (rather than hand-patching the DOM) matches the rest of this
	 * file's plain-string-template style and keeps each view's markup easy to read in one place.
	 */
	function render( view, data ) {
		var enforced = !! cfg.enforced;

		if ( ! overlayEl ) {
			overlayEl = document.createElement( 'div' );
			overlayEl.id = 'totalsecwp-2fa-overlay';
			overlayEl.style.cssText =
				'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100000;' +
				'display:flex;align-items:center;justify-content:center';
			document.body.appendChild( overlayEl );

			// Reminder + enforced state: no backdrop-click dismissal — only "Set up" or "Log out"
			// get you out. Manage mode (opened by choice from profile.php, not auto-shown as a
			// nag) is always freely dismissible regardless of the enforced flag, which doesn't
			// apply to it.
			overlayEl.addEventListener( 'click', function ( e ) {
				if ( e.target !== overlayEl ) {
					return;
				}
				if ( ! cfg.autoShow ) {
					close();
				} else if ( ! enforced && 'intro' === view ) {
					snoozeThenClose();
				}
			} );
		}

		var panel = document.createElement( 'div' );
		panel.style.cssText =
			'position:relative;background:#fff;border-radius:6px;padding:28px 32px;' +
			'max-width:440px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.28)';

		if ( 'begin' === view || 'confirm-error' === view ) {
			panel.innerHTML = renderEnroll( data );
		} else if ( 'done' === view ) {
			panel.innerHTML = renderDone( data );
		} else if ( 'manage' === view ) {
			panel.innerHTML = renderManage( data );
		} else {
			panel.innerHTML = renderIntro();
		}

		overlayEl.innerHTML = '';
		overlayEl.appendChild( panel );
		wire( view, data );

		// Redrawn on every render() call that has an otpauth URI to draw, not just the initial
		// "Set up now" click — confirm-error re-renders (e.g. submitting an empty code) rebuild
		// this panel from scratch too, and previously only that one click handler drew the QR,
		// so any error after that point left the QR permanently blank with no way back to it.
		if ( ( 'begin' === view || 'confirm-error' === view ) && data && data.otpauth && window.qrcode ) {
			try {
				var qr = window.qrcode( 0, 'M' );
				qr.addData( data.otpauth );
				qr.make();
				var target = document.getElementById( 'totalsecwp-2fa-qr' );
				if ( target ) target.innerHTML = qr.createSvgTag( 5, 8 );
			} catch ( e ) {
				// Manual key is still shown — QR rendering is a nice-to-have.
			}
		}
	}

	function renderIntro() {
		var enforced = !! cfg.enforced;
		var manage = ! cfg.autoShow;
		var remaining = cfg.remainingDays;

		var closeBtn = enforced
			? ''
			: '<button id="totalsecwp-2fa-close" type="button" aria-label="Close" ' +
				'style="position:absolute;top:10px;right:14px;border:0;background:none;' +
				'font-size:20px;line-height:1;cursor:pointer;color:#787c82">&times;</button>';

		var deadlineLine;
		if ( manage ) {
			deadlineLine = '<p style="color:#50575e;margin-bottom:16px">' +
				'Protect your account with an authenticator app (Google Authenticator, Authy, 1Password, etc).</p>';
		} else if ( enforced ) {
			deadlineLine = '<p style="color:#d63638;font-weight:600;margin-bottom:16px">' +
				'Your grace period has ended — two-factor authentication is now required to continue.</p>';
		} else {
			deadlineLine = '<p style="color:#50575e;margin-bottom:16px">' +
				'Two-factor authentication will be required for your account in ' +
				'<strong>' + remaining + ' day' + ( 1 === remaining ? '' : 's' ) + '</strong>. ' +
				'Set it up now to avoid being locked out of anything other than this reminder.</p>';
		}

		return (
			closeBtn +
			'<h2 style="margin-top:0;font-size:18px;color:#1d2327">' +
			( manage ? 'Set up two-factor authentication' : 'Two-factor authentication required' ) +
			'</h2>' +
			deadlineLine +
			'<div style="display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px;margin-top:20px">' +
			( enforced || manage ? '' :
				'<button id="totalsecwp-2fa-snooze" type="button" ' +
				'style="padding:6px 14px;border:1px solid #dcdcde;border-radius:3px;' +
				'background:#fff;cursor:pointer;font-size:13px">Remind me tomorrow</button>'
			) +
			( manage ? '' :
				'<a id="totalsecwp-2fa-logout" href="' + cfg.logoutUrl + '" ' +
				'style="padding:6px 14px;border:1px solid #dcdcde;border-radius:3px;' +
				'background:#fff;cursor:pointer;font-size:13px;color:#1d2327;text-decoration:none;' +
				'display:inline-flex;align-items:center">Log out</a>'
			) +
			'<button id="totalsecwp-2fa-begin" type="button" ' +
			'style="padding:6px 16px;border:none;border-radius:3px;' +
			'background:#2271b1;color:#fff;cursor:pointer;font-size:13px;font-weight:600">' +
			'Set up now</button>' +
			'</div>'
		);
	}

	function renderEnroll( data ) {
		data = data || {};
		var error = data.error
			? '<p style="color:#d63638;font-size:13px;margin:8px 0 0">' + escapeHtml( data.error ) + '</p>'
			: '';

		return (
			'<h2 style="margin-top:0;font-size:18px;color:#1d2327">Scan with your authenticator app</h2>' +
			'<div id="totalsecwp-2fa-qr" style="display:flex;justify-content:center;margin:12px 0"></div>' +
			'<p style="font-size:12px;color:#646970;text-align:center;word-break:break-all">' +
			'Can’t scan? Enter this key manually: <code>' + escapeHtml( data.manual_key || '' ) + '</code></p>' +
			'<label for="totalsecwp-2fa-code" style="display:block;margin-top:14px;font-weight:600">' +
			'Enter the 6-digit code</label>' +
			'<input id="totalsecwp-2fa-code" type="text" inputmode="numeric" autocomplete="one-time-code" ' +
			'maxlength="6" style="width:100%;box-sizing:border-box;font-size:16px;letter-spacing:2px;' +
			'padding:6px 8px;margin-top:4px" />' +
			error +
			'<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:20px">' +
			'<button id="totalsecwp-2fa-confirm" type="button" ' +
			'style="padding:6px 16px;border:none;border-radius:3px;' +
			'background:#2271b1;color:#fff;cursor:pointer;font-size:13px;font-weight:600">Confirm</button>' +
			'</div>'
		);
	}

	function renderDone( data ) {
		data = data || {};
		var codes = data.backup_codes || [];
		var codesHtml = codes.map( function ( c ) { return '<code>' + escapeHtml( c ) + '</code>'; } ).join( ' ' );

		return (
			'<h2 style="margin-top:0;font-size:18px;color:#1d2327">Two-factor authentication enabled</h2>' +
			'<p style="color:#50575e">Save these one-time backup codes somewhere safe — each works once, ' +
			'if you ever lose access to your authenticator app:</p>' +
			'<div style="background:#f6f7f7;border-radius:4px;padding:12px;line-height:2;font-size:13px">' +
			codesHtml +
			'</div>' +
			'<div style="display:flex;justify-content:flex-end;margin-top:20px">' +
			'<button id="totalsecwp-2fa-finish" type="button" ' +
			'style="padding:6px 16px;border:none;border-radius:3px;' +
			'background:#2271b1;color:#fff;cursor:pointer;font-size:13px;font-weight:600">Done</button>' +
			'</div>'
		);
	}

	function renderManage( data ) {
		data = data || {};
		var error = data.error
			? '<p style="color:#d63638;font-size:13px;margin:8px 0 0">' + escapeHtml( data.error ) + '</p>'
			: '';

		return (
			'<button id="totalsecwp-2fa-close" type="button" aria-label="Close" ' +
			'style="position:absolute;top:10px;right:14px;border:0;background:none;' +
			'font-size:20px;line-height:1;cursor:pointer;color:#787c82">&times;</button>' +
			'<h2 style="margin-top:0;font-size:18px;color:#1d2327">Two-factor authentication</h2>' +
			'<p style="color:#00a32a;font-weight:600;margin-bottom:16px">Enabled for your account.</p>' +
			error +
			'<div style="display:flex;justify-content:flex-end;margin-top:20px">' +
			'<button id="totalsecwp-2fa-disable" type="button" ' +
			'style="padding:6px 16px;border:none;border-radius:3px;' +
			'background:#d63638;color:#fff;cursor:pointer;font-size:13px;font-weight:600">Disable 2FA</button>' +
			'</div>'
		);
	}

	function escapeHtml( s ) {
		var div = document.createElement( 'div' );
		div.textContent = String( s );
		return div.innerHTML;
	}

	function wire( view, data ) {
		var closeEl = document.getElementById( 'totalsecwp-2fa-close' );
		if ( closeEl ) closeEl.addEventListener( 'click', cfg.autoShow ? snoozeThenClose : close );

		var snoozeEl = document.getElementById( 'totalsecwp-2fa-snooze' );
		if ( snoozeEl ) snoozeEl.addEventListener( 'click', function () {
			this.disabled = true;
			this.textContent = 'Snoozing…';
			snoozeThenClose();
		} );

		var beginEl = document.getElementById( 'totalsecwp-2fa-begin' );
		if ( beginEl ) beginEl.addEventListener( 'click', function () {
			var btn = this;
			btn.disabled = true;
			btn.textContent = 'Loading…';
			restFetch( '/auth/2fa/begin' )
				.then( function ( res ) {
					render( 'begin', res ); // QR itself is drawn inside render() — see there.
				} )
				.catch( function ( e ) {
					render( 'begin', { error: e.message } );
				} );
		} );

		var confirmEl = document.getElementById( 'totalsecwp-2fa-confirm' );
		if ( confirmEl ) confirmEl.addEventListener( 'click', function () {
			var btn = this;
			var input = document.getElementById( 'totalsecwp-2fa-code' );
			var code = input ? input.value.trim() : '';
			if ( ! code ) {
				render( 'confirm-error', Object.assign( {}, data, { error: 'Enter the code from your authenticator app.' } ) );
				return;
			}
			btn.disabled = true;
			btn.textContent = 'Verifying…';
			restFetch( '/auth/2fa/confirm', { code: code } )
				.then( function ( res ) {
					render( 'done', res );
				} )
				.catch( function ( e ) {
					render( 'confirm-error', Object.assign( {}, data, { error: e.message } ) );
				} );
		} );

		var disableEl = document.getElementById( 'totalsecwp-2fa-disable' );
		if ( disableEl ) disableEl.addEventListener( 'click', function () {
			if ( ! window.confirm( 'Disable two-factor authentication for your account?' ) ) return;
			var btn = this;
			btn.disabled = true;
			btn.textContent = 'Disabling…';
			restFetch( '/auth/2fa/disable' )
				.then( function () {
					window.location.reload(); // Same reasoning as the enroll "Done" button below.
				} )
				.catch( function ( e ) {
					render( 'manage', { error: e.message } );
				} );
		} );

		var finishEl = document.getElementById( 'totalsecwp-2fa-finish' );
		if ( finishEl ) finishEl.addEventListener( 'click', function () {
			// A full reload, not just closing the overlay: this user is now enrolled, so every
			// other piece of state that depended on "not yet enrolled" (this popup's own
			// should_show() check, LoginGuard's hard redirect) needs to be re-evaluated fresh.
			window.location.reload();
		} );
	}
} )();
