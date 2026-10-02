/**
 * Passkey sign-in button for wp-login.php.
 *
 * Plain vanilla JS, no build step — this loads on the login page, before any of the
 * dashboard's own ES-module bundle exists, so it can't share code with it. Fetches a
 * single-use challenge from the public /auth/passkey/login-options endpoint, lets the
 * authenticator sign it, then submits the signed assertion with the login form itself, so
 * WordPress's own sign-in (wp_signon) completes the login — see PasskeyLogin::authenticate().
 */
( function () {
	'use strict';

	function base64urlToBuffer( str ) {
		var pad = str.length % 4 === 0 ? '' : '===='.slice( str.length % 4 );
		var base64 = ( str + pad ).replace( /-/g, '+' ).replace( /_/g, '/' );
		var raw = window.atob( base64 );
		var buf = new Uint8Array( raw.length );
		for ( var i = 0; i < raw.length; i++ ) {
			buf[ i ] = raw.charCodeAt( i );
		}
		return buf.buffer;
	}

	function bufferToBase64url( buf ) {
		var bytes = new Uint8Array( buf );
		var binary = '';
		for ( var i = 0; i < bytes.byteLength; i++ ) {
			binary += String.fromCharCode( bytes[ i ] );
		}
		return window.btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	/**
	 * Decode the specific binary fields a PublicKeyCredentialRequestOptions actually has.
	 * Deliberately NOT a generic "any key named id" walk — rp.id (a plain domain string, no
	 * relation to rpId's binary siblings elsewhere in the spec) matches that name too and is
	 * not base64url at all, so a naive walk mis-decodes it and atob() throws.
	 */
	function decodeOptions( options ) {
		if ( ! options || typeof options !== 'object' ) {
			return;
		}
		if ( typeof options.challenge === 'string' ) {
			options.challenge = base64urlToBuffer( options.challenge );
		}
		if ( Array.isArray( options.allowCredentials ) ) {
			options.allowCredentials.forEach( function ( cred ) {
				if ( cred && typeof cred.id === 'string' ) {
					cred.id = base64urlToBuffer( cred.id );
				}
			} );
		}
	}

	function setMessage( msg, isError ) {
		var el = document.getElementById( 'totalsecwp-passkey-msg' );
		if ( ! el ) {
			return;
		}
		el.textContent = msg;
		el.hidden = ! msg;
		el.classList.toggle( 'is-error', !! isError );
	}

	function setField( name, value ) {
		var el = document.getElementById( 'totalsecwp_passkey_' + name );
		if ( el ) {
			el.value = value;
		}
	}

	/**
	 * Unwrap a REST response. A success response from this plugin's own controllers is always
	 * { success:true, data:{...} } (see AbstractController::ok()); a failure is a WP_Error,
	 * serialized by core as { code, message, data:{status} } — a different top-level shape, not
	 * a "data" envelope at all. Reading either shape the other one's way silently produces
	 * undefined instead of a clear error, which is what threw "reading 'publicKey' of undefined"
	 * the first time this endpoint failed.
	 */
	function unwrapRest( json, httpOk ) {
		if ( httpOk && json && true === json.success ) {
			return { ok: true, data: json.data };
		}
		return { ok: false, message: ( json && json.message ) || 'Request failed.' };
	}

	async function signIn() {
		if ( ! window.PublicKeyCredential || ! navigator.credentials || ! navigator.credentials.get ) {
			setMessage( 'This browser does not support passkeys.', true );
			return;
		}
		if ( ! window.TotalSecWPPasskey || ! window.TotalSecWPPasskey.restBase ) {
			setMessage( 'Passkey sign-in is not configured.', true );
			return;
		}

		var restBase = window.TotalSecWPPasskey.restBase.replace( /\/$/, '' );
		setMessage( 'Requesting your passkey…', false );

		try {
			var optRes = await window.fetch( restBase + '/auth/passkey/login-options' );
			var optResult = unwrapRest( await optRes.json(), optRes.ok );
			if ( ! optResult.ok ) {
				throw new Error( optResult.message || 'Could not start passkey sign-in.' );
			}

			// optResult.data.options is already shaped as { publicKey: {...} } — the exact
			// object navigator.credentials.get() expects, not something to re-wrap.
			var options = optResult.data.options;
			decodeOptions( options.publicKey );

			var assertion = await navigator.credentials.get( options );
			if ( ! assertion ) {
				throw new Error( 'No passkey was selected.' );
			}

			var form = document.getElementById( 'loginform' );
			if ( ! form ) {
				throw new Error( 'Login form not found.' );
			}

			setMessage( 'Signing you in…', false );

			setField( 'flow', optResult.data.flow );
			setField( 'id', bufferToBase64url( assertion.rawId ) );
			setField( 'client_data', bufferToBase64url( assertion.response.clientDataJSON ) );
			setField( 'auth_data', bufferToBase64url( assertion.response.authenticatorData ) );
			setField( 'signature', bufferToBase64url( assertion.response.signature ) );

			// A passkey sign-in carries no username/password: clear them (and their `required`
			// flags) so only the assertion is submitted, then post the form to wp-login.php.
			[ 'user_login', 'user_pass' ].forEach( function ( id ) {
				var input = document.getElementById( id );
				if ( input ) {
					input.value = '';
					input.removeAttribute( 'required' );
				}
			} );
			HTMLFormElement.prototype.submit.call( form );
		} catch ( err ) {
			// A user cancelling the OS/browser passkey prompt throws a benign NotAllowedError —
			// show a plain retry hint instead of a scary technical message for that one case.
			if ( err && 'NotAllowedError' === err.name ) {
				setMessage( 'Passkey sign-in was cancelled.', true );
			} else {
				setMessage( ( err && err.message ) || 'Passkey sign-in failed.', true );
			}
		}
	}

	document.addEventListener( 'DOMContentLoaded', function () {
		var btn = document.getElementById( 'totalsecwp-passkey-btn' );
		if ( btn ) {
			btn.addEventListener( 'click', signIn );
		}
	} );
} )();
