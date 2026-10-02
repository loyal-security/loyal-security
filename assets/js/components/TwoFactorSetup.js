/**
 * Two-factor setup + session management panel.
 */
import { h, useState, useEffect, useRef, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState, Toggle, Modal } from './ui.js';
import { useStore } from '../store.js';

/**
 * Renders a QR code SVG into a container div using the globally loaded qrcode-generator.
 * Falls back to nothing if the library didn't load.
 */
function QrCode( { uri } ) {
	const ref = useRef( null );
	useEffect( () => {
		if ( ! ref.current || ! window.qrcode ) return;
		try {
			const qr = window.qrcode( 0, 'M' ); // type=0 auto-size, error level M
			qr.addData( uri );
			qr.make();
			ref.current.innerHTML = qr.createSvgTag( 5, 8 );
		} catch ( e ) {
			// silent — manual key is still shown
		}
	}, [ uri ] );
	return h( 'div', { ref, className: 'ts-qrcode', 'aria-label': 'QR code for authenticator app setup' } );
}

/**
 * Lists the devices the user has chosen to trust for 30 days after a successful 2FA
 * verification, with per-device and bulk revocation. Revoking drops the trust token so the
 * next sign-in from that device requires 2FA again.
 */
function TrustedDevices() {
	const store = useStore();
	const [ devices, setDevices ] = useState( null );
	const [ busy, setBusy ]       = useState( '' );

	const load = () => api.get( '/auth/trusted-devices' )
		.then( ( d ) => setDevices( ( d && d.devices ) || [] ) )
		.catch( ( e ) => { setDevices( [] ); store.toast( e.message, 'error' ); } );

	useEffect( () => { load(); }, [] );

	const revoke = async ( hash ) => {
		setBusy( hash );
		try {
			await api.del( '/auth/trusted-devices/' + encodeURIComponent( hash ) );
			store.toast( 'Device revoked.', 'success' );
			await load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const revokeAll = async () => {
		if ( ! devices || ! devices.length ) return;
		if ( ! window.confirm( 'Revoke trust for every device? Each will require 2FA again on the next sign-in.' ) ) return;
		setBusy( 'all' );
		try {
			// Revoke one-by-one (no bulk endpoint).
			for ( const d of devices ) {
				await api.del( '/auth/trusted-devices/' + encodeURIComponent( d.token_hash ) );
			}
			store.toast( 'All devices revoked.', 'success' );
			await load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
			load();
		} finally {
			setBusy( '' );
		}
	};

	return h( Card, {
		title: 'Trusted Devices',
		actions: devices && devices.length
			? h( Button, { variant: 'danger', disabled: !! busy, onClick: revokeAll }, busy === 'all' ? 'Revoking…' : 'Revoke all' )
			: null,
	},
		devices === null
			? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
			: devices.length === 0
				? h( EmptyState, { icon: '📵', title: 'No trusted devices', hint: 'Devices you choose to trust after 2FA verification will appear here.' } )
				: h( 'table', { className: 'ts-table' },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'Device' ), h( 'th', null, 'Trusted' ), h( 'th', null, 'Expires' ), h( 'th', null, '' )
						) ),
						h( 'tbody', null, devices.map( ( d ) =>
							h( 'tr', { key: d.token_hash },
								h( 'td', { className: 'ts-uri', title: d.user_agent }, d.user_agent || 'Unknown device' ),
								h( 'td', null, fmtDate( d.issued_at ) ),
								h( 'td', null, fmtDate( d.expires_at ) ),
								h( 'td', null, h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => revoke( d.token_hash ) }, busy === d.token_hash ? 'Revoking…' : 'Revoke' ) )
							)
						) )
				  )
	);
}

/**
 * Admin-wide view across every user's trusted devices — distinct from TrustedDevices above,
 * which is scoped to the current user's own for self-service. Every viewer of this page already
 * has manage_total_security_wp (the page itself is gated on it), so no extra client-side
 * capability check is needed here; the REST endpoints enforce it server-side regardless.
 * Exists so a compromised device can be revoked immediately by whoever finds it, without first
 * tracking down which specific user account trusted it.
 */
function AllTrustedDevicesCard() {
	const store = useStore();
	const [ devices, setDevices ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ query, setQuery ] = useState( '' );
	const [ roleFilter, setRoleFilter ] = useState( '' );

	const load = () => api.get( '/auth/trusted-devices-admin' )
		.then( ( d ) => setDevices( ( d && d.devices ) || [] ) )
		.catch( ( e ) => { setDevices( [] ); store.toast( e.message, 'error' ); } );
	useEffect( () => { load(); }, [] );

	const revoke = async ( userId, hash ) => {
		const key = userId + ':' + hash;
		setBusy( key );
		try {
			await api.del( '/auth/trusted-devices-admin/' + userId + '/' + encodeURIComponent( hash ) );
			store.toast( 'Device revoked.', 'success' );
			await load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const allRoles = devices
		? Array.from( new Set( devices.flatMap( ( d ) => d.roles ) ) ).sort()
		: [];

	const q = query.trim().toLowerCase();
	const filtered = ( devices || [] ).filter( ( d ) => {
		if ( roleFilter && ! d.roles.includes( roleFilter ) ) return false;
		if ( ! q ) return true;
		return d.login.toLowerCase().includes( q ) || d.display_name.toLowerCase().includes( q );
	} );

	return h( Card, { title: 'All Trusted Devices', actions: h( Badge, { tone: 'neutral' }, ( devices || [] ).length + ' total' ) },
		h( 'p', { className: 'ts-muted' }, 'Every device any user on this site has chosen to trust after 2FA verification. Revoke one immediately if it\'s lost, stolen, or otherwise compromised.' ),
		devices === null
			? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
			: h( Fragment, null,
				h( 'div', { className: 'ts-actions-row', style: { marginBottom: '10px', gap: '8px' } },
					h( 'input', {
						type: 'text', placeholder: 'Search username or name…',
						value: query, onChange: ( e ) => setQuery( e.target.value ),
						style: { flex: '1 1 200px' },
					} ),
					allRoles.length > 1 && h( 'select', {
						value: roleFilter, onChange: ( e ) => setRoleFilter( e.target.value ),
					},
						h( 'option', { value: '' }, 'All roles' ),
						allRoles.map( ( r ) => h( 'option', { key: r, value: r }, r.charAt( 0 ).toUpperCase() + r.slice( 1 ) ) )
					)
				),
				filtered.length === 0
					? h( EmptyState, { icon: '📵', title: 'No matching devices', hint: devices.length ? 'Try a different search or role filter.' : 'No user on this site has a trusted device yet.' } )
					: h( 'table', { className: 'ts-table', style: { width: '100%' } },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'User' ), h( 'th', null, 'Roles' ), h( 'th', null, 'Device' ), h( 'th', null, 'Trusted' ), h( 'th', null, 'Expires' ), h( 'th', null, '' )
						) ),
						h( 'tbody', null, filtered.map( ( d ) => h( 'tr', { key: d.user_id + ':' + d.token_hash },
							h( 'td', null, d.display_name, h( 'br', null ), h( 'span', { className: 'ts-muted' }, '@' + d.login ) ),
							h( 'td', null, d.roles.join( ', ' ) ),
							h( 'td', { className: 'ts-uri', title: d.user_agent }, d.user_agent || 'Unknown device' ),
							h( 'td', null, fmtDate( d.issued_at ) ),
							h( 'td', null, fmtDate( d.expires_at ) ),
							h( 'td', null, h( Button, {
								variant: 'danger', disabled: busy === ( d.user_id + ':' + d.token_hash ),
								onClick: () => revoke( d.user_id, d.token_hash ),
							}, busy === ( d.user_id + ':' + d.token_hash ) ? 'Revoking…' : 'Revoke' ) )
						) ) )
					)
			)
	);
}

const RESERVED_SLUGS = [
	'', 'wp-admin', 'wp-login', 'wp-login.php', 'wp-content', 'wp-includes', 'wp-json',
	'xmlrpc.php', 'feed', 'comments', 'embed', 'admin', 'login', 'favicon.ico', 'robots.txt',
	'sitemap.xml', 'wp-cron.php',
];

/** Standard WP roles offered for enforcement — matches the default force_2fa_roles set. */
const FORCE_2FA_ROLE_OPTIONS = [ 'administrator', 'editor', 'author', 'contributor', 'subscriber' ];

/**
 * Site-wide policy: require 2FA enrollment for the selected roles, not just whoever has
 * opted in personally. Surfaced here (not only in the generic Settings page) because this is
 * exactly what the dashboard's "Enforce two-factor authentication" health-score item checks —
 * a visitor who already enrolled themselves and lands on this page from that recommendation
 * should find the actual control right here, not just the tooling for their own account. The
 * same setting (auth.force_2fa / auth.force_2fa_roles) still appears in Settings too, for
 * anyone who prefers managing every module from one place.
 */
function ForceTwoFactorCard() {
	const store = useStore();
	const [ loaded, setLoaded ] = useState( false );
	const [ enabled, setEnabled ] = useState( false );
	const [ roles, setRoles ] = useState( [] );
	const [ graceDays, setGraceDays ] = useState( 7 );
	const [ busy, setBusy ] = useState( false );

	const load = () => api.get( '/settings' )
		.then( ( all ) => {
			const auth = ( all && all.auth ) || {};
			setEnabled( !! auth.force_2fa );
			setRoles( Array.isArray( auth.force_2fa_roles ) ? auth.force_2fa_roles : [] );
			setGraceDays( Number.isFinite( auth.force_2fa_grace_days ) ? auth.force_2fa_grace_days : 7 );
		} )
		.catch( ( e ) => store.toast( e.message, 'error' ) )
		.finally( () => setLoaded( true ) );
	useEffect( () => { load(); }, [] );

	const save = async ( next ) => {
		setBusy( true );
		try {
			await api.post( '/settings/auth', next );
			store.toast( 'Saved.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( false );
		}
	};

	const toggle = ( checked ) => {
		setEnabled( checked );
		save( { force_2fa: checked } );
	};

	const toggleRole = ( role, checked ) => {
		const next = checked ? [ ...roles, role ] : roles.filter( ( r ) => r !== role );
		setRoles( next );
		save( { force_2fa_roles: next } );
	};

	const saveGraceDays = () => {
		const days = Math.max( 0, parseInt( graceDays, 10 ) || 0 );
		setGraceDays( days );
		save( { force_2fa_grace_days: days } );
	};

	if ( ! loaded ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	return h( Card, {
		title: 'Enforce Two-Factor Authentication',
		actions: h( Badge, { tone: enabled ? 'success' : 'neutral' }, enabled ? 'Enforced' : 'Not enforced' ),
	},
		h( 'p', null, 'Requires the selected roles to enroll 2FA before they can do anything else — the single most effective login defence. This is separate from your own enrollment above: it applies to every account with a matching role, not just yours.' ),
		h( Toggle, {
			checked: enabled,
			disabled: busy,
			onChange: toggle,
			label: enabled ? 'Enforced for the roles below' : 'Not enforced',
		} ),
		enabled && h( 'div', { className: 'ts-actions-row', style: { flexWrap: 'wrap', marginTop: '10px' } },
			FORCE_2FA_ROLE_OPTIONS.map( ( role ) => h( 'label', { key: role, style: { display: 'flex', alignItems: 'center', gap: '6px', marginRight: '14px' } },
				h( 'input', {
					type: 'checkbox',
					checked: roles.includes( role ),
					disabled: busy,
					onChange: ( e ) => toggleRole( role, e.target.checked ),
				} ),
				role.charAt( 0 ).toUpperCase() + role.slice( 1 )
			) )
		),
		enabled && h( 'div', { style: { marginTop: '16px', paddingTop: '14px', borderTop: '1px solid var(--ts-border)' } },
			h( 'label', { htmlFor: 'ts-2fa-grace-days', style: { display: 'block', fontWeight: 600, marginBottom: '4px' } }, 'Grace period' ),
			h( 'p', { className: 'ts-muted', style: { marginTop: 0, marginBottom: '8px' } },
				'A newly-enforced user gets this many days, with dismissible reminders, before being redirected and blocked. Doesn’t affect deadlines already given out — see the roll-out list below to extend anyone individually.' ),
			h( 'div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } },
				h( 'input', {
					id: 'ts-2fa-grace-days', type: 'number', min: 0, max: 90, style: { width: '80px' },
					value: graceDays, disabled: busy,
					onChange: ( e ) => setGraceDays( e.target.value ),
				} ),
				h( 'span', null, 'days' ),
				h( Button, { variant: 'ghost', disabled: busy, onClick: saveGraceDays }, 'Save' )
			)
		)
	);
}

/**
 * Roll-out status for every user currently subject to force_2fa but not yet enrolled — how
 * many days they have left (or that they're already past their deadline), with a per-user
 * "extend" action for an admin to grant more time without changing the site-wide default.
 */
function GracePeriodRolloutCard() {
	const store = useStore();
	const [ loaded, setLoaded ] = useState( false );
	const [ rows, setRows ] = useState( [] );
	const [ busyId, setBusyId ] = useState( 0 );

	const load = () => api.get( '/auth/2fa-grace' )
		.then( ( r ) => setRows( Array.isArray( r ) ? r : [] ) )
		.catch( ( e ) => store.toast( e.message, 'error' ) )
		.finally( () => setLoaded( true ) );
	useEffect( () => { load(); }, [] );

	const extend = async ( userId ) => {
		setBusyId( userId );
		try {
			await api.post( '/auth/2fa-grace/extend', { user_id: userId, days: 7 } );
			store.toast( 'Extended by 7 days.', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusyId( 0 );
		}
	};

	const enforceNow = async ( userId, name ) => {
		if ( ! window.confirm( 'End ' + name + '’s grace period now? Their next admin page load will redirect them to enroll.' ) ) return;
		setBusyId( userId );
		try {
			await api.post( '/auth/2fa-grace/enforce', { user_id: userId } );
			store.toast( 'Enforced immediately.', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusyId( 0 );
		}
	};

	if ( ! loaded ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	return h( Card, { title: 'Roll-out status', actions: h( Badge, { tone: rows.length ? 'warning' : 'success' }, rows.length + ' pending' ) },
		rows.length === 0
			? h( EmptyState, { icon: '✅', title: 'Everyone is enrolled', hint: 'No user in an enforced role is still waiting on 2FA.' } )
			: h( 'table', { className: 'ts-table', style: { width: '100%' } },
				h( 'thead', null, h( 'tr', null,
					h( 'th', null, 'User' ), h( 'th', null, 'Roles' ), h( 'th', null, 'Status' ), h( 'th', { colSpan: 2 }, 'Actions' )
				) ),
				h( 'tbody', null, rows.map( ( r ) => h( 'tr', { key: r.id },
					h( 'td', null, r.name, h( 'br', null ), h( 'span', { className: 'ts-muted' }, '@' + r.login ) ),
					h( 'td', null, r.roles.join( ', ' ) ),
					h( 'td', null, r.enforced
						? h( Badge, { tone: 'danger' }, 'Enforced now' )
						: h( Badge, { tone: 'warning' }, r.remaining_days + ' day' + ( 1 === r.remaining_days ? '' : 's' ) + ' left' )
					),
					h( 'td', null, h( Button, {
						variant: 'default', disabled: busyId === r.id,
						onClick: () => extend( r.id ),
					}, busyId === r.id ? 'Extending…' : '+7 days' ) ),
					h( 'td', null, r.enforced
						? null
						: h( Button, {
							variant: 'danger', disabled: busyId === r.id,
							onClick: () => enforceNow( r.id, r.name ),
						}, busyId === r.id ? 'Enforcing…' : 'Enforce now' )
					)
				) ) )
			)
	);
}

/**
 * Hides wp-login.php behind a custom slug. Opt-in and deployed with a self-test +
 * auto-rollback on the server side (LoginUrlInstaller), so a save that fails verification
 * never leaves the site unable to log in — see the "how recovery works" hint below the form.
 */
function LoginUrlCard() {
	const store = useStore();
	const [ status, setStatus ] = useState( null );
	const [ slug, setSlug ] = useState( '' );
	const [ busy, setBusy ] = useState( '' );
	const [ error, setError ] = useState( '' );
	const [ result, setResult ] = useState( null );

	const load = () => api.get( '/auth/login-url' ).then( ( d ) => { setStatus( d ); setSlug( d.slug || '' ); } ).catch( ( e ) => store.toast( e.message, 'error' ) );
	useEffect( () => { load(); }, [] );

	const validate = ( value ) => {
		if ( value.length < 3 || value.length > 64 || ! /^[a-z0-9-]+$/.test( value ) ) {
			return 'Use 3–64 letters, numbers, or hyphens.';
		}
		if ( RESERVED_SLUGS.includes( value ) ) {
			return 'That slug is reserved — choose another.';
		}
		return '';
	};

	const enable = async () => {
		const value = slug.trim().toLowerCase();
		const problem = validate( value );
		if ( problem ) { setError( problem ); return; }
		setError( '' );
		setBusy( 'enable' );
		try {
			const res = await api.post( '/auth/login-url', { enabled: true, slug: value } );
			setResult( res );
			store.toast( 'Custom login URL verified and active.', 'success' );
			load();
		} catch ( e ) {
			// A failed self-test (e.g. no mod_rewrite — most commonly an Nginx host) still
			// carries the manual Nginx snippet in the error's data — show it instead of leaving
			// the admin with only a bare error and no way to finish enabling the feature.
			setResult( e.data && e.data.nginx_snippet ? { nginx_snippet: e.data.nginx_snippet } : null );
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const disable = async () => {
		if ( ! window.confirm( 'Disable the custom login URL and restore /wp-login.php?' ) ) return;
		setBusy( 'disable' );
		try {
			await api.post( '/auth/login-url', { enabled: false } );
			setResult( null );
			store.toast( 'Custom login URL disabled.', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	if ( ! status ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	return h( Card, {
		title: 'Custom Login URL',
		actions: h( Badge, { tone: status.enabled ? 'success' : 'neutral' }, status.enabled ? 'Enabled' : 'Disabled' ),
	},
		h( 'p', null, 'Moves the login form off the well-known /wp-login.php path so automated brute-force bots can\'t find it. Logout links and emailed password-reset links keep working on the original path.' ),

		status.enabled && h( 'p', null, 'Current login URL: ', h( 'code', null, status.url ), ' ',
			h( Button, { variant: 'ghost', onClick: () => { navigator.clipboard && navigator.clipboard.writeText( status.url ); store.toast( 'Copied.', 'success' ); } }, 'Copy' )
		),

		! status.enabled && h( 'div', { className: 'ts-actions-row' },
			h( 'input', {
				id: 'ts-login-slug', name: 'login_slug',
				type: 'text', placeholder: 'e.g. my-secret-login', value: slug,
				onChange: ( e ) => { setSlug( e.target.value ); setError( '' ); },
			} ),
			h( Button, { variant: 'primary', disabled: busy === 'enable', onClick: enable }, busy === 'enable' ? 'Verifying…' : 'Enable' )
		),
		error && h( 'p', { className: 'ts-notice ts-notice--danger' }, error ),

		result && result.nginx_snippet && h( 'details', { className: 'ts-details', open: ! status.enabled },
			h( 'summary', null, 'Running Nginx? Add this manually' ),
			h( 'pre', null, result.nginx_snippet )
		),

		status.enabled && h( Button, { variant: 'danger', disabled: !! busy, onClick: disable }, busy === 'disable' ? 'Disabling…' : 'Disable' ),

		h( 'p', { className: 'ts-muted' }, 'Recovery: if you ever get locked out, add ',
			h( 'code', null, "define('TOTALSECWP_DISABLE_LOGIN_URL', true);" ), ' to wp-config.php to instantly restore /wp-login.php — no database access needed.' )
	);
}

/* ─── Passkey (WebAuthn) helpers ──────────────────────────────────────── */

function b64urlToBuffer( str ) {
	const pad = str.length % 4 === 0 ? '' : '===='.slice( str.length % 4 );
	const base64 = ( str + pad ).replace( /-/g, '+' ).replace( /_/g, '/' );
	const raw = window.atob( base64 );
	const buf = new Uint8Array( raw.length );
	for ( let i = 0; i < raw.length; i++ ) buf[ i ] = raw.charCodeAt( i );
	return buf.buffer;
}

function bufferToB64url( buf ) {
	const bytes = new Uint8Array( buf );
	let binary = '';
	for ( let i = 0; i < bytes.byteLength; i++ ) binary += String.fromCharCode( bytes[ i ] );
	return window.btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
}

/**
 * Decode the specific binary fields a PublicKeyCredentialCreationOptions actually has.
 * Deliberately NOT a generic "any key named id" walk — rp.id is a plain domain string (no
 * relation to the binary user.id/excludeCredentials[].id fields that share the name "id"),
 * and mis-decoding it as base64url throws in atob().
 */
function decodePasskeyOptions( options ) {
	if ( ! options || typeof options !== 'object' ) return;
	if ( typeof options.challenge === 'string' ) {
		options.challenge = b64urlToBuffer( options.challenge );
	}
	if ( options.user && typeof options.user.id === 'string' ) {
		options.user.id = b64urlToBuffer( options.user.id );
	}
	if ( Array.isArray( options.excludeCredentials ) ) {
		options.excludeCredentials.forEach( ( cred ) => {
			if ( cred && typeof cred.id === 'string' ) {
				cred.id = b64urlToBuffer( cred.id );
			}
		} );
	}
}

/**
 * Passkeys: a complete, passwordless sign-in method — not a second factor layered on top of
 * TOTP/password, which is why it's its own card rather than a sub-section of the TOTP one.
 */
function PasskeysCard() {
	const store = useStore();
	const [ passkeys, setPasskeys ] = useState( null );
	const [ busy, setBusy ] = useState( '' );

	const load = () => api.get( '/auth/passkey/list' )
		.then( ( d ) => setPasskeys( ( d && d.passkeys ) || [] ) )
		.catch( ( e ) => { setPasskeys( [] ); store.toast( e.message, 'error' ); } );
	useEffect( () => { load(); }, [] );

	const addPasskey = async () => {
		if ( ! window.PublicKeyCredential || ! navigator.credentials || ! navigator.credentials.create ) {
			store.toast( 'This browser does not support passkeys.', 'error' );
			return;
		}
		setBusy( 'add' );
		try {
			const optRes = await api.post( '/auth/passkey/register-options', {} );
			// optRes.options is already shaped as { publicKey: {...} } — the exact object
			// navigator.credentials.create() expects, not something to re-wrap.
			const options = optRes.options;
			decodePasskeyOptions( options.publicKey );

			const cred = await navigator.credentials.create( options );
			if ( ! cred ) throw new Error( 'No passkey was created.' );

			const label = window.prompt( 'Name this passkey (e.g. "Work laptop"):', '' ) || '';

			await api.post( '/auth/passkey/register', {
				clientDataJSON: bufferToB64url( cred.response.clientDataJSON ),
				attestationObject: bufferToB64url( cred.response.attestationObject ),
				label,
			} );
			store.toast( 'Passkey added.', 'success' );
			load();
		} catch ( e ) {
			if ( e && 'NotAllowedError' === e.name ) {
				store.toast( 'Passkey setup was cancelled.', 'error' );
			} else {
				store.toast( e.message || 'Could not add passkey.', 'error' );
			}
		} finally {
			setBusy( '' );
		}
	};

	const remove = async ( id ) => {
		if ( ! window.confirm( 'Remove this passkey? It will no longer be able to sign in.' ) ) return;
		setBusy( id );
		try {
			await api.del( '/auth/passkey/' + encodeURIComponent( id ) );
			store.toast( 'Passkey removed.', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	return h( Card, {
		title: 'Passkeys',
		actions: h( Button, { variant: 'primary', disabled: !! busy, onClick: addPasskey }, busy === 'add' ? 'Waiting for device…' : '+ Add a passkey' ),
	},
		h( 'p', null, 'Sign in with your device’s fingerprint, face, screen lock, or a security key — no password, no code to type. A passkey is a complete sign-in method on its own, shown as a button on the login page.' ),
		passkeys === null
			? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
			: passkeys.length === 0
				? h( EmptyState, { icon: '🔑', title: 'No passkeys yet', hint: 'Add one from this device to enable passwordless sign-in.' } )
				: h( 'table', { className: 'ts-table' },
					h( 'thead', null, h( 'tr', null,
						h( 'th', null, 'Passkey' ), h( 'th', null, 'Added' ), h( 'th', null, 'Last used' ), h( 'th', null, '' )
					) ),
					h( 'tbody', null, passkeys.map( ( p ) =>
						h( 'tr', { key: p.id },
							h( 'td', null, p.label || 'Passkey' ),
							h( 'td', null, fmtDate( p.created_at ) ),
							h( 'td', null, p.last_used_at ? fmtDate( p.last_used_at ) : 'Never' ),
							h( 'td', null, h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => remove( p.id ) }, busy === p.id ? 'Removing…' : 'Remove' ) )
						)
					) )
				  )
	);
}

/** Format a timestamp (epoch seconds or date string) into a short local date. */
function fmtDate( ts ) {
	if ( ! ts ) return '—';
	let d;
	if ( typeof ts === 'number' || /^\d+$/.test( '' + ts ) ) {
		d = new Date( Number( ts ) * 1000 );
	} else {
		d = new Date( ( '' + ts ).replace( ' ', 'T' ) );
	}
	return isNaN( d.getTime() ) ? String( ts ) : d.toLocaleDateString();
}

export function TwoFactorSetup() {
	const store = useStore();
	const [ status, setStatus ] = useState( null );
	const [ enroll, setEnroll ] = useState( null );
	const [ code, setCode ] = useState( '' );
	const [ backup, setBackup ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ authPolicyModalOpen, setAuthPolicyModalOpen ] = useState( false );

	const load = () => api.get( '/auth/2fa/status' ).then( setStatus ).catch( ( e ) => store.toast( e.message, 'error' ) );
	useEffect( () => { load(); }, [] );

	// Auto-resume a pending enrollment: fetch the existing QR data so the user can
	// complete the confirmation without generating a new (mismatching) secret.
	useEffect( () => {
		if ( status && status.pending && ! status.enabled && ! enroll && ! backup ) {
			begin();
		}
	}, [ status ] ); // eslint-disable-line react-hooks/exhaustive-deps

	const begin = async () => {
		setBusy( 'begin' );
		try {
			setEnroll( await api.post( '/auth/2fa/begin', {} ) );
			setBackup( null );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const confirm = async () => {
		setBusy( 'confirm' );
		try {
			const res = await api.post( '/auth/2fa/confirm', { code } );
			setBackup( res.backup_codes || [] );
			setEnroll( null );
			setCode( '' );
			store.toast( 'Two-factor enabled!', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const disable = async () => {
		if ( ! window.confirm( 'Disable two-factor authentication for your account?' ) ) return;
		try {
			await api.post( '/auth/2fa/disable', {} );
			store.toast( 'Two-factor disabled.', 'success' );
			setBackup( null );
			setEnroll( null );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	// Reset a pending enrollment and generate a fresh secret (e.g. user switched apps).
	const resetEnroll = async () => {
		if ( ! window.confirm( 'Generate a new setup key? Your authenticator will need to be re-scanned.' ) ) return;
		try {
			await api.post( '/auth/2fa/disable', {} );
			setEnroll( await api.post( '/auth/2fa/begin', {} ) );
			setCode( '' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	const logoutOthers = async () => {
		try { await api.post( '/auth/sessions/destroy-mine', {} ); store.toast( 'Other sessions ended.', 'success' ); }
		catch ( e ) { store.toast( e.message, 'error' ); }
	};

	const logoutEveryone = async () => {
		if ( ! window.confirm( 'Force-logout EVERY user on this site? They will need to log in again.' ) ) return;
		try { const r = await api.post( '/auth/sessions/destroy-all', {} ); store.toast( `${ r.users_logged_out } user(s) logged out.`, 'success' ); }
		catch ( e ) { store.toast( e.message, 'error' ); }
	};

	if ( ! status ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	return h(
		Fragment,
		null,
		h(
			Card,
			{
				title: '🔐 Site-Wide 2FA & Login Policy',
				actions: h( Button, { variant: 'primary', onClick: () => setAuthPolicyModalOpen( true ) }, 'Manage policy' ),
			},
			h( 'p', { className: 'ts-muted', style: { marginTop: 0, marginBottom: 0 } },
				'Require 2FA enrollment for specific roles, set the grace period, and hide the login form behind a custom URL.'
			)
		),

		h( GracePeriodRolloutCard, null ),

		h( Modal, {
			open: authPolicyModalOpen,
			onClose: () => setAuthPolicyModalOpen( false ),
			title: 'Site-Wide 2FA & Login Policy',
			icon: '🔐',
			size: 'lg',
		},
			h( ForceTwoFactorCard, null ),
			h( LoginUrlCard, null )
		),

		h(
			Card,
			{
				title: 'Two-Factor Authentication (TOTP)',
				actions: h( Badge, { tone: status.enabled ? 'success' : 'neutral' }, status.enabled ? 'Enabled' : 'Disabled' ),
			},
			status.enabled && ! backup && h( Fragment, null,
				h( 'p', null, `Two-factor is active. ${ status.backup_left } backup code(s) remaining.` ),
				h( 'p', { className: 'ts-muted' }, 'You can opt to trust a device for 30 days after successful 2FA verification. Manage trusted devices below.' ),
				h( Button, { variant: 'danger', onClick: disable }, 'Disable 2FA' )
			),

			! status.enabled && ! enroll && ! backup && h( Fragment, null,
				h( 'p', null, 'Protect your account with a time-based one-time password from an authenticator app (Google Authenticator, Authy, 1Password, etc.).' ),
				h( 'p', { className: 'ts-muted' }, 'You can opt to trust a device for 30 days after successful 2FA verification. Manage trusted devices below.' ),
				h( Button, { variant: 'primary', disabled: busy === 'begin', onClick: begin }, busy === 'begin' ? 'Preparing…' : 'Set up 2FA' )
			),

			enroll && h( Fragment, null,
				h( 'ol', { className: 'ts-enroll' },
					h( 'li', null, 'In your authenticator app choose "Add account" then scan the QR code below, or choose "Enter a setup key" to type it manually.' ),
					h( 'li', null, 'Enter your account name and this key:',
						h( 'div', { className: 'ts-key' }, enroll.manual_key )
					),
					h( 'li', null, 'Scan this QR code with your authenticator app:',
						h( QrCode, { uri: enroll.otpauth } ),
						h( 'details', { className: 'ts-otpauth-details' },
							h( 'summary', null, "Can't scan? Copy the URI instead" ),
							h( 'input', { id: 'ts-2fa-otpauth', name: 'otpauth_uri', type: 'text', readOnly: true, value: enroll.otpauth, onClick: ( e ) => e.target.select(), className: 'ts-otpauth' } )
						)
					),
					h( 'li', null, 'Enter the 6-digit code it generates to confirm:' )
				),
				h( 'div', { className: 'ts-actions-row' },
					h( 'input', { id: 'ts-2fa-code', name: 'totp_code', type: 'text', value: code, placeholder: '123456', inputmode: 'numeric', onChange: ( e ) => setCode( e.target.value ), className: 'ts-codeinput' } ),
					h( Button, { variant: 'primary', disabled: busy === 'confirm', onClick: confirm }, busy === 'confirm' ? 'Verifying…' : 'Confirm & enable' ),
					h( Button, { variant: 'secondary', onClick: resetEnroll }, 'Use a different app' )
				)
			),

			backup && h( Fragment, null,
				h( 'p', { className: 'ts-warn' }, '⚠️ Save these one-time backup codes now — they are shown only once. Each works once if you lose your authenticator.' ),
				h( 'div', { className: 'ts-backup' }, backup.map( ( c, i ) => h( 'code', { key: i }, c ) ) ),
				h( Button, { variant: 'primary', onClick: () => setBackup( null ) }, 'I have saved them' )
			)
		),

		h( PasskeysCard, null ),

		h( TrustedDevices, null ),
		h( AllTrustedDevicesCard, null ),

		h(
			Card,
			{ title: 'Session management' },
			h( 'p', null, 'End sessions if you suspect account compromise.' ),
			h( 'div', { className: 'ts-actions-row' },
				h( Button, { onClick: logoutOthers }, 'Log out my other sessions' ),
				h( Button, { variant: 'danger', onClick: logoutEveryone }, 'Force-logout everyone' )
			)
		)
	);
}
