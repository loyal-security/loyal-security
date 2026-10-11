/**
 * Setup wizard panel — deploys the standalone WAF (Optimized Mode) with verification.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner } from './ui.js';
import { useStore } from '../store.js';

export function Wizard() {
	const store = useStore();
	const [ status, setStatus ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ ipInput, setIpInput ] = useState( '' );
	const [ tele, setTele ] = useState( null );

	const load = () => api.get( '/wizard/status' ).then( ( s ) => {
		setStatus( s );
		// Pre-fill the IP field with the detected admin IP (only on first load).
		setIpInput( ( prev ) => prev || s.my_ip || '' );
	} ).catch( ( e ) => store.toast( e.message, 'error' ) );

	const loadTelemetry = () => api.get( '/telemetry/status' ).then( setTele ).catch( () => {} );

	useEffect( () => { load(); loadTelemetry(); }, [] );

	const setConsent = async ( accepted ) => {
		setBusy( 'consent' );
		try {
			await api.post( '/telemetry/consent', { accepted } );
			if ( window.LoyalSecurity && window.LoyalSecurity.telemetry ) {
				window.LoyalSecurity.telemetry.needs_consent = false;
				window.LoyalSecurity.telemetry.consent_given = accepted;
			}
			store.toast( accepted ? 'Thanks — anonymous sharing enabled.' : 'Sharing left off.', 'success' );
			await loadTelemetry();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const run = async ( action, endpoint, body, okMsg ) => {
		setBusy( action );
		try {
			const res = await api.post( endpoint, body || {} );
			store.toast( res.message || okMsg, res.ok === false ? 'error' : 'success' );
			await load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const addIp = () => run( 'whitelist-ip', '/wizard/whitelist-ip', { ip: ipInput.trim() }, 'IP added to whitelist.' );

	if ( ! status ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ), h( 'span', null, 'Detecting server…' ) );
	}

	const srv = status.server || {};
	const optimized = status.mode === 'optimized';

	const whitelist = status.ip_whitelist || [];
	const ipAlreadySaved = whitelist.includes( ipInput.trim() );

	return h(
		Fragment,
		null,
		h(
			Card,
			{ title: 'Step 1 — Environment', actions: h( Badge, { tone: optimized ? 'success' : 'info' }, optimized ? 'Optimized' : 'Standard' ) },
			row( 'Web server', srv.server || 'unknown' ),
			row( 'PHP SAPI', srv.sapi || '—' ),
			row( 'Recommended deploy', srv.strategy === 'htaccess' ? '.htaccess (php_value)' : srv.strategy === 'user_ini' ? srv.user_ini_name : 'Manual' ),
			row( 'Prepend script', status.prepend_exists ? '✅ present' : '❌ missing' ),
			row( 'WAF config', status.config_exists ? '✅ generated' : '⚠️ not yet generated' )
		),

		h(
			Card,
			{ title: 'Step 2 — Whitelist your IP' },
			h( 'p', null, 'Add your IP to the firewall whitelist so you can never accidentally lock yourself out. The IP below was detected from your current request.' ),
			status.my_ip_is_proxy && h( 'p', { className: 'ts-notice ts-notice--warn' }, 'Your request reached this site through a proxy or CDN, and only its address is visible, so it is not offered here: allowing it would let every visitor through. Add the proxy under Firewall → Trusted proxies (Cloudflare is recognised automatically while “Trust Cloudflare” is on), then reload this page.' ),
			h( 'div', { className: 'ts-actions-row', style: { alignItems: 'center', gap: '8px' } },
				h( 'input', {
					id: 'ts-wizard-whitelist-ip',
					name: 'whitelist_ip',
					type: 'text',
					className: 'regular-text',
					value: ipInput,
					onChange: ( e ) => setIpInput( e.target.value ),
					placeholder: 'e.g. 203.0.113.42',
					style: { fontFamily: 'monospace' },
				} ),
				h( Button, {
					variant: 'primary',
					disabled: !! busy || ! ipInput.trim() || ipAlreadySaved,
					onClick: addIp,
				}, busy === 'whitelist-ip' ? 'Saving…' : ipAlreadySaved ? 'Already whitelisted ✅' : 'Add to whitelist' )
			),
			whitelist.length > 0 && h( 'p', { className: 'ts-hint' }, 'Whitelisted IPs: ',
				h( 'code', null, whitelist.join( ', ' ) )
			)
		),

		h(
			Card,
			{ title: 'Step 3 — Optimized Mode', actions: h( Badge, { tone: optimized ? 'success' : 'info' }, 'Current: ' + ( optimized ? 'Optimized' : 'Standard' ) ) },
			h( 'p', null, 'Optimized Mode runs the firewall before WordPress loads via PHP\'s auto_prepend_file. Deployment is backed up and self-tested automatically; if the test fails it rolls back to Standard Mode.' ),
			h( 'div', { className: 'ts-actions-row' },
				optimized
					? h( Button, { variant: 'primary', disabled: !! busy, onClick: () => run( 'rollback', '/wizard/rollback', null, 'Reverted to Standard Mode.' ) }, busy === 'rollback' ? 'Reverting…' : 'Deploy Standard Mode' )
					: h( Button, { variant: 'primary', disabled: !! busy, onClick: () => run( 'deploy', '/wizard/deploy', null, 'Deployment attempted.' ) }, busy === 'deploy' ? 'Deploying…' : 'Deploy Optimized Mode' ),
				h( Button, { disabled: !! busy, onClick: () => run( 'verify', '/wizard/verify', null, 'Verified.' ) }, busy === 'verify' ? 'Verifying…' : 'Verify' )
			),
			srv.strategy === 'manual' && h( 'p', { className: 'ts-hint' }, 'Automatic deployment is unavailable on this server. Add ', h( 'code', null, `auto_prepend_file = "${ srv.prepend_path }"` ), ' to your PHP configuration manually.' )
		),

		h(
			Card,
			{
				title: 'Step 4 — Anonymous data sharing (optional)',
				actions: tele && h( Badge, { tone: tele.consent_given ? 'success' : 'info' }, tele.consent_given ? 'Enabled' : 'Off' ),
			},
			h( 'p', null, 'If an attack ever bypasses your firewall, Loyal Security can send an ', h( 'strong', null, 'anonymous' ), ' report of the malicious request so we can build a new rule and push it to all users. We share only the attacker’s request data — never your content, logins, or personal data, and your site is identified by a random ID, never your URL. You can change this any time in Bypass Telemetry settings.' ),
			h( 'div', { className: 'ts-actions-row' },
				h( Button, {
					variant: 'primary',
					disabled: busy === 'consent' || ( tele && tele.consent_given ),
					onClick: () => setConsent( true ),
				}, ( tele && tele.consent_given ) ? 'Sharing enabled ✅' : busy === 'consent' ? 'Saving…' : 'I agree — share anonymously' ),
				h( Button, {
					disabled: busy === 'consent' || ( tele && ! tele.consent_given && tele.consent_timestamp > 0 ),
					onClick: () => setConsent( false ),
				}, 'No thanks' )
			)
		),

		h(
			Card,
			{ title: 'Step 5 — Finish' },
			h( 'p', null, status.setup_complete ? 'Setup is complete. ✅' : 'Mark setup complete to dismiss the onboarding prompt.' ),
			! status.setup_complete && h( Button, { variant: 'primary', disabled: !! busy, onClick: () => run( 'complete', '/wizard/complete', null, 'Setup complete!' ) }, 'Mark complete' )
		)
	);

	function row( label, value ) {
		return h( 'div', { className: 'ts-row' },
			h( 'div', { className: 'ts-row__label' }, h( 'strong', null, label ) ),
			h( 'div', null, value )
		);
	}
}
