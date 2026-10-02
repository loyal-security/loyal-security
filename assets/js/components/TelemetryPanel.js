/**
 * Bypass Telemetry settings panel.
 *
 * Lets the admin grant or withdraw consent for anonymous firewall-bypass reporting at any
 * time (GDPR), tune what is shared, and inspect a real sample of what would be transmitted.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Toggle, Spinner, LoadError } from './ui.js';
import { useStore } from '../store.js';

export function TelemetryPanel() {
	const store = useStore();
	const [ state, setState ] = useState( null );
	const [ loadErr, setLoadErr ] = useState( null );
	const [ busy, setBusy ] = useState( false );
	const [ sample, setSample ] = useState( null );
	const [ showSample, setShowSample ] = useState( false );

	const load = () => api.get( '/telemetry/status' )
		.then( ( d ) => { setState( d ); setLoadErr( null ); } )
		.catch( ( e ) => { setLoadErr( e.message || 'Failed to load telemetry settings.' ); store.toast( e.message, 'error' ); } );

	useEffect( () => { load(); }, [] );

	const save = async ( patch ) => {
		setBusy( true );
		try {
			const body = {
				accepted: patch.consent_given !== undefined ? patch.consent_given : state.consent_given,
				...( patch.share_attacker_ip !== undefined ? { share_attacker_ip: patch.share_attacker_ip } : {} ),
				...( patch.near_miss_capture !== undefined ? { near_miss_capture: patch.near_miss_capture } : {} ),
			};
			const res = await api.post( '/telemetry/consent', body );
			if ( body.accepted && ! res.registered ) {
				// Consent itself is recorded either way — this only means the one-time cloud
				// registration call didn't succeed yet (e.g. a transient network error). It
				// keeps retrying automatically on the hourly telemetry flush; no action needed
				// unless it's still unregistered after a while.
				store.toast( 'Consent saved, but registering with the cloud failed — it will keep retrying automatically.', 'warning' );
			} else {
				store.toast( 'Preferences saved.', 'success' );
			}
			await load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( false );
		}
	};

	const loadSample = async () => {
		setShowSample( ( v ) => ! v );
		if ( ! sample ) {
			try {
				setSample( await api.get( '/telemetry/sample' ) );
			} catch ( e ) {
				store.toast( e.message, 'error' );
			}
		}
	};

	if ( ! state ) {
		// A failed load otherwise sat on "Loading…" forever with no retry.
		if ( loadErr ) {
			return h( LoadError, { message: loadErr, onRetry: load } );
		}
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ), h( 'span', null, 'Loading…' ) );
	}

	const on = !! state.consent_given;

	return h(
		Fragment,
		null,
		h(
			Card,
			{
				title: 'Bypass Telemetry',
				actions: h( Badge, { tone: on ? 'success' : 'neutral' }, on ? 'Sharing enabled' : 'Disabled' ),
			},
			h( 'p', null, 'When an attack is confirmed to have bypassed your firewall, Loyal Security can send an anonymous report of the malicious request so we can build a new rule and push it to all users. We share only the attacker’s request data — never your content, logins, or personal data. Your site is identified by a random ID (',
				h( 'code', null, state.install_id || '—' ),
				'), never your URL.'
			),
			h(
				'div',
				{ className: 'ts-row' },
				h( 'div', { className: 'ts-row__label' }, h( 'strong', null, 'Share anonymous bypass reports' ) ),
				h( Toggle, {
					checked: on,
					disabled: busy,
					onChange: ( v ) => save( { consent_given: v } ),
				} )
			),
			on && h(
				'div',
				{ className: 'ts-row' },
				h( 'div', { className: 'ts-row__label' },
					h( 'strong', null, 'Include attacker IP addresses' ),
					h( 'p', { className: 'ts-hint' }, 'Helps identify repeat offenders. When off, IPs are hashed before sending.' )
				),
				h( Toggle, {
					checked: !! state.share_attacker_ip,
					disabled: busy,
					onChange: ( v ) => save( { share_attacker_ip: v } ),
				} )
			),
			on && h(
				'div',
				{ className: 'ts-row' },
				h( 'div', { className: 'ts-row__label' },
					h( 'strong', null, 'Capture near-miss requests' ),
					h( 'p', { className: 'ts-hint' }, 'Record allowed-but-suspicious requests so the exact bypassing payload can be reported. Redacted before storage.' )
				),
				h( Toggle, {
					checked: !! state.near_miss_capture,
					disabled: busy,
					onChange: ( v ) => save( { near_miss_capture: v } ),
				} )
			)
		),
		h(
			Card,
			{ title: 'Transparency', actions: h( Button, { onClick: loadSample }, showSample ? 'Hide sample' : 'View sample report' ) },
			h( 'p', null, 'This is a real, fully-redacted example of exactly what would be transmitted. Nothing is sent from this screen.' ),
			showSample && h(
				'pre',
				{ className: 'ts-consent-sample' },
				sample ? JSON.stringify( sample, null, 2 ) : h( Spinner, { label: 'Loading sample' } )
			)
		)
	);
}
