/**
 * First-load GDPR consent modal for anonymous firewall-bypass telemetry.
 *
 * Shown once (per policy version) when window.LoyalSecurity.telemetry.needs_consent is true.
 * Records an explicit accept/decline; nothing is ever transmitted until the user accepts.
 */
import { h, useState } from '../el.js';
import { api } from '../api.js';
import { Button, Spinner } from './ui.js';
import { useStore } from '../store.js';

export function ConsentModal( { onResolved } ) {
	const store = useStore();
	const [ busy, setBusy ] = useState( '' );
	const [ showSample, setShowSample ] = useState( false );
	const [ sample, setSample ] = useState( null );

	const resolve = async ( accepted ) => {
		setBusy( accepted ? 'accept' : 'decline' );
		try {
			await api.post( '/telemetry/consent', { accepted } );
			if ( window.LoyalSecurity && window.LoyalSecurity.telemetry ) {
				window.LoyalSecurity.telemetry.needs_consent = false;
				window.LoyalSecurity.telemetry.consent_given = accepted;
			}
		} catch ( e ) {
			// The save FAILED — do not report the choice as resolved. Previously onResolved was
			// called in `finally` regardless, so the caller recorded consent the server never
			// stored: App.js dismissed the modal (re-appearing only next load) and, worse, the
			// FirewallPanel flow proceeded to a cloud submit the server then rejected for
			// missing consent. Surface the error and keep the modal open so the user can retry.
			setBusy( '' );
			store.toast( ( e && e.message ) || 'Could not save your choice. Please try again.', 'error' );
			return;
		}
		setBusy( '' );
		onResolved && onResolved( accepted );
	};

	const loadSample = async () => {
		setShowSample( ( v ) => ! v );
		if ( ! sample ) {
			try {
				setSample( await api.get( '/telemetry/sample' ) );
			} catch ( e ) {
				setSample( { error: 'Unable to load sample.' } );
			}
		}
	};

	return h(
		'div',
		{ className: 'ts-pro-modal-overlay' },
		h(
			'div',
			{
				className: 'ts-pro-modal ts-consent-modal',
				role: 'dialog',
				'aria-modal': 'true',
				'aria-label': 'Anonymous Security Data Sharing',
			},
			h( 'h2', null, h( 'span', { 'aria-hidden': 'true' }, '🛡️ ' ), 'Help improve protection for everyone' ),
			h(
				'p',
				null,
				'If an attack ever bypasses your firewall, Loyal Security can send an ',
				h( 'strong', null, 'anonymous' ),
				' report of the malicious request to our security network. We use it to build a new firewall rule and push it to every site — including yours.'
			),
			h(
				'ul',
				{ className: 'ts-consent-list' },
				h( 'li', null, '✅ Shares the ', h( 'strong', null, 'attacker’s' ), ' request data needed to write a rule.' ),
				h( 'li', null, '🚫 Never your content, logins, passwords, cookies, or personal data.' ),
				h( 'li', null, '🎭 Your site is identified only by a random ID — never your URL.' ),
				h( 'li', null, '🔌 You can turn this off any time in Settings → Bypass Telemetry.' )
			),
			h(
				'p',
				{ className: 'ts-consent-transparency' },
				h( 'a', { href: '#', onClick: ( e ) => { e.preventDefault(); loadSample(); } },
					showSample ? 'Hide sample report' : 'View a sample report' )
			),
			showSample && h(
				'pre',
				{ className: 'ts-consent-sample' },
				sample ? JSON.stringify( sample, null, 2 ) : h( Spinner, { label: 'Loading sample' } )
			),
			h(
				'div',
				{ className: 'ts-consent-actions' },
				h( Button, {
					variant: 'primary',
					disabled: !! busy,
					onClick: () => resolve( true ),
				}, busy === 'accept' ? 'Saving…' : 'I agree — share anonymous reports' ),
				h( Button, {
					disabled: !! busy,
					onClick: () => resolve( false ),
				}, busy === 'decline' ? 'Saving…' : 'No thanks' )
			)
		)
	);
}
