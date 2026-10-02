/**
 * Integrations — a single, discoverable home for the third-party services this plugin can
 * connect to. The login CAPTCHA (Cloudflare Turnstile / Google reCAPTCHA) is configured here;
 * the integrations provided by the separate Loyal Security Pro plugin (Cloudflare edge sync,
 * webhook and incident-routing alerts) appear as short descriptions, or as Pro's own cards when
 * it is installed.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, InfoTip, Spinner, LoadError, FieldRow } from './ui.js';
import { settingHelp } from '../settings-help.js';
import { useStore } from '../store.js';
import { ProGate } from './ProGate.js';

function fieldLabel( mod, key, text ) {
	return h( Fragment, null, text, h( InfoTip, { help: settingHelp( mod, key ), label: text } ) );
}

/** Where to go set up a site/key for each provider — shown next to the Provider select once
 * something other than "None" is chosen, since that's exactly the moment an admin needs it. */
const CAPTCHA_PROVIDER_SETUP_URL = {
	turnstile: 'https://dash.cloudflare.com/?to=/:account/turnstile',
	recaptcha_v3: 'https://www.google.com/recaptcha/admin/create',
};
const CAPTCHA_PROVIDER_LABEL = {
	turnstile: 'Cloudflare Turnstile',
	recaptcha_v3: 'Google reCAPTCHA',
};

function CaptchaCard( { auth, patch, store } ) {
	const [ draft, setDraft ] = useState( {
		captcha_provider: auth.captcha_provider || 'none',
		captcha_site_key: auth.captcha_site_key || '',
		captcha_secret_key: auth.captcha_secret_key || '',
		captcha_min_score: auth.captcha_min_score ?? 0.5,
		captcha_protect_login: auth.captcha_protect_login ?? true,
		captcha_protect_register: auth.captcha_protect_register ?? true,
		captcha_protect_lostpassword: auth.captcha_protect_lostpassword ?? true,
	} );
	const [ busy, setBusy ] = useState( false );

	useEffect( () => {
		setDraft( {
			captcha_provider: auth.captcha_provider || 'none',
			captcha_site_key: auth.captcha_site_key || '',
			captcha_secret_key: auth.captcha_secret_key || '',
			captcha_min_score: auth.captcha_min_score ?? 0.5,
			captcha_protect_login: auth.captcha_protect_login ?? true,
			captcha_protect_register: auth.captcha_protect_register ?? true,
			captcha_protect_lostpassword: auth.captcha_protect_lostpassword ?? true,
		} );
	}, [ auth ] );

	const save = async () => {
		setBusy( true );
		try {
			await patch( 'auth', draft );
			store.toast( 'CAPTCHA settings saved.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( false );
		}
	};

	const off = 'none' === draft.captcha_provider;
	const connected = ! off && !! draft.captcha_site_key && !! draft.captcha_secret_key;

	return h( Card,
		{ title: '🤖 CAPTCHA', actions: h( Badge, { tone: off ? 'neutral' : ( connected ? 'success' : 'warning' ) }, off ? 'Off' : ( connected ? 'Connected' : 'Incomplete' ) ) },
		h( 'p', { className: 'ts-hint' }, 'Challenge the login form with Cloudflare Turnstile or Google reCAPTCHA v3 to stop scripted brute-force and credential-stuffing tools.' ),
		h( FieldRow, { label: fieldLabel( 'auth', 'captcha_provider', 'Provider' ), id: 'ts-int-captcha-provider' },
			h( 'select', {
				id: 'ts-int-captcha-provider', value: draft.captcha_provider,
				onChange: ( e ) => setDraft( ( d ) => ( { ...d, captcha_provider: e.target.value } ) ),
			},
				h( 'option', { value: 'none' }, 'None' ),
				h( 'option', { value: 'turnstile' }, 'Cloudflare Turnstile' ),
				h( 'option', { value: 'recaptcha_v3' }, 'Google reCAPTCHA v3' )
			)
		),
		! off && h( 'p', { className: 'ts-hint', style: { marginTop: '-6px' } },
			'Need a site key? ',
			h( 'a', { href: CAPTCHA_PROVIDER_SETUP_URL[ draft.captcha_provider ], target: '_blank', rel: 'noopener' },
				'Set up ' + CAPTCHA_PROVIDER_LABEL[ draft.captcha_provider ] + ' →'
			)
		),
		! off && h( FieldRow, { label: fieldLabel( 'auth', 'captcha_site_key', 'Site key' ), id: 'ts-int-captcha-site' },
			h( 'input', {
				id: 'ts-int-captcha-site', type: 'text', value: draft.captcha_site_key,
				onChange: ( e ) => setDraft( ( d ) => ( { ...d, captcha_site_key: e.target.value } ) ),
			} )
		),
		! off && h( FieldRow, { label: fieldLabel( 'auth', 'captcha_secret_key', 'Secret key' ), id: 'ts-int-captcha-secret' },
			h( 'input', {
				id: 'ts-int-captcha-secret', type: 'password', autoComplete: 'new-password', placeholder: '••••••••••••••••',
				value: draft.captcha_secret_key,
				onChange: ( e ) => setDraft( ( d ) => ( { ...d, captcha_secret_key: e.target.value } ) ),
			} )
		),
		'recaptcha_v3' === draft.captcha_provider && h( FieldRow, { label: fieldLabel( 'auth', 'captcha_min_score', 'Minimum score' ), id: 'ts-int-captcha-score' },
			h( 'input', {
				id: 'ts-int-captcha-score', type: 'number', step: '0.1', min: '0', max: '1', value: draft.captcha_min_score,
				onChange: ( e ) => setDraft( ( d ) => ( { ...d, captcha_min_score: Number( e.target.value ) } ) ),
			} )
		),
		// Per-form protection. All three default on — the moment a provider + keys are set every
		// form is already protected (see Captcha::configured() server-side), so this is an
		// opt-*out* per form, not something that needs enabling.
		! off && h( 'div', { style: { marginTop: '4px' } },
			h( 'p', { className: 'ts-hint', style: { marginBottom: '6px' } }, 'Protect these forms:' ),
			h( 'label', { className: 'ts-checkbox-label', htmlFor: 'ts-int-captcha-login', style: { display: 'block', marginBottom: '6px' } },
				h( 'input', {
					id: 'ts-int-captcha-login', type: 'checkbox', checked: draft.captcha_protect_login,
					onChange: ( e ) => setDraft( ( d ) => ( { ...d, captcha_protect_login: e.target.checked } ) ),
				} ),
				' Login'
			),
			h( 'label', { className: 'ts-checkbox-label', htmlFor: 'ts-int-captcha-register', style: { display: 'block', marginBottom: '6px' } },
				h( 'input', {
					id: 'ts-int-captcha-register', type: 'checkbox', checked: draft.captcha_protect_register,
					onChange: ( e ) => setDraft( ( d ) => ( { ...d, captcha_protect_register: e.target.checked } ) ),
				} ),
				' Registration'
			),
			h( 'label', { className: 'ts-checkbox-label', htmlFor: 'ts-int-captcha-lostpw' },
				h( 'input', {
					id: 'ts-int-captcha-lostpw', type: 'checkbox', checked: draft.captcha_protect_lostpassword,
					onChange: ( e ) => setDraft( ( d ) => ( { ...d, captcha_protect_lostpassword: e.target.checked } ) ),
				} ),
				' Lost password'
			)
		),
		h( 'div', { className: 'ts-actions-row', style: { marginTop: '12px' } },
			h( Button, { variant: 'primary', disabled: busy, onClick: save }, busy ? 'Saving…' : 'Save changes' )
		)
	);
}

export function IntegrationsPanel() {
	const store = useStore();
	const [ settings, setSettings ] = useState( null );
	const [ error, setError ] = useState( '' );

	const load = () => {
		setError( '' );
		api.get( '/settings' ).then( setSettings ).catch( ( e ) => setError( e.message ) );
	};
	useEffect( load, [] );

	// Partial save — POST /settings/{module} merges into the stored module blob server-side
	// (Settings::update_module does array_merge), so sending just the changed keys is safe and
	// never clobbers fields this panel doesn't touch.
	const patch = async ( mod, partial ) => {
		const saved = await api.post( '/settings/' + mod, partial );
		setSettings( ( s ) => ( { ...s, [ mod ]: saved } ) );
		return saved;
	};

	if ( error ) {
		return h( LoadError, { message: error, onRetry: load } );
	}
	if ( ! settings ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	return h( Fragment, null,
		h( 'p', { className: 'ts-hint' }, 'Third-party services this plugin can connect to.' ),
		h( CaptchaCard, { auth: settings.auth || {}, patch, store } ),
		h( ProGate, {
			feature: 'integrations.cloudflare',
			title: 'Cloudflare edge sync',
			bullets: [ 'Mirror your ban list to Cloudflare IP Access Rules', 'Attackers blocked at the edge, before they reach this server' ],
		} ),
		h( ProGate, {
			feature: 'notifications.webhook',
			title: 'Webhook & incident-routing alerts',
			bullets: [ 'Slack, Discord, Teams or any HTTPS webhook', 'PagerDuty and OpsGenie incident routing' ],
		} )
	);
}
