/**
 * Hardening panel — runtime guards, server rules, and wp-config constants.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, Toggle, InfoTip, EmptyState, ScrollPanel } from './ui.js';
import { settingHelp } from '../settings-help.js';
import { useStore } from '../store.js';

const RUNTIME_ITEMS = [
	[ 'obfuscate_version', 'Obfuscate WordPress version', 'Removes generator tags and asset version fingerprints.' ],
	[ 'disable_xmlrpc', 'Disable XML-RPC', 'Blocks xmlrpc.php (brute-force amplification vector).' ],
	[ 'disable_pingback', 'Disable pingbacks', 'Removes pingback methods + X-Pingback header (DDoS reflection).' ],
	[ 'block_author_enum', 'Block author enumeration', 'Stops ?author=N user discovery.' ],
];

const EXPOSURE_STATUS_TONE = { exposed: 'danger', protected: 'success', info: 'neutral' };

export function HardeningChecklist() {
	const store = useStore();
	const [ status, setStatus ] = useState( null );
	const [ settings, setSettings ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ constants, setConstants ] = useState( { DISALLOW_FILE_EDIT: true, DISALLOW_FILE_MODS: false, FORCE_SSL_ADMIN: false } );
	const [ exposure, setExposure ] = useState( null );
	const [ exposureBusy, setExposureBusy ] = useState( '' );
	const [ learning, setLearning ] = useState( [] );
	const [ nsInput, setNsInput ] = useState( '' );
	const [ corsInput, setCorsInput ] = useState( '' );

	const load = async () => {
		const [ st, se, ex ] = await Promise.all( [
			api.get( '/hardening/status' ), api.get( '/settings' ), api.get( '/hardening/exposure' ),
		] );
		setStatus( st );
		setSettings( se.hardening || {} );
		setExposure( ex );
		if ( st.config ) {
			setConstants( {
				DISALLOW_FILE_EDIT: !! st.config.DISALLOW_FILE_EDIT,
				DISALLOW_FILE_MODS: !! st.config.DISALLOW_FILE_MODS,
				FORCE_SSL_ADMIN: !! st.config.FORCE_SSL_ADMIN,
			} );
		}
		if ( st.runtime && st.runtime.restrict_rest_all ) {
			api.get( '/hardening/rest-learning' ).then( ( d ) => setLearning( d.items || [] ) ).catch( () => {} );
		}
	};

	useEffect( () => { load().catch( ( e ) => store.toast( e.message, 'error' ) ); }, [] );

	const scanExposure = async () => {
		setExposureBusy( 'scan' );
		try {
			setExposure( await api.post( '/hardening/exposure-scan', {} ) );
			store.toast( 'Attack surface scan complete.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setExposureBusy( '' );
		}
	};

	const fixExposure = async ( id ) => {
		setExposureBusy( id );
		try {
			const res = await api.post( '/hardening/exposure-fix', { id } );
			store.toast( res.message || 'Done.', res.ok === false ? 'error' : 'success' );
			setExposure( await api.get( '/hardening/exposure' ) );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setExposureBusy( '' );
		}
	};

	const saveNamespaces = async ( next ) => {
		setSettings( { ...settings, rest_public_namespaces: next } );
		try {
			await api.post( '/settings/hardening', { rest_public_namespaces: next } );
			store.toast( 'Saved — applies on the next page load.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	const addNamespace = () => {
		const ns = nsInput.trim().replace( /^\/+|\/+$/g, '' );
		if ( '' === ns ) return;
		const current = settings.rest_public_namespaces || [];
		if ( current.includes( ns ) ) { setNsInput( '' ); return; }
		saveNamespaces( [ ...current, ns ] );
		setNsInput( '' );
	};

	const removeNamespace = ( ns ) => {
		saveNamespaces( ( settings.rest_public_namespaces || [] ).filter( ( n ) => n !== ns ) );
	};

	const saveCorsAllowlist = async ( next ) => {
		setSettings( { ...settings, rest_cors_allowlist: next } );
		try {
			await api.post( '/settings/hardening', { rest_cors_allowlist: next } );
			store.toast( 'Saved — applies on the next page load.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	const addCorsOrigin = () => {
		const origin = corsInput.trim().replace( /\/+$/, '' );
		if ( '' === origin ) return;
		const current = settings.rest_cors_allowlist || [];
		if ( current.includes( origin ) ) { setCorsInput( '' ); return; }
		saveCorsAllowlist( [ ...current, origin ] );
		setCorsInput( '' );
	};

	const removeCorsOrigin = ( origin ) => {
		saveCorsAllowlist( ( settings.rest_cors_allowlist || [] ).filter( ( o ) => o !== origin ) );
	};

	const toggleRuntime = async ( key, value ) => {
		setSettings( { ...settings, [ key ]: value } );
		try {
			await api.post( '/settings/hardening', { [ key ]: value } );
			store.toast( 'Saved — applies on the next page load.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	const serverRules = async ( action ) => {
		setBusy( 'server' );
		try {
			const res = await api.post( '/hardening/server-rules', { action } );
			if ( 'revert' === action ) {
				store.toast( 'Server rules removed.', 'success' );
			} else if ( res && res.result && res.result.error ) {
				// The write succeeded but the site failed its post-apply health check, so it was
				// automatically reverted — tell the admin what happened rather than a bare
				// "applied" that would leave them thinking the rules are still in effect.
				store.toast( 'Rolled back automatically: ' + res.result.error, 'error' );
			} else if ( res && false === res.ok ) {
				store.toast( 'Could not apply server rules — check that .htaccess is writable.', 'error' );
			} else {
				store.toast( 'Server rules applied.', 'success' );
			}
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const applyConfig = async ( action ) => {
		setBusy( 'config' );
		try {
			const body = action === 'revert' ? { action: 'revert' } : constants;
			const res = await api.post( '/hardening/config', body );
			store.toast( res.message || 'Done.', res.ok === false ? 'error' : 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	if ( ! status || ! settings ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	const exposureItems = ( exposure && exposure.items ) || [];
	const exposedCount  = exposureItems.filter( ( f ) => 'exposed' === f.status ).length;

	return h(
		Fragment,
		null,
		h(
			Card,
			{
				title: '🔎 Attack Surface Scan',
				actions: h( Button, { variant: 'primary', disabled: !! exposureBusy, onClick: scanExposure }, 'scan' === exposureBusy ? 'Scanning…' : 'Scan now' ),
			},
			h( 'p', null, 'Checks for exposed backup/config files, version-disclosure files, a reachable debug.log, and settings that leave XML-RPC or author enumeration open.' ),
			! exposureItems.length
				? h( EmptyState, { icon: '🔎', title: 'No scan yet', hint: 'Click "Scan now" to check your attack surface.' } )
				: h( 'div', { className: 'ts-exposure-list' },
					exposureItems.map( ( f ) => h( 'div', { key: f.id, className: 'ts-row' },
						h( 'div', { className: 'ts-row__label' },
							h( 'span', { className: 'ts-row__name' },
								h( 'strong', null, f.title ),
								h( Badge, { tone: EXPOSURE_STATUS_TONE[ f.status ] || 'neutral' }, f.status )
							),
							h( 'span', null, f.detail )
						),
						f.fix && h( Button, {
							variant: 'danger',
							disabled: !! exposureBusy,
							onClick: () => fixExposure( f.fix.id ),
						}, exposureBusy === f.fix.id ? 'Working…' : f.fix.label )
					) )
				),
			exposure && exposure.scanned_at
				? h( 'p', { className: 'ts-muted' }, 'Last scanned: ' + new Date( exposure.scanned_at * 1000 ).toLocaleString() )
				: null,
			exposedCount > 0 && h( 'p', { className: 'ts-notice ts-notice--danger' }, exposedCount + ' finding(s) need attention.' )
		),

		h(
			Card,
			{ title: 'Runtime hardening' },
			RUNTIME_ITEMS.map( ( [ key, label, hint ] ) =>
				h( 'div', { key, className: 'ts-row' },
					h( 'div', { className: 'ts-row__label' },
						h( 'span', { className: 'ts-row__name' },
							h( 'strong', null, label ),
							h( InfoTip, { help: settingHelp( 'hardening', key ), label } )
						),
						h( 'span', null, hint )
					),
					h( Toggle, { checked: !! settings[ key ], onChange: ( v ) => toggleRuntime( key, v ) } )
				)
			)
		),

		h(
			Card,
			{ title: 'REST API protection' },
			h( 'div', { className: 'ts-row' },
				h( 'div', { className: 'ts-row__label' },
					h( 'span', { className: 'ts-row__name' },
						h( 'strong', null, 'Restrict REST users endpoint' ),
						h( InfoTip, { help: settingHelp( 'hardening', 'restrict_rest_users' ), label: 'Restrict REST users endpoint' } )
					),
					h( 'span', null, 'Hides /wp-json/wp/v2/users from anonymous callers.' )
				),
				h( Toggle, { checked: !! settings.restrict_rest_users, onChange: ( v ) => toggleRuntime( 'restrict_rest_users', v ) } )
			),
			h( 'div', { className: 'ts-row' },
				h( 'div', { className: 'ts-row__label' },
					h( 'span', { className: 'ts-row__name' },
						h( 'strong', null, 'Restrict cross-origin API access (CORS)' ),
						h( InfoTip, { help: settingHelp( 'hardening', 'restrict_rest_cors' ), label: 'Restrict cross-origin API access (CORS)' } )
					),
					h( 'span', null, 'By default WordPress lets any website read your REST API using a logged-in visitor’s cookies. This limits that to your own site plus the origins allowed below.' )
				),
				h( Toggle, { checked: !! settings.restrict_rest_cors, onChange: ( v ) => toggleRuntime( 'restrict_rest_cors', v ) } )
			),
			settings.restrict_rest_cors && h( 'div', { className: 'ts-row' },
				h( 'div', { style: { width: '100%' } },
					h( 'div', { className: 'ts-row__label' }, h( 'strong', null, 'Trusted cross-origin callers' ) ),
					h( 'div', { className: 'ts-pills' },
						( settings.rest_cors_allowlist || [] ).map( ( origin ) => h( Badge, { key: origin, tone: 'info' },
							origin, ' ', h( 'a', { href: '#', onClick: ( e ) => { e.preventDefault(); removeCorsOrigin( origin ); } }, '×' )
						) )
					),
					h( 'div', { className: 'ts-actions-row' },
						h( 'input', {
							id: 'ts-rest-cors-origin', name: 'rest_cors_origin',
							type: 'text', placeholder: 'e.g. https://app.example.com', value: corsInput,
							onChange: ( e ) => setCorsInput( e.target.value ),
							onKeyDown: ( e ) => e.key === 'Enter' && addCorsOrigin(),
						} ),
						h( Button, { onClick: addCorsOrigin }, 'Add' )
					)
				)
			),
			h( 'div', { className: 'ts-row' },
				h( 'div', { className: 'ts-row__label' },
					h( 'span', { className: 'ts-row__name' },
						h( 'strong', null, 'Require auth for entire REST API' ),
						h( InfoTip, { help: settingHelp( 'hardening', 'restrict_rest_all' ), label: 'Require auth for entire REST API' } )
					),
					h( 'span', null, 'Blocks all anonymous REST access except the namespaces exempted below — needed by WooCommerce, most form plugins, etc.' )
				),
				h( Toggle, { checked: !! settings.restrict_rest_all, onChange: ( v ) => toggleRuntime( 'restrict_rest_all', v ) } )
			),
			settings.restrict_rest_all && h( 'div', { className: 'ts-row' },
				h( 'div', { className: 'ts-row__label' },
					h( 'span', { className: 'ts-row__name' }, h( 'strong', null, 'Learning mode' ) ),
					h( 'span', null, 'While on, anonymous REST hits are only logged, never blocked — review the list below, then turn this off to start enforcing.' )
				),
				h( Toggle, { checked: !! settings.rest_learning_mode, onChange: ( v ) => toggleRuntime( 'rest_learning_mode', v ) } )
			),
			h( 'div', { className: 'ts-row__label' }, h( 'strong', null, 'Always-public namespaces (exempt from the switch above)' ) ),
			h( 'div', { className: 'ts-pills' },
				( settings.rest_public_namespaces || [] ).map( ( ns ) => h( Badge, { key: ns, tone: 'info' },
					ns, ' ', h( 'a', { href: '#', onClick: ( e ) => { e.preventDefault(); removeNamespace( ns ); } }, '×' )
				) )
			),
			h( 'div', { className: 'ts-actions-row' },
				h( 'input', {
					id: 'ts-rest-public-namespace', name: 'rest_public_namespace',
					type: 'text', placeholder: 'e.g. my-plugin/v1', value: nsInput,
					onChange: ( e ) => setNsInput( e.target.value ),
					onKeyDown: ( e ) => e.key === 'Enter' && addNamespace(),
				} ),
				h( Button, { onClick: addNamespace }, 'Add' )
			),
			settings.restrict_rest_all && settings.rest_learning_mode && h( Fragment, null,
				h( 'div', { className: 'ts-row__label', style: { marginTop: '12px' } }, h( 'strong', null, 'Anonymous REST activity seen' ) ),
				! learning.length
					? h( 'p', { className: 'ts-muted' }, 'No anonymous REST traffic observed yet.' )
					: h( ScrollPanel, { maxHeight: '420px' },
						h( 'table', { className: 'ts-table' },
							h( 'thead', null, h( 'tr', null, h( 'th', null, 'Namespace' ), h( 'th', null, 'Hits' ), h( 'th', null, 'Last seen' ), h( 'th', null, '' ) ) ),
							h( 'tbody', null, learning.map( ( row ) => h( 'tr', { key: row.namespace },
								h( 'td', null, h( 'code', null, row.namespace ) ),
								h( 'td', null, row.count ),
								h( 'td', null, new Date( row.last_seen * 1000 ).toLocaleString() ),
								h( 'td', null, h( Button, { variant: 'ghost', onClick: () => { const cur = settings.rest_public_namespaces || []; if ( ! cur.includes( row.namespace ) ) saveNamespaces( [ ...cur, row.namespace ] ); } }, 'Exempt' ) )
							) ) )
						)
					)
			),
			h( 'p', null, h( 'a', { href: '#/rest-inventory' }, 'Full route inventory & rate limits →' ) )
		),

		h(
			Card,
			{
				title: 'Server rules (.htaccess)',
				actions: h( Badge, { tone: status.server_rules ? 'success' : 'neutral' }, status.server_rules ? 'Applied' : 'Not applied' ),
			},
			h( 'p', null, 'Disables directory browsing, blocks sensitive files, and prevents PHP execution in uploads/ and wp-includes/.' ),
			h( 'div', { className: 'ts-actions-row' },
				h( Button, { variant: 'primary', disabled: busy === 'server', onClick: () => serverRules( 'apply' ) }, busy === 'server' ? 'Working…' : 'Apply rules' ),
				status.server_rules && h( Button, { variant: 'danger', disabled: busy === 'server', onClick: () => serverRules( 'revert' ) }, 'Remove' )
			),
			h( 'details', { className: 'ts-details' },
				h( 'summary', null, 'Nginx equivalent (manual)' ),
				h( 'pre', null, status.nginx )
			)
		),

		h(
			Card,
			{
				title: 'wp-config.php hardening',
				actions: h( Badge, { tone: status.config && status.config.writable ? 'info' : 'danger' }, status.config && status.config.writable ? 'Writable' : 'Not writable' ),
			},
			[
				[ 'DISALLOW_FILE_EDIT', 'Disable theme/plugin file editor' ],
				[ 'DISALLOW_FILE_MODS', 'Lockdown: block all plugin/theme installs & updates' ],
				[ 'FORCE_SSL_ADMIN', 'Force SSL for admin & logins' ],
			].map( ( [ key, label ] ) =>
				h( 'div', { key, className: 'ts-row' },
					h( 'div', { className: 'ts-row__label' },
						h( 'span', { className: 'ts-row__name' },
							h( 'strong', null, label ),
							h( InfoTip, { help: settingHelp( 'hardening', key ), label } )
						),
						h( 'span', null, key )
					),
					h( Toggle, { checked: !! constants[ key ], onChange: ( v ) => setConstants( { ...constants, [ key ]: v } ) } )
				)
			),
			h( 'div', { className: 'ts-actions-row' },
				h( Button, { variant: 'primary', disabled: busy === 'config' || ! ( status.config && status.config.writable ), onClick: () => applyConfig( 'apply' ) }, busy === 'config' ? 'Writing…' : 'Apply to wp-config.php' ),
				status.config && status.config.block_present && h( Button, { variant: 'danger', disabled: busy === 'config', onClick: () => applyConfig( 'revert' ) }, 'Remove' )
			)
		)
	);
}
