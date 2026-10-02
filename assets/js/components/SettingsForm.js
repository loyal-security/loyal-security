/**
 * Settings panel — generic, schema-light editor over every module's settings.
 *
 * Renders a control per setting inferred from its value type (boolean → toggle, number →
 * numeric input, array → comma list, string → text/select) and saves per module via the
 * REST API. This keeps "every feature customizable from the backend" without hand-coding a
 * form for each toggle.
 */
import { h, useState, useEffect } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Toggle, Spinner, InfoTip, Badge, ScrollPanel } from './ui.js';
import { settingHelp } from '../settings-help.js';
import { useStore } from '../store.js';

/** Friendly labels + module ordering. Exported for reuse anywhere else a module id needs to
 * read as a name a human recognizes (e.g. the Hub fleet card's "modules active" list). */
export const MODULE_LABELS = {
	firewall: 'Firewall',
	hardening: 'Hardening',
	scanner: 'Scanner',
	integrity: 'Integrity',
	incident: 'Incident',
	auth: 'Identity & Access',
	audit: 'Audit Log',
	notifications: 'Notifications',
	backup: 'Backup & Recovery',
	threatintel: 'Threat Intelligence',
	traffic: 'Live Traffic',
};

/** Settings rendered as a dropdown with fixed choices. */
const ENUMS = {
	'firewall.geo_mode': [ 'off', 'allow', 'block' ],
	'auth.captcha_provider': [ 'none', 'turnstile', 'recaptcha_v3' ],
};

/** Secret fields rendered as password inputs. */
const SECRETS = [ 'captcha_secret_key', 'safe_browsing_api_key' ];

/** Read-only fields rendered as plain text (derived/computed values). */
const READONLY = [ 'channel' ];

/**
 * Internal bookkeeping fields the plugin persists inside the settings option but that are not
 * user-editable (maps/lists maintained by the code, not the operator). Hidden from the generic
 * form so they don't render as "[object Object]" or get clobbered on save. `license_key` is the
 * feed-subscription key, which the separate Pro plugin stores when its licence is activated.
 */
const HIDDEN = [ 'auto_whitelist_ips', 'feed_versions', 'patch_gap_notified', 'last_sync', 'license_key' ];

/**
 * Read `?highlight=module.key` off the current hash, e.g. `#/settings?highlight=firewall.enabled`
 * (mirrors the `paramFromHash` convention already used by LogTable.js). Lets other panels —
 * chiefly the Dashboard's Recommendations list — deep-link straight to a specific field instead
 * of just landing on the generic Settings page.
 */
function highlightFromHash() {
	try {
		const hash = window.location.hash || '';
		const query = hash.split( '?' )[ 1 ] || '';
		return new URLSearchParams( query ).get( 'highlight' ) || '';
	} catch ( _ ) {
		return '';
	}
}

export function SettingsForm() {
	const store = useStore();
	const [ all, setAll ] = useState( null );
	const [ active, setActive ] = useState( null );
	const [ drafts, setDrafts ] = useState( {} ); // mod -> draft object
	const [ open, setOpen ] = useState( {} ); // mod -> bool (which <details> are expanded)
	const [ busy, setBusy ] = useState( '' ); // mod id currently saving, or ''
	const [ query, setQuery ] = useState( '' );
	const [ highlight, setHighlight ] = useState( '' );
	const [ globalDraft, setGlobalDraft ] = useState( { delete_on_uninstall: false } );
	const [ globalBusy, setGlobalBusy ] = useState( false );

	useEffect( () => {
		api.get( '/settings' ).then( ( data ) => {
			setAll( data );
			// Seed a draft for every module.
			const seeded = {};
			Object.keys( data ).forEach( ( m ) => { seeded[ m ] = { ...data[ m ] }; } );
			setDrafts( seeded );

			// A deep-link (`?highlight=module.key`) opens straight to that module + field;
			// otherwise fall back to expanding just the first module, as before.
			const hl  = highlightFromHash();
			const dot = hl.indexOf( '.' );
			if ( dot > 0 && data[ hl.slice( 0, dot ) ] ) {
				const mod = hl.slice( 0, dot );
				setActive( mod );
				setOpen( { [ mod ]: true } );
				setHighlight( hl.slice( dot + 1 ) );
			} else {
				const first = Object.keys( data )[ 0 ];
				setActive( first );
				setOpen( { [ first ]: true } );
			}
		} ).catch( ( e ) => store.toast( e.message, 'error' ) );

		api.get( '/settings/global' ).then( ( g ) => setGlobalDraft( g ) ).catch( () => {} );
	}, [] );

	// Scroll the highlighted field into view once its <details> section has opened and
	// rendered — a raw setState from jumpTo() isn't enough on its own, since the field the
	// user searched for is often well below the fold inside a long, just-expanded module.
	// Declared here (with the other hooks, before the loading early-return below) rather than
	// further down where it was first written — a hook after a conditional return violates
	// the Rules of Hooks (it's skipped entirely on the first, `!all` render), which threw a
	// real "React error #310" in production.
	useEffect( () => {
		if ( ! highlight ) return undefined;
		const id = window.requestAnimationFrame( () => {
			const el = document.getElementById( active + '.' + highlight );
			if ( el ) el.scrollIntoView( { behavior: 'smooth', block: 'center' } );
		} );
		return () => window.cancelAnimationFrame( id );
	}, [ highlight, active ] );

	const selectModule = ( mod ) => {
		setActive( mod );
		setOpen( ( o ) => ( { ...o, [ mod ]: true } ) );
	};

	const setDraft = ( mod, next ) => setDrafts( ( d ) => ( { ...d, [ mod ]: next } ) );

	const save = async ( mod ) => {
		setBusy( mod );
		try {
			const saved = await api.post( '/settings/' + mod, drafts[ mod ] );
			setAll( ( a ) => ( { ...a, [ mod ]: saved } ) );
			setDraft( mod, { ...saved } );
			store.toast( 'Settings saved.', 'success' );
			window.dispatchEvent( new Event( 'totalsecwp:setup-changed' ) );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// Toggle a module's top-level `enabled` flag from the section header and persist immediately.
	const toggleEnabled = async ( mod, value ) => {
		const next = { ...( drafts[ mod ] || {} ), enabled: value };
		setDraft( mod, next );
		setBusy( mod );
		try {
			const saved = await api.post( '/settings/' + mod, next );
			setAll( ( a ) => ( { ...a, [ mod ]: saved } ) );
			setDraft( mod, { ...saved } );
			store.toast( value ? 'Module enabled.' : 'Module disabled.', 'success' );
			window.dispatchEvent( new Event( 'totalsecwp:setup-changed' ) );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const saveGlobal = async () => {
		setGlobalBusy( true );
		try {
			const saved = await api.post( '/settings/global', globalDraft );
			setGlobalDraft( saved );
			store.toast( 'Settings saved.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setGlobalBusy( false );
		}
	};

	if ( ! all || ! active ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	const modules = Object.keys( all );
	const humanize = ( k ) => k.replace( /_/g, ' ' ).replace( /\b\w/g, ( c ) => c.toUpperCase() );

	// Cross-module setting finder: match the query against module id/label, the setting key,
	// its humanized label, and its help text so any setting in the plugin is locatable.
	const q = query.trim().toLowerCase();
	const results = q ? modules.flatMap( ( mod ) =>
		Object.keys( all[ mod ] ).filter( ( key ) => {
			if ( HIDDEN.includes( key ) ) {
				return false;
			}
			let help = '';
			try { help = JSON.stringify( settingHelp( mod, key ) || '' ); } catch ( e ) { help = ''; }
			return `${ mod } ${ MODULE_LABELS[ mod ] || '' } ${ key } ${ humanize( key ) } ${ help }`.toLowerCase().includes( q );
		} ).map( ( key ) => ( { mod, key } ) )
	) : [];

	const jumpTo = ( mod, key ) => {
		selectModule( mod );
		setHighlight( key );
		setQuery( '' );
	};

	// A module is "dirty" when its draft has diverged from the last-saved snapshot in `all`
	// — drives both the small indicator on the collapsed section header and the floating
	// save bar below, so "you changed something, go save it" is visible without having to
	// scroll all the way to the bottom of a (possibly long) expanded section to find the
	// button that was already there.
	const isDirty = ( mod ) => !! drafts[ mod ] && !! all[ mod ] && JSON.stringify( drafts[ mod ] ) !== JSON.stringify( all[ mod ] );
	const dirtyModules = modules.filter( isDirty );

	return h(
		'div',
		{ className: 'ts-settings' },
		h( 'div', { className: 'ts-settings__search', style: { position: 'relative', marginBottom: '12px' } },
			h( 'span', { style: { position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', opacity: '0.6' } }, '🔍' ),
			h( 'input', {
				id: 'ts-settings-search',
				name: 'settings_search',
				type: 'search',
				value: query,
				placeholder: 'Search all settings…',
				onChange: ( e ) => setQuery( e.target.value ),
				style: { width: '100%', padding: '8px 10px 8px 32px', boxSizing: 'border-box' },
			} ),
			q && h( 'div', {
				className: 'ts-settings__results',
				style: { position: 'absolute', zIndex: '10', left: '0', right: '0', background: '#fff', border: '1px solid #dcdcde', borderRadius: '4px', marginTop: '2px', maxHeight: '320px', overflow: 'auto', boxShadow: '0 6px 24px rgba(0,0,0,0.12)' },
			},
				results.length
					? results.slice( 0, 50 ).map( ( r ) => h( 'button', {
							key: r.mod + '.' + r.key,
							type: 'button',
							onClick: () => jumpTo( r.mod, r.key ),
							style: { display: 'flex', width: '100%', justifyContent: 'space-between', gap: '12px', padding: '8px 12px', border: '0', borderBottom: '1px solid #f0f0f1', background: 'transparent', cursor: 'pointer', textAlign: 'left' },
						},
							h( 'span', null, humanize( r.key ) ),
							h( 'span', { style: { opacity: '0.6', fontSize: '12px' } }, MODULE_LABELS[ r.mod ] || r.mod )
						) )
					: h( 'div', { style: { padding: '10px 12px', opacity: '0.7' } }, 'No matching settings.' )
			)
		),
		// One collapsible <details> per module. The module's `enabled` toggle lives in the
		// summary so on/off state is visible at a glance without expanding the section.
		h( ScrollPanel, { maxHeight: '600px' },
		h( 'div', { className: 'ts-settings-groups' },
			modules.map( ( mod ) => {
				const draft = drafts[ mod ] || {};
				const hasEnabled = typeof draft.enabled === 'boolean';
				return h( 'details', {
					key: mod,
					className: 'ts-settings-group',
					open: !! open[ mod ],
				},
					h( 'summary', {
						className: 'ts-settings-group__summary',
						onClick: ( e ) => {
							e.preventDefault();
							setOpen( ( o ) => ( { ...o, [ mod ]: ! o[ mod ] } ) );
							setActive( mod );
						},
					},
						h( 'span', { className: 'ts-settings-group__title' }, MODULE_LABELS[ mod ] || mod ),
						isDirty( mod ) && h( Badge, { tone: 'warning' }, 'Unsaved' ),
						hasEnabled && h( 'span', {
							className: 'ts-settings-group__toggle',
							// Stop the click from toggling the <details> open/closed state.
							onClick: ( e ) => e.stopPropagation(),
						},
							h( Toggle, {
								checked: !! draft.enabled,
								disabled: busy === mod,
								label: draft.enabled ? 'Enabled' : 'Disabled',
								onChange: ( v ) => toggleEnabled( mod, v ),
							} )
						)
					),
					h( 'div', { className: 'ts-settings-group__body' },
						Object.keys( draft )
							// `enabled` is surfaced in the summary toggle; don't repeat it in the body.
							// HIDDEN fields are internal bookkeeping, not operator-editable.
							.filter( ( key ) => key !== 'enabled' && ! HIDDEN.includes( key ) )
							.map( ( key ) => renderField( mod, key, draft[ key ] ) ),
						active === mod && h( 'div', { className: 'ts-actions-row', style: { marginTop: '12px' } },
							h( Button, { variant: 'primary', disabled: busy === mod, onClick: () => save( mod ) }, busy === mod ? 'Saving…' : 'Save changes' )
						)
					)
				);
			} )
		),
		),

		// Floating save bar: stays pinned to the bottom of the viewport whenever any module
		// has unsaved changes, so the Save button is reachable without hunting for it inside
		// a possibly-long expanded section — the problem with the in-section button alone.
		dirtyModules.length > 0 && h( 'div', { className: 'ts-settings-savebar' },
			dirtyModules.map( ( mod ) => h( 'div', { key: mod, className: 'ts-settings-savebar__row' },
				h( 'span', { className: 'ts-settings-savebar__label' },
					'Unsaved changes in ', h( 'strong', null, MODULE_LABELS[ mod ] || mod )
				),
				h( Button, { variant: 'primary', disabled: busy === mod, onClick: () => save( mod ) }, busy === mod ? 'Saving…' : 'Save changes' )
			) )
		),

		h(
			Card,
			{
				title: 'Danger Zone',
				className: 'ts-card--danger',
				actions: h( Button, { variant: 'primary', disabled: globalBusy, onClick: saveGlobal }, globalBusy ? 'Saving…' : 'Save changes' ),
			},
			h( 'p', { className: 'ts-hint', style: { color: '#d63638' } },
				'These actions affect plugin data globally and may be irreversible.'
			),
			h( 'div', { className: 'ts-row' },
				h( 'div', { className: 'ts-row__label' },
					h( 'span', { className: 'ts-row__name' },
						h( 'strong', null, 'Delete All Data On Uninstall' )
					),
					h( 'span', null, 'global.delete_on_uninstall' )
				),
				h( 'div', { className: 'ts-row__control' },
					h( Toggle, {
						checked: !! globalDraft.delete_on_uninstall,
						onChange: ( v ) => setGlobalDraft( { ...globalDraft, delete_on_uninstall: v } ),
					} )
				)
			),
			!! globalDraft.delete_on_uninstall && h( 'p', {
				className: 'ts-hint',
				style: { color: '#d63638', marginTop: '8px' },
			},
				'⚠ When the plugin is deleted, all settings, firewall rules, security logs, scan history, and backups will be permanently erased.'
			)
		)
	);

	function renderField( mod, key, value ) {
		const id = mod + '.' + key;
		const label = key.replace( /_/g, ' ' ).replace( /\b\w/g, ( c ) => c.toUpperCase() );
		const draft = drafts[ mod ] || {};
		const update = ( v ) => setDraft( mod, { ...draft, [ key ]: v } );

		let control;
		if ( READONLY.includes( key ) ) {
			control = h( 'span', { style: { padding: '4px 8px', background: '#f6f7f7', borderRadius: '4px' } }, String( value ?? '' ) );
		} else if ( typeof value === 'boolean' ) {
			control = h( Toggle, { checked: value, onChange: ( v ) => update( v ) } );
		} else if ( ENUMS[ id ] ) {
			control = h( 'select', { id, name: id, value, onChange: ( e ) => update( e.target.value ) },
				ENUMS[ id ].map( ( opt ) => h( 'option', { key: opt, value: opt }, opt ) )
			);
		} else if ( typeof value === 'number' ) {
			control = h( 'input', { id, name: id, type: 'number', value, onChange: ( e ) => update( Number( e.target.value ) ) } );
		} else if ( Array.isArray( value ) ) {
			control = h( ListField, { value, onCommit: update, id } );
		} else {
			control = h( 'input', {
				id, name: id,
				type: SECRETS.includes( key ) ? 'password' : 'text',
				value: value == null ? '' : value,
				onChange: ( e ) => update( e.target.value ),
			} );
		}

		const isHit = key === highlight;
		return h( 'div', {
			key,
			className: 'ts-row' + ( isHit ? ' is-highlight' : '' ),
			style: isHit ? { outline: '2px solid #2271b1', outlineOffset: '2px', borderRadius: '4px' } : null,
		},
			h( 'div', { className: 'ts-row__label' },
				h( 'label', { className: 'ts-row__name', htmlFor: id },
					h( 'strong', null, label ),
					h( InfoTip, { help: settingHelp( mod, key ), label } )
				),
				h( 'span', null, id )
			),
			h( 'div', { className: 'ts-row__control' }, control )
		);
	}
}

/**
 * Multi-line list editor for array-valued settings (IP allowlists, path lists, …). The raw
 * textarea text is kept in local state and only parsed into an array on blur — parsing on every
 * keystroke (split+filter(Boolean)) stripped the newline the instant it was typed, making it
 * impossible to add a second line by typing. Re-syncs when the committed value changes elsewhere
 * (e.g. a reset), but not while focused, so typing is never interrupted.
 */
function ListField( { value, onCommit, id } ) {
	const [ text, setText ] = useState( ( value || [] ).join( '\n' ) );
	const [ focused, setFocused ] = useState( false );

	useEffect( () => {
		if ( ! focused ) {
			setText( ( value || [] ).join( '\n' ) );
		}
	}, [ value, focused ] );

	const commit = () => {
		setFocused( false );
		onCommit( text.split( /\n+/ ).map( ( s ) => s.trim() ).filter( Boolean ) );
	};

	return h( 'textarea', {
		id, name: id,
		rows: 3,
		value: text,
		placeholder: 'One per line',
		onFocus: () => setFocused( true ),
		onChange: ( e ) => setText( e.target.value ),
		onBlur: commit,
	} );
}
