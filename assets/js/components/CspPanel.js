/**
 * CSP Manager panel.
 *
 * Lets administrators:
 *   1. Choose a mode: Off / Report-Only / Enforce
 *   2. Toggle service presets (GA, FB Pixel, Stripe, etc.) with one click
 *   3. Add custom per-directive source values (advanced)
 *   4. Run a site scan to auto-detect which presets are needed
 *   5. Review recent CSP violation reports
 *
 * The generated policy is previewed live in a <pre> block so admins can
 * see exactly what header will be emitted before saving.
 */
import { h, useState, useEffect, useCallback, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState, ConfirmDialog } from './ui.js';
import { useStore } from '../store.js';
import { useIsAdvancedView } from './ViewMode.js';
import { usePaged, ListSearch, matchesQuery } from './PaginatedList.js';

/* ─── helpers ──────────────────────────────────────────────────────────── */

function modeTone( mode ) {
	if ( mode === 'enforce' )     return 'danger';
	if ( mode === 'report-only' ) return 'warning';
	return 'neutral';
}

function modeLabel( mode ) {
	if ( mode === 'enforce' )     return 'Enforce';
	if ( mode === 'report-only' ) return 'Report-Only';
	return 'Off';
}

function fmtTs( ts ) {
	if ( ! ts ) return '—';
	return new Date( ts * 1000 ).toLocaleString();
}

/* ─── ModeToggle ────────────────────────────────────────────────────────── */

function ModeToggle( { enabled, mode, onChange } ) {
	const opts = [
		{ key: 'off',         label: 'Off',         hint: 'No CSP header sent.' },
		{ key: 'report-only', label: 'Report-Only',  hint: 'Header sent; violations logged but not blocked. Safe to test.' },
		{ key: 'enforce',     label: 'Enforce',      hint: 'Violations are blocked. Test in Report-Only first.' },
	];

	const current = ! enabled ? 'off' : mode;

	return h( 'div', { className: 'ts-csp-modes' },
		opts.map( ( o ) => {
			const active = current === o.key;
			return h( 'button', {
				key: o.key,
				type: 'button',
				className: 'ts-csp-mode' + ( active ? ' ts-csp-mode--active ts-csp-mode--' + o.key : '' ),
				onClick: () => onChange( o.key ),
				title: o.hint,
			},
				h( 'span', { className: 'ts-csp-mode__label' }, o.label ),
				h( 'span', { className: 'ts-csp-mode__hint' }, o.hint )
			);
		} )
	);
}

/* ─── PresetTile ────────────────────────────────────────────────────────── */

function PresetTile( { preset, active, onToggle } ) {
	const initial = ( preset.label || '?' ).charAt( 0 ).toUpperCase();
	return h( 'button', {
		type: 'button',
		className: 'ts-csp-preset' + ( active ? ' ts-csp-preset--active' : '' ),
		onClick: () => onToggle( preset.slug ),
	},
		h( 'span', {
			className: 'ts-csp-preset__logo',
			style: { background: preset.color || '#6b7280' },
		}, initial ),
		h( 'span', { className: 'ts-csp-preset__label' }, preset.label ),
		active && h( 'span', { className: 'ts-csp-preset__check' }, '✓' )
	);
}

/* ─── PendingReview ─────────────────────────────────────────────────────── */

function PendingReview( { onPolicyChanged } ) {
	const store                       = useStore();
	const [ data, setData ]           = useState( null );
	const [ loading, setLoading ]     = useState( true );
	const [ working, setWorking ]     = useState( {} ); // domain → true while request in flight
	const [ clearing, setClearing ]   = useState( false );
	const [ query, setQuery ]         = useState( '' );

	const load = useCallback( async () => {
		setLoading( true );
		try {
			const res = await api.get( '/csp/pending' );
			setData( res );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setLoading( false );
		}
	}, [] );

	useEffect( () => { load(); }, [ load ] );

	const approve = async ( domain, action, preset ) => {
		setWorking( ( w ) => ( { ...w, [ domain ]: true } ) );
		try {
			await api.post( '/csp/pending/approve', { domain, action, preset } );
			store.toast( 'Approved — policy updated.', 'success' );
			await load();
			if ( onPolicyChanged ) onPolicyChanged();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setWorking( ( w ) => { const n = { ...w }; delete n[ domain ]; return n; } );
		}
	};

	const dismiss = async ( domain ) => {
		setWorking( ( w ) => ( { ...w, [ domain ]: true } ) );
		try {
			await api.post( '/csp/pending/dismiss', { domain } );
			store.toast( 'Dismissed.', 'success' );
			await load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setWorking( ( w ) => { const n = { ...w }; delete n[ domain ]; return n; } );
		}
	};

	const clearAll = async () => {
		if ( ! window.confirm( 'Clear the entire pending list?' ) ) return;
		setClearing( true );
		try {
			await api.post( '/csp/pending/clear', {} );
			store.toast( 'Pending list cleared.', 'success' );
			setData( null );
			await load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setClearing( false );
		}
	};

	// usePaged() must run on every render (Rules of Hooks) — compute it before the early
	// returns below, which become reachable once loading/data resolve.
	const items = data?.items || [];
	const filtered = items.filter( ( item ) => matchesQuery( item, query, [ 'domain', 'preset' ] ) );
	const { pageItems, pager } = usePaged( filtered, 25 );

	if ( loading && ! data ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	if ( ! items.length ) {
		return h( EmptyState, {
			icon: '✅',
			title: 'No pending domains',
			hint: 'Domains blocked by your CSP will appear here for review. Make sure violation logging is enabled.',
		} );
	}

	return h( 'div', null,
		h( 'div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' } },
			h( 'p', { className: 'ts-muted', style: { margin: 0 } },
				items.length + ' domain' + ( items.length !== 1 ? 's' : '' ) + ' pending review'
			),
			h( Button, { variant: 'ghost', disabled: clearing, onClick: clearAll },
				clearing ? 'Clearing…' : 'Clear All'
			)
		),
		items.length > 8 && h( 'div', { className: 'ts-toolbar', style: { marginBottom: '12px' } },
			h( ListSearch, { value: query, onChange: setQuery, placeholder: 'Search domain or preset…' } )
		),
		! filtered.length
			? h( EmptyState, { icon: '🔍', title: 'No matching domains', hint: 'Try a different search term.' } )
			: h( 'div', { className: 'ts-csp-pending-list' },
			pageItems.map( ( item ) => {
				const busy   = !! working[ item.domain ];
				const preset = item.preset || null;

				return h( 'div', { key: item.domain, className: 'ts-csp-pending-item' },
					h( 'div', { className: 'ts-csp-pending-item__meta' },
						h( 'code', { className: 'ts-csp-pending-item__domain' }, item.domain ),
						h( 'span', { className: 'ts-muted ts-csp-pending-item__directives' },
							( item.directives || [] ).join( ', ' )
						),
						h( 'span', { className: 'ts-muted ts-csp-pending-item__count' },
							item.count + ' hit' + ( item.count !== 1 ? 's' : '' ) +
							' · first seen ' + fmtTs( item.first_seen )
						)
					),
					h( 'div', { className: 'ts-csp-pending-item__actions' },
						preset
							? h( Button, {
								variant: 'primary',
								disabled: busy,
								onClick: () => approve( item.domain, 'preset', preset ),
							}, busy ? '…' : 'Enable ' + preset + ' preset' )
							: h( Button, {
								variant: 'primary',
								disabled: busy,
								onClick: () => approve( item.domain, 'custom' ),
							}, busy ? '…' : 'Allow domain' ),
						h( Button, {
							variant: 'ghost',
							disabled: busy,
							onClick: () => dismiss( item.domain ),
						}, 'Dismiss' )
					)
				);
			} )
		),
		pager
	);
}

/* ─── ScanResults ───────────────────────────────────────────────────────── */

function ScanResults( { scan, enabledPresets, onApplyPresets, scanning } ) {
	if ( scanning ) {
		return h( 'div', { className: 'ts-csp-scan-running' },
			h( Spinner, null ),
			h( 'p', null, 'Scanning your site… this may take up to 15 seconds.' )
		);
	}

	if ( ! scan ) {
		return h( 'p', { className: 'ts-muted', style: { marginTop: '8px' } },
			'No scan run yet. Click "Scan My Site" to discover which presets you need.'
		);
	}

	if ( scan.error ) {
		return h( 'p', { className: 'ts-notice ts-notice--danger' }, 'Scan error: ' + scan.error );
	}

	const newPresets = ( scan.presets || [] ).filter( ( p ) => ! enabledPresets.includes( p ) );

	return h( 'div', { className: 'ts-csp-scan-results' },
		h( 'p', { className: 'ts-muted', style: { fontSize: '12px' } },
			'Scanned at ' + fmtTs( scan.scanned_at ) + '. Checked ',
			h( 'strong', null, scan.pages_scanned || 1 ),
			' page' + ( ( scan.pages_scanned || 1 ) > 1 ? 's' : '' ) + '. Found ',
			h( 'strong', null, ( scan.domains || [] ).length ),
			' external hosts.'
		),
		( scan.presets || [] ).length
			? h( Fragment, null,
				h( 'p', null,
					h( 'strong', null, 'Detected services: ' ),
					( scan.presets || [] ).join( ', ' )
				),
				newPresets.length
					? h( Button, {
						variant: 'primary',
						onClick: () => onApplyPresets( scan.presets || [] ),
					}, 'Enable ' + newPresets.length + ' suggested preset' + ( newPresets.length > 1 ? 's' : '' ) )
					: h( 'p', { className: 'ts-muted' }, 'All detected presets are already enabled.' )
			)
			: h( 'p', { className: 'ts-muted' }, 'No known third-party services detected on the homepage.' ),

		( scan.domains || [] ).length > 0 && h( 'details', { style: { marginTop: '8px' } },
			h( 'summary', { className: 'ts-muted', style: { fontSize: '12px', cursor: 'pointer' } }, 'All discovered hosts (' + scan.domains.length + ')' ),
			h( 'div', { className: 'ts-csp-domain-list' },
				( scan.domains || [] ).map( ( d ) => h( 'code', { key: d, className: 'ts-csp-domain' }, d ) )
			)
		)
	);
}

/* ─── CustomDirectives ──────────────────────────────────────────────────── */

function CustomDirectives( { custom, onChange } ) {
	const DIRECTIVES = [
		'default-src', 'script-src', 'style-src', 'img-src', 'font-src',
		'connect-src', 'frame-src', 'object-src', 'media-src', 'worker-src',
		'base-uri', 'form-action', 'manifest-src',
	];

	const [ newDirective, setNewDirective ] = useState( DIRECTIVES[ 0 ] );
	const [ newValue, setNewValue ]         = useState( '' );

	const addValue = () => {
		const v = newValue.trim();
		if ( ! v ) return;
		const existing = custom[ newDirective ] || [];
		if ( ! existing.includes( v ) ) {
			onChange( { ...custom, [ newDirective ]: [ ...existing, v ] } );
		}
		setNewValue( '' );
	};

	const removeValue = ( directive, value ) => {
		const remaining = ( custom[ directive ] || [] ).filter( ( x ) => x !== value );
		const next      = { ...custom };
		if ( remaining.length ) {
			next[ directive ] = remaining;
		} else {
			delete next[ directive ];
		}
		onChange( next );
	};

	const hasCustom = Object.keys( custom ).length > 0;

	return h( 'div', { className: 'ts-csp-custom' },
		hasCustom && h( 'div', { className: 'ts-csp-custom__entries' },
			Object.entries( custom ).map( ( [ directive, values ] ) =>
				h( 'div', { key: directive, className: 'ts-csp-custom__row' },
					h( 'code', { className: 'ts-csp-custom__directive' }, directive ),
					h( 'div', { className: 'ts-csp-custom__values' },
						( values || [] ).map( ( v ) =>
							h( 'span', { key: v, className: 'ts-csp-custom__chip' },
								v,
								h( 'button', {
									type: 'button',
									className: 'ts-csp-custom__remove',
									onClick: () => removeValue( directive, v ),
									'aria-label': 'Remove ' + v,
								}, '×' )
							)
						)
					)
				)
			)
		),
		h( 'div', { className: 'ts-csp-custom__add' },
			h( 'select', {
				id: 'ts-csp-new-directive',
				name: 'csp_new_directive',
				value: newDirective,
				onChange: ( e ) => setNewDirective( e.target.value ),
				className: 'ts-select ts-select--sm',
			},
				DIRECTIVES.map( ( d ) => h( 'option', { key: d, value: d }, d ) )
			),
			h( 'input', {
				id: 'ts-csp-new-value',
				name: 'csp_new_value',
				type: 'text',
				placeholder: "e.g. https://cdn.example.com or 'unsafe-inline'",
				value: newValue,
				onChange: ( e ) => setNewValue( e.target.value ),
				onKeyDown: ( e ) => e.key === 'Enter' && addValue(),
				className: 'ts-input ts-input--sm ts-input--wide',
			} ),
			h( Button, { variant: 'primary', onClick: addValue }, 'Add' )
		)
	);
}

/* ─── ViolationFilterBar ────────────────────────────────────────────────── */

function ViolationFilterBar( { filters, onFilters, directives } ) {
	const [ local, setLocal ] = useState( filters );

	const apply = () => onFilters( local );
	const onKey = ( e ) => { if ( e.key === 'Enter' ) apply(); };
	const clear = () => {
		const reset = { directive: '', search: '' };
		setLocal( reset );
		onFilters( reset );
	};

	return h( 'div', { className: 'ts-filters' },
		h( 'select', {
			id: 'ts-csp-filter-directive',
			name: 'csp_filter_directive',
			value: local.directive,
			onChange: ( e ) => {
				const next = { ...local, directive: e.target.value };
				setLocal( next );
				onFilters( next );
			},
			className: 'ts-select ts-select--sm',
		},
			h( 'option', { value: '' }, 'All directives' ),
			directives.map( ( d ) => h( 'option', { key: d, value: d }, d ) )
		),
		h( 'input', {
			id: 'ts-csp-filter-search',
			name: 'csp_filter_search',
			type: 'text',
			placeholder: 'Search blocked URI / page…',
			value: local.search,
			onChange: ( e ) => setLocal( ( f ) => ( { ...f, search: e.target.value } ) ),
			onKeyDown: onKey,
			className: 'ts-input ts-input--sm ts-input--wide',
		} ),
		h( Button, { variant: 'primary', onClick: apply }, 'Apply' ),
		h( Button, { variant: 'ghost', onClick: clear }, 'Clear' )
	);
}

/* ─── ViolationLog ──────────────────────────────────────────────────────── */

// Blocked values with no source that could ever be added to the policy automatically.
const NOT_ALLOWLISTABLE = [ 'none', 'self' ];

function ViolationLog( { onPolicyChanged } ) {
	const store                     = useStore();
	const [ data, setData ]         = useState( null );
	const [ loading, setLoading ]   = useState( true );
	const [ error, setError ]       = useState( null );
	const [ clearing, setClearing ] = useState( false );
	const [ page, setPage ]         = useState( 1 );
	const [ filters, setFilters ]   = useState( { directive: '', search: '' } );
	const [ allowing, setAllowing ] = useState( {} ); // id → true while request in flight

	// Must not leave `data` untouched on failure: falling through to the "No violations" empty
	// state below would misreport a failed request as "everything's fine".
	const load = useCallback( async ( p, f ) => {
		setLoading( true );
		try {
			const res = await api.get( '/csp/violations', {
				page: p,
				per_page: 50,
				directive: f.directive,
				search: f.search,
			} );
			setData( res );
			setError( null );
		} catch ( e ) {
			setError( e.message || 'Failed to load the violation log.' );
		} finally {
			setLoading( false );
		}
	}, [] );

	useEffect( () => { load( page, filters ); }, [ page, filters, load ] );

	const applyFilters = ( f ) => {
		setFilters( f );
		setPage( 1 );
	};

	const clearAll = async () => {
		if ( ! window.confirm( 'Clear all CSP violation records?' ) ) return;
		setClearing( true );
		try {
			await api.del( '/csp/violations' );
			store.toast( 'Violation log cleared.', 'success' );
			setData( null );
			setPage( 1 );
			load( 1, filters );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setClearing( false );
		}
	};

	const allow = async ( v ) => {
		setAllowing( ( a ) => ( { ...a, [ v.id ]: true } ) );
		try {
			const res = await api.post( '/csp/violations/allow', { id: v.id } );
			store.toast(
				'preset' === res.applied
					? 'Preset "' + res.preset + '" enabled.'
					: '"' + res.value + '" added to ' + res.directive + '.',
				'success'
			);
			if ( onPolicyChanged ) await onPolicyChanged();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setAllowing( ( a ) => { const n = { ...a }; delete n[ v.id ]; return n; } );
		}
	};

	const totalPages  = data ? Math.max( 1, Math.ceil( data.total / data.per_page ) ) : 1;
	const directives  = data?.directives || [];
	const filtered    = !! ( filters.directive || filters.search );

	return h( Card, {
		title: 'Violation Log',
		actions: data && data.total
			? h( Button, { variant: 'ghost', disabled: clearing, onClick: clearAll }, clearing ? 'Clearing…' : 'Clear All' )
			: null,
	},
		h( ViolationFilterBar, { filters, onFilters: applyFilters, directives } ),
		loading && ! data
			? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
			: error
				? h( 'div', { className: 'ts-notice ts-notice--danger', style: { display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'space-between' } },
					h( 'span', null, '⚠️ Could not load the violation log: ' + error ),
					h( Button, { variant: 'ghost', onClick: () => load( page, filters ) }, 'Retry' )
				)
				: ! data || ! data.items || ! data.items.length
				? h( EmptyState, {
					icon: '✅',
					title: filtered ? 'No matching violations' : 'No violations',
					hint: filtered
						? 'Try a different directive or search term.'
						: 'Violations will appear here when a browser reports a CSP block.',
				} )
				: h( Fragment, null,
					h( 'table', { className: 'ts-table ts-table--traffic' },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'Last Seen' ),
							h( 'th', null, 'Directive' ),
							h( 'th', null, 'Blocked URI' ),
							h( 'th', null, 'Hits' ),
							h( 'th', null, 'Page' ),
							h( 'th', null, 'Action' ),
						) ),
						h( 'tbody', null, data.items.map( ( v ) => {
							const busy         = !! allowing[ v.id ];
							const canAllow     = v.blocked && ! NOT_ALLOWLISTABLE.includes( v.blocked );
							return h( 'tr', { key: v.id },
								h( 'td', { className: 'ts-muted ts-col--time', title: 'First seen ' + fmtTs( v.first_seen ) }, fmtTs( v.ts ) ),
								h( 'td', null, h( 'code', null, v.directive || '—' ) ),
								h( 'td', { className: 'ts-uri', title: v.blocked || '' }, v.blocked || '—' ),
								h( 'td', { className: 'ts-muted' }, v.hits || 1 ),
								h( 'td', { className: 'ts-uri', title: v.doc_uri || '' }, v.doc_uri || '—' ),
								h( 'td', null,
									canAllow
										? h( Button, {
											variant: 'ghost',
											disabled: busy,
											onClick: () => allow( v ),
										}, busy ? '…' : 'Add to CSP' )
										: h( 'span', { className: 'ts-muted' }, '—' )
								)
							);
						} ) )
					),
					data.total > data.per_page && h( 'div', { className: 'ts-pager' },
						h( Button, { disabled: page <= 1, onClick: () => setPage( page - 1 ) }, '‹ Prev' ),
						h( 'span', null, 'Page ' + page + ' / ' + totalPages + ' · ' + data.total + ' violations' ),
						h( Button, { disabled: page >= totalPages, onClick: () => setPage( page + 1 ) }, 'Next ›' )
					)
				)
	);
}

/* ─── Main panel ────────────────────────────────────────────────────────── */

export function CspPanel() {
	const store = useStore();
	const advanced = useIsAdvancedView();

	const [ policy, setPolicy ]     = useState( null );
	const [ loading, setLoading ]   = useState( true );
	const [ loadErr, setLoadErr ]   = useState( null );
	const [ saving, setSaving ]     = useState( false );
	const [ confirmEnforce, setConfirmEnforce ] = useState( false );
	const [ scanning, setScanning ] = useState( false );
	const [ scan, setScan ]         = useState( null );
	const [ tab, setTab ]           = useState( 'presets' ); // 'presets' | 'custom' | 'scan' | 'pending' | 'violations'

	// Editable state (mirrors policy from server until saved).
	const [ enabled, setEnabled ]     = useState( false );
	const [ mode, setMode ]           = useState( 'report-only' );
	const [ presets, setPresets ]     = useState( [] );
	const [ custom, setCustom ]       = useState( {} );
	const [ vlog, setVlog ]           = useState( true );
	const [ nonceInline, setNonceInline ] = useState( false );
	const [ strictEval, setStrictEval ]   = useState( false );
	const [ preview, setPreview ]     = useState( '' );
	const [ presetList, setPresetList ] = useState( [] );
	const [ pendingCount, setPendingCount ] = useState( 0 );
	const [ codebaseScan, setCodebaseScan ] = useState( null );
	const [ codebaseScanning, setCodebaseScanning ] = useState( false );
	const [ autoScanned, setAutoScanned ] = useState( false );

	// Refresh pending count (called after approvals/dismissals).
	const refreshPendingCount = useCallback( async () => {
		try {
			const res = await api.get( '/csp/pending' );
			setPendingCount( res?.total ?? 0 );
		} catch ( _ ) { /* ignore */ }
	}, [] );

	// Re-sync editable state after something outside this component's own Save button wrote
	// to the policy (pending-domain approval, or the violation log's "Add to CSP" action).
	const refreshAfterPolicyWrite = useCallback( async () => {
		const d = await api.get( '/csp/policy' );
		setPreview( d.preview || '' );
		setPresets( d.presets || [] );
		setCustom( d.custom_directives || {} );
		await refreshPendingCount();
	}, [ refreshPendingCount ] );

	// Load current policy on mount.
	const loadPolicy = useCallback( async () => {
		setLoading( true );
		setLoadErr( null );
		try {
			// The policy load is what decides whether CSP is on — if it throws, we must NOT fall
			// through to the default render (mode Off / no presets), which is indistinguishable
			// from CSP genuinely being disabled and misrepresents a security control's real
			// state. Only the scan fetches are allowed to fail quietly (they're background data).
			const d = await api.get( '/csp/policy' );
			applyFromServer( d );
			try {
				const s  = await api.get( '/csp/scan' );
				const cs = await api.get( '/csp/codebase-scan' );
				setScan( s );
				setCodebaseScan( cs );
			} catch ( _ ) { /* scan data is non-critical */ }
			await refreshPendingCount();
		} catch ( e ) {
			setLoadErr( ( e && e.message ) || 'Failed to load the CSP policy.' );
		} finally {
			setLoading( false );
		}
	}, [ refreshPendingCount ] );

	useEffect( () => { loadPolicy(); }, [ loadPolicy ] );

	const applyFromServer = ( d ) => {
		setEnabled( d.enabled ?? false );
		setMode( d.mode ?? 'report-only' );
		setPresets( d.presets ?? [] );
		setCustom( d.custom_directives ?? {} );
		setVlog( d.violations_log ?? true );
		setNonceInline( d.nonce_protect_inline ?? false );
		setStrictEval( d.strict_eval ?? false );
		setPreview( d.preview ?? '' );
		setPresetList( d.presets_list ?? [] );
		setPolicy( d );
	};

	const handleModeChange = ( key ) => {
		if ( key === 'off' ) {
			setEnabled( false );
		} else {
			setEnabled( true );
			setMode( key );
		}
	};

	const togglePreset = ( slug ) => {
		setPresets( ( p ) =>
			p.includes( slug ) ? p.filter( ( x ) => x !== slug ) : [ ...p, slug ]
		);
		setPreview( '' ); // mark stale until next save
	};

	const applyScannedPresets = ( suggested ) => {
		setPresets( ( p ) => Array.from( new Set( [ ...p, ...suggested ] ) ) );
		setPreview( '' ); // mark stale until next save
	};

	// In Basic view the scan doesn't just suggest — it builds the policy directly, since the
	// whole point of Basic is not asking a non-technical owner to recognize "do I use Google
	// reCAPTCHA?" themselves. Advanced view keeps the manual "enable N suggested presets" step
	// (see ScanResults) so a technical user can review before applying.
	const runScan = async () => {
		setScanning( true );
		try {
			const result = await api.post( '/csp/scan', {} );
			setScan( result );
			if ( ! advanced && result && result.presets && result.presets.length ) {
				applyScannedPresets( result.presets );
			}
		} catch ( e ) {
			store.toast( 'Scan failed: ' + e.message, 'error' );
		} finally {
			setScanning( false );
		}
	};

	// Switching Advanced → Basic while sat on a tab that only exists in Advanced (Custom
	// Sources, Site Scanner) would otherwise leave the tab bar with nothing selected and the
	// content area blank — fall back to Service Presets, the one tab guaranteed to exist in
	// both views.
	useEffect( () => {
		if ( ! advanced && ( tab === 'custom' || tab === 'scan' ) ) {
			setTab( 'presets' );
		}
	}, [ advanced, tab ] );

	// First time a Basic-view admin opens CSP with no scan on record, run one automatically
	// instead of leaving them to notice a hidden "Scan my site" action — this is the one place
	// Basic behaves entirely differently from Advanced, not just a leaner version of it.
	// Guarded to fire once per mount (autoScanned) and only once the initial load has actually
	// told us there's no scan on record yet (loading false, scan still null).
	useEffect( () => {
		if ( advanced || loading || autoScanned || ! enabled || scan ) return;
		setAutoScanned( true );
		runScan();
	}, [ advanced, loading, enabled, scan, autoScanned ] );

	const runCodebaseScan = async () => {
		setCodebaseScanning( true );
		try {
			const result = await api.post( '/csp/codebase-scan', {} );
			setCodebaseScan( result );
		} catch ( e ) {
			store.toast( 'Codebase scan failed: ' + e.message, 'error' );
		} finally {
			setCodebaseScanning( false );
		}
	};

	const save = async () => {
		setSaving( true );
		try {
			await api.post( '/csp/policy', {
				enabled,
				mode,
				presets,
				custom_directives: custom,
				violations_log: vlog,
				nonce_protect_inline: nonceInline,
				strict_eval: strictEval,
			} );
			// Re-fetch the full policy from the server so client state stays in sync
			// (guards against any server-side rewrite or caching discrepancy).
			const confirmed = await api.get( '/csp/policy' );
			applyFromServer( confirmed );
			store.toast( 'CSP policy saved.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setSaving( false );
			setConfirmEnforce( false );
		}
	};

	// Switching into Enforce (from a state that wasn't already Enforce) can block real
	// scripts/styles/fonts sitewide with the very next page load — that's the one save on
	// this panel that isn't safely reversible with another click, so it's the one gated by
	// a confirm. Re-saving while already enforced (e.g. adding a preset) does not re-prompt.
	const wasEnforced = !! ( policy && policy.enabled && policy.mode === 'enforce' );
	const enteringEnforce = enabled && mode === 'enforce' && ! wasEnforced;

	const handleSaveClick = () => {
		if ( enteringEnforce ) {
			setConfirmEnforce( true );
			return;
		}
		save();
	};

	if ( loading ) {
		return h( Card, { title: 'CSP Manager' }, h( 'div', { className: 'ts-loading' }, h( Spinner, null ) ) );
	}

	if ( loadErr ) {
		return h( Card, { title: 'CSP Manager' },
			h( 'p', { className: 'ts-notice ts-notice--danger' }, '⚠️ Could not load the CSP policy: ' + loadErr ),
			h( 'p', { className: 'ts-muted' }, 'The current protection state is unknown — this is not the same as CSP being off.' ),
			h( Button, { variant: 'primary', onClick: loadPolicy }, 'Retry' )
		);
	}

	const currentMode = ! enabled ? 'off' : mode;

	return h( Fragment, null,

		h( ConfirmDialog, {
			open: confirmEnforce,
			title: 'Switch CSP to Enforce mode?',
			message: 'You haven’t confirmed this policy is safe in Report-Only mode. Enforcing now will block any real script, style, image, or font that isn’t already covered by your presets or custom sources — sitewide, starting with the next page load.',
			consequence: 'If something breaks, switch back to Report-Only or Off from this same panel — the change takes effect immediately, in either direction.',
			confirmLabel: saving ? 'Enforcing…' : 'Enforce Policy',
			busy: saving,
			danger: true,
			onCancel: () => setConfirmEnforce( false ),
			onConfirm: save,
		} ),

		h( Card, { title: 'CSP Manager',
			actions: h( 'div', { style: { display: 'flex', gap: '8px', alignItems: 'center' } },
				h( Badge, { tone: modeTone( currentMode ) }, modeLabel( currentMode ) ),
				h( Button, { variant: 'primary', disabled: saving, onClick: handleSaveClick },
					saving ? 'Saving…' : 'Save Policy'
				)
			),
		},

			// Mode toggle.
			h( 'div', { className: 'ts-csp-section' },
				h( 'h3', { className: 'ts-csp-section__title' }, 'Mode' ),
				h( ModeToggle, { enabled, mode, onChange: handleModeChange } )
			),

			// Learning-mode-style suggestion: only once the server says enough time has passed
			// with zero admin action — never a bare "you should enforce" nag on day one.
			policy && policy.ready_to_enforce && currentMode === 'report-only' && h(
				'div', { className: 'ts-notice ts-notice--info', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' } },
				h( 'span', null,
					`You’ve been in Report-Only for ${ policy.days_in_current_mode } day(s)`,
					policy.violations_since_mode_change
						? `, with ${ policy.violations_since_mode_change } violation(s) logged and reviewable in the Pending Review / Violations tabs. `
						: ' with no violations logged. ',
					'Ready to switch to Enforce?'
				),
				h( Button, { variant: 'primary', onClick: () => { setMode( 'enforce' ); setEnabled( true ); setConfirmEnforce( true ); } }, 'Review & Enforce' )
			),

			enabled && h( Fragment, null,

				// Violations-log checkbox.
				h( 'div', { className: 'ts-csp-section ts-csp-section--row' },
					h( 'label', { className: 'ts-checkbox-label', htmlFor: 'ts-csp-vlog' },
						h( 'input', {
							id: 'ts-csp-vlog',
							name: 'csp_vlog',
							type: 'checkbox',
							checked: vlog,
							onChange: ( e ) => setVlog( e.target.checked ),
						} ),
						' Log violations (browsers POST reports to ' + ( policy?.report_uri || '/csp/report' ) + ')'
					)
				),

				// Strict inline protection — advanced-only: these two change how the policy
				// actually behaves (not just which sources it allows), so they need the same
				// "know what you're doing" bar as Custom Sources. Nonce-protect only ever
				// touches script-src — style-src deliberately keeps plain 'unsafe-inline' (see
				// CspPolicy::build()'s docblock). A nonce in style-src looked equally safe on
				// paper but isn't: it makes the browser stop honouring 'unsafe-inline' for
				// style="..." attributes too, which have no nonce mechanism of their own — that
				// shipped once, broke a real page's layout in Enforce, and was reverted. Strict
				// eval has no graceful-degrade path either; the label says so plainly rather than
				// let a technical user assume it's equally free.
				advanced && h( 'div', { className: 'ts-csp-section' },
					h( 'h3', { className: 'ts-csp-section__title' }, 'Strict inline protection' ),
					h( 'p', { className: 'ts-muted', style: { marginTop: '-4px', marginBottom: '10px' } },
						'Closes two gaps every WordPress CSP ships with by default: inline scripts trusted purely by being inline, and unrestricted eval(). Inline styles are deliberately left as-is — see the tooltip. Off by default so existing policies don’t change behavior on an update — review in Report-Only first.'
					),
					h( 'label', { className: 'ts-checkbox-label', htmlFor: 'ts-csp-nonce', style: { display: 'block', marginBottom: '8px' } },
						h( 'input', {
							id: 'ts-csp-nonce', name: 'csp_nonce_inline', type: 'checkbox',
							checked: nonceInline,
							onChange: ( e ) => setNonceInline( e.target.checked ),
						} ),
						' Nonce-tag inline scripts — modern browsers stop trusting untagged inline scripts; older browsers are unaffected. Inline styles are not touched (style attributes have no nonce mechanism — adding one there blocks them instead of protecting them).'
					),
					h( 'label', { className: 'ts-checkbox-label', htmlFor: 'ts-csp-eval' },
						h( 'input', {
							id: 'ts-csp-eval', name: 'csp_strict_eval', type: 'checkbox',
							checked: strictEval,
							onChange: ( e ) => setStrictEval( e.target.checked ),
						} ),
						' Block eval() / new Function() — no fallback for older browsers. If a plugin genuinely needs eval, Report-Only will show it as a violation before anything breaks.'
					)
				),

				// Tab bar. Basic view keeps Service Presets + Pending Review — the scan builds
				// the policy automatically (see runScan), and Pending Review is the safety net
				// for anything the scan didn't catch (a conditional script, a logged-in-only
				// page). Custom Sources and Site Scanner stay Advanced-only: raw-directive
				// editing and scan mechanics a non-technical owner has no use for once the
				// auto-scan has already run.
				h( 'div', { className: 'ts-tabbar' },
					( advanced
						? [
							[ 'presets',    'Service Presets' ],
							[ 'custom',     'Custom Sources' ],
							[ 'scan',       'Site Scanner' ],
							[ 'pending',    pendingCount > 0 ? 'Pending Review (' + pendingCount + ')' : 'Pending Review' ],
						]
						: [
							[ 'presets', 'Service Presets' ],
							[ 'pending', pendingCount > 0 ? 'Pending Review (' + pendingCount + ')' : 'Pending Review' ],
						]
					).map( ( [ key, label ] ) =>
						h( 'button', {
							key,
							type: 'button',
							className: 'ts-tab'
								+ ( tab === key ? ' ts-tab--active' : '' )
								+ ( key === 'pending' && pendingCount > 0 ? ' ts-tab--alert' : '' ),
							onClick: () => setTab( key ),
						}, label )
					)
				),

				// Presets grid. Basic view adds a scan-status strip above it — the grid itself is
				// the same component either way, just pre-checked by the scan in Basic instead
				// of starting empty.
				tab === 'presets' && h( 'div', { className: 'ts-csp-section' },
					! advanced && h( 'div', { className: 'ts-csp-autoscan', style: { marginBottom: '14px' } },
						h( 'p', { className: 'ts-muted', style: { marginBottom: '10px' } },
							'We scan your site to find the outside services it already uses — fonts, analytics, payment processors — and turn those on below automatically. Installed something new? Rescan any time.'
						),
						h( 'div', { style: { display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' } },
							h( Button, { variant: 'default', disabled: scanning, onClick: runScan },
								scanning ? 'Scanning…' : ( scan ? 'Rescan my site' : 'Scan my site' )
							),
							scan && scan.scanned_at && ! scanning && h( 'span', { className: 'ts-muted', style: { fontSize: '12px' } },
								'Last scanned ' + fmtTs( scan.scanned_at )
								+ ( ( scan.presets || [] ).length ? ` — found ${ scan.presets.length } service${ scan.presets.length > 1 ? 's' : '' }.` : ' — found nothing to add automatically.' )
							)
						),
						scanning && h( 'div', { className: 'ts-csp-scan-running', style: { marginTop: '10px' } },
							h( Spinner, null ),
							h( 'p', null, 'Scanning your site… this may take up to 15 seconds.' )
						)
					),
					h( 'p', { className: 'ts-muted', style: { marginBottom: '12px' } },
						'Enable presets for the third-party services your site uses. The WordPress preset is always included.'
					),
					h( 'div', { className: 'ts-csp-presets-grid' },
						presetList.map( ( p ) =>
							h( PresetTile, {
								key: p.slug,
								preset: p,
								active: presets.includes( p.slug ),
								onToggle: togglePreset,
							} )
						)
					)
				),

				// Custom directives.
				advanced && tab === 'custom' && h( 'div', { className: 'ts-csp-section' },
					h( 'p', { className: 'ts-muted', style: { marginBottom: '12px' } },
						'Add individual source values to any directive. Use for services not covered by presets.'
					),
					h( CustomDirectives, { custom, onChange: setCustom } )
				),

				// Site scanner.
				advanced && tab === 'scan' && h( 'div', { className: 'ts-csp-section' },
					h( 'h3', { className: 'ts-csp-section__title' }, 'Page Scan' ),
					h( 'div', { style: { display: 'flex', gap: '8px', marginBottom: '12px' } },
						h( Button, { variant: 'primary', disabled: scanning, onClick: runScan },
							scanning ? 'Scanning…' : 'Scan My Site'
						),
						h( 'span', { className: 'ts-muted', style: { alignSelf: 'center', fontSize: '12px' } },
							'Fetches your homepage and a few common pages to discover external resources.'
						)
					),
					h( ScanResults, {
						scan,
						enabledPresets: presets,
						onApplyPresets: applyScannedPresets,
						scanning,
					} ),

					h( 'h3', { className: 'ts-csp-section__title', style: { marginTop: '24px' } }, 'Codebase Scan' ),
					h( 'div', { style: { display: 'flex', gap: '8px', marginBottom: '12px' } },
						h( Button, { variant: 'secondary', disabled: codebaseScanning, onClick: runCodebaseScan },
							codebaseScanning ? 'Scanning files…' : 'Scan Plugin & Theme Files'
						),
						h( 'span', { className: 'ts-muted', style: { alignSelf: 'center', fontSize: '12px' } },
							'Reads PHP, JS, and CSS files to find CDN references that only appear in code.'
						)
					),
					codebaseScanning && h( 'div', { className: 'ts-csp-scan-running' },
						h( Spinner, null ),
						h( 'p', null, 'Scanning plugin and theme files… this may take 20–30 seconds.' )
					),
					! codebaseScanning && h( ScanResults, {
						scan: codebaseScan,
						enabledPresets: presets,
						onApplyPresets: applyScannedPresets,
						scanning: false,
					} )
				),

				// Pending-domain review — available in both views (see tab bar note above).
				tab === 'pending' && h( 'div', { className: 'ts-csp-section' },
					h( 'p', { className: 'ts-muted', style: { marginBottom: '12px' } },
						'External domains blocked by your CSP appear here. Approve to add them to your policy, or dismiss to keep them blocked.'
					),
					h( PendingReview, { onPolicyChanged: refreshAfterPolicyWrite } )
				),

				// Policy preview.
				h( 'div', { className: 'ts-csp-section' },
					h( 'h3', { className: 'ts-csp-section__title' }, 'Generated Header Preview' ),
					enabled && ! preview
						? h( 'p', { className: 'ts-muted', style: { fontSize: '12px', fontStyle: 'italic' } },
							'Preview will appear after you save the policy.'
						)
						: h( 'pre', { className: 'ts-csp-preview' },
							( enabled ? ( mode === 'enforce' ? 'Content-Security-Policy: ' : 'Content-Security-Policy-Report-Only: ' ) : '(CSP disabled)' ) +
							( enabled ? preview : '' )
						)
				)
			)
		),

		// Violation log always visible below.
		enabled && vlog && h( ViolationLog, { onPolicyChanged: refreshAfterPolicyWrite } )
	);
}
