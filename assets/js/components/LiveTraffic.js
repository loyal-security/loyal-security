/**
 * Live Traffic.
 *
 * Two-tab panel:
 *   1. Security Events — WAF/auth events only. Polls /logs/live every 5s, capped at 50 rows.
 *   2. All Traffic     — every HTTP request (not just blocked ones), from the Live Traffic
 *                        buffer (its size and whether it records at all are settings —
 *                        Settings → Live Traffic). The newest requests are shown live.
 *
 * Shared features on both tabs: color-coded rows, expandable row detail, block-IP, pause/resume.
 */
import { h, useState, useEffect, useRef, useCallback, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState } from './ui.js';
import { useStore } from '../store.js';

const POLL_MS  = 5000;
const MAX_ROWS = 50;
const MAX_ROWS_ALL = 100;

/* ─── helpers ──────────────────────────────────────────────────────────── */

export function trafficTone( severity ) {
	const s = Number( severity ) || 0;
	if ( s >= 40 ) return 'danger';
	if ( s >= 30 ) return 'warning';
	return 'info';
}

/** 'waf.block' → 'WAF › Block' */
export function formatEventType( type ) {
	if ( ! type ) return '—';
	return String( type )
		.split( '.' )
		.map( ( p ) => p.charAt( 0 ).toUpperCase() + p.slice( 1 ) )
		.join( ' › ' );
}

/** Extract country from an enriched event (may be a top-level field already). */
export function eventCountry( ev ) {
	if ( ev && ev.country ) return ev.country;
	let ctx = ev && ev.context;
	if ( typeof ctx === 'string' ) {
		try { ctx = JSON.parse( ctx ); } catch ( _ ) { ctx = null; }
	}
	if ( ctx && typeof ctx === 'object' ) {
		return ctx.country || ctx.country_code || ctx.geo || '';
	}
	return '';
}

/** UA type → badge tone. */
function uaTone( type ) {
	if ( type === 'scanner' ) return 'danger';
	if ( type === 'bot' )     return 'warning';
	if ( type === 'crawler' ) return 'info';
	if ( type === 'human' )   return 'success';
	return 'neutral';
}

/** Method badge colour. */
function methodTone( method ) {
	const m = ( method || '' ).toUpperCase();
	if ( m === 'POST' || m === 'PUT' || m === 'PATCH' ) return 'warning';
	if ( m === 'DELETE' ) return 'danger';
	return 'neutral';
}

function statusTone( code ) {
	const c = Number( code ) || 200;
	if ( c >= 500 ) return 'danger';
	if ( c >= 400 ) return 'warning';
	if ( c >= 300 ) return 'info';
	return 'success';
}

/* ─── Sub-components ─────────────────────────────────────────────────── */

function StatBar( { total, blocked, perMin, loading, totalLabel } ) {
	return h( 'div', { className: 'ts-traffic-statbar' },
		h( 'div', { className: 'ts-traffic-stat' },
			h( 'span', { className: 'ts-traffic-stat__value' }, loading ? '…' : total ),
			h( 'span', { className: 'ts-traffic-stat__label' }, totalLabel || 'Events (view)' )
		),
		h( 'div', { className: 'ts-traffic-stat ts-traffic-stat--danger' },
			h( 'span', { className: 'ts-traffic-stat__value' }, loading ? '…' : blocked ),
			h( 'span', { className: 'ts-traffic-stat__label' }, 'Blocked' )
		),
		h( 'div', { className: 'ts-traffic-stat ts-traffic-stat--info' },
			h( 'span', { className: 'ts-traffic-stat__value' }, loading ? '…' : perMin ),
			h( 'span', { className: 'ts-traffic-stat__label' }, 'Events/min' )
		)
	);
}

function FilterBar( { filters, onFilters, types } ) {
	const [ local, setLocal ] = useState( filters );

	const apply = () => onFilters( local );

	const set = ( key ) => ( e ) => setLocal( ( f ) => ( { ...f, [ key ]: e.target.value } ) );

	const onKey = ( e ) => {
		if ( e.key === 'Enter' ) apply();
	};

	return h( 'div', { className: 'ts-filters ts-traffic-filters' },
		h( 'input', {
			id: 'ts-traffic-filter-ip',
			name: 'traffic_filter_ip',
			type: 'text',
			placeholder: 'Filter by IP…',
			value: local.ip,
			onChange: set( 'ip' ),
			onKeyDown: onKey,
			className: 'ts-input ts-input--sm',
		} ),
		h( 'input', {
			id: 'ts-traffic-filter-search',
			name: 'traffic_filter_search',
			type: 'text',
			placeholder: 'Search URI / UA…',
			value: local.search,
			onChange: set( 'search' ),
			onKeyDown: onKey,
			className: 'ts-input ts-input--sm ts-input--wide',
		} ),
		types && h( 'select', {
			id: 'ts-traffic-filter-type',
			name: 'traffic_filter_type',
			value: local.type,
			onChange: ( e ) => { setLocal( ( f ) => ( { ...f, type: e.target.value } ) ); onFilters( { ...local, type: e.target.value } ); },
			className: 'ts-select ts-select--sm',
		},
			h( 'option', { value: '' }, 'All types' ),
			types.map( ( t ) => h( 'option', { key: t, value: t }, formatEventType( t ) ) )
		),
		h( Button, { variant: 'primary', onClick: apply }, 'Apply' ),
		h( Button, { variant: 'ghost', onClick: () => { const r = { ip: '', search: '', type: '' }; setLocal( r ); onFilters( r ); } }, 'Clear' )
	);
}

/** Expanded row: context details + block-IP + view-in-log actions (security events tab). */
function RowDetail( { ev, onBlock, blocking } ) {
	const ctx = typeof ev.context === 'object' ? ev.context : null;
	const country = eventCountry( ev );

	const logLink = '#/logs?ip=' + encodeURIComponent( ev.ip || '' );

	return h( 'div', { className: 'ts-incident' },
		h( 'dl', { className: 'ts-incident__grid' },
			ev.method && h( Fragment, null,
				h( 'div', { className: 'ts-incident__pair' },
					h( 'dt', null, 'Method' ),
					h( 'dd', null, h( Badge, { tone: methodTone( ev.method ) }, ev.method ) )
				)
			),
			country && h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Country' ),
				h( 'dd', null, country )
			),
			ev.ua_type && ev.ua_type !== 'unknown' && h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'UA Type' ),
				h( 'dd', null, h( Badge, { tone: uaTone( ev.ua_type ) }, ev.ua_type ) )
			),
			ev.ua_family && h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Browser/Client' ),
				h( 'dd', null, ev.ua_family )
			),
			ev.user_agent && h( 'div', { className: 'ts-incident__pair ts-incident__pair--full' },
				h( 'dt', null, 'User Agent' ),
				h( 'dd', { className: 'ts-muted', style: { fontSize: '12px', wordBreak: 'break-all' } }, ev.user_agent )
			),
			ctx && ctx.rule_id && h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Rule' ),
				h( 'dd', null, h( 'code', null, ctx.rule_id ) )
			),
			ctx && ctx.score && h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Score' ),
				h( 'dd', null, String( ctx.score ) )
			)
		),
		ctx && ctx.decoded_payload && h( 'div', { className: 'ts-incident__raw' },
			h( 'h4', null, 'Decoded attack payload' ),
			h( 'pre', null, typeof ctx.decoded_payload === 'string' ? ctx.decoded_payload : JSON.stringify( ctx.decoded_payload, null, 2 ) )
		),
		h( 'div', { className: 'ts-incident__actions' },
			ev.ip && h( Button, {
				variant: 'danger',
				disabled: blocking === ev.ip,
				onClick: () => onBlock( ev.ip ),
			}, blocking === ev.ip ? 'Blocking…' : '⛔ Block IP' ),
			ev.ip && h( 'a', {
				className: 'ts-btn ts-btn--ghost',
				href: logLink,
			}, '🔍 View in Audit Log' )
		)
	);
}

/** Expanded row: all-traffic tab. */
function AllTrafficRowDetail( { ev, onBlock, blocking } ) {
	const logLink = '#/logs?ip=' + encodeURIComponent( ev.ip || '' );

	return h( 'div', { className: 'ts-incident' },
		h( 'dl', { className: 'ts-incident__grid' },
			h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Method' ),
				h( 'dd', null, h( Badge, { tone: methodTone( ev.method ) }, ev.method || '—' ) )
			),
			h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'HTTP Status' ),
				h( 'dd', null, h( Badge, { tone: statusTone( ev.status ) }, String( ev.status || '—' ) ) )
			),
			ev.country && h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Country' ),
				h( 'dd', null, ev.country )
			),
			h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Client type' ),
				h( 'dd', null, h( Badge, { tone: uaTone( ev.ua_type ) }, ev.ua_type || 'unknown' ) )
			),
			ev.ua_family && h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Browser/Client' ),
				h( 'dd', null, ev.ua_family )
			),
			ev.referer && h( 'div', { className: 'ts-incident__pair ts-incident__pair--full' },
				h( 'dt', null, 'Referer' ),
				h( 'dd', { className: 'ts-muted', style: { fontSize: '12px', wordBreak: 'break-all' } }, ev.referer )
			),
			ev.rule_id && h( 'div', { className: 'ts-incident__pair' },
				h( 'dt', null, 'Matched rule' ),
				h( 'dd', null, h( 'code', null, ev.rule_id ), ev.rule_category ? ' (' + ev.rule_category + ')' : '' )
			),
			ev.decoded_payload && h( 'div', { className: 'ts-incident__pair ts-incident__pair--full' },
				h( 'dt', null, 'Payload' ),
				h( 'dd', null, h( 'code', { style: { fontSize: '12px', wordBreak: 'break-all' } }, typeof ev.decoded_payload === 'string' ? ev.decoded_payload : JSON.stringify( ev.decoded_payload ) ) )
			)
		),
		h( 'div', { className: 'ts-incident__actions' },
			ev.ip && h( Button, {
				variant: 'danger',
				disabled: blocking === ev.ip,
				onClick: () => onBlock( ev.ip ),
			}, blocking === ev.ip ? 'Blocking…' : '⛔ Block IP' ),
			ev.ip && h( 'a', { className: 'ts-btn ts-btn--ghost', href: logLink }, '🔍 View in Audit Log' )
		)
	);
}

/* ─── Security Events tab ─────────────────────────────────────────────── */

function SecurityEventsTab( { store } ) {
	const [ rows, setRows ]           = useState( [] );
	const [ loading, setLoading ]     = useState( true );
	const [ error, setError ]         = useState( null );
	const [ paused, setPaused ]       = useState( false );
	const [ expanded, setExpanded ]   = useState( null );
	const [ blocking, setBlocking ]   = useState( '' );
	const [ updatedAt, setUpdatedAt ] = useState( null );
	const [ summary, setSummary ]     = useState( null );
	const [ filters, setFilters ]     = useState( { ip: '', search: '', type: '' } );
	const [ types, setTypes ]         = useState( [] );

	const sinceRef    = useRef( 0 );
	const pausedRef   = useRef( false );
	const filtersRef  = useRef( filters );

	useEffect( () => { pausedRef.current = paused; }, [ paused ] );
	useEffect( () => { filtersRef.current = filters; }, [ filters ] );

	useEffect( () => {
		api.get( '/logs/types' ).then( setTypes ).catch( () => {} );
	}, [] );

	const refreshSummary = useCallback( () => {
		api.get( '/logs/summary', { window: 3600 } ).then( setSummary ).catch( () => {} );
	}, [] );

	useEffect( () => {
		refreshSummary();
		const id = setInterval( refreshSummary, 30000 );
		return () => clearInterval( id );
	}, [ refreshSummary ] );

	const poll = useCallback( async () => {
		if ( pausedRef.current ) return;
		const f = filtersRef.current;
		try {
			const params = { since: sinceRef.current, limit: MAX_ROWS };
			if ( f.ip )     params.ip     = f.ip;
			if ( f.search ) params.search = f.search;
			const data = await api.get( '/logs/live', params );
			const items = ( data && data.items ) || [];

			if ( items.length ) {
				setRows( ( prev ) => {
					const seen  = new Set( prev.map( ( r ) => r.id ) );
					const fresh = items.filter( ( r ) => ! seen.has( r.id ) && ( ! f.type || r.event_type === f.type ) );
					return [ ...fresh, ...prev ].slice( 0, MAX_ROWS );
				} );
				const maxId = items.reduce( ( m, r ) => Math.max( m, Number( r.id ) || 0 ), sinceRef.current );
				sinceRef.current = maxId;
			}
			setUpdatedAt( new Date() );
			setError( null );
		} catch ( e ) {
			setError( e.message );
		} finally {
			setLoading( false );
		}
	}, [] );

	useEffect( () => {
		poll();
		const id = setInterval( poll, POLL_MS );
		return () => clearInterval( id );
	}, [ poll ] );

	const toggle = () => {
		const next = ! paused;
		setPaused( next );
		if ( ! next ) poll();
	};

	const applyFilters = ( f ) => {
		setFilters( f );
		setRows( [] );
		sinceRef.current = 0;
		setLoading( true );
	};

	const blockIp = async ( ip ) => {
		if ( ! ip ) return;
		if ( ! window.confirm( 'Permanently block ' + ip + ' at the firewall?' ) ) return;
		setBlocking( ip );
		try {
			await api.post( '/traffic/block', { ip } );
			store.toast( 'Blocked ' + ip, 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBlocking( '' );
		}
	};

	const visibleRows = filters.type
		? rows.filter( ( r ) => r.event_type === filters.type )
		: rows;

	const blocked  = summary ? summary.blocked  : visibleRows.filter( ( r ) => ( r.severity || 0 ) >= 30 ).length;
	const perMin   = summary ? String( summary.req_per_min ) : '—';

	const actions = h( 'div', { style: { display: 'flex', gap: '8px', alignItems: 'center' } },
		h( 'span', { className: 'ts-muted', style: { fontSize: '12px' } },
			paused ? 'Paused' : '● Live',
			updatedAt && ! paused ? '  ' + updatedAt.toLocaleTimeString() : ''
		),
		h( Button, { variant: paused ? 'primary' : 'ghost', onClick: toggle },
			paused ? '▶ Resume' : '⏸ Pause'
		)
	);

	return h( Fragment, null,
		h( 'div', { className: 'ts-traffic-tabbar-actions' }, actions ),

		h( StatBar, {
			total:   visibleRows.length,
			blocked,
			perMin,
			loading: loading && ! rows.length,
		} ),

		h( FilterBar, { filters, onFilters: applyFilters, types } ),

		error && h( 'p', { className: 'ts-notice ts-notice--danger' }, 'Poll error: ' + error ),

		loading && ! rows.length
			? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
			: ! visibleRows.length
				? h( EmptyState, {
					icon: '📡',
					title: 'No security events in the last 24 hours',
					hint: 'This tab shows WAF blocks, brute-force attempts, geo-blocks, and login failures. Switch to All Traffic to see every visit, blocked or not.',
				} )
				: h( 'div', { className: 'ts-table-wrap' },
					h( 'table', { className: 'ts-table ts-table--traffic' },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'Time' ),
							h( 'th', null, 'Event' ),
							h( 'th', null, 'Sev' ),
							h( 'th', null, 'Method' ),
							h( 'th', null, 'IP' ),
							h( 'th', null, 'Country' ),
							h( 'th', { className: 'ts-col--uri' }, 'URI' ),
							h( 'th', null, '' )
						) ),
						h( 'tbody', null, visibleRows.map( ( ev ) => {
							const open  = expanded === ev.id;
							const tone  = trafficTone( ev.severity );
							const country = eventCountry( ev );
							const toggleRow = () => setExpanded( open ? null : ev.id );
							return h( Fragment, { key: ev.id },
								h( 'tr', {
									className: 'ts-row--clickable ts-row--' + tone,
									onClick: toggleRow,
									role: 'button',
									tabIndex: 0,
									'aria-expanded': open,
									onKeyDown: ( e ) => {
										if ( e.key === 'Enter' || e.key === ' ' ) {
											e.preventDefault();
											toggleRow();
										}
									},
								},
									h( 'td', { className: 'ts-muted ts-col--time' }, ev.created_at || '—' ),
									h( 'td', null, h( Badge, { tone }, formatEventType( ev.event_type ) ) ),
									h( 'td', null, h( Badge, { tone }, ev.severity_label || String( ev.severity ) ) ),
									h( 'td', null, ev.method
										? h( Badge, { tone: methodTone( ev.method ) }, ev.method )
										: '—'
									),
									h( 'td', { className: 'ts-col--ip' }, ev.ip || '—' ),
									h( 'td', null, country || '—' ),
									h( 'td', { className: 'ts-uri', title: ev.request_uri || '' }, ev.request_uri || '—' ),
									h( 'td', { className: 'ts-col--toggle', 'aria-hidden': 'true' }, open ? '−' : '+' )
								),
								open && h( 'tr', { className: 'ts-detail' },
									h( 'td', { colSpan: 8 },
										h( RowDetail, { ev, onBlock: blockIp, blocking } )
									)
								)
							);
						} ) )
					)
				)
	);
}

/* ─── All Traffic tab (free: capped, read-only depth) ─────────────────── */

function AllTrafficTab( { store } ) {
	const [ rows, setRows ]           = useState( [] );
	const [ loading, setLoading ]     = useState( true );
	const [ error, setError ]         = useState( null );
	const [ paused, setPaused ]       = useState( false );
	const [ expanded, setExpanded ]   = useState( null );
	const [ blocking, setBlocking ]   = useState( '' );
	const [ updatedAt, setUpdatedAt ] = useState( null );
	const [ summary, setSummary ]     = useState( null );
	const [ filters, setFilters ]     = useState( { ip: '', search: '' } );
	const [ captureOff, setCaptureOff ] = useState( false );

	const sinceRef   = useRef( 0 );
	const pausedRef  = useRef( false );
	const filtersRef = useRef( filters );

	useEffect( () => { pausedRef.current = paused; }, [ paused ] );
	useEffect( () => { filtersRef.current = filters; }, [ filters ] );

	useEffect( () => {
		api.get( '/traffic/summary', { window: 3600 } ).then( setSummary ).catch( () => {} );
		const tid = setInterval( () => { api.get( '/traffic/summary', { window: 3600 } ).then( setSummary ).catch( () => {} ); }, 30000 );
		return () => clearInterval( tid );
	}, [] );

	const poll = useCallback( async () => {
		if ( pausedRef.current ) return;
		const f = filtersRef.current;
		try {
			const data = await api.get( '/traffic/stream', {
				since:  sinceRef.current,
				limit:  MAX_ROWS_ALL,
				ip:     f.ip     || undefined,
				search: f.search || undefined,
			} );
			const items = ( data && data.items ) || [];
			setCaptureOff( !! ( data && data.capture_off ) );

			if ( items.length ) {
				setRows( ( prev ) => {
					const seen  = new Set( prev.map( ( r ) => r.id ) );
					const fresh = items.filter( ( r ) => ! seen.has( r.id ) );
					return [ ...fresh, ...prev ].slice( 0, MAX_ROWS_ALL );
				} );
				const maxTs = items.reduce( ( m, r ) => Math.max( m, Number( r.ts ) || 0 ), sinceRef.current );
				sinceRef.current = maxTs;
			}
			setUpdatedAt( new Date() );
			setError( null );
		} catch ( e ) {
			setError( e.message );
		} finally {
			setLoading( false );
		}
	}, [] );

	useEffect( () => {
		poll();
		const id = setInterval( poll, POLL_MS );
		return () => clearInterval( id );
	}, [ poll ] );

	const toggle = () => {
		const next = ! paused;
		setPaused( next );
		if ( ! next ) poll();
	};

	const applyFilters = ( f ) => {
		setFilters( f );
		setRows( [] );
		sinceRef.current = 0;
		setLoading( true );
	};

	const blockIp = async ( ip ) => {
		if ( ! ip ) return;
		if ( ! window.confirm( 'Permanently block ' + ip + ' at the firewall?' ) ) return;
		setBlocking( ip );
		try {
			await api.post( '/traffic/block', { ip } );
			store.toast( 'Blocked ' + ip, 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBlocking( '' );
		}
	};

	const blocked = summary ? summary.blocked : 0;
	const perMin  = summary ? String( summary.req_per_min ) : '—';

	const actions = h( 'div', { style: { display: 'flex', gap: '8px', alignItems: 'center' } },
		h( 'span', { className: 'ts-muted', style: { fontSize: '12px' } },
			paused ? 'Paused' : '● Live',
			updatedAt && ! paused ? '  ' + updatedAt.toLocaleTimeString() : ''
		),
		h( Button, { variant: paused ? 'primary' : 'ghost', onClick: toggle },
			paused ? '▶ Resume' : '⏸ Pause'
		)
	);

	return h( Fragment, null,
		h( 'div', { className: 'ts-traffic-tabbar-actions' }, actions ),

		h( StatBar, {
			total: rows.length,
			blocked,
			perMin,
			loading: loading && ! rows.length,
			totalLabel: 'Requests (last ' + MAX_ROWS_ALL + ')',
		} ),

		h( FilterBar, { filters, onFilters: applyFilters, types: null } ),

		error && h( 'p', { className: 'ts-notice ts-notice--danger' }, 'Poll error: ' + error ),

		loading && ! rows.length
			? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
			: ! rows.length
				? h( EmptyState, {
					icon: '📡',
					title: captureOff ? 'Recording all traffic is off' : 'No traffic yet',
					hint: captureOff
						? 'Turn on “Capture All” under Settings → Live Traffic to record every request here.'
						: 'Every visit — human or bot, allowed or blocked — will appear here as it arrives.',
				} )
				: h( 'div', null,
					h( 'div', { className: 'ts-table-wrap' },
						h( 'table', { className: 'ts-table ts-table--traffic' },
							h( 'thead', null, h( 'tr', null,
								h( 'th', null, 'Time' ),
								h( 'th', null, 'Method' ),
								h( 'th', null, 'Status' ),
								h( 'th', null, 'IP' ),
								h( 'th', null, 'Country' ),
								h( 'th', null, 'Client' ),
								h( 'th', null, 'Event' ),
								h( 'th', { className: 'ts-col--uri' }, 'URI' ),
								h( 'th', null, '' )
							) ),
							h( 'tbody', null, rows.map( ( ev ) => {
								const key  = ev.id || ( ev.ts + ev.ip + ev.uri );
								const open = expanded === key;
								const tone = ev.severity >= 40 ? 'danger' : ev.severity >= 30 ? 'warning' : 'neutral';
								const isBlocked = ev.event_type && ev.event_type !== 'request.normal';
								const toggleRow = () => setExpanded( open ? null : key );
								return h( Fragment, { key },
									h( 'tr', {
										className: 'ts-row--clickable' + ( isBlocked ? ' ts-row--' + tone : '' ),
										onClick: toggleRow,
										role: 'button',
										tabIndex: 0,
										'aria-expanded': open,
										onKeyDown: ( e ) => {
											if ( e.key === 'Enter' || e.key === ' ' ) {
												e.preventDefault();
												toggleRow();
											}
										},
									},
										h( 'td', { className: 'ts-muted ts-col--time' }, ev.ts ? new Date( ev.ts * 1000 ).toLocaleTimeString() : '—' ),
										h( 'td', null, ev.method ? h( Badge, { tone: methodTone( ev.method ) }, ev.method ) : '—' ),
										h( 'td', null, ev.status ? h( Badge, { tone: statusTone( ev.status ) }, String( ev.status ) ) : '—' ),
										h( 'td', { className: 'ts-col--ip' }, ev.ip || '—' ),
										h( 'td', null, ev.country || '—' ),
										h( 'td', null, ev.ua_type && ev.ua_type !== 'unknown'
											? h( Badge, { tone: uaTone( ev.ua_type ) }, ev.ua_type )
											: ( ev.ua_family || '—' )
										),
										h( 'td', null, isBlocked
											? h( Badge, { tone }, formatEventType( ev.event_type ) )
											: h( 'span', { className: 'ts-muted' }, 'Normal' )
										),
										h( 'td', { className: 'ts-uri', title: ev.uri || '' }, ev.uri || '—' ),
										h( 'td', { className: 'ts-col--toggle' }, open ? '−' : '+' )
									),
									open && h( 'tr', { className: 'ts-detail' },
										h( 'td', { colSpan: 9 },
											h( AllTrafficRowDetail, { ev, onBlock: blockIp, blocking } )
										)
									)
								);
							} ) )
						)
					),
					h( 'p', { className: 'ts-muted', style: { fontSize: '11px', marginTop: '8px', padding: '0 4px' } },
						'Showing the newest ' + MAX_ROWS_ALL + ' requests, live. How many requests are kept is set by “Buffer Size” under Settings → Live Traffic.'
					)
				)
	);
}

/* ─── Main component ─────────────────────────────────────────────────── */

export function LiveTraffic() {
	const store = useStore();
	const [ tab, setTab ] = useState( 'security' );

	const TABS = [
		{ key: 'security', label: '🛡 Security Events' },
		{ key: 'all',      label: '📡 All Traffic' },
	];

	return h( Card, {
		title: 'Live Traffic',
		actions: h( 'div', { className: 'ts-tabs' },
			TABS.map( ( t ) => h( 'button', {
				key: t.key,
				type: 'button',
				className: 'ts-tab' + ( tab === t.key ? ' is-active' : '' ),
				onClick: () => setTab( t.key ),
			}, t.label ) )
		),
	},
		tab === 'security'
			? h( SecurityEventsTab, { store } )
			: h( AllTrafficTab, { store } )
	);
}
