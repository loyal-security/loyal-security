/**
 * Audit log panel — filterable, paginated event table with CSV export.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api, saveFile } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState, severityTone, ScrollPanel } from './ui.js';
import { describeEvent, incidentDetails, attackMatches, severityLabel, eventTypeMeta } from '../events.js';
import { useStore } from '../store.js';

/** Read a filter param from the URL hash (e.g. #/logs?ip=1.2.3.4 or
 *  #/logs?search=cleanup_abc123&type=incident.quarantine.add) so deep links from other panels —
 *  Live Traffic's "View in Audit Log", the cleanup-run tiles — can pre-filter this panel. */
function paramFromHash( name ) {
	try {
		const hash  = window.location.hash || '';
		const query = hash.split( '?' )[ 1 ] || '';
		return new URLSearchParams( query ).get( name ) || '';
	} catch ( _ ) {
		return '';
	}
}
const ipFromHash     = () => paramFromHash( 'ip' );
const typeFromHash   = () => paramFromHash( 'type' );
const searchFromHash = () => paramFromHash( 'search' );

export function LogTable() {
	const store = useStore();
	const [ data, setData ] = useState( null );
	const [ types, setTypes ] = useState( [] );
	const [ loading, setLoading ] = useState( true );
	const [ error, setError ] = useState( null );
	const [ expanded, setExpanded ] = useState( null );
	const [ logins, setLogins ] = useState( [] );
	const [ banning, setBanning ] = useState( '' );
	const [ filters, setFilters ] = useState( () => ( {
		search: searchFromHash(), type: typeFromHash(), ip: ipFromHash(), country: '', min_severity: 0, page: 1, per_page: 50,
	} ) );

	// On failure this MUST NOT leave `data` untouched and fall through to the "No events" empty
	// state below — on a security audit log, a failed request silently rendering as "nothing to
	// see here" is a false all-clear, not a harmless empty list.
	const load = async ( f ) => {
		setLoading( true );
		try {
			const params = { ...f };
			Object.keys( params ).forEach( ( k ) => {
				if ( params[ k ] === '' || params[ k ] === 0 ) delete params[ k ];
			} );
			setData( await api.get( '/logs', params ) );
			setError( null );
		} catch ( e ) {
			setError( e.message || 'Failed to load the audit log.' );
		} finally {
			setLoading( false );
		}
	};

	// While already on this panel, pick up new ?ip=/?type=/?search= params from another deep
	// link (Live Traffic's "View in Audit Log", the cleanup-run tiles) without a full remount.
	useEffect( () => {
		const onHash = () => {
			const ip     = ipFromHash();
			const type   = typeFromHash();
			const search = searchFromHash();
			if ( ip || type || search ) {
				setFilters( ( f ) => ( { ...f, ip: ip || f.ip, type: type || f.type, search: search || f.search, page: 1 } ) );
			}
		};
		window.addEventListener( 'hashchange', onHash );
		return () => window.removeEventListener( 'hashchange', onHash );
	}, [] );

	useEffect( () => {
		api.get( '/logs/types' ).then( setTypes ).catch( () => {} );
		api.get( '/logs/login-activity' ).then( ( d ) => setLogins( d.items || [] ) ).catch( () => {} );
	}, [] );

	useEffect( () => {
		load( filters );
	}, [ filters.type, filters.min_severity, filters.ip, filters.page, filters.per_page ] );

	// Force an immediate reload with the current filters (not just a state update): the
	// auto-reload effect below only fires when type/min_severity/ip/page/per_page change, so
	// relying on setFilters() alone silently does nothing when "Search" is clicked while already
	// on page 1 (the common case) — the search box's text would never actually be queried.
	const apply = () => {
		const next = { ...filters, page: 1 };
		setFilters( next );
		load( next );
	};

	// Same reasoning as apply(): filters not in the auto-reload effect's dependency list
	// (search, country) would silently keep showing the old results if Clear only called
	// setFilters() — the effect wouldn't re-fire when the *other* filters were already empty.
	const clear = () => {
		const next = { search: '', type: '', ip: '', country: '', min_severity: 0, page: 1, per_page: 50 };
		setFilters( next );
		load( next );
	};

	const banIp = async ( ip ) => {
		if ( ! ip || ! window.confirm( 'Permanently block ' + ip + '?' ) ) return;
		setBanning( ip );
		try {
			await api.post( '/traffic/block', { ip } );
			store.toast( 'Blocked ' + ip, 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBanning( '' );
		}
	};

	const [ exporting, setExporting ] = useState( false );
	const exportCsv = async () => {
		setExporting( true );
		try {
			const file = await api.get( '/logs/export', {
				search:       filters.search       || '',
				type:         filters.type         || '',
				ip:           filters.ip           || '',
				country:      filters.country      || '',
				min_severity: filters.min_severity || 0,
			} );
			saveFile( file.filename, file.content, file.mime || 'text/csv' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setExporting( false );
		}
	};

	const totalPages = data ? Math.max( 1, Math.ceil( data.total / data.per_page ) ) : 1;

	return h(
		Fragment,
		null,
		h( LoginActivity, { items: logins } ),
		h(
		Card,
		{
			title: 'Audit Log',
			actions: h( 'button', { type: 'button', className: 'ts-btn', onClick: exportCsv, disabled: exporting }, exporting ? 'Exporting…' : 'Export CSV' ),
		},
		h(
			'div',
			{ className: 'ts-filters' },
			h( 'input', {
				id: 'ts-log-search', name: 'log_search',
				type: 'text', placeholder: 'Search URI, UA, context…', value: filters.search,
				onChange: ( e ) => setFilters( { ...filters, search: e.target.value } ),
				onKeyDown: ( e ) => e.key === 'Enter' && apply(),
			} ),
			h( 'input', {
				id: 'ts-log-ip', name: 'log_ip',
				type: 'text', placeholder: 'Filter by IP…', value: filters.ip || '',
				style: { width: '140px' },
				onChange: ( e ) => setFilters( { ...filters, ip: e.target.value, page: 1 } ),
				onKeyDown: ( e ) => e.key === 'Enter' && apply(),
			} ),
			h( 'input', {
				id: 'ts-log-country', name: 'log_country',
				type: 'text', placeholder: 'Country (US, DE…)', value: filters.country || '',
				style: { width: '140px' },
				onChange: ( e ) => setFilters( { ...filters, country: e.target.value.toUpperCase() } ),
				onKeyDown: ( e ) => e.key === 'Enter' && apply(),
			} ),
			h( 'select', { id: 'ts-log-type', name: 'log_type', value: filters.type, onChange: ( e ) => setFilters( { ...filters, type: e.target.value, page: 1 } ) },
				h( 'option', { value: '' }, 'All types' ),
				// A deep link (e.g. the cleanup-run tiles) can preselect several comma-joined
				// types at once — inject a matching option so the dropdown shows that it's
				// filtered instead of silently falling back to "All types".
				filters.type && filters.type.includes( ',' ) && h(
					'option',
					{ value: filters.type },
					`Filtered (${ filters.type.split( ',' ).length } types)`
				),
				types.map( ( t ) => h( 'option', { key: t, value: t }, eventTypeMeta( t ).label ) )
			),
			h( 'select', { id: 'ts-log-severity', name: 'log_min_severity', value: filters.min_severity, onChange: ( e ) => setFilters( { ...filters, min_severity: Number( e.target.value ), page: 1 } ) },
				h( 'option', { value: 0 }, 'Any severity' ),
				h( 'option', { value: 20 }, 'Notice+' ),
				h( 'option', { value: 30 }, 'Warning+' ),
				h( 'option', { value: 40 }, 'Critical' )
			),
			h( Button, { variant: 'primary', onClick: apply }, 'Search' ),
			( filters.ip || filters.search || filters.type || filters.country || filters.min_severity ) && h( Button, {
				variant: 'ghost',
				onClick: clear,
			}, 'Clear' )
		),

		loading && ! data ? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
			: error ? h( 'div', { className: 'ts-notice ts-notice--danger', style: { display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'space-between' } },
				h( 'span', null, '⚠️ Could not load the audit log: ' + error ),
				h( Button, { variant: 'ghost', onClick: () => load( filters ) }, 'Retry' )
			)
			: ! data || ! data.items.length ? h( EmptyState, { icon: '📜', title: 'No events', hint: 'Nothing matches these filters yet.' } )
			: h( Fragment, null,
				h( ScrollPanel, { maxHeight: '520px' },
				h( 'table', { className: 'ts-table' },
					h( 'thead', null, h( 'tr', null,
						h( 'th', null, 'Time' ), h( 'th', null, 'Type' ), h( 'th', null, 'Sev' ),
						h( 'th', null, 'User' ), h( 'th', null, 'IP' ), h( 'th', null, 'Country' ), h( 'th', null, 'URI' ), h( 'th', null, '' )
					) ),
					h( 'tbody', null, data.items.map( ( ev ) => {
						const d = describeEvent( ev );
						return h( Fragment, { key: ev.id },
							h( 'tr', null,
								h( 'td', null, ev.created_at ),
								h( 'td', null,
									h( 'div', { className: 'ts-evt' },
										h( 'span', { className: 'ts-evt__icon', 'aria-hidden': 'true' }, d.icon ),
										h( 'span', { className: 'ts-evt__text' },
											h( 'span', { className: 'ts-evt__title' }, d.title ),
											h( 'code', { className: 'ts-evt__code' }, ev.event_type )
										)
									)
								),
								h( 'td', null, h( Badge, { tone: severityTone( ev.severity ) }, severityLabel( ev.severity ) ) ),
								h( 'td', null, ev.user_id || '—' ),
								h( 'td', null, ev.ip || '—' ),
								h( 'td', null, ev.country || '—' ),
								h( 'td', { className: 'ts-uri', title: ev.request_uri || '' }, ev.request_uri || '—' ),
								h( 'td', { style: { display: 'flex', gap: '4px' } },
									ev.ip && h( Button, {
										variant: 'ghost', title: 'Ban this IP',
										disabled: banning === ev.ip,
										onClick: () => banIp( ev.ip ),
									}, banning === ev.ip ? '…' : '⛔' ),
									h( Button, { variant: 'ghost', onClick: () => setExpanded( expanded === ev.id ? null : ev.id ) }, expanded === ev.id ? '−' : '+' )
								)
							),
							expanded === ev.id && h( 'tr', { className: 'ts-detail' },
								h( 'td', { colSpan: 8 }, h( IncidentDetail, { event: ev, summary: d.summary } ) )
							)
						);
					} ) )
				)
				),
				h( 'div', { className: 'ts-pager' },
					h( Button, { disabled: data.page <= 1, onClick: () => setFilters( { ...filters, page: data.page - 1 } ) }, '‹ Prev' ),
					h( 'span', null, `Page ${ data.page } / ${ totalPages } · ${ data.total } events` ),
					h( Button, { disabled: data.page >= totalPages, onClick: () => setFilters( { ...filters, page: data.page + 1 } ) }, 'Next ›' )
				)
			)
		)
	);
}

/**
 * Compact timeline of the most recent login events (success / failure / blocked) with a
 * coloured status dot. Free feature surfaced at the top of the Logs panel.
 */
function LoginActivity( { items } ) {
	if ( ! items || ! items.length ) {
		return null;
	}

	const isSuccess = ( type ) => type === 'auth.login.success';
	const label = ( type ) => isSuccess( type ) ? 'Success' : ( type === 'auth.login.blocked' ? 'Blocked' : 'Failed' );

	return h(
		Card,
		{ title: 'Login Activity' },
		h( 'ul', { className: 'ts-timeline' },
			items.map( ( ev, i ) => h( 'li', { key: i, className: 'ts-timeline__item' },
				h( 'span', {
					className: 'ts-dot ' + ( isSuccess( ev.type ) ? 'ts-dot--ok' : 'ts-dot--bad' ),
					'aria-hidden': 'true',
				} ),
				h( 'span', { className: 'ts-timeline__user' }, ev.username || '—' ),
				h( 'span', { className: 'ts-muted' }, ' @ ' ),
				h( 'span', { className: 'ts-timeline__ip' }, ev.ip || '—' ),
				h( Badge, { tone: isSuccess( ev.type ) ? 'success' : 'danger' }, label( ev.type ) ),
				h( 'span', { className: 'ts-muted ts-timeline__time' }, ev.created_at || '' )
			) )
		)
	);
}

/**
 * Expanded incident report for one audit-log row: a plain-language summary, structured
 * details, the signature matches behind a WAF block, and the raw payload for power users.
 */
function IncidentDetail( { event: ev, summary } ) {
	const details = incidentDetails( ev );
	const matches = attackMatches( ev );
	const ruleId  = ev.context && ( ev.context.rule_id || ev.context.rule );

	return h(
		'div',
		{ className: 'ts-incident' },
		summary && h( 'p', { className: 'ts-incident__summary' }, summary ),
		ruleId && h( 'p', null,
			h( 'a', { href: '#/firewall' }, '🛡️ View suggested virtual patches for rule ' + ruleId + ' →' )
		),
		details.length
			? h(
					'dl',
					{ className: 'ts-incident__grid' },
					details.map( ( row, i ) =>
						h( 'div', { key: i, className: 'ts-incident__pair' },
							h( 'dt', null, row.label ),
							h( 'dd', null, row.value )
						)
					)
			  )
			: null,
		matches.length
			? h(
					'div',
					{ className: 'ts-incident__matches' },
					h( 'h4', null, 'Why it was flagged' ),
					h( 'table', { className: 'ts-table' },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'Rule' ),
							h( 'th', null, 'Type' ),
							h( 'th', null, 'Found in' ),
							h( 'th', null, 'Score' ),
							h( 'th', null, 'Detail' )
						) ),
						h( 'tbody', null, matches.map( ( m, i ) =>
							h( 'tr', { key: i },
								h( 'td', null, h( 'code', null, m.rule ) ),
								h( 'td', null, m.category ),
								h( 'td', null, m.where ),
								h( 'td', null, String( m.score ) ),
								h( 'td', null, m.desc )
							)
						) )
					)
			  )
			: null,
		h( 'details', { className: 'ts-incident__raw' },
			h( 'summary', null, 'Raw event data' ),
			h( 'pre', null, JSON.stringify( { ua: ev.user_agent, method: ev.method, context: ev.context, proxy: ev.proxy_headers }, null, 2 ) )
		)
	);
}
