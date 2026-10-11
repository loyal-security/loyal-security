/**
 * Threat Intelligence panel — feed status and CVE vulnerability table.
 *
 * Every site gets every dataset and the vulnerability scanner; updates arrive twice a day, or
 * hourly with a Loyal Security Pro subscription to the feed service.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState, LoadError, severityTone } from './ui.js';
import { useStore } from '../store.js';
import { usePaged, ListSearch, matchesQuery } from './PaginatedList.js';

export function ThreatIntelPanel() {
	const store = useStore();
	const [ status, setStatus ]     = useState( null );
	const [ statusError, setStatusError ] = useState( null );
	const [ vulns, setVulns ]       = useState( null );
	const [ vulnsError, setVulnsError ] = useState( null );
	const [ syncing, setSyncing ]       = useState( false );
	const [ conn, setConn ]             = useState( null );
	const [ testing, setTesting ]       = useState( false );
	const [ registering, setRegistering ] = useState( false );

	const loadStatus = () =>
		api.get( '/threatintel/status' )
			.then( ( d ) => { setStatus( d ); setStatusError( null ); } )
			.catch( ( e ) => {
				store.toast( e.message, 'error' );
				setStatusError( e.message || 'Failed to load feed status.' );
			} );

	const loadVulns = () =>
		api.get( '/threatintel/vulnerabilities' )
			.then( ( d ) => { setVulns( d ); setVulnsError( null ); } )
			.catch( ( e ) => {
				store.toast( e.message, 'error' );
				setVulnsError( e.message || 'Failed to load vulnerabilities.' );
			} );

	useEffect( () => {
		loadStatus();
		loadVulns();
	}, [] );

	const sync = async () => {
		setSyncing( true );
		try {
			const s = await api.post( '/threatintel/sync', {} );
			setStatus( s );

			const result = s.sync_result || {};
			const errorDatasets = Object.keys( result.errors || {} );
			if ( result.synced ) {
				store.toast( 'Feed synced — new rules downloaded.', 'success' );
			} else if ( errorDatasets.length > 0 ) {
				store.toast( 'Sync failed for: ' + errorDatasets.join( ', ' ) + '.', 'error' );
			} else {
				store.toast( 'Already up to date — no new signatures available from the feed right now.', 'info' );
			}

			loadVulns();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setSyncing( false );
		}
	};

	const runConnectionTest = async () => {
		setTesting( true );
		try {
			const res = await api.post( '/threatintel/connection-test', {} );
			setConn( res );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setTesting( false );
		}
	};

	/**
	 * Grant bypass-telemetry consent (if not already given) and register this install with
	 * LicenseKit right now — the same action available on the Bypass Telemetry settings screen,
	 * surfaced here too since this is where the operator sees "Install recognized" fail.
	 */
	const registerInstall = async () => {
		setRegistering( true );
		try {
			// force: true — discards any existing local secret first. Without it, a stale/orphaned
			// secret (e.g. the server-side record was lost) makes this button a silent no-op
			// forever, since ensure_secret() short-circuits once ANY non-empty secret is stored
			// locally, regardless of whether the server still recognizes it.
			const res = await api.post( '/telemetry/consent', { accepted: true, force: true } );
			store.toast( res.registered ? 'Registered with LicenseKit.' : 'Consent granted, but registration failed — try again shortly.', res.registered ? 'success' : 'error' );
			await runConnectionTest();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setRegistering( false );
		}
	};

	if ( ! status ) {
		if ( statusError ) {
			return h( Card, { title: 'Threat Intelligence' }, h( LoadError, { message: statusError, onRetry: loadStatus } ) );
		}
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	const isPro    = status.tier === 'pro';
	const channel  = status.channel || 'free';
	const lastSync = status.last_sync || '—';
	const versions = status.feed_versions || {};

	return h( Fragment, null,

		/* Status card */
		h( Card, {
			title: 'Threat Intelligence Feed',
			actions: h( 'div', { style: { display: 'flex', gap: '8px', alignItems: 'center' } },
				h( Button, {
					variant: 'ghost',
					disabled: testing,
					onClick: runConnectionTest,
					title: 'Check that this site can reach LicenseKit and is authenticated correctly',
				}, testing ? 'Testing…' : 'Test connection' ),
				h( Button, {
					variant: 'primary',
					disabled: syncing,
					onClick: sync,
				}, syncing ? 'Syncing…' : 'Sync now' ),
			),
		},
			h( 'div', { className: 'ts-tiles' },
				h( StatusTile, { label: 'Channel', value: channel.toUpperCase(),
					tone: isPro ? 'success' : 'neutral' } ),
				h( StatusTile, { label: 'Last sync', value: lastSync } ),
				h( StatusTile, { label: 'WAF rules', value: versions.waf || '—' } ),
				h( StatusTile, { label: 'Malware sigs', value: versions.malware || '—' } ),
				h( StatusTile, { label: 'Patches', value: versions.patches || '—' } ),
				h( StatusTile, { label: 'CVE DB', value: versions.cve || '—' } ),
			)
		),

		/* Connection self-test result (only after the operator runs it) */
		conn && h( ConnectionTestCard, { conn, onRegister: registerInstall, registering } ),

		/* Patch-gap protection (early virtual patching) */
		h( PatchGapCard, { patchGap: status.patch_gap } ),

		/* The feed service delivers updates twice a day; a Pro subscription makes it hourly. */
		! isPro && h( Card, { title: 'Hourly updates with Pro' },
			h( 'p', { style: { marginBottom: '12px' } },
				'This site receives firewall, malware and vulnerability data twice a day. A Pro subscription to the feed service delivers the same updates ',
				h( 'strong', null, 'every hour' ),
				'.'
			),
			h( 'a', { href: '#/upgrade', className: 'ts-btn' }, 'See upgrade options →' )
		),

		/* Vulnerability status summary */
		h( VulnerabilityStatusCard, { vulns, isPro, lastSync } ),

		/* Vulnerabilities table */
		h( VulnerabilitiesCard, { vulns, vulnsError, onRetry: loadVulns, isPro, store } )
	);
}

/**
 * Renders the LicenseKit connection self-test: liveness + the /diagnostics report, translated
 * into a pass/fail line per link (reachability, install, signature, license) with the exact fix
 * for whatever is wrong — mirrors the symptom→fix table in docs/plugin-integration.md §6.
 */
function ConnectionTestCard( { conn, onRegister, registering } ) {
	const d = conn.diagnostics || null;
	const reachable = !! ( conn.health && conn.health.ok );
	const needsRegister = !! ( d && d.install && ! d.install.registered );

	// Overall verdict.
	const chainOk = reachable && d &&
		d.install && d.install.registered &&
		( d.signature === 'valid' || d.signature === 'missing' );

	const rows = [];
	const row = ( ok, label, detail ) => rows.push(
		h( 'li', { key: label, className: 'ts-modlist__item' },
			h( 'span', null,
				h( 'span', { style: { marginRight: '6px' } }, ok ? '✅' : ( ok === null ? '➖' : '❌' ) ),
				label
			),
			detail && h( 'span', { className: 'ts-muted', style: { fontSize: '12px' } }, detail )
		)
	);

	row( reachable, 'Reachable', reachable ? ( conn.base || '' ) : ( conn.error === 'not_configured' ? 'No API base configured' : 'Cannot reach ' + ( conn.base || 'server' ) ) );

	if ( d ) {
		const inst = d.install || {};
		row( !! inst.recognized, 'Install recognized', inst.registered ? 'HMAC secret registered' : 'Call telemetry/register (grant consent)' );

		const sigOk = d.signature === 'valid' ? true : ( d.signature === 'missing' ? null : false );
		row( sigOk, 'Signature: ' + ( d.signature || '—' ), sigInterpretation( d.signature ) );

		const lic = d.license || {};
		const tier = lic.tier || 'free';
		row( tier === 'pro', 'License tier: ' + tier, tier === 'pro' ? '' : 'Free/unknown — check the X-LoyalSec-License hash or plan' );

		const skew = Math.abs( Number( d.clock_skew_seconds || 0 ) );
		row( skew < 300, 'Clock skew: ' + ( d.clock_skew_seconds ?? '?' ) + 's', skew < 300 ? '' : 'Fix server NTP — reputation will reject as stale' );

		if ( d.require_hmac ) {
			row( d.signature === 'valid', 'HMAC enforced by server', d.signature === 'valid' ? '' : 'Server now requires a valid signature' );
		}
	}

	return h( Card, {
		title: '🔌 LicenseKit connection test',
		actions: h( Badge, { tone: chainOk ? 'success' : 'danger' }, chainOk ? 'Wired correctly' : 'Needs attention' ),
	},
		! d && ! reachable && h( 'p', { className: 'ts-notice ts-notice--danger' },
			'Could not reach LicenseKit. Check the API base URL and that the site has outbound network access.' ),
		h( 'ul', { className: 'ts-modlist' }, rows ),
		needsRegister && h( 'div', { className: 'ts-actions-row', style: { marginTop: '8px' } },
			h( Button, {
				variant: 'secondary',
				disabled: !! registering,
				onClick: onRegister,
				title: 'Grants bypass-telemetry consent (if not already given) and registers this install with LicenseKit for a signed HMAC secret',
			}, registering ? 'Registering…' : 'Grant consent & register' )
		)
	);
}

function sigInterpretation( sig ) {
	switch ( sig ) {
		case 'valid':               return '';
		case 'missing':             return 'Unsigned (accepted until server cutover)';
		case 'no_secret_on_server': return 'Register first, then sign with the returned secret';
		case 'invalid':             return 'HMAC wrong — sign the exact raw body bytes';
		default:                    return '';
	}
}

/**
 * Early virtual patching (patch-gap protection): plugins that shipped a security fix the site
 * has not installed yet, but which are already shielded by a virtual patch from the feed.
 */
function PatchGapCard( { patchGap } ) {
	const items = ( patchGap && patchGap.items ) || [];
	const count = ( patchGap && patchGap.count ) || 0;

	return h( Card, {
		title: '🛡️ Early Virtual Patching',
		actions: h( Badge, { tone: count ? 'warning' : 'success' },
			count ? count + ' shielded' : 'none active' ),
	},
		h( 'p', { className: 'ts-muted', style: { marginTop: 0 } },
			'When a plugin releases a security fix, the feed can deploy a virtual patch that ',
			'protects this site during the gap before you update. These plugins are shielded now — ',
			'update them when convenient to remove the vulnerable code entirely.'
		),
		count === 0
			? h( 'p', { className: 'ts-notice ts-notice--success' },
				'✅ No installed plugin is currently in a patch gap.' )
			: h( 'table', { className: 'ts-table' },
				h( 'thead', null, h( 'tr', null,
					h( 'th', null, 'Plugin' ),
					h( 'th', null, 'Installed' ),
					h( 'th', null, 'Fixed in' ),
					h( 'th', null, 'Issue' ),
					h( 'th', null, 'Confidence' ),
				) ),
				h( 'tbody', null, items.map( ( p ) =>
					h( 'tr', { key: p.rule_id || p.slug },
						h( 'td', null,
							h( 'div', null, p.name || p.slug ),
							p.detected_at && h( 'div', { style: { fontSize: '11px', opacity: '.7' } },
								'detected ' + p.detected_at )
						),
						h( 'td', null, p.installed_version || '—' ),
						h( 'td', null, p.version_to ? p.version_to : '—' ),
						h( 'td', null,
							h( 'span', null, patchGapTypeLabel( p.vulnerability_type ) ),
							p.summary && h( 'div', { style: { fontSize: '11px', opacity: '.7' } }, p.summary )
						),
						h( 'td', null, patchGapConfidence( p.confidence ) )
					)
				) )
			)
	);
}

function patchGapTypeLabel( t ) {
	if ( ! t ) return 'Security fix';
	return String( t ).replace( /_/g, ' ' ).replace( /\b\w/g, ( c ) => c.toUpperCase() );
}

function patchGapConfidence( c ) {
	if ( c === null || c === undefined || isNaN( Number( c ) ) ) return '—';
	const pct = Math.round( Number( c ) * 100 );
	const tone = pct >= 85 ? 'success' : ( pct >= 50 ? 'warning' : 'neutral' );
	return h( Badge, { tone }, pct + '%' );
}

/**
 * At-a-glance vulnerability posture: open finding count, last scan date, a feed-quality banner
 * (community vs. real-time CVE), and the three most recent CVE findings with severity badges.
 */
function VulnerabilityStatusCard( { vulns, isPro, lastSync } ) {
	const items   = ( vulns && vulns.vulnerabilities ) || [];
	const openCnt = items.length;
	// Most recent first when a date is available, otherwise preserve feed order.
	const recent  = items
		.slice()
		.sort( ( a, b ) => vulnTime( b ) - vulnTime( a ) )
		.slice( 0, 3 );

	return h( Card, {
		title: 'Vulnerability Status',
		actions: h( Badge, { tone: openCnt ? 'danger' : 'success' }, openCnt + ' open' ),
	},
		h( 'div', { className: 'ts-tiles' },
			h( 'div', { className: 'ts-tile' },
				h( 'div', { className: 'ts-tile__value' }, openCnt ),
				h( 'div', { className: 'ts-tile__label' }, 'Open vulnerabilities' )
			),
			h( 'div', { className: 'ts-tile' },
				h( 'div', { className: 'ts-tile__value', style: { fontSize: '14px' } }, lastSync || '—' ),
				h( 'div', { className: 'ts-tile__label' }, 'Last scan' )
			)
		),

		isPro
			? h( 'p', { className: 'ts-notice ts-notice--success' }, '✅ Hourly vulnerability updates active.' )
			: h( 'p', { className: 'ts-notice ts-notice--info' }, 'Vulnerability data updates twice a day.' ),

		recent.length > 0 && h( 'ul', { className: 'ts-modlist' },
			recent.map( ( v ) => h( 'li', { key: v.id, className: 'ts-modlist__item' },
				h( 'span', null,
					h( 'code', null, v.cve_id || '—' ),
					' ',
					h( 'span', { className: 'ts-muted' }, v.title || v.slug || v.type || '' )
				),
				h( Badge, { tone: vulnTone( v ) }, vulnSevLabel( v ) )
			) )
		)
	);
}

/** Best-effort timestamp for a vulnerability finding (epoch seconds, ms, or date string). */
function vulnTime( v ) {
	const raw = v.published || v.detected_at || v.created_at || v.updated || 0;
	if ( ! raw ) return 0;
	if ( typeof raw === 'number' ) return raw < 1e12 ? raw * 1000 : raw;
	// SQL datetimes are UTC; parse them as such (a bare date like "2026-10-01" already is).
	const t = new Date( ( ( s ) => ( /T[\d:.]+$/.test( s ) ? s + 'Z' : s ) )( ( '' + raw ).replace( ' ', 'T' ) ) ).getTime();
	return isNaN( t ) ? 0 : t;
}

/**
 * Tone/label for a vulnerability, matching the Vulnerabilities table below exactly (same
 * severityTone( v.severity ) + v.severity_label/cvss_score fields) so the same finding never
 * shows two different severities depending on which card happens to render it.
 */
function vulnTone( v ) {
	const sev = Number( v.severity );
	if ( ! isNaN( sev ) && sev > 0 ) return severityTone( sev );
	const cvss = Number( v.cvss_score );
	if ( ! isNaN( cvss ) && cvss > 0 ) {
		if ( cvss >= 9 ) return 'danger';
		if ( cvss >= 7 ) return 'warning';
		if ( cvss >= 4 ) return 'info';
		return 'neutral';
	}
	return 'danger';
}

function vulnSevLabel( v ) {
	if ( v.severity_label ) {
		const s = String( v.severity_label );
		return s.charAt( 0 ).toUpperCase() + s.slice( 1 ).toLowerCase();
	}
	const cvss = Number( v.cvss_score );
	if ( ! isNaN( cvss ) && cvss > 0 ) {
		return 'CVSS ' + cvss;
	}
	return 'Known CVE';
}

function StatusTile( { label, value, tone } ) {
	return h( 'div', { className: 'ts-tile' },
		tone
			? h( Badge, { tone }, value )
			: h( 'div', { className: 'ts-tile__value' }, value ),
		h( 'div', { className: 'ts-tile__label' }, label )
	);
}

function VulnerabilitiesCard( { vulns, vulnsError, onRetry, isPro, store } ) {
	const [ vulnQuery, setVulnQuery ] = useState( '' );
	const [ vulnSeverity, setVulnSeverity ] = useState( '' ); // '' | 'critical' | 'high' | 'medium' | 'low'

	// All hooks (including the useState inside usePaged) must run unconditionally on every
	// render — the early returns below for the loading/error/empty states must come after every
	// hook call, or the hook count changes between renders and React throws error #310.
	const items = ( vulns && vulns.vulnerabilities ) || [];

	// Search + severity filter + pagination. Even after the server-side "active CVEs only" fix a
	// site on old plugins can legitimately have many advisories, so make the list navigable.
	const sevBucket = ( v ) => {
		const s = Number( v.severity );
		if ( s >= 40 || 'critical' === String( v.severity_label || '' ).toLowerCase() ) return 'critical';
		if ( s >= 30 || 'high' === String( v.severity_label || '' ).toLowerCase() ) return 'high';
		if ( s >= 20 || 'medium' === String( v.severity_label || '' ).toLowerCase() ) return 'medium';
		return 'low';
	};
	const filtered = items.filter( ( v ) => {
		if ( vulnSeverity && sevBucket( v ) !== vulnSeverity ) return false;
		return matchesQuery( v, vulnQuery, [ 'cve_id', 'title', 'slug', 'type', 'source' ] );
	} );
	const { pageItems: pagedVulns, pager: vulnsPager } = usePaged( filtered, 25 );

	if ( ! vulns ) {
		if ( vulnsError ) {
			return h( Card, { title: 'Vulnerabilities' }, h( LoadError, { message: vulnsError, onRetry } ) );
		}
		return h( Card, { title: 'Vulnerabilities' }, h( Spinner, null ) );
	}

	if ( vulns.cve_db_loaded === false ) {
		return h( Card, { title: 'Vulnerabilities' },
			h( EmptyState, {
				icon: '⚠️',
				title: 'CVE database not loaded',
				hint: 'The CVE advisory database has not been synced yet. Click "Sync now" above to fetch the latest advisories from the feed server.',
			} )
		);
	}
	// Wordfence's vulnerability database requires visible attribution wherever its data is
	// displayed — shown whenever any currently-listed finding is Wordfence-sourced, rather
	// than per-row, so it reads as a clear data-source credit rather than clutter. Source
	// value spelling is our best guess (see docs) pending confirmation from LicenseKit's dev.
	const wordfenceNotice = items.some( ( v ) => 'wordfence' === String( v.source || '' ).toLowerCase() )
		? h( 'p', { className: 'ts-notice ts-notice--info' },
			'Some vulnerability data provided by ',
			h( 'a', { href: 'https://www.wordfence.com/', target: '_blank', rel: 'noopener noreferrer' }, 'Wordfence Intelligence' ), '.'
		  )
		: null;

	// Feed-supplied virtual patches for a known CVE are merged into the active ruleset
	// automatically whenever virtual patching is enabled (both Standard and Optimized mode) —
	// there is no per-CVE "apply" action to perform here. So this only navigates to the
	// Firewall panel where the operator can confirm virtual patching is on and see the rule,
	// rather than firing a no-op request and toasting a fake "applied" success.
	const viewInFirewall = ( patchId ) => {
		if ( ! patchId ) return;
		window.location.hash = '#/firewall';
	};

	return h( Card, {
		title: 'Vulnerabilities',
		actions: h( Badge, { tone: items.length ? 'danger' : 'success' }, String( items.length ) ),
	},
		wordfenceNotice,
		items.length > 0 && h( 'div', { className: 'ts-toolbar', style: { display: 'flex', gap: '8px', margin: '0 0 12px', alignItems: 'center' } },
			h( ListSearch, { value: vulnQuery, onChange: setVulnQuery, placeholder: 'Search CVE, component, slug, source…' } ),
			h( 'select', { id: 'ts-vuln-severity', name: 'vuln_severity', value: vulnSeverity, onChange: ( e ) => setVulnSeverity( e.target.value ) },
				h( 'option', { value: '' }, 'All severities' ),
				h( 'option', { value: 'critical' }, 'Critical' ),
				h( 'option', { value: 'high' }, 'High' ),
				h( 'option', { value: 'medium' }, 'Medium' ),
				h( 'option', { value: 'low' }, 'Low' )
			),
			( vulnQuery || vulnSeverity ) && h( Button, { variant: 'ghost', onClick: () => { setVulnQuery( '' ); setVulnSeverity( '' ); } }, 'Clear' )
		),
		items.length === 0
			? h( EmptyState, { icon: '✅', title: 'No vulnerabilities found',
				hint: 'No installed plugins, themes, or core match the CVE database.' } )
			: filtered.length === 0
			? h( EmptyState, { icon: '🔍', title: 'No matching vulnerabilities', hint: 'Try a different search term or clear the filter.' } )
			: h( Fragment, null, h( 'table', { className: 'ts-table' },
				h( 'thead', null, h( 'tr', null,
					h( 'th', null, 'CVE' ),
					h( 'th', null, 'Component' ),
					h( 'th', null, 'Severity' ),
					h( 'th', null, 'Installed' ),
					h( 'th', null, 'Fixed in' ),
					h( 'th', null, 'Source' ),
					h( 'th', null, 'Protection' ),
				) ),
				h( 'tbody', null, pagedVulns.map( ( v ) =>
					h( 'tr', { key: v.id },
						h( 'td', null, h( 'code', null, v.cve_id ) ),
						h( 'td', null,
							h( 'div', null, v.title ),
							h( 'div', { style: { fontSize: '11px', opacity: '.7' } }, v.slug || v.type )
						),
						h( 'td', null, h( Badge, { tone: severityTone( v.severity ) },
							v.severity_label || ( null != v.cvss_score ? 'CVSS ' + v.cvss_score : '—' ) ) ),
						h( 'td', null, v.installed || '—' ),
						h( 'td', null, v.max_version ? '<= ' + v.max_version : '—' ),
						h( 'td', null, v.source || '—' ),
						h( 'td', null,
							v.virtual_patch_id
								? h( Button, {
									variant: 'secondary',
									onClick: () => viewInFirewall( v.virtual_patch_id ),
									title: 'This CVE has a virtual patch that is active automatically while virtual patching is enabled. Opens the Firewall panel to confirm.',
								  }, 'View in Firewall →' )
								: h( Badge, { tone: 'neutral' }, 'No patch available' )
						)
					)
				) )
			), vulnsPager
	) );
}	
