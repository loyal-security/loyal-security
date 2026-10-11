/**
 * Dashboard panel — fetches the aggregated security status and renders the score, module
 * health, headline counters, recommendations, and recent critical activity.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Spinner, Badge, Button, EmptyState, ScrollPanel } from './ui.js';
import { ActivityItem } from './ActivityItem.js';
import { useStore } from '../store.js';
import { useIsPro } from './ProGate.js';

export function Dashboard() {
	const store = useStore();
	const [ status, setStatus ]   = useState( null );
	const [ error, setError ]     = useState( null );
	const [ loading, setLoading ] = useState( true );
	const [ tiTier, setTiTier ]   = useState( null );
	// Server-verified tier (not the stale window hint) so the upgrade prompts disappear/appear
	// with the real license state within a session. Must be called unconditionally, before the
	// loading/error early returns below, so hook order never changes between renders.
	const isPro = useIsPro();

	const load = async () => {
		setLoading( true );
		try {
			const data = await api.get( '/status' );
			setStatus( data );
			setError( null );
		} catch ( e ) {
			setError( e.message );
		} finally {
			setLoading( false );
		}
	};

	useEffect( () => {
		load();
		api.get( '/threatintel/status' )
			.then( ( d ) => setTiTier( d.tier || 'free' ) )
			.catch( () => {} );
	}, [] );

	if ( loading && ! status ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ), h( 'span', null, 'Loading security status…' ) );
	}

	if ( error ) {
		return h(
			Card,
			{ title: 'Unable to load status' },
			h( 'p', { className: 'ts-error' }, error ),
			h( Button, { onClick: load, variant: 'primary' }, 'Retry' )
		);
	}

	const s = status || {};
	const counters = s.counters || {};
	const gradeTone = s.score >= 80 ? 'success' : s.score >= 65 ? 'warning' : 'danger';
	const tier = isPro ? 'pro' : 'free';
	const upgradeUrl = ( window.LoyalSecurity && window.LoyalSecurity.upgrade_url ) || '';

	return h(
		Fragment,
		null,

		/* ---- Plan banner ------------------------------------------------- */
		h( 'div', { className: 'ts-plan-banner ts-plan-banner--' + tier },
			h( 'div', { className: 'ts-plan-banner__left' },
				h( 'span', { className: 'ts-plan-badge' }, isPro ? '⭐ Pro' : '🆓 Free Plan' ),
				isPro
					? h( 'span', { className: 'ts-plan-banner__text' }, 'Loyal Security Pro is active. Thank you for your support!' )
					: h( 'span', { className: 'ts-plan-banner__text' }, 'Everything that protects this site is included. The separate Loyal Security Pro plugin adds automation, hourly threat-intelligence updates and agency tools.' )
			),
			! isPro && h( 'a', { href: upgradeUrl, className: 'ts-plan-banner__cta' }, 'About Pro →' )
		),

		/* ---- Pro teaser --------------------------------------------------- */
		! isPro && h(
			Card,
			{
				title: 'What Pro adds',
				actions: h( Button, { variant: 'primary', onClick: () => { window.location.hash = '#/upgrade'; } }, 'See Pro' ),
			},
			h( 'ul', { className: 'ts-reclist' },
				h( 'li', { className: 'ts-reclist__item' }, h( 'strong', null, 'Under Attack Mode' ), ' - one-click emergency lockdown when you are actively being targeted' ),
				h( 'li', { className: 'ts-reclist__item' }, h( 'strong', null, 'Sentinel AI' ), ' - correlates attack signals into one verdict instead of a hundred raw log lines' ),
				h( 'li', { className: 'ts-reclist__item' }, h( 'strong', null, 'Daily scans & auto-quarantine' ), ' - infected files isolated the moment they are found, not on your next login' ),
				h( 'li', { className: 'ts-reclist__item' }, h( 'strong', null, 'Agency tooling' ), ' - white-label branding, staff roles, and a hub dashboard for managing client sites' )
			)
		),

		/* ---- Setup Wizard quick-switch -------------------------------------
		 * Re-running the wizard used to mean either hunting for a hidden sidebar link (hidden
		 * entirely on Pro) or reinstalling the plugin. These jump straight to the Level step for
		 * a given site type — one click fewer than the full wizard for anyone just switching
		 * presets, not doing first-run setup. */
		h(
			Card,
			{
				title: '🚀 Setup Wizard',
				actions: h( Button, { variant: 'ghost', onClick: () => { window.location.hash = '#/onboarding'; } }, 'Open full wizard →' ),
			},
			h( 'p', { className: 'ts-muted', style: { marginTop: 0 } },
				'Switch presets any time — this only changes what gets pre-checked next, nothing is applied until you confirm.'
			),
			h( 'div', { className: 'ts-actions-row' },
				h( Button, { variant: 'default', onClick: () => { window.location.hash = '#/onboarding?type=blog'; } }, 'Blog / content site' ),
				h( Button, { variant: 'default', onClick: () => { window.location.hash = '#/onboarding?type=store'; } }, 'Store / eCommerce' ),
				h( Button, { variant: 'default', onClick: () => { window.location.hash = '#/onboarding?type=agency'; } }, 'Agency-managed site' )
			)
		),

		h(
			'div',
			{ className: 'ts-grid ts-grid--top' },
			// Score hero.
			h(
				'div',
				{ className: 'ts-score ts-score--' + gradeTone },
				h( 'div', { className: 'ts-score__num' }, s.score ?? '—' ),
				h( 'div', { className: 'ts-score__meta' },
					h( 'div', { className: 'ts-score__grade' }, 'Grade ' + ( s.grade || '?' ) ),
					h( 'div', { className: 'ts-score__sub' }, 'Security score' ),
					null != s.score_trend && h( 'div', {
						className: 'ts-score__trend' + ( s.score_trend > 0 ? ' is-up' : s.score_trend < 0 ? ' is-down' : ' is-flat' ),
						title: 'Compared to 7 days ago',
					}, s.score_trend > 0 ? ( '▲ +' + s.score_trend ) : ( s.score_trend < 0 ? ( '▼ ' + s.score_trend ) : '– steady' ) )
				)
			),
			// Counter tiles.
			h(
				'div',
				{ className: 'ts-tiles' },
				tile( '', counters.waf_blocks_24h ?? 0, 'WAF blocks (24h)' ),
				tile( '', counters.active_bans ?? 0, 'Active bans' ),
				tile( '', counters.open_findings ?? 0, 'Open findings' ),
				tile( '', counters.quarantined ?? 0, 'Quarantined' ),
				tile( '', counters.failed_logins_24h ?? 0, 'Failed logins (24h)' ),
				// Only surfaced when at least one installed plugin is in a patch gap, so the row
				// stays quiet otherwise. Clickable through to Threat Intelligence for detail.
				( counters.patch_gap ?? 0 ) > 0 && tile( '🛡️', counters.patch_gap, 'Patch-gap shielded', 'threatintel' )
			)
		),
		h(
			'div',
			{ className: 'ts-grid ts-grid--cols' },
			h(
				Card,
				{ title: 'Recommendations' },
				( s.recommendations && s.recommendations.length )
					? h( 'ul', { className: 'ts-reclist' }, s.recommendations.map( ( r, i ) => {
							// Recommendations may be plain strings (legacy) or { text, action, route, highlight }.
							const text = typeof r === 'string' ? r : r.text;
							const route = ( r && typeof r === 'object' ) ? r.route : '';
							const action = ( r && typeof r === 'object' ) ? r.action : '';
							const highlight = ( r && typeof r === 'object' ) ? r.highlight : '';
							return h( 'li', { key: i, className: 'ts-reclist__item', style: { display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'space-between' } },
								h( 'span', null, text ),
								route && h( Button, { variant: 'primary', onClick: () => {
									window.location.hash = '#/' + route + ( highlight ? '?highlight=' + encodeURIComponent( highlight ) : '' );
								} }, action || 'Fix' )
							);
						} ) )
					: h( EmptyState, { icon: '✅', title: 'All clear', hint: 'No outstanding recommendations.' } )
			),
			h(
				Card,
				{ title: 'Module health' },
				h(
					ScrollPanel,
					null,
					h(
						'ul',
						{ className: 'ts-modlist' },
						( s.modules || [] ).map( ( m ) =>
							h(
								'li',
								{ key: m.id, className: 'ts-modlist__item' },
								h( 'span', null, m.title ),
								h( Badge, { tone: m.enabled ? 'success' : 'neutral' }, m.enabled ? 'Enabled' : 'Off' )
							)
						)
					)
				)
			)
		),
		tiTier === 'free' && h(
			Card,
			{
				title: '🌐 Hourly threat-intelligence updates',
				actions: h( Button, { variant: 'primary', onClick: () => { window.location.hash = '#/threatintel'; } }, 'Learn more' ),
			},
			h( 'p', { style: { margin: 0 } },
				'This site receives firewall, malware and vulnerability updates twice a day. A ',
				h( 'strong', null, 'Pro' ),
				' subscription to the feed service delivers them every hour.'
			)
		),
		h(
			'div',
			{ className: 'ts-grid ts-grid--cols' },
			h(
				Card,
				{ title: 'Recent critical activity', actions: h( 'a', { href: '#/logs', className: 'ts-card__link' }, 'View all →' ) },
				( s.recent_events && s.recent_events.length )
					? h(
							ScrollPanel,
							null,
							h(
								'ul',
								{ className: 'ts-feed' },
								s.recent_events.map( ( ev ) => h( ActivityItem, { key: ev.id, event: ev } ) )
							)
					  )
					: h( EmptyState, { icon: '🌿', title: 'All quiet', hint: 'No attacks or critical events recorded yet — that’s a good sign.' } )
			),
			h( LoginTimeline, null )
		)
	);
}

function tile( icon, value, label, route ) {
	const inner = [
		h( 'div', { className: 'ts-tile__icon' }, icon ),
		h( 'div', { className: 'ts-tile__value' }, value ),
		h( 'div', { className: 'ts-tile__label' }, label ),
	];
	if ( route ) {
		return h(
			'button',
			{
				type: 'button',
				className: 'ts-tile ts-tile--link',
				title: 'View details',
				onClick: () => { window.location.hash = '#/' + route; },
			},
			...inner
		);
	}
	return h( 'div', { className: 'ts-tile' }, ...inner );
}

/**
 * Compact feed of the most recent login outcomes (successes, failures, blocks).
 * Reads from the dedicated /logs/login-activity endpoint so the dashboard surfaces
 * who has been getting into (or trying to get into) the site at a glance.
 */
function LoginTimeline() {
	const [ items, setItems ]     = useState( null );
	const [ error, setError ]     = useState( null );

	useEffect( () => {
		let alive = true;
		api.get( '/logs/login-activity' )
			.then( ( d ) => { if ( alive ) setItems( ( d && d.items ) || [] ); } )
			.catch( ( e ) => { if ( alive ) setError( e.message ); } );
		return () => { alive = false; };
	}, [] );

	let body;
	if ( error ) {
		body = h( 'p', { className: 'ts-error' }, error );
	} else if ( items === null ) {
		body = h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	} else if ( ! items.length ) {
		body = h( EmptyState, { icon: '🔐', title: 'No login activity', hint: 'No recent sign-in attempts recorded yet.' } );
	} else {
		body = h( ScrollPanel, null, h( 'ul', { className: 'ts-feed' },
			items.slice( 0, 10 ).map( ( ev, i ) => {
				const ok = ev.type === 'auth.login.success';
				return h( 'li', { key: i, className: 'ts-login-row', style: { display: 'flex', alignItems: 'center', gap: '8px' } },
					h( 'span', {
						className: 'ts-login-dot',
						title: ok ? 'Successful login' : 'Failed / blocked',
						role: 'img',
						// Not color-only: give assistive tech (and color-blind users, via the
						// title tooltip) an explicit label for the success/failure state.
						'aria-label': ok ? 'Successful login' : 'Failed or blocked login',
						style: {
							flex: '0 0 auto',
							width: '9px',
							height: '9px',
							borderRadius: '50%',
							background: ok ? '#46b450' : '#d63638',
						},
					} ),
					h( 'span', { style: { fontWeight: '600' } }, ev.username || '—' ),
					h( 'span', { className: 'ts-muted', style: { fontSize: '12px' } }, ev.ip || '—' ),
					h( 'span', { className: 'ts-muted', style: { marginLeft: 'auto', fontSize: '12px' } }, timeAgo( ev.created_at ) )
				);
			} )
		) );
	}

	return h( Card, { title: 'Recent Login Activity', className: 'ts-login-timeline' }, body );
}

/** Render an ISO/SQL timestamp as a compact relative "time ago" string. */
function timeAgo( ts ) {
	if ( ! ts ) return '—';
	// Stored as UTC ("Y-m-d H:i:s"); without the Z the browser read it as local time and the
	// list was off by the viewer's UTC offset ("3h ago" for a sign-in a minute old).
	const then = new Date( ( ( s ) => ( /T[\d:.]+$/.test( s ) ? s + 'Z' : s ) )( ( '' + ts ).replace( ' ', 'T' ) ) ).getTime();
	if ( isNaN( then ) ) return ts;
	const secs = Math.max( 0, Math.floor( ( Date.now() - then ) / 1000 ) );
	if ( secs < 60 ) return secs + 's ago';
	const mins = Math.floor( secs / 60 );
	if ( mins < 60 ) return mins + 'm ago';
	const hrs = Math.floor( mins / 60 );
	if ( hrs < 24 ) return hrs + 'h ago';
	const days = Math.floor( hrs / 24 );
	return days + 'd ago';
}
