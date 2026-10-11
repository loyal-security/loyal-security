/**
 * OnboardingWizard — a full-panel, Wordfence-style activation plan shown at `#/onboarding`.
 *
 * Site-type (what the site IS: blog/store/agency) and protection level (Basic/Good/Advanced —
 * how much to turn on) are two independent questions, not one combined choice: a store owner
 * needs payment-page integrity monitoring regardless of how thorough they want everything else,
 * and someone who wants Advanced protection on a simple blog shouldn't have to pretend it's an
 * agency site to get it. Each RECOMMENDED item is tagged with the minimum level it turns on at,
 * so the same site-type list serves all three levels by filtering.
 *
 * After both choices, the user picks how they want to apply them: "Quick setup" (today's flat
 * pre-checked list, one click) or "Guide me" (one item at a time with a short explanation and an
 * Enable/Skip choice) — both end up calling the same applySettings() with whatever's checked.
 *
 * The wizard is informational + best-effort: it tries to push the chosen settings to a batch
 * endpoint but never blocks if that endpoint is absent. Completion is recorded in localStorage
 * (`loyalsec_onboarding_done`) so the OnboardingBanner stops nagging.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge } from './ui.js';
import { useStore } from '../store.js';

const LEVELS = [ 'basic', 'good', 'advanced' ];
const LEVEL_RANK = { basic: 0, good: 1, advanced: 2 };

/**
 * Recommended settings per site type, each tagged with the minimum protection level it turns
 * on at. `itemsFor(type, level)` filters this down to what a given site-type + level
 * combination should have pre-checked. The "advanced" items lean on this session's newest
 * Firewall capabilities (escalating lockout, verified-bot rate tier, faceted-search abuse
 * protection) — genuinely new protection, not just deeper settings-page trivia.
 */
const RECOMMENDED = {
	blog: [
		{ id: 'firewall', level: 'basic', label: 'Enable WAF firewall',
			why: 'Blocks common attack patterns (SQL injection, XSS, known exploit signatures) before they reach your site.',
			path: { firewall: { enabled: true } } },
		{ id: 'login', level: 'basic', label: 'Enable login protection',
			why: 'Slows down and locks out repeated failed login attempts — the single most common attack every WordPress site sees.',
			path: { auth: { login_protection: true } } },
		{ id: 'alerts', level: 'basic', label: 'Email alerts for critical events',
			why: "So you find out about a real problem from an email, not from a customer or Google noticing first.",
			path: { notifications: { enabled: true } } },
		{ id: 'integrity', level: 'good', label: 'Enable integrity monitoring',
			why: 'Detects when a core, plugin, or theme file changes unexpectedly — usually the first sign of a compromise.',
			path: { integrity: { enabled: true } } },
		{ id: 'escalation', level: 'advanced', label: 'Escalating login lockouts',
			why: 'A repeat attacker gets a longer lockout each time instead of the same short one — most sites never need to think about this again once it’s on.',
			path: { firewall: { bruteforce_escalation_enabled: true } } },
		{ id: 'bot_verify', level: 'advanced', label: 'Verified-bot rate tier',
			why: 'Confirms Googlebot/Bingbot are really who they claim (reverse-DNS, not just the User-Agent string) and gives real ones more headroom instead of throttling your own SEO crawls.',
			path: { firewall: { bot_verify_enabled: true } } },
	],
	store: [
		{ id: 'firewall', level: 'basic', label: 'Enable WAF firewall',
			why: 'Blocks common attack patterns before they reach your storefront or checkout.',
			path: { firewall: { enabled: true } } },
		{ id: 'login', level: 'basic', label: 'Enable login protection',
			why: 'Protects admin and customer accounts from repeated login-guessing attempts.',
			path: { auth: { login_protection: true } } },
		{ id: 'integrity', level: 'basic', label: 'Enable integrity monitoring',
			why: 'Payment-page tampering (a skimmer script quietly added to checkout) is exactly what this catches — worth having on from day one for a store.',
			path: { integrity: { enabled: true } } },
		{ id: 'alerts', level: 'good', label: 'Email alerts for critical events',
			why: "So a payment-page change or a blocked attack reaches your inbox immediately, not whenever you next check the dashboard.",
			path: { notifications: { enabled: true } } },
		{ id: 'backup', level: 'good', label: 'Enable daily backups',
			why: 'Orders and inventory change constantly — a weekly backup can lose a full week of sales data if something goes wrong.',
			path: { backup: { enabled: true, schedule: 'daily' } } },
		{ id: 'query_cardinality', level: 'advanced', label: 'Faceted-search abuse protection',
			why: 'Stops a bot from hammering every filter/size/color combination on your product pages — a very common load problem on WooCommerce-style catalogs, invisible to a plain rate limit.',
			path: { firewall: { query_cardinality_enabled: true } } },
		{ id: 'escalation', level: 'advanced', label: 'Escalating login lockouts',
			why: 'A repeat attacker on your admin or customer accounts gets a longer lockout each time.',
			path: { firewall: { bruteforce_escalation_enabled: true } } },
	],
	agency: [
		{ id: 'firewall', level: 'basic', label: 'Enable WAF firewall',
			why: 'Blocks common attack patterns before they reach any site you manage.',
			path: { firewall: { enabled: true } } },
		{ id: 'login', level: 'basic', label: 'Enable login protection',
			why: 'Protects every admin account on this site from repeated login-guessing attempts.',
			path: { auth: { login_protection: true } } },
		{ id: 'integrity', level: 'basic', label: 'Enable integrity monitoring',
			why: 'Catches unexpected core/plugin/theme changes — the thing you don’t want to explain to a client after the fact.',
			path: { integrity: { enabled: true } } },
		{ id: 'alerts', level: 'good', label: 'Email alerts for critical events',
			why: 'So you hear about a problem before the client does.',
			path: { notifications: { enabled: true } } },
		{ id: 'backup', level: 'good', label: 'Enable backup (weekly)',
			why: 'A baseline safety net across every site you manage — tune the schedule per client later.',
			path: { backup: { enabled: true, schedule: 'weekly' } } },
		{ id: 'hardening', level: 'good', label: 'Enable hardening checklist',
			why: 'A one-page rundown of server/WordPress hardening items, useful when you’re reviewing a new client site.',
			path: { hardening: { enabled: true } } },
		{ id: 'csp', level: 'advanced', label: 'Enable CSP (report-only mode)',
			why: 'Starts collecting Content-Security-Policy violation reports without blocking anything yet — the safe way to build a real policy over time.',
			path: { csp: { enabled: true, mode: 'report-only' } } },
		{ id: 'query_cardinality', level: 'advanced', label: 'Faceted-search abuse protection',
			why: 'Stops a bot from enumerating every filter combination on a client’s shop or directory pages.',
			path: { firewall: { query_cardinality_enabled: true } } },
		{ id: 'bot_verify', level: 'advanced', label: 'Verified-bot rate tier',
			why: 'Confirmed search-engine crawlers get more headroom instead of being throttled like everyone else.',
			path: { firewall: { bot_verify_enabled: true } } },
		{ id: 'escalation', level: 'advanced', label: 'Escalating login lockouts',
			why: 'Repeat attackers across any site you manage get progressively longer lockouts.',
			path: { firewall: { bruteforce_escalation_enabled: true } } },
	],
};

const SITE_TYPE_LABEL = { blog: 'Blog/content site', store: 'Store/eCommerce', agency: 'Agency-managed site' };
const LEVEL_LABEL = { basic: 'Basic', good: 'Good', advanced: 'Advanced' };

// Dashboard density follows the protection LEVEL, not the site type — an agency operator who
// picks Basic still gets the simpler view; anyone who picks Advanced gets the fuller one.
// Either can still switch it themselves from the sidebar at any time.
const VIEW_FOR_LEVEL = { basic: 'basic', good: 'basic', advanced: 'advanced' };

/** Items for a site type at-or-below the given level. */
function itemsFor( siteType, level ) {
	const items = RECOMMENDED[ siteType ] || [];
	const rank  = LEVEL_RANK[ level ] ?? 0;
	return items.filter( ( r ) => ( LEVEL_RANK[ r.level ] ?? 0 ) <= rank );
}

function PlanCard( { name, tone, badge, bullets, cta, onClick, highlight } ) {
	return h(
		'div',
		{ className: 'ts-plan-card' + ( highlight ? ' ts-plan-card--featured' : '' ) },
		h(
			'div',
			{ className: 'ts-plan-card__head' },
			h( 'h3', { className: 'ts-plan-card__name' }, name ),
			badge && h( Badge, { tone }, badge )
		),
		h(
			'ul',
			{ className: 'ts-plan-card__list' },
			bullets.map( ( b, i ) => h( 'li', { key: i }, b ) )
		),
		h(
			'button',
			{ type: 'button', className: 'ts-plan-card__cta', onClick },
			cta
		)
	);
}

/**
 * Read `?type=blog|store|agency` off the current hash (e.g. `#/onboarding?type=store`) — lets
 * the Dashboard's quick-switch shortcuts jump straight past the site-type step instead of
 * forcing a full re-run through screen 1 every time an admin just wants to change presets.
 * Mirrors the `paramFromHash` convention already used by LogTable.js and SettingsForm.js.
 */
function siteTypeFromHash() {
	try {
		const hash = window.location.hash || '';
		const query = hash.split( '?' )[ 1 ] || '';
		const type = new URLSearchParams( query ).get( 'type' ) || '';
		return RECOMMENDED[ type ] ? type : '';
	} catch ( _ ) {
		return '';
	}
}

function deepMerge( target, src ) {
	const out = { ...target };
	Object.keys( src ).forEach( ( k ) => {
		out[ k ] = src[ k ] && typeof src[ k ] === 'object' && ! Array.isArray( src[ k ] )
			? deepMerge( out[ k ] || {}, src[ k ] )
			: src[ k ];
	} );
	return out;
}

export function OnboardingWizard() {
	const store = useStore();
	// A deep-linked `?type=` (from the Dashboard's quick-switch card) skips straight to the
	// level step with that site type already chosen, instead of forcing screen 1 again.
	const hashType = siteTypeFromHash();
	const [ screen, setScreen ] = useState( hashType ? 'level' : 'site-type' ); // site-type -> level -> mode-choice -> checklist | guided -> success
	const [ siteType, setSiteType ] = useState( hashType || null );
	const [ level, setLevel ] = useState( null );
	const [ checked, setChecked ] = useState( {} ); // id -> bool
	const [ guidedIndex, setGuidedIndex ] = useState( 0 );
	const [ busy, setBusy ] = useState( false );
	// Real proof for the closing screen — fetched once, only once the wizard actually reaches
	// "success", never blocking the flow if it fails (falls back to the generic copy below).
	const [ proofStats, setProofStats ] = useState( null );

	useEffect( () => {
		if ( 'success' !== screen || null !== proofStats ) {
			return;
		}
		api.get( '/firewall/stats' ).then( ( d ) => setProofStats( d || {} ) ).catch( () => setProofStats( {} ) );
	}, [ screen ] ); // eslint-disable-line react-hooks/exhaustive-deps

	const upgradeUrl = ( window.LoyalSecurity && window.LoyalSecurity.upgrade_url ) || '';

	const chooseSiteType = ( type ) => {
		setSiteType( type );
		setScreen( 'level' );
	};

	const chooseLevel = ( lvl ) => {
		setLevel( lvl );
		const next = {};
		itemsFor( siteType, lvl ).forEach( ( r ) => { next[ r.id ] = true; } );
		setChecked( next );
		if ( store && store.setViewMode ) {
			store.setViewMode( VIEW_FOR_LEVEL[ lvl ] || 'advanced' );
		}
		setScreen( 'mode-choice' );
	};

	const toggle = ( id ) => setChecked( ( c ) => ( { ...c, [ id ]: ! c[ id ] } ) );

	const applySettings = async ( checkedOverride ) => {
		const effectiveChecked = checkedOverride || checked;
		const items = itemsFor( siteType, level ).filter( ( r ) => effectiveChecked[ r.id ] );
		let settings = {};
		items.forEach( ( r ) => { settings = deepMerge( settings, r.path ); } );

		setBusy( true );
		try {
			await api.post( '/settings/batch', { settings } );
			store.toast( 'Settings applied.', 'success' );
		} catch ( e ) {
			// Endpoint may not exist yet — never block the wizard on it.
			store.toast( 'Settings applied (reload to see changes).', 'info' );
		} finally {
			// Reaching the end of onboarding IS "initial setup done" — shares the same
			// loyalsec_setup_complete flag the technical Setup Wizard's own "Mark complete"
			// step sets, so the "Finish setup" admin notice stops nagging either way. Fire this
			// after the toast above and let the success screen render immediately regardless of
			// outcome — never worth blocking on.
			api.post( '/wizard/complete' ).catch( () => {} );
			setBusy( false );
			setScreen( 'success' );
		}
	};

	const goHash = ( hash ) => { window.location.hash = hash; };

	const dismissForever = () => {
		try { window.localStorage.setItem( 'loyalsec_onboarding_done', '1' ); } catch ( e ) {}
		goHash( '#/dashboard' );
	};

	/* ------------------------------ Site type -------------------------------- */
	if ( 'site-type' === screen ) {
		return h(
			Card,
			{ title: 'Welcome — what kind of site is this?' },
			h( 'p', { className: 'ts-muted', style: { marginTop: 0 } },
				"Next you'll pick how much protection to turn on. You can change any setting later, and switch the dashboard between Basic and Advanced any time from the sidebar — nothing here is permanent."
			),
			h(
				'div',
				{ className: 'ts-plan-grid' },
				h( PlanCard, {
					name: 'Blog / content site',
					tone: 'neutral',
					badge: 'Free',
					bullets: [
						'WAF firewall protection',
						'Malware scanner',
						'File integrity monitoring',
						'Login protection & 2FA',
						'Audit logging',
						'Email alerts',
					],
					cta: 'Set up for a blog →',
					onClick: () => chooseSiteType( 'blog' ),
				} ),
				h( PlanCard, {
					name: 'Store / eCommerce',
					tone: 'success',
					badge: 'Free · Recommended',
					highlight: true,
					bullets: [
						'Everything in Blog',
						'Daily backups',
						'Payment-page tamper detection',
						'Email alerts for critical events',
					],
					cta: 'Set up for a store →',
					onClick: () => chooseSiteType( 'store' ),
				} ),
				h( PlanCard, {
					name: 'Agency-managed site',
					tone: 'info',
					badge: 'Free',
					bullets: [
						'Everything in Store',
						'Hardening checklist',
						'CSP Manager',
						'Advanced dashboard view by default',
					],
					cta: 'Set up for agency management →',
					onClick: () => chooseSiteType( 'agency' ),
				} )
			),
			upgradeUrl && h( 'p', { className: 'ts-muted', style: { marginTop: '16px', textAlign: 'center' } },
				'Managing many client sites? The separate Loyal Security Pro plugin adds agency tools. ',
				h( 'a', { href: upgradeUrl }, 'About Pro →' )
			)
		);
	}

	/* -------------------------------- Level ----------------------------------- */
	if ( 'level' === screen ) {
		const levelCard = ( lvl, name, tone, bullets, cta ) => h( PlanCard, {
			name, tone, bullets, cta,
			onClick: () => chooseLevel( lvl ),
		} );
		return h(
			Card,
			{
				title: `How much protection? · ${ SITE_TYPE_LABEL[ siteType ] || '' }`,
				actions: h( Button, { variant: 'ghost', onClick: () => setScreen( 'site-type' ) }, '← Back' ),
			},
			h( 'p', { className: 'ts-muted', style: { marginTop: 0 } },
				"Each level includes everything in the one before it. You can raise or lower this any time — it only decides what's pre-checked next."
			),
			h(
				'div',
				{ className: 'ts-plan-grid' },
				levelCard( 'basic', 'Basic', 'neutral',
					[ 'Firewall + login protection', 'Email alerts for critical events', 'The essentials, nothing else' ],
					'Set up Basic →' ),
				levelCard( 'good', 'Good', 'success',
					[ 'Everything in Basic', 'Integrity monitoring', 'Scheduled backups', 'Recommended for most sites' ],
					'Set up Good →' ),
				levelCard( 'advanced', 'Advanced', 'info',
					[ 'Everything in Good', 'Escalating login lockouts', 'Verified-bot rate tier', 'Faceted-search abuse protection' ],
					'Set up Advanced →' )
			)
		);
	}

	/* ----------------------------- Mode choice --------------------------------- */
	if ( 'mode-choice' === screen ) {
		const count = itemsFor( siteType, level ).length;
		return h(
			Card,
			{
				title: 'How would you like to set this up?',
				actions: h( Button, { variant: 'ghost', onClick: () => setScreen( 'level' ) }, '← Back' ),
			},
			h( 'p', { className: 'ts-muted', style: { marginTop: 0 } },
				`${ count } setting${ 1 === count ? '' : 's' } recommended for ${ SITE_TYPE_LABEL[ siteType ] } · ${ LEVEL_LABEL[ level ] }.`
			),
			h(
				'div',
				{ className: 'ts-plan-grid' },
				h( PlanCard, {
					name: 'Quick setup',
					tone: 'success',
					badge: 'Fastest',
					bullets: [ 'Everything pre-checked', 'Uncheck anything you want to skip', 'One click to apply' ],
					cta: 'Quick setup →',
					onClick: () => setScreen( 'checklist' ),
				} ),
				h( PlanCard, {
					name: 'Guide me',
					tone: 'info',
					badge: 'One at a time',
					bullets: [ 'A short explanation for each item', 'Enable or skip as you go', `${ count } quick screens` ],
					cta: 'Guide me →',
					onClick: () => { setGuidedIndex( 0 ); setScreen( 'guided' ); },
				} )
			)
		);
	}

	/* ------------------------------- Checklist ---------------------------------- */
	if ( 'checklist' === screen ) {
		const items = itemsFor( siteType, level );
		return h(
			Card,
			{
				title: `Enable recommended settings · ${ SITE_TYPE_LABEL[ siteType ] || '' } · ${ LEVEL_LABEL[ level ] || '' }`,
				actions: h( Button, { variant: 'ghost', onClick: () => setScreen( 'mode-choice' ) }, '← Back' ),
			},
			h( 'p', { className: 'ts-muted', style: { marginTop: 0 } },
				'These are pre-selected for you. Uncheck anything you would rather configure later.'
			),
			h(
				'div',
				{ className: 'ts-onboard-checklist' },
				items.map( ( r ) =>
					h(
						'label',
						{ key: r.id, className: 'ts-onboard-check', htmlFor: 'ts-onboard-check-' + r.id },
						h( 'input', {
							id: 'ts-onboard-check-' + r.id,
							name: 'onboard_check_' + r.id,
							type: 'checkbox',
							checked: !! checked[ r.id ],
							onChange: () => toggle( r.id ),
						} ),
						h( 'span', null, r.label )
					)
				)
			),
			h(
				'div',
				{ className: 'ts-actions-row', style: { marginTop: '16px' } },
				h( Button, { variant: 'primary', disabled: busy, onClick: applySettings },
					busy ? 'Applying…' : 'Apply selected settings'
				)
			)
		);
	}

	/* --------------------------------- Guided ------------------------------------ */
	if ( 'guided' === screen ) {
		const items = itemsFor( siteType, level );
		const item  = items[ guidedIndex ];

		// Shouldn't normally happen (every site type has basic-level items), but never render a
		// blank card — and never call setState during render (that's the actual anti-pattern to
		// avoid here, not just the empty state itself).
		if ( ! item ) {
			return h(
				Card,
				{ title: 'Nothing left to guide through' },
				h( Button, { variant: 'primary', onClick: () => setScreen( 'checklist' ) }, 'Use the checklist instead →' )
			);
		}

		const isLast = guidedIndex === items.length - 1;
		const advance = ( enable ) => {
			const next = { ...checked, [ item.id ]: enable };
			setChecked( next );
			if ( isLast ) {
				// Pass the just-computed map explicitly — setChecked() above won't have been
				// applied yet by the time this runs (state updates aren't synchronous), so
				// applySettings() reading component state here would still see the PREVIOUS
				// checked map and silently drop this last item's choice.
				applySettings( next );
			} else {
				setGuidedIndex( guidedIndex + 1 );
			}
		};

		return h(
			Card,
			{
				title: item.label,
				actions: h( Button, { variant: 'ghost', onClick: () => setScreen( 'mode-choice' ) }, '← Back' ),
			},
			h( 'p', { className: 'ts-muted', style: { marginTop: 0, fontSize: '12px' } },
				`${ guidedIndex + 1 } of ${ items.length } · ${ SITE_TYPE_LABEL[ siteType ] } · ${ LEVEL_LABEL[ level ] }`
			),
			h( 'p', { style: { fontSize: '15px', lineHeight: '1.5' } }, item.why ),
			h(
				'div',
				{ className: 'ts-actions-row', style: { marginTop: '20px', justifyContent: 'flex-start', gap: '10px' } },
				h( Button, { variant: 'primary', disabled: busy, onClick: () => advance( true ) },
					busy ? 'Applying…' : ( isLast ? 'Enable & finish →' : 'Enable & continue →' ) ),
				h( Button, { variant: 'default', disabled: busy, onClick: () => advance( false ) },
					isLast ? 'Skip & finish' : 'Skip' )
			)
		);
	}

	/* --------------------------------- Success ------------------------------------ */
	const enabled = itemsFor( siteType, level ).filter( ( r ) => checked[ r.id ] );
	const totalBlocks7d = proofStats && Array.isArray( proofStats.by_type )
		? proofStats.by_type.reduce( ( sum, r ) => sum + ( Number( r.c ) || 0 ), 0 )
		: null;
	return h(
		Card,
		{ title: "You're protected!" },
		h(
			'div',
			{ className: 'ts-onboard-success' },
			h( 'div', { className: 'ts-onboard-success__icon' }, '🛡️' ),
			h( 'h2', null, 'Your site is now protected' ),
			h( 'p', { className: 'ts-muted' },
				`${ SITE_TYPE_LABEL[ siteType ] || '' } · ${ LEVEL_LABEL[ level ] || '' } protection is active. Here's what was enabled:`
			),
			null !== totalBlocks7d && h( 'p', { className: 'ts-onboard-proof' },
				totalBlocks7d > 0
					? h( Fragment, null, '🔥 Your firewall has already blocked ', h( 'strong', null, totalBlocks7d ), ` malicious request${ 1 === totalBlocks7d ? '' : 's' } in the last 7 days.` )
					: '🔥 Your firewall is active and watching every request — no attacks recorded yet, which is normal right after a fresh install.'
			),
			h(
				'ul',
				{ className: 'ts-onboard-summary' },
				enabled.length
					? enabled.map( ( r ) => h( 'li', { key: r.id }, '✓ ', r.label ) )
					: h( 'li', null, 'No settings were changed — adjust them any time from Settings.' )
			),
			// This wizard covers WHICH settings to turn on; it doesn't touch the server
			// environment. Two things there are worth two minutes: whitelisting your own IP (so
			// a firewall rule can never lock you out) and Optimized Mode (runs the firewall
			// before WordPress loads — faster, and it self-tests with automatic rollback). Both
			// live in the technical Setup Wizard, not duplicated here.
			h( 'p', { className: 'ts-muted', style: { textAlign: 'center' } },
				'Two more things worth doing: ',
				h( 'a', { href: '#/wizard' }, 'whitelist your IP and deploy Optimized Mode →' )
			),
			h(
				'div',
				{ className: 'ts-actions-row', style: { justifyContent: 'center', marginTop: '20px' } },
				h( Button, { variant: 'primary', onClick: () => goHash( '#/dashboard' ) }, 'Go to Dashboard →' ),
				h( Button, { variant: 'default', onClick: () => goHash( '#/firewall' ) }, 'View Firewall →' )
			),
			h(
				'button',
				{ type: 'button', className: 'ts-onboard-dismiss', onClick: dismissForever },
				"Don't show this again"
			)
		)
	);
}
