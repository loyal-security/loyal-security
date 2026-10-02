/**
 * ProGate / ProPanel — how the free dashboard points out features of the separate Loyal
 * Security Pro plugin.
 *
 * The free plugin contains no Pro functionality — neither PHP nor interface code. Where a Pro
 * feature would appear, it shows a static teaser (name, a few points, a link to the upgrade
 * screen). When the Pro plugin is installed it registers its own components in
 * `window.TotalSecurityWP.proComponents` / `proPanels`, and those render instead.
 *
 * `useIsPro()` / `fetchTier()` read the licence tier from the server (`/status/license`); they
 * only decide which wording a teaser shows, never whether anything is unlocked.
 *
 * Usage:
 *   import { ProGate, ProPanel } from '../components/ProGate.js';
 *   h( ProGate, { feature: 'backup.woo_delta', title: 'WooCommerce-aware backups', bullets: [ '…' ] } )
 *   h( ProPanel, { route: 'uptime', title: 'Uptime Monitor', description: '…', bullets: [ '…' ] } )
 */
import { h, useState, useEffect } from '../el.js';

// Whether the Pro plugin is active, shared by every teaser on the page. Only the wording of the
// teasers depends on it.
let _tier = ( window.TotalSecurityWP && window.TotalSecurityWP.tier ) || 'free'; // optimistic initial value
let _fetchedAt = 0; // timestamp (ms) of last server verification
let _inflightPromise = null; // dedupe concurrent fetches
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Resolve the active tier from the server, honouring a 5-minute cache and
 * de-duplicating concurrent calls. Falls back to the last known value on a
 * network error so a transient blip never spuriously locks the UI.
 *
 * @return {Promise<string>} 'free' or 'pro'
 */
export function fetchTier() {
	const now = Date.now();
	if ( _fetchedAt > 0 && now - _fetchedAt < CACHE_TTL ) {
		return Promise.resolve( _tier );
	}
	if ( _inflightPromise ) {
		return _inflightPromise;
	}

	const cfg = window.TotalSecurityWP || { root: '', nonce: '' };
	const url = cfg.root.replace( /\/$/, '' ) + '/status/license';

	_inflightPromise = fetch( url, {
		credentials: 'same-origin',
		headers: { 'X-WP-Nonce': cfg.nonce },
	} )
		.then( ( r ) => r.json() )
		.then( ( body ) => {
			_tier = ( body && body.data && body.data.tier ) || 'free';
			_fetchedAt = Date.now();
			_inflightPromise = null;
			return _tier;
		} )
		.catch( () => {
			_inflightPromise = null;
			return _tier; // keep last known value on network error
		} );

	return _inflightPromise;
}

/**
 * True when the Pro plugin is active. Reads the cached value instantly and refreshes it from the
 * server in the background.
 */
export function useIsPro() {
	const [ tier, setTier ] = useState( _tier );
	useEffect( () => {
		let alive = true;
		fetchTier().then( ( t ) => {
			if ( alive ) {
				setTier( t );
			}
		} );
		return () => {
			alive = false;
		};
	}, [] );
	return 'pro' === tier;
}

/**
 * Registries the separate Loyal Security Pro plugin fills from its own enqueued script (when it
 * is installed and active) — never the free plugin, which ships no Pro interface code at all:
 *
 *   window.TotalSecurityWP.proComponents[ 'agency.whitelabel' ] = WhiteLabelPanel; // a section
 *   window.TotalSecurityWP.proPanels[ 'uptime' ] = UptimePanel;                   // a whole screen
 */
function registered( registryName, key ) {
	const registry = window.TotalSecurityWP && window.TotalSecurityWP[ registryName ];
	return registry && typeof registry[ key ] === 'function' ? registry[ key ] : null;
}

/**
 * Static description of a Pro feature: what it does and where to get it. Contains no working
 * controls — the free plugin only points out features the separate Pro plugin provides.
 */
function ProTeaser( { title, description, bullets } ) {
	const isPro = useIsPro();
	return h(
		'div',
		{ className: 'ts-pro-gate ts-pro-teaser' },
		h( 'span', { className: 'ts-pro-badge' }, 'PRO' ),
		h( 'h3', { className: 'ts-pro-teaser__title' }, title ),
		description && h( 'p', { className: 'ts-muted' }, description ),
		Array.isArray( bullets ) && bullets.length
			? h( 'ul', { className: 'ts-teaser-list' }, bullets.slice( 0, 5 ).map( ( b, i ) => h( 'li', { key: i }, b ) ) )
			: null,
		isPro
			? h( 'p', { className: 'ts-muted' }, 'This feature is provided by the Loyal Security Pro plugin. Update Pro to the latest version to use it here.' )
			: h( 'a', { className: 'ts-pro-cta', href: '#/upgrade' }, 'See upgrade options →' )
	);
}

/**
 * A Pro feature inside a free screen. Renders the component the Pro plugin registered for
 * `feature`, otherwise `fallback` when given, otherwise a static teaser card.
 *
 * @param {Object}   props
 * @param {string}   props.feature       Feature id (e.g. 'backup.woo_delta').
 * @param {string}   [props.title]       Feature name.
 * @param {string}   [props.description] One-sentence description.
 * @param {string[]} [props.bullets]     Up to 5 short points.
 * @param {Object}   [props.proProps]    Props passed through to the registered Pro component.
 * @param {*}        [props.fallback]    Rendered instead of the teaser when nothing is registered.
 */
export function ProGate( { feature, title, description, bullets, proProps, fallback } ) {
	const ProComponent = registered( 'proComponents', feature );
	if ( ProComponent ) {
		return h( ProComponent, proProps || {} );
	}
	if ( undefined !== fallback ) {
		return fallback;
	}
	return h( ProTeaser, { title, description, bullets } );
}

/** True when the Pro plugin registered its own screen for `route`. */
export function proPanelRegistered( route ) {
	return null !== registered( 'proPanels', route );
}

/**
 * A whole Pro screen. Renders the screen the Pro plugin registered for `route`, otherwise a
 * teaser card describing it.
 *
 * @param {Object}   props
 * @param {string}   props.route         Dashboard route key (e.g. 'uptime').
 * @param {string}   props.title         Screen name.
 * @param {string}   props.description   One-sentence description.
 * @param {string[]} props.bullets       Up to 5 short points.
 */
export function ProPanel( { route, title, description, bullets, ...rest } ) {
	const Panel = registered( 'proPanels', route );
	if ( Panel ) {
		return h( Panel, rest );
	}
	return h( ProTeaser, { title, description, bullets } );
}
