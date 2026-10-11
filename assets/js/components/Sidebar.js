/**
 * Left navigation for the dashboard SPA. Routes are hash-based so deep links from the
 * WordPress submenu (`admin.php?page=loyal-security#/firewall`) work without a server.
 */
import { h, cx, useState } from '../el.js';
import { useIsPro, proPanelRegistered } from './ProGate.js';
import { useStore } from '../store.js';

/**
 * Flat route registry. The `group` field drives the collapsible sidebar sections (see
 * GROUP_ORDER for their display order). The array stays flat — and exported — because App.js
 * looks routes up by key for the topbar title. `integrity` is intentionally absent: it now
 * lives as a tab inside ScanPanel, reached via the `scanner` route.
 *
 * `pro: true` marks a screen provided by the separate Loyal Security Pro plugin. Until Pro
 * registers that screen, it is listed (with a PRO tag) under the "Loyal Security Pro" group and
 * opens a short description of the feature.
 */
export const ROUTES = [
	{ key: 'dashboard', label: 'Dashboard', icon: '📊', group: 'Overview' },
	{ key: 'emergency', label: 'Under Attack', icon: '🚨', group: 'Overview', pro: true },

	{ key: 'firewall', label: 'Firewall', icon: '🔥', group: 'Protection' },
	{ key: 'scanner', label: 'Scanner & Integrity', icon: '🔬', group: 'Protection' },
	{ key: 'quarantine', label: 'Quarantine', icon: '🧪', group: 'Protection' },
	{ key: 'repair', label: 'Repair Center', icon: '🩹', group: 'Protection' },
	{ key: 'backup', label: 'Backup & Recovery', icon: '💾', group: 'Protection' },

	{ key: 'hardening', label: 'Hardening', icon: '🛠️', group: 'Hardening' },
	{ key: 'csp', label: 'CSP Manager', icon: '🔒', group: 'Hardening' },
	{ key: '2fa', label: 'Two-Factor Auth', icon: '🔐', group: 'Hardening' },

	{ key: 'logs', label: 'Audit Log', icon: '📜', group: 'Monitoring' },
	{ key: 'live-traffic', label: 'Live Traffic', icon: '📡', group: 'Monitoring' },
	{ key: 'threat-hunting', label: 'Threat Hunting', icon: '🔍', group: 'Monitoring', pro: true },
	{ key: 'uptime', label: 'Uptime Monitor', icon: '📶', group: 'Monitoring', pro: true },

	{ key: 'sentinel', label: 'Sentinel AI', icon: '🧠', group: 'Intelligence & Compliance', pro: true },
	{ key: 'threatintel', label: 'Threat Intel', icon: '🌐', group: 'Intelligence & Compliance' },
	{ key: 'compliance', label: 'Compliance', icon: '✅', group: 'Intelligence & Compliance', pro: true },
	{ key: 'rest-inventory', label: 'REST Inventory', icon: '🗂️', group: 'Intelligence & Compliance', pro: true },

	{ key: 'agency', label: 'Agency & Hub', icon: '🏢', group: 'Agency & Hub', pro: true },

	// Deliberately visible on Pro too — this is also how an admin re-runs the wizard to switch
	// site-type/protection-level presets later, not just a first-run/upsell screen.
	{ key: 'onboarding', label: 'Setup Wizard', icon: '🚀', group: 'Administration' },
	{ key: 'notifications', label: 'Notifications', icon: '🔔', group: 'Administration' },
	{ key: 'integrations', label: 'Integrations', icon: '🔌', group: 'Administration' },
	{ key: 'reporting', label: 'Reporting', icon: '📄', group: 'Administration', pro: true },
	{ key: 'telemetry', label: 'Bypass Telemetry', icon: '📨', group: 'Administration', advancedOnly: true },
	{ key: 'settings', label: 'Settings', icon: '⚙️', group: 'Administration' },
	{ key: 'upgrade', label: 'About Pro', icon: '⭐', group: 'Loyal Security Pro' },
];

/** Group that lists the Pro screens the Pro plugin has not registered (see ROUTES). */
const PRO_GROUP = 'Loyal Security Pro';

/** Display order of the collapsible sidebar sections. */
const GROUP_ORDER = [
	'Overview',
	'Protection',
	'Hardening',
	'Monitoring',
	'Intelligence & Compliance',
	'Agency & Hub',
	'Administration',
	PRO_GROUP,
];

function NavGroup( { title, routes, active } ) {
	// Groups start expanded; collapse state is local and does not persist across page loads.
	const [ collapsed, setCollapsed ] = useState( false );

	return h(
		'div',
		{ className: 'ts-nav-group' },
		h(
			'button',
			{
				type: 'button',
				className: 'ts-nav-group__title',
				'aria-expanded': collapsed ? 'false' : 'true',
				onClick: () => setCollapsed( ( c ) => ! c ),
			},
			h( 'span', null, title ),
			h( 'span', { className: 'ts-nav-group__toggle', 'aria-hidden': 'true' }, collapsed ? '▸' : '▾' )
		),
		! collapsed &&
			h(
				'ul',
				{ className: 'ts-nav-group__items' },
				routes.map( ( r ) =>
					h(
						'li',
						{ key: r.key },
						h(
							'a',
							{
								href: '#/' + r.key,
								className: cx( 'ts-nav__item', { 'is-active': active === r.key } ),
							},
							h( 'span', { className: 'ts-nav__icon' }, r.icon ),
							h( 'span', { className: 'ts-nav__label' }, r.label ),
							r.proTag && h( 'span', { className: 'ts-nav__tag' }, 'PRO' )
						)
					)
				)
			)
	);
}

export function Sidebar( { active, score } ) {
	const isPro = useIsPro();
	const store = useStore();
	const viewMode = store ? store.state.viewMode : 'advanced';

	// Pro screens the Pro plugin hasn't registered are listed together, tagged PRO.
	const routesFor = ( group ) => ROUTES
		.map( ( r ) => ( r.pro && ! proPanelRegistered( r.key ) ) ? { ...r, group: PRO_GROUP, proTag: true } : r )
		.map( ( r ) => ( 'upgrade' === r.key && isPro ) ? { ...r, label: 'Loyal Security Pro' } : r )
		.filter( ( r ) => r.group === group && ( ! r.advancedOnly || viewMode === 'advanced' ) );

	return h(
		'nav',
		{ className: 'ts-sidebar' },
		h(
			'div',
			{ className: 'ts-brand' },
			h( 'span', { className: 'ts-brand__mark' }, '🛡️' ),
			h( 'span', { className: 'ts-brand__name' }, ( window.LoyalSecurity && window.LoyalSecurity.brand_name ) || 'Loyal Security' )
		),
		store && h(
			'div',
			{ className: 'ts-view-toggle', role: 'group', 'aria-label': 'Dashboard view density' },
			h( 'button', {
				type: 'button',
				className: cx( 'ts-view-toggle__opt', { 'is-active': viewMode === 'basic' } ),
				title: 'Fewer, simpler controls — raw/technical fields stay tucked behind Advanced.',
				onClick: () => store.setViewMode( 'basic' ),
			}, 'Basic' ),
			h( 'button', {
				type: 'button',
				className: cx( 'ts-view-toggle__opt', { 'is-active': viewMode === 'advanced' } ),
				title: 'Every control visible, including raw/technical fields.',
				onClick: () => store.setViewMode( 'advanced' ),
			}, 'Advanced' )
		),
		typeof score === 'number' &&
			h(
				'div',
				{ className: cx( 'ts-scorechip', score >= 80 ? 'is-good' : score >= 65 ? 'is-mid' : 'is-bad' ) },
				h( 'strong', null, score ),
				h( 'span', null, '/100' )
			),
		h(
			'div',
			{ className: 'ts-nav' },
			GROUP_ORDER.map( ( group ) => {
				const routes = routesFor( group );
				if ( ! routes.length ) {
					return null;
				}
				return h( NavGroup, { key: group, title: group, routes, active } );
			} )
		),
		store && h( ThemeToggle, { theme: store.state.theme, onChange: store.setTheme } )
	);
}

/** Light/Dark/System switch for the plugin's own UI — independent of the visitor's OS setting
 *  and of WordPress core's admin color scheme, both of which the CSS also reacts to on their
 *  own (see admin.css's dark-mode block); this lets an admin explicitly override either one
 *  just for this app. Anchored to the bottom of the sidebar via .ts-sidebar__footer. */
function ThemeToggle( { theme, onChange } ) {
	const options = [
		{ value: 'system', label: '🖥️', title: 'Match system' },
		{ value: 'light', label: '☀️', title: 'Light' },
		{ value: 'dark', label: '🌙', title: 'Dark' },
	];
	return h(
		'div',
		{ className: 'ts-sidebar__footer' },
		h( 'span', { className: 'ts-theme-toggle__label' }, 'Theme' ),
		h(
			'div',
			{ className: 'ts-theme-toggle', role: 'group', 'aria-label': 'Theme' },
			options.map( ( opt ) =>
				h( 'button', {
					key: opt.value,
					type: 'button',
					className: cx( 'ts-theme-toggle__opt', { 'is-active': theme === opt.value } ),
					title: opt.title,
					'aria-label': opt.title,
					'aria-pressed': theme === opt.value,
					onClick: () => onChange( opt.value ),
				}, opt.label )
			)
		)
	);
}
