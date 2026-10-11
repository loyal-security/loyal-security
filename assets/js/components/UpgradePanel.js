/**
 * About Pro — what the separate Loyal Security Pro plugin adds, with live plan data fetched from
 * LicenseKit through the plugin's own REST proxy (`GET /upgrade/pricing` →
 * `Core\LicenseKit::pricing()`), rendered natively as part of the dashboard.
 *
 * This deliberately does NOT iframe LicenseKit's own pricing page: an admin screen that's
 * mostly a remote site in an iframe reads as an ad wrapper rather than plugin UI to
 * WordPress.org reviewers, and it would silently break if LicenseKit ever added
 * frame-blocking headers of its own (which, for a security product's billing pages, it
 * probably should). Fetching the data and rendering it with the dashboard's own components
 * keeps the same "always matches the live catalog" property without either risk.
 */
import { h, useState, useEffect } from '../el.js';
import { api } from '../api.js';
import { Spinner, Card, LoadError } from './ui.js';
import { ProGate } from './ProGate.js';

const BILLING_LABEL = {
	monthly: '/mo',
	yearly: '/yr',
	one_time: '',
	lifetime: '',
};

const FEATURES = [
	{ icon: '🚨', title: 'Under Attack Mode', body: 'One click applies the full emergency posture — aggressive rate limits, a bot challenge wall, and locked-down login/REST/XML-RPC surfaces — and auto-expires so it can’t be left on by accident.' },
	{ icon: '🛰️', title: 'Live threat intelligence', body: 'Hourly WAF signature updates and CVE-matched virtual patching for what’s actually installed on your site, with automatic patching as new advisories publish.' },
	{ icon: '🤖', title: 'Sentinel AI triage', body: 'Correlates firewall matches, login attempts, and audit events into an evidence bundle and returns a threat verdict — so a hundred blocks becomes one actionable case.' },
	{ icon: '🗓️', title: 'Faster scans & auto-quarantine', body: 'Daily or twice-daily malware scans (the free plugin scans weekly), and infected files are isolated the moment a critical match is found.' },
	{ icon: '📊', title: 'Reporting & compliance', body: 'Extended audit retention, scheduled digests, PDF export, and a compliance checker mapping active controls to common framework expectations.' },
	{ icon: '🛒', title: 'WooCommerce delta backup', body: 'Continuous capture of order, customer, and stock changes between full backups, so a restore never silently discards a day of transactions.' },
	{ icon: '🏢', title: 'Agency tooling', body: 'Hub-and-satellite fleet dashboard, white-label branding, and security-manager roles for staff who shouldn’t need full WordPress admin access.' },
];

function formatPrice( cents ) {
	return '$' + ( cents / 100 ).toFixed( 2 ).replace( /\.00$/, '' );
}

function PlanCard( { plan, checkoutUrl } ) {
	const suffix = BILLING_LABEL[ plan.billing_period ] || '';
	const isYearly = plan.billing_period === 'yearly';
	return h(
		'div',
		{ className: 'ts-upgrade-plan' + ( isYearly ? ' ts-upgrade-plan--best' : '' ) },
		isYearly && h( 'div', { className: 'ts-upgrade-plan__ribbon' }, 'Best value' ),
		h( 'div', { className: 'ts-upgrade-plan__name' }, plan.name ),
		h(
			'div',
			{ className: 'ts-upgrade-plan__price' },
			formatPrice( plan.price ),
			suffix && h( 'span', { className: 'ts-upgrade-plan__suffix' }, suffix )
		),
		h(
			'div',
			{ className: 'ts-upgrade-plan__meta' },
			plan.activation_limit + ' site' + ( plan.activation_limit !== 1 ? 's' : '' )
		),
		plan.purchasable
			? h(
				'a',
				{
					className: 'ts-btn ts-btn--primary',
					href: checkoutUrl,
					target: '_blank',
					rel: 'noopener noreferrer',
				},
				'Get ' + plan.name
			)
			: h( 'span', { className: 'ts-btn ts-btn--ghost is-disabled', title: 'Checkout for this plan isn’t live yet' }, 'Coming soon' )
	);
}

function FeatureGrid() {
	return h(
		'div',
		{ className: 'ts-upgrade-features' },
		FEATURES.map( ( f ) =>
			h(
				'div',
				{ key: f.title, className: 'ts-upgrade-feature' },
				h( 'div', { className: 'ts-upgrade-feature__icon' }, f.icon ),
				h( 'div', { className: 'ts-upgrade-feature__title' }, f.title ),
				h( 'p', { className: 'ts-upgrade-feature__body' }, f.body )
			)
		)
	);
}

/**
 * Where a buyer goes next. The free plugin has no licence field: the licence is activated inside
 * the separate Pro plugin, which can register its own licence card here (`license.manage`).
 */
function GetProCard( { isPro } ) {
	const cfg = window.LoyalSecurity || {};
	const getProUrl = cfg.checkout_url || cfg.pricing_url || '#';
	return h( ProGate, {
		feature: 'license.manage',
		fallback: h( Card, { title: isPro ? 'Loyal Security Pro is active' : 'Already bought Loyal Security Pro?' },
			h( 'p', null,
				isPro
					? 'Manage your licence from the Loyal Security Pro plugin.'
					: 'Pro is a separate plugin you download after purchase. Install and activate it like any other plugin, then enter your licence key in it.'
			),
			! isPro && h( 'a', { className: 'ts-btn ts-btn--primary', href: getProUrl, target: '_blank', rel: 'noopener noreferrer' },
				'Get Loyal Security Pro →'
			)
		),
	} );
}

export function UpgradePanel() {
	const cfg   = window.LoyalSecurity || {};
	const isPro = cfg.tier === 'pro';

	const [ data,    setData    ] = useState( null );
	const [ error,   setError   ] = useState( null );
	const [ loading, setLoading ] = useState( true );

	const load = () => {
		setLoading( true );
		setError( null );
		api.get( '/upgrade/pricing' )
			.then( ( res ) => setData( res ) )
			.catch( ( err ) => setError( err.message || 'Failed to load pricing.' ) )
			.finally( () => setLoading( false ) );
	};

	useEffect( () => {
		if ( ! isPro ) load();
	}, [] );

	if ( isPro ) {
		return h( 'div', { className: 'ts-upgrade-page' }, h( GetProCard, { isPro } ) );
	}

	const fallbackUrl = cfg.pricing_url || 'https://licensekit.loyalsecuritywp.com/pricing';
	// This panel is embedded in one specific site's dashboard, so only single-site plans belong
	// here — an admin managing this one site has no use for a 25-site Agency tier. Agencies buy
	// those directly from the LicenseKit pricing page (linked below and in the empty state).
	const allPlans     = data && data.available ? data.plans : [];
	const plans        = allPlans.filter( ( p ) => ( p.activation_limit || 1 ) <= 1 );
	const checkoutUrl  = ( data && data.checkout_url ) || cfg.checkout_url || fallbackUrl;

	return h(
		'div',
		{ className: 'ts-upgrade-page' },

		h(
			Card,
			{ title: 'Free protects a site. Pro runs an operation.' },
			h(
				'p',
				{ style: { color: 'var(--ts-text)' } },
				'Loyal Security is a complete security suite — dual-mode WAF, hardening, malware scanning, integrity monitoring, 2FA, backups, and audit logging, with nothing locked. Loyal Security Pro is a separate plugin that adds automation, hourly threat-intelligence updates and agency tools.'
			),
			h( FeatureGrid, null )
		),

		h(
			Card,
			{ title: 'Plans' },

			loading && h(
				'div',
				{ className: 'ts-upgrade-loading' },
				h( Spinner, null ),
				h( 'span', null, 'Loading pricing…' )
			),

			! loading && error && h( LoadError, { message: error, onRetry: load } ),

			! loading && ! error && plans.length === 0 && h(
				'div',
				{ className: 'ts-notice' },
				h( 'p', null, 'Pricing isn’t available to display here right now.' ),
				h(
					'a',
					{ className: 'ts-btn ts-btn--primary', href: fallbackUrl, target: '_blank', rel: 'noopener noreferrer' },
					'View plans on LicenseKit →'
				)
			),

			! loading && ! error && plans.length > 0 && h(
				'div',
				{ className: 'ts-upgrade-plans' },
				plans.map( ( plan ) => h( PlanCard, { key: plan.id, plan, checkoutUrl: checkoutUrl } ) )
			),

			! loading && ! error && plans.length > 0 && h(
				'p',
				{ className: 'ts-upgrade-footnote' },
				'Licensed per site. You activate or move a licence from inside the Loyal Security Pro plugin — no support ticket needed.'
			),

			! loading && ! error && h(
				'p',
				{ className: 'ts-upgrade-footnote' },
				'Managing more than one site? ',
				h( 'a', { href: fallbackUrl, target: '_blank', rel: 'noopener noreferrer' }, 'See multi-site & agency plans →' )
			)
		),

		h( GetProCard, { isPro } )
	);
}
