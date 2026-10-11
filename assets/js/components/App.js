/**
 * Root application component: hash router + layout shell.
 *
 * Panels are registered in `PANELS`. As each build phase lands its panel, it is imported
 * and added here; unregistered routes fall back to a friendly placeholder so the app keeps
 * working throughout the phased build.
 */
import { h, useState, useEffect } from '../el.js';
import { StoreProvider } from '../store.js';
import { Sidebar, ROUTES } from './Sidebar.js';
import { Toasts, EmptyState, Card } from './ui.js';
import { Dashboard } from './Dashboard.js';
import { FirewallPanel } from './FirewallPanel.js';
import { Wizard } from './Wizard.js';
import { LogTable } from './LogTable.js';
import { ScanPanel } from './ScanPanel.js';
import { QuarantineList } from './QuarantineList.js';
import { RepairCenter } from './RepairCenter.js';
import { HardeningChecklist } from './HardeningChecklist.js';
import { TwoFactorSetup } from './TwoFactorSetup.js';
import { SettingsForm } from './SettingsForm.js';
import { NotificationsPanel } from './NotificationsPanel.js';
import { IntegrationsPanel } from './IntegrationsPanel.js';
import { BackupPanel } from './BackupPanel.js';
import { ThreatIntelPanel } from './ThreatIntelPanel.js';
import { LiveTraffic } from './LiveTraffic.js';
import { CspPanel } from './CspPanel.js';
import { OnboardingBanner } from './OnboardingBanner.js';
import { OnboardingWizard } from './OnboardingWizard.js';
import { UpgradePanel } from './UpgradePanel.js';
import { TelemetryPanel } from './TelemetryPanel.js';
import { ConsentModal } from './ConsentModal.js';
import { fetchTier, ProPanel } from './ProGate.js';
import { api } from '../api.js';

/**
 * Screens provided by the separate Loyal Security Pro plugin. The free plugin ships no Pro
 * interface code: each route shows the screen Pro registers (window.LoyalSecurity.proPanels),
 * or a short description of the feature when Pro isn't installed.
 */
const PRO_SCREENS = {
	emergency: {
		title: 'Under Attack Mode',
		description: 'A one-click emergency shield for a site under active attack.',
		bullets: [ 'Aggressive rate limits and a bot challenge wall', 'Locks down login, the REST API and XML-RPC', 'Switches itself off after the duration you choose' ],
	},
	agency: {
		title: 'Agency & Hub',
		description: 'Tools for agencies that run security across many sites.',
		bullets: [ 'White-label dashboard under your own brand', 'Security Manager roles with scoped access', 'Hub & satellite view of a whole fleet of sites', 'Multisite network support' ],
	},
	reporting: {
		title: 'Reporting',
		description: 'Scheduled and client-ready security reports.',
		bullets: [ 'Weekly security digest by email', 'Printable, client-ready security report' ],
	},
	'threat-hunting': {
		title: 'Threat Hunting',
		description: 'Find attackers who spread their activity across many requests and IP addresses.',
		bullets: [ 'Correlated incident chains from the audit log', 'IP flows that group addresses used by the same actor', 'One timeline per actor across every IP' ],
	},
	uptime: {
		title: 'Uptime Monitor',
		description: 'External uptime checks with downtime alerts.',
		bullets: [ 'Checks the site from outside every few minutes', '30-day uptime history', 'Alerts when the site goes down and when it comes back' ],
	},
	compliance: {
		title: 'Compliance',
		description: 'Maps the protections you have switched on to common compliance frameworks.',
		bullets: [ 'PCI-DSS, GDPR and SOC 2 control checklists', 'Pass/fail per control with guidance', 'Printable report' ],
	},
	'rest-inventory': {
		title: 'REST Inventory',
		description: 'Every REST API route on the site, grouped by the plugin or theme that registered it.',
		bullets: [ 'Spot routes you did not expect', 'Per-route rate limits' ],
	},
	sentinel: {
		title: 'Sentinel AI',
		description: 'An AI security analyst that reviews suspicious activity and recommends — or takes — a response.',
		bullets: [ 'Plain-language verdicts on suspicious actors', 'Review, autonomous or shadow response modes', 'Every action reversible from the incident feed' ],
	},
};

const proScreen = ( route ) => ( props ) => h( ProPanel, { route, ...PRO_SCREENS[ route ], ...props } );

/** Route key -> component. Extend as panels are built. */
const PANELS = {
	dashboard: Dashboard,
	firewall: FirewallPanel,
	wizard: Wizard,
	logs: LogTable,
	scanner: ScanPanel,
	integrity: ( props ) => h( ScanPanel, { ...props, defaultTab: 'integrity' } ),
	quarantine: QuarantineList,
	repair: RepairCenter,
	backup: BackupPanel,
	hardening: HardeningChecklist,
	'2fa': TwoFactorSetup,
	settings: SettingsForm,
	notifications: NotificationsPanel,
	integrations: IntegrationsPanel,
	threatintel: ThreatIntelPanel,
	'live-traffic': LiveTraffic,
	csp: CspPanel,
	onboarding: OnboardingWizard,
	upgrade: UpgradePanel,
	telemetry: TelemetryPanel,
	...Object.fromEntries( Object.keys( PRO_SCREENS ).map( ( route ) => [ route, proScreen( route ) ] ) ),
};

function Placeholder( { route } ) {
	const meta = ROUTES.find( ( r ) => r.key === route );
	return h(
		Card,
		{ title: meta ? meta.label : 'Coming soon' },
		h( EmptyState, {
			icon: meta ? meta.icon : '🚧',
			title: 'Panel under construction',
			hint: 'This module ships in a later build phase.',
		} )
	);
}

function currentRoute() {
	const hash = window.location.hash.replace( /^#\/?/, '' ).split( '?' )[ 0 ];
	return hash || 'dashboard';
}

export function App() {
	const [ route, setRoute ] = useState( currentRoute() );
	const [ score, setScore ] = useState( null );

	// First-load GDPR consent for anonymous bypass telemetry. Only admins are asked, and only
	// when consent has not yet been recorded against the current policy version.
	const tcfg = ( window.LoyalSecurity && window.LoyalSecurity.telemetry ) || {};
	const canManage = !! ( window.LoyalSecurity && window.LoyalSecurity.caps && window.LoyalSecurity.caps.manage );
	const [ showConsent, setShowConsent ] = useState( !! tcfg.needs_consent && canManage );

	useEffect( () => {
		const onHash = () => setRoute( currentRoute() );
		window.addEventListener( 'hashchange', onHash );
		return () => window.removeEventListener( 'hashchange', onHash );
	}, [] );

	// Refresh the Pro-plugin status now and then (it only changes the wording of Pro teasers).
	useEffect( () => {
		const id = setInterval( () => {
			fetchTier();
		}, 5 * 60 * 1000 );
		return () => clearInterval( id );
	}, [] );

	// Keep the sidebar score chip fresh.
	useEffect( () => {
		let alive = true;
		api.get( '/status' ).then( ( d ) => alive && setScore( d.score ) ).catch( () => {} );
		return () => {
			alive = false;
		};
	}, [ route ] );

	const Panel = PANELS[ route ] || ( () => h( Placeholder, { route } ) );
	const meta = ROUTES.find( ( r ) => r.key === route );

	return h(
		StoreProvider,
		null,
		h(
			'div',
			{ className: 'ts-app' },
			h( Sidebar, { active: route, score } ),
			h(
				'main',
				{ className: 'ts-main' },
				h(
					'header',
					{ className: 'ts-topbar' },
					h( 'h1', null, meta ? meta.label : ( ( window.LoyalSecurity && window.LoyalSecurity.brand_name ) || 'Loyal Security' ) )
				),
				h(
					'div',
					{ className: 'ts-content' },
					h( OnboardingBanner, null ),
					h( Panel, null )
				),
				// Countries shown on these screens come from Cloudflare when the site is behind it,
				// otherwise from the bundled DB-IP Lite table. Its licence (CC BY 4.0, see
				// data/geo/NOTICE.txt) asks for this link on pages that display or use its results.
				h(
					'footer',
					{ className: 'ts-footer-credit' },
					'Country data: ',
					h( 'a', { href: 'https://db-ip.com', target: '_blank', rel: 'noopener noreferrer' }, 'IP Geolocation by DB-IP' )
				)
			),
			h( Toasts, null ),
			showConsent &&
				h( ConsentModal, {
					onResolved: () => setShowConsent( false ),
				} )
		)
	);
}
