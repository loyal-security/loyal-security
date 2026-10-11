/**
 * Firewall panel — WAF mode, activity stats, and IP ban management.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState, LoadError, Toggle, Modal } from './ui.js';
import { eventTypeMeta } from '../events.js';
import { useStore } from '../store.js';
import { ConsentModal } from './ConsentModal.js';
import { ProGate, useIsPro } from './ProGate.js';

export function FirewallPanel() {
	const store = useStore();
	const viewMode = store ? store.state.viewMode : 'advanced';
	const [ stats, setStats ] = useState( null );
	const [ statsError, setStatsError ] = useState( null );
	const [ bans, setBans ] = useState( null );
	const [ bansError, setBansError ] = useState( null );
	const [ bansOffset, setBansOffset ] = useState( 0 );
	const [ form, setForm ] = useState( { ip: '', reason: '', type: 'temporary', ttl: 3600 } );
	const [ busy, setBusy ] = useState( false );
	const [ settings, setSettings ] = useState( null );
	const [ suggestions, setSuggestions ] = useState( null );
	const [ virtualPatches, setVirtualPatches ] = useState( null );
	const [ patchError, setPatchError ] = useState( null );
	const [ patchBusy, setPatchBusy ] = useState( '' );
	const [ patchTab, setPatchTab ] = useState( 'suggested' );
	const [ consentPromptFor, setConsentPromptFor ] = useState( null );
	const [ botRules, setBotRules ] = useState( null );
	const [ botRulesError, setBotRulesError ] = useState( null );
	const [ botForm, setBotForm ] = useState( { signature: '', type: 'verified', trustedSuffix: '', note: '' } );
	const [ botBusy, setBotBusy ] = useState( false );
	const [ botToggling, setBotToggling ] = useState( '' );
	const isPro = useIsPro();
	const [ botModalOpen, setBotModalOpen ] = useState( false );
	const [ importSources, setImportSources ] = useState( null );
	const [ importBusy, setImportBusy ] = useState( false );
	const [ importResults, setImportResults ] = useState( null );
	const [ loginProtectionModalOpen, setLoginProtectionModalOpen ] = useState( false );
	// Summary stats for the collapsed Bot Management card — the detailed cards (rules table, AI
	// suggestions, faceted-search settings) still load their data on panel mount as before; only
	// their on-screen presentation moved into the popup, so these counts are ready before it opens.
	const botTrustedCount = ( botRules || [] ).filter( ( r ) => 'verified' === r.type && r.enabled ).length;
	const botBlockedCount = ( botRules || [] ).filter( ( r ) => 'blocked' === r.type && r.enabled ).length;
	const botFacetedOn = settings ? ( settings.query_cardinality_enabled !== false ) : null;
	// Real evidence this specific site would benefit from Sentinel AI's bot suggestions —
	// only shown when it's true, tied to this site's own last-7-days activity, not a generic
	// upsell shown to everyone regardless of whether it applies to them.
	const botBlocks7d = ( ( stats && stats.by_type ) || [] ).find( ( r ) => 'waf.bot.block' === r.event_type );
	const botBlocks7dCount = botBlocks7d ? Number( botBlocks7d.c ) || 0 : 0;
	// Anonymous data-sharing consent (shared with Bypass Telemetry / Cloud Reputation). When
	// already given, approving a suggestion submits it to the cloud automatically (server side)
	// — the "Submit to Cloud" action only needs to appear while consent is still missing, where
	// it doubles as the consent prompt.
	const consentGiven = !! ( window.LoyalSecurity && window.LoyalSecurity.telemetry && window.LoyalSecurity.telemetry.consent_given );

	const BANS_PER_PAGE = 50;
	const loadStats = () => api.get( '/firewall/stats' ).then( ( d ) => { setStats( d ); setStatsError( null ); } )
		.catch( ( e ) => setStatsError( e.message || 'Failed to load firewall stats.' ) );
	// Paginated: without passing offset/per_page the server capped at 50, so bans beyond the
	// first page were invisible AND unremovable while the badge still reported the true total.
	const loadBans = ( offset = bansOffset ) => api.get( '/firewall/bans', { per_page: BANS_PER_PAGE, offset } )
		.then( ( d ) => { setBans( d ); setBansOffset( offset ); setBansError( null ); } )
		.catch( ( e ) => setBansError( e.message || 'Failed to load active bans.' ) );
	// On failure, set the list to [] (not left null) so renderPatchList shows the empty state
	// under the error banner instead of an eternal spinner.
	const loadSuggestions = () => api.get( '/firewall/patch-suggestions' ).then( ( d ) => { setSuggestions( d.items || [] ); setPatchError( null ); } ).catch( ( e ) => { setSuggestions( [] ); setPatchError( e.message || 'Failed to load virtual patches.' ); } );
	const loadVirtualPatches = () => api.get( '/firewall/virtual-patches' ).then( ( d ) => { setVirtualPatches( d.items || [] ); setPatchError( null ); } ).catch( ( e ) => { setVirtualPatches( [] ); setPatchError( e.message || 'Failed to load virtual patches.' ); } );
	const loadBotRules = () => api.get( '/firewall/bot-rules' ).then( ( d ) => { setBotRules( d.items || [] ); setBotRulesError( null ); } ).catch( ( e ) => { setBotRules( [] ); setBotRulesError( e.message || 'Failed to load bot rules.' ); } );


	useEffect( () => {
		loadStats();
		loadBans();
		loadSuggestions();
		loadVirtualPatches();
		loadBotRules();
		api.get( '/settings' ).then( ( d ) => d.firewall && setSettings( d.firewall ) ).catch( () => {} );
		api.get( '/firewall/import/detect' ).then( ( d ) => setImportSources( d.sources || {} ) ).catch( () => setImportSources( {} ) );
	}, [] );

	const runCompetitorImport = async () => {
		setImportBusy( true );
		try {
			const res = await api.post( '/firewall/import/run', {} );
			setImportResults( res.results || {} );
			const totalImported = Object.values( res.results || {} ).reduce( ( sum, r ) => sum + ( r.imported || 0 ) + ( r.whitelisted || 0 ), 0 );
			store.toast( totalImported > 0 ? `Imported ${ totalImported } IP entr${ 1 === totalImported ? 'y' : 'ies' }.` : 'Nothing new to import.', 'success' );
			loadBans();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setImportBusy( false );
		}
	};

	const addBotRule = async () => {
		const signature = botForm.signature.trim();
		if ( ! signature ) {
			store.toast( 'Enter a user-agent signature to match.', 'warning' );
			return;
		}
		setBotBusy( true );
		try {
			await api.post( '/firewall/bot-rules', {
				signature,
				type: botForm.type,
				trusted_suffix: botForm.trustedSuffix.trim(),
				note: botForm.note.trim(),
			} );
			store.toast( 'Bot rule added.', 'success' );
			setBotForm( { signature: '', type: 'verified', trustedSuffix: '', note: '' } );
			loadBotRules();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBotBusy( false );
		}
	};

	const toggleBotRule = async ( rule, enabled ) => {
		setBotToggling( rule.id );
		const prev = botRules;
		setBotRules( botRules.map( ( r ) => ( r.id === rule.id ? { ...r, enabled } : r ) ) );
		try {
			await api.post( '/firewall/bot-rules/toggle', { id: rule.id, enabled } );
		} catch ( e ) {
			setBotRules( prev );
			store.toast( e.message, 'error' );
		} finally {
			setBotToggling( '' );
		}
	};

	const removeBotRule = async ( rule ) => {
		if ( ! window.confirm( 'Remove the bot rule for "' + rule.signature + '"?' ) ) return;
		try {
			await api.post( '/firewall/bot-rules/delete', { id: rule.id } );
			store.toast( 'Bot rule removed.', 'success' );
			loadBotRules();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	// Enable/disable an already-approved virtual patch without deleting it.
	const toggleVirtualPatch = async ( rule, enabled ) => {
		setPatchBusy( 'vp-toggle:' + rule.id );
		const prev = virtualPatches;
		setVirtualPatches( virtualPatches.map( ( r ) => ( r.id === rule.id ? { ...r, enabled } : r ) ) );
		try {
			await api.post( '/firewall/virtual-patches/toggle', { id: rule.id, enabled } );
			store.toast( enabled ? 'Virtual patch enabled.' : 'Virtual patch disabled.', 'success' );
		} catch ( e ) {
			setVirtualPatches( prev );
			store.toast( e.message, 'error' );
		} finally {
			setPatchBusy( '' );
		}
	};

	const deleteVirtualPatch = async ( rule ) => {
		if ( ! window.confirm( 'Remove this virtual patch permanently? This cannot be undone.' ) ) {
			return;
		}
		setPatchBusy( 'vp-delete:' + rule.id );
		try {
			await api.post( '/firewall/virtual-patches/delete', { id: rule.id } );
			store.toast( 'Virtual patch removed.', 'success' );
			loadVirtualPatches();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setPatchBusy( '' );
		}
	};

	// Review action on a finding's auto-drafted virtual-patch suggestion (see PatchSuggester).
	const patchAction = async ( f, action ) => {
		setPatchBusy( 'patch:' + action + ':' + f.id );
		try {
			const res = await api.post( '/scan/findings/patch', { id: f.id, action } );
			if ( 'approve' === action && res.patch_status !== 'submitted' && res.cloud_error ) {
				// Applying locally always succeeds independently — this only means the
				// same-step cloud auto-submit didn't, and why (surfaced instead of silently
				// staying "Applied locally" with no explanation). cloud_error_body is
				// LicenseKit's actual response body (e.g. a Zod validation message) — shown
				// so a rejection is diagnosable from the browser, no server log access needed.
				store.toast(
					'Virtual patch applied locally, but cloud submission failed: ' + res.cloud_error
						+ ( res.cloud_error_body ? ' — ' + res.cloud_error_body : '' ),
					'warning'
				);
			} else {
				store.toast(
					action === 'reject' ? 'Suggestion dismissed.'
						: action === 'submit_cloud' ? 'Submitted to cloud for review.'
						: res.patch_status === 'submitted' ? 'Virtual patch applied and submitted to cloud — live now.'
						: 'Virtual patch applied — live now.',
					'success'
				);
			}
			loadSuggestions();
			// Approving adds the rule to CustomVirtualPatches server-side, so the Active/Disabled
			// tab lists and their counts are now stale until the virtual-patch list is reloaded
			// too. (reject/submit_cloud don't change that list.)
			if ( 'approve' === action ) {
				loadVirtualPatches();
			}
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setPatchBusy( '' );
		}
	};

	// Save a single setting change immediately; optimistic update with rollback on error.
	const toggleSetting = async ( key, value ) => {
		const prev = settings;
		const next = { ...settings, [ key ]: value };
		setSettings( next );
		try {
			const saved = await api.post( '/settings/firewall', next );
			setSettings( saved );
		} catch ( e ) {
			setSettings( prev );
			store.toast( e.message, 'error' );
		}
	};

	const addBan = async () => {
		if ( ! form.ip ) {
			store.toast( 'Enter an IP or CIDR range.', 'warning' );
			return;
		}
		setBusy( true );
		try {
			await api.post( '/firewall/bans', form );
			store.toast( 'Ban added.', 'success' );
			setForm( { ip: '', reason: '', type: 'temporary', ttl: 3600 } );
			loadBans();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( false );
		}
	};

	const removeBan = async ( ip ) => {
		try {
			await api.post( '/firewall/bans/delete', { ip } );
			store.toast( 'Ban removed.', 'success' );
			loadBans();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	const mode = stats ? stats.mode : '…';
	const firewallEnabled = settings ? settings.enabled !== false : true;
	const trustBadgeEnabled = !! ( settings && settings.trust_badge_enabled );
	const trustBadgeFloating = ! settings || settings.trust_badge_floating !== false;
	const trustBadgePosition = ( settings && settings.trust_badge_position ) || 'bottom-right';
	const trustBadgeStyle = ( settings && settings.trust_badge_style ) || 'dark';

	return h(
		Fragment,
		null,

		/* ---- Migrate from another security plugin (only shown if one is detected) ------- */
		importSources && Object.values( importSources ).some( ( s ) => s.detected ) && ! importResults && h(
			Card,
			{ title: '📦 Switching from another security plugin?' },
			h( 'p', { style: { marginTop: 0 } },
				'Found IP allow/block list data from: ',
				h( 'strong', null, Object.values( importSources ).filter( ( s ) => s.detected ).map( ( s ) => s.name ).join( ', ' ) ),
				'. Import it here instead of retyping it by hand — nothing already in your lists is changed or removed.'
			),
			h( Button, { variant: 'primary', disabled: importBusy, onClick: runCompetitorImport }, importBusy ? 'Importing…' : 'Import IP lists' )
		),
		importResults && h(
			Card,
			{ title: '📦 Import results' },
			h( 'table', { className: 'ts-table' },
				h( 'thead', null, h( 'tr', null, h( 'th', null, 'Source' ), h( 'th', null, 'Found' ), h( 'th', null, 'Blocked imported' ), h( 'th', null, 'Whitelisted' ) ) ),
				h( 'tbody', null, Object.keys( importResults ).map( ( slug ) => {
					const r = importResults[ slug ];
					const name = ( importSources && importSources[ slug ] && importSources[ slug ].name ) || slug;
					return h( 'tr', { key: slug },
						h( 'td', null, name ),
						h( 'td', null, r.error ? h( Badge, { tone: 'danger' }, 'Error' ) : r.found ),
						h( 'td', null, r.imported || 0 ),
						h( 'td', null, r.whitelisted || 0 )
					);
				} ) )
			)
		),

		h(
			Card,
			{
				title: '🏷️ Trust Badge',
				actions: settings !== null && h( Toggle, {
					checked: trustBadgeEnabled,
					onChange: ( v ) => toggleSetting( 'trust_badge_enabled', v ),
					label: trustBadgeEnabled ? 'Enabled' : 'Disabled',
				} ),
			},
			h( 'p', { style: { marginTop: 0 } },
				'Show visitors this site is actively protected, with a real, live 30-day attack count. Costs nothing, and every site that displays it is a bit of free word-of-mouth for the plugin.'
			),
			! trustBadgeEnabled && h( 'p', { className: 'ts-hint', style: { marginTop: 0 } },
				'Off by default. Once enabled it appears on its own as a floating badge — like a cookie notice — no shortcode needed.'
			),
			trustBadgeEnabled && h( Fragment, null,
				settingRow(
					'Show as floating badge',
					'Appears automatically in the corner of every public page. Turn this off to place it yourself instead, using the shortcode below.',
					trustBadgeFloating,
					( v ) => toggleSetting( 'trust_badge_floating', v )
				),
				trustBadgeFloating && h( 'div', { style: { display: 'flex', gap: '16px', flexWrap: 'wrap', marginTop: '4px' } },
					field( 'Position', h( 'select', {
						id: 'ts-badge-position', name: 'trust_badge_position', value: trustBadgePosition,
						onChange: ( e ) => toggleSetting( 'trust_badge_position', e.target.value ),
					},
						h( 'option', { value: 'bottom-right' }, 'Bottom right' ),
						h( 'option', { value: 'bottom-left' }, 'Bottom left' )
					), 'ts-badge-position' ),
					field( 'Appearance', h( 'select', {
						id: 'ts-badge-style', name: 'trust_badge_style', value: trustBadgeStyle,
						onChange: ( e ) => toggleSetting( 'trust_badge_style', e.target.value ),
					},
						h( 'option', { value: 'dark' }, 'Dark' ),
						h( 'option', { value: 'light' }, 'Light' )
					), 'ts-badge-style' )
				)
			),
			h( 'p', { className: 'ts-hint', style: { marginTop: '14px', marginBottom: '4px' } },
				trustBadgeEnabled && trustBadgeFloating
					? 'Want it in a specific spot instead of floating? Place it yourself with this shortcode:'
					: 'Place it yourself with this shortcode:'
			),
			h( 'div', { style: { display: 'flex', gap: '8px', alignItems: 'center', opacity: trustBadgeEnabled ? 1 : 0.5 } },
				h( 'code', { style: { flex: '1 1 auto', background: 'var(--ts-bg)', padding: '8px 10px', borderRadius: '6px', fontSize: '13px' } }, '[loyal_security_badge]' ),
				h( Button, {
					variant: 'ghost',
					onClick: () => {
						try { navigator.clipboard.writeText( '[loyal_security_badge]' ); store.toast( 'Shortcode copied.', 'success' ); }
						catch ( e ) { store.toast( 'Copy failed — select the text manually.', 'error' ); }
					},
				}, 'Copy' )
			),
			h( 'p', { className: 'ts-hint', style: { marginBottom: 0 } },
				'Paste it into any widget, page, or post. Add ', h( 'code', null, 'style="light"' ), ' for a light-background version: ',
				h( 'code', null, '[loyal_security_badge style="light"]' )
			)
		),

		/* ---- Global enable/disable ---------------------------------------- */
		h(
			Card,
			{
				title: '🔥 Web Application Firewall',
				actions: settings !== null && h(
					Toggle,
					{
						checked: firewallEnabled,
						onChange: ( v ) => toggleSetting( 'enabled', v ),
						label: firewallEnabled ? 'Active' : 'Disabled',
					}
				),
			},
			h( 'p', null,
				firewallEnabled
					? 'The firewall is actively protecting your site. Toggle off to temporarily disable all WAF checks.'
					: h( 'strong', { style: { color: '#dc2626' } }, '⚠️ Firewall is disabled. Your site is not protected by the Loyal Security firewall.' )
			)
		),

		h(
			Card,
			{
				title: '🔐 Login Protection & Access Rules',
				actions: h( Button, { variant: 'primary', onClick: () => setLoginProtectionModalOpen( true ) }, 'Manage' ),
			},
			h( 'p', { className: 'ts-hint', style: { marginTop: 0 } },
				'Audit mode, admin bypass rules, and brute-force lockout thresholds for the login form.'
			),
			settings && h( 'div', { style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
				h( Badge, { tone: settings.detection_only ? 'warning' : 'success' }, settings.detection_only ? 'Audit mode: On' : 'Blocking: Active' ),
				h( Badge, { tone: 'neutral' }, 'Lockout after ' + ( settings.bruteforce_max ?? 5 ) + ' attempts' ),
				h( Badge, { tone: settings.bruteforce_escalation_enabled !== false ? 'success' : 'neutral' }, 'Escalating lockouts: ' + ( settings.bruteforce_escalation_enabled !== false ? 'On' : 'Off' ) )
			)
		),

		h( Modal, {
			open: loginProtectionModalOpen,
			onClose: () => setLoginProtectionModalOpen( false ),
			title: 'Login Protection & Access Rules',
			icon: '🔐',
			size: 'lg',
		},

		h(
			Card,
			{ title: 'Protection mode' },
			settings === null
				? h( Spinner, null )
				: h(
					Fragment,
					null,
					settingRow(
						'Audit mode (log-only)',
						'Detects and logs attacks but never blocks them. Use this for a few days to confirm no false positives before enabling full protection.',
						!! settings.detection_only,
						( v ) => toggleSetting( 'detection_only', v )
					),
					settingRow(
						'Auto-whitelist admin IPs on login',
						'Adds your IP to the bypass list the moment you log in as an administrator, preventing accidental self-lockout from DDoS burst or rate-limit bans.',
						settings.auto_whitelist_admins !== false,
						( v ) => toggleSetting( 'auto_whitelist_admins', v )
					),
					settingRow(
						'Skip heuristic checks for logged-in admins',
						'Bypasses bot, geo, rate-limit, and signature checks for users with admin rights. Active IP bans still apply.',
						settings.whitelist_admins !== false,
						( v ) => toggleSetting( 'whitelist_admins', v )
					)
				)
		),

		h(
			Card,
			{ title: '🔐 Login Protection' },
			settings === null
				? h( Spinner, null )
				: h(
					Fragment,
					null,
					h( NumberRow, {
						id: 'firewall.bruteforce_max',
						label: 'Failed attempts before lockout',
						hint: 'How many failed logins from one IP within the window below trigger a lockout.',
						value: settings.bruteforce_max ?? 5,
						onCommit: ( v ) => toggleSetting( 'bruteforce_max', v ),
					} ),
					h( NumberRow, {
						id: 'firewall.bruteforce_window',
						label: 'Window',
						hint: 'How far back failed attempts are counted toward the threshold above.',
						value: settings.bruteforce_window ?? 600,
						suffix: 'seconds',
						onCommit: ( v ) => toggleSetting( 'bruteforce_window', v ),
					} ),
					h( NumberRow, {
						id: 'firewall.bruteforce_lockout',
						label: 'Base lockout',
						hint: 'How long a first-time lockout lasts. Repeat offenders get progressively longer bans below.',
						value: settings.bruteforce_lockout ?? 1800,
						suffix: 'seconds',
						onCommit: ( v ) => toggleSetting( 'bruteforce_lockout', v ),
					} ),
					settingRow(
						'Escalating lockouts for repeat offenders',
						'Each time the same IP earns another lockout within the escalation window, the ban duration multiplies instead of staying flat.',
						settings.bruteforce_escalation_enabled !== false,
						( v ) => toggleSetting( 'bruteforce_escalation_enabled', v )
					),
					settings.bruteforce_escalation_enabled !== false && h(
						Fragment,
						null,
						h( NumberRow, {
							id: 'firewall.bruteforce_escalation_multiplier',
							label: 'Escalation multiplier',
							hint: 'Each repeat lockout is this many times longer than the last, up to the cap below.',
							value: settings.bruteforce_escalation_multiplier ?? 2,
							suffix: '×',
							onCommit: ( v ) => toggleSetting( 'bruteforce_escalation_multiplier', v ),
						} ),
						h( NumberRow, {
							id: 'firewall.bruteforce_escalation_cap',
							label: 'Maximum lockout',
							hint: 'Escalation never pushes a temporary lockout past this length.',
							value: settings.bruteforce_escalation_cap ?? 86400,
							suffix: 'seconds',
							onCommit: ( v ) => toggleSetting( 'bruteforce_escalation_cap', v ),
						} ),
						h( NumberRow, {
							id: 'firewall.bruteforce_escalation_window',
							label: 'Escalation memory',
							hint: 'How far back past lockouts still count as repeat offenses. Older lockouts age out and stop escalating the next one.',
							value: settings.bruteforce_escalation_window ?? 604800,
							suffix: 'seconds',
							onCommit: ( v ) => toggleSetting( 'bruteforce_escalation_window', v ),
						} )
					)
				)
		)
		),

		h(
			Card,
			{
				title: '🤖 Bot Management',
				actions: h( Button, { variant: 'primary', onClick: () => setBotModalOpen( true ) }, 'Manage bot rules' ),
			},
			h( 'p', { className: 'ts-hint', style: { marginTop: 0 } },
				'Trusted crawlers, blocked signatures, the verified-bot rate tier and faceted-search abuse protection, all in one place.'
			),
			h( 'div', { style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
				h( Badge, { tone: 'success' }, botTrustedCount + ' trusted' ),
				h( Badge, { tone: botBlockedCount ? 'danger' : 'neutral' }, botBlockedCount + ' blocked' ),
				null !== botFacetedOn && h( Badge, { tone: botFacetedOn ? 'success' : 'neutral' }, 'Faceted-search: ' + ( botFacetedOn ? 'On' : 'Off' ) )
			),
			botBlocks7dCount > 0 && h( 'p', { className: 'ts-hint', style: { marginTop: '12px', marginBottom: 0 } },
				'This site blocked ', h( 'strong', null, botBlocks7dCount ), ' bot request' + ( 1 === botBlocks7dCount ? '' : 's' ) + ' in the last 7 days.'
			)
		),

		h( Modal, {
			open: botModalOpen,
			onClose: () => setBotModalOpen( false ),
			title: 'Bot Management',
			icon: '🤖',
			size: 'lg',
		},
		h( ProGate, {
			feature: 'firewall.cloudflare',
			title: 'Cloudflare Edge Sync',
			bullets: [
				'Push blocked bot signatures to Cloudflare Custom Rules — rejected at the edge, before they reach your server.',
				'Works alongside the origin firewall below; your own Cloudflare dashboard rules are never touched.',
			],
		} ),
		h(
			Card,
			{ title: '🤖 Verified Bots' },
			settings === null
				? h( Spinner, null )
				: h(
					Fragment,
					null,
					h( 'p', { className: 'ts-hint', style: { marginTop: 0 } },
						'A request claiming to be Googlebot, Bingbot, or another known crawler is checked with forward-confirmed reverse DNS — never live, in the request path; verification runs in the background and a claim is treated as an ordinary visitor until confirmed. A verified bot gets the more generous rate tier below instead of the everyday visitor limit.'
					),
					settingRow(
						'Enable verified-bot rate tier',
						'When off, known-bot user agents are still never blocked outright (see the bad-agent list above), they just get no rate-limit concession.',
						settings.bot_verify_enabled !== false,
						( v ) => toggleSetting( 'bot_verify_enabled', v )
					),
					settings.bot_verify_enabled !== false && h(
						Fragment,
						null,
						h( NumberRow, {
							id: 'firewall.bot_verify_requests',
							label: 'Verified-bot request limit',
							hint: 'Requests allowed per window for a confirmed bot — separate from, and typically higher than, the everyday visitor limit.',
							value: settings.bot_verify_requests ?? 600,
							suffix: 'requests',
							onCommit: ( v ) => toggleSetting( 'bot_verify_requests', v ),
						} ),
						h( NumberRow, {
							id: 'firewall.bot_verify_window',
							label: 'Window',
							hint: 'The time window the request limit above applies over.',
							value: settings.bot_verify_window ?? 60,
							suffix: 'seconds',
							onCommit: ( v ) => toggleSetting( 'bot_verify_window', v ),
						} ),
						h( NumberRow, {
							id: 'firewall.bot_verify_ttl_days',
							label: 'Re-verify after',
							hint: 'How long a verified verdict is trusted before that IP is checked again.',
							value: settings.bot_verify_ttl_days ?? 30,
							suffix: 'days',
							onCommit: ( v ) => toggleSetting( 'bot_verify_ttl_days', v ),
						} )
					)
				)
		),

		h(
			Card,
			{ title: '🚫 Blocked Bot Groups' },
			settings === null
				? h( Spinner, null )
				: h(
					Fragment,
					null,
					h( 'p', { className: 'ts-hint', style: { marginTop: 0 } },
						'Vulnerability scanners and attack tools (sqlmap, Nikto, WPScan and similar) are always blocked. The two groups below are off by default because legitimate services use them.'
					),
					settingRow(
						'Block generic HTTP clients (curl, python-requests, Go)',
						'Payment webhooks, shipping and accounting integrations, uptime checks and server cron jobs often use these clients. Turn this on only if nothing on your site receives such calls.',
						!! settings.block_http_clients,
						( v ) => toggleSetting( 'block_http_clients', v )
					),
					settingRow(
						'Block SEO crawlers (Ahrefs, Semrush, Majestic, Moz, Petal)',
						'These crawlers can be heavy, but SEO tools you use on your own site rely on them, and Petal is a search engine.',
						!! settings.block_seo_crawlers,
						( v ) => toggleSetting( 'block_seo_crawlers', v )
					)
				)
		),

		h(
			Card,
			{ title: '📋 Bot Rules', actions: botRules ? h( Badge, { tone: 'neutral' }, botRules.length ) : null },
			h( 'p', { className: 'ts-hint', style: { marginTop: 0 } },
				'Every trusted crawler and every bot you have blocked or added by hand, in one list. Builtin entries can be disabled but not removed; anything you add here can be fully removed.'
			),
			h( 'div', { className: 'ts-banform' },
				field( 'Signature (UA substring)', h( 'input', {
					id: 'ts-bot-signature', name: 'bot_signature', type: 'text',
					value: botForm.signature, placeholder: 'e.g. mycustombot',
					onChange: ( e ) => setBotForm( { ...botForm, signature: e.target.value } ),
				} ), 'ts-bot-signature' ),
				field( 'Type', h( 'select', {
					id: 'ts-bot-type', name: 'bot_type', value: botForm.type,
					onChange: ( e ) => setBotForm( { ...botForm, type: e.target.value } ),
				},
					h( 'option', { value: 'verified' }, 'Verified / trusted' ),
					h( 'option', { value: 'blocked' }, 'Blocked' )
				), 'ts-bot-type' ),
				'verified' === botForm.type && field(
					'Trusted DNS suffix (optional)',
					h( 'input', {
						id: 'ts-bot-suffix', name: 'bot_trusted_suffix', type: 'text',
						value: botForm.trustedSuffix, placeholder: 'e.g. googlebot.com',
						onChange: ( e ) => setBotForm( { ...botForm, trustedSuffix: e.target.value } ),
					} ),
					'ts-bot-suffix'
				),
				'verified' === botForm.type && h( 'p', { className: 'ts-hint', style: { marginTop: '-8px' } },
					'Without a suffix this bot is still always trusted (never blocked), it just never earns the verified-bot rate tier above, since nothing confirms the claim. With one, a matching IP is forward-confirmed by reverse DNS the same way Googlebot/Bingbot are.'
				),
				field( 'Note (optional)', h( 'input', {
					id: 'ts-bot-note', name: 'bot_note', type: 'text',
					value: botForm.note, placeholder: 'Why you added this',
					onChange: ( e ) => setBotForm( { ...botForm, note: e.target.value } ),
				} ), 'ts-bot-note' ),
				h( Button, { variant: 'primary', disabled: botBusy, onClick: addBotRule }, botBusy ? 'Adding…' : 'Add bot rule' )
			)
		),

		h(
			Card,
			{ title: 'All Bot Rules' },
			! botRules
				? ( botRulesError ? h( LoadError, { message: botRulesError, onRetry: loadBotRules } ) : h( Spinner, null ) )
				: ( botRules.length
					? h( 'div', { className: 'ts-table-wrap' }, h( 'table', { className: 'ts-table' },
							h( 'thead', null, h( 'tr', null,
								h( 'th', null, 'Signature' ), h( 'th', null, 'Type' ), h( 'th', null, 'Origin' ),
								h( 'th', null, 'Trusted suffix' ), h( 'th', null, 'Rate limit' ), h( 'th', null, 'Note' ),
								h( 'th', null, 'Enabled' ), h( 'th', null, '' )
							) ),
							h( 'tbody', null, botRules.map( ( r ) =>
								h( 'tr', { key: r.id },
									h( 'td', null, h( 'code', null, r.signature ) ),
									h( 'td', null, h( Badge, { tone: 'verified' === r.type ? 'success' : 'danger' }, r.type ) ),
									h( 'td', null, h( Badge, { tone: 'builtin' === r.origin ? 'neutral' : 'info' }, r.origin ) ),
									h( 'td', { className: 'ts-muted' }, r.trusted_suffix || '—' ),
									h( 'td', null, 'verified' === r.type ? h( BotRateCell, { rule: r, onSaved: loadBotRules } ) : '—' ),
									h( 'td', { className: 'ts-muted' }, r.note || '—' ),
									h( 'td', null, h( Toggle, {
										checked: !! r.enabled,
										disabled: botToggling === r.id,
										onChange: ( v ) => toggleBotRule( r, v ),
									} ) ),
									h( 'td', null, 'custom' === r.origin && h( Button, { variant: 'ghost', onClick: () => removeBotRule( r ) }, 'Remove' ) )
								)
							) )
					  ) )
					: h( EmptyState, { icon: '🤖', title: 'No bot rules', hint: 'Add one above.' } ) )
		),

		h( ProGate, {
			feature: 'sentinel.ai',
			title: 'AI Bot Suggestions',
			bullets: [
				'Sentinel AI reviews recent bot/crawler traffic and suggests which signatures to trust or block.',
				'Runs automatically in the background (and on demand) — every suggestion is a one-click Accept/Reject.',
				'Never touches a signature the site already trusts, like Googlebot or Bingbot.',
			],
		} ),

		h(
			Card,
			{ title: '🧩 Faceted-Search Abuse Protection' },
			settings === null
				? h( Spinner, null )
				: h(
					Fragment,
					null,
					h( 'p', { className: 'ts-hint', style: { marginTop: 0 } },
						'Tracks how many DIFFERENT filter/search combinations one IP requests on the same page — catches a bot walking every combination on a shop or archive page even when each individual combination is only requested once, which a plain request-rate limit would miss entirely.'
					),
					settingRow(
						'Enable faceted-search abuse protection',
						'Legitimate browsing (a shopper clicking through a few filters) stays well under the default threshold — this targets enumeration, not normal use.',
						settings.query_cardinality_enabled !== false,
						( v ) => toggleSetting( 'query_cardinality_enabled', v )
					),
					settings.query_cardinality_enabled !== false && h(
						Fragment,
						null,
						h( NumberRow, {
							id: 'firewall.query_cardinality_max',
							label: 'Distinct combinations before blocking',
							hint: 'How many different filter/query combinations one IP can request within the window below before it is treated as abuse.',
							value: settings.query_cardinality_max ?? 120,
							suffix: 'combinations',
							onCommit: ( v ) => toggleSetting( 'query_cardinality_max', v ),
						} ),
						h( NumberRow, {
							id: 'firewall.query_cardinality_window',
							label: 'Window',
							hint: 'The time window the combination count above is tracked over.',
							value: settings.query_cardinality_window ?? 600,
							suffix: 'seconds',
							onCommit: ( v ) => toggleSetting( 'query_cardinality_window', v ),
						} )
					)
				)
		)
		),

		h(
			Card,
			{
				title: 'Firewall mode',
				actions: h( Fragment, null,
					stats && stats.patch_gap > 0 && h( Badge, {
						tone: 'warning',
						title: 'Installed plugins currently shielded by an early virtual patch (patch-gap protection)',
					}, '🛡️ ' + stats.patch_gap + ' patch-gap protected' ),
					h( Badge, { tone: mode === 'optimized' ? 'success' : 'info' }, mode === 'optimized' ? 'Optimized' : 'Standard' )
				),
			},
			h( 'p', null,
				mode === 'optimized'
					? 'The standalone firewall runs before WordPress loads (best protection & performance).'
					: 'The firewall runs inside WordPress. Run the Setup Wizard to enable Optimized Mode.'
			),
			stats && stats.patch_gap > 0 && h( 'p', { className: 'ts-notice ts-notice--info' },
				'🛡️ ' + stats.patch_gap + ' installed plugin' + ( stats.patch_gap === 1 ? ' is' : 's are' )
					+ ' shielded by early virtual patching. See ',
				h( 'a', { href: '#/threatintel' }, 'Threat Intelligence' ),
				' for details, and update those plugins when convenient.'
			),
			h( 'a', { href: '#/wizard', className: 'ts-btn ts-btn--primary' }, 'Open Setup Wizard' )
		),

		h(
			Card,
			{
				title: '🛡️ Virtual Patches',
				actions: h( 'div', { className: 'ts-tabs' },
					patchTabs( suggestions, virtualPatches ).map( ( t ) =>
						h( 'button', {
							key: t.key,
							type: 'button',
							className: 'ts-tab' + ( patchTab === t.key ? ' is-active' : '' ),
							onClick: () => setPatchTab( t.key ),
						}, t.label )
					)
				),
			},
			// A load failure otherwise left every tab spinning forever (renderPatchList shows a
			// Spinner whenever its list is still null) with no message or retry.
			patchError && h( 'div', { className: 'ts-notice ts-notice--danger', style: { marginBottom: '12px', display: 'flex', gap: '10px', alignItems: 'center' } },
				h( 'span', null, '⚠️ ' + patchError ),
				h( Button, { variant: 'ghost', onClick: () => { loadSuggestions(); loadVirtualPatches(); } }, 'Retry' )
			),
			patchTab === 'suggested' && renderPatchList( suggestions, pendingOnly, suggestionItem,
				{ icon: '✅', title: 'No suggestions yet', hint: 'The scanner drafts a virtual-patch rule automatically when it finds a vulnerable request handler (not a planted malware file) in an installed plugin.' } ),
			patchTab === 'active' && renderPatchList( virtualPatches, ( r ) => r.enabled, virtualPatchItem,
				{ icon: '🌿', title: 'No active virtual patches', hint: 'Approve a suggestion from the Suggested tab, or re-enable one from Disabled.' } ),
			patchTab === 'disabled' && renderPatchList( virtualPatches, ( r ) => ! r.enabled, virtualPatchItem,
				{ icon: '✅', title: 'Nothing disabled', hint: 'Rules you turn off from the Active tab appear here — re-enable any time.' } ),
			patchTab === 'dismissed' && renderPatchList( suggestions, dismissedOnly, suggestionItem,
				{ icon: '🌿', title: 'Nothing dismissed', hint: 'Suggestions you dismiss from the Suggested tab appear here.' } )
		),
		consentPromptFor && h( ConsentModal, {
			onResolved: ( accepted ) => {
				const target = consentPromptFor;
				setConsentPromptFor( null );
				if ( accepted ) patchAction( target, 'submit_cloud' );
			},
		} ),

		h(
			'div',
			{ className: 'ts-grid ts-grid--cols' },
			h(
				Card,
				{ title: 'Blocks by type (7 days)' },
				! stats ? ( statsError ? h( LoadError, { message: statsError, onRetry: loadStats } ) : h( Spinner, null ) )
					: ( stats.by_type && stats.by_type.length
						? h( 'ul', { className: 'ts-modlist' }, stats.by_type.map( ( r ) =>
								h( 'li', { key: r.event_type, className: 'ts-modlist__item' },
									h( 'span', { className: 'ts-evt', title: r.event_type }, h( 'span', { className: 'ts-evt__icon', 'aria-hidden': 'true' }, eventTypeMeta( r.event_type ).icon ), h( 'span', null, eventTypeMeta( r.event_type ).label ) ),
									h( Badge, { tone: 'warning' }, r.c )
								) ) )
						: h( EmptyState, { icon: '🌿', title: 'No blocks', hint: 'No firewall activity in the last 7 days.' } ) )
			),
			h(
				Card,
				{ title: 'Top offending IPs (7 days)' },
				! stats ? ( statsError ? h( LoadError, { message: statsError, onRetry: loadStats } ) : h( Spinner, null ) )
					: ( stats.top_ips && stats.top_ips.length
						? h( 'ul', { className: 'ts-modlist' }, stats.top_ips.map( ( r ) =>
								h( 'li', { key: r.ip, className: 'ts-modlist__item' },
									h( 'span', null, r.ip ),
									h( 'span', null,
										h( Badge, { tone: 'danger' }, r.c ),
										' ',
										h( Button, { variant: 'ghost', onClick: () => addBanQuick( r.ip ) }, 'Ban' )
									)
								) ) )
						: h( EmptyState, { icon: '🌿', title: 'Nothing here', hint: 'No offenders recorded.' } ) )
			)
		),

		h(
			Card,
			{ title: 'Add IP ban' },
			h( 'div', { className: 'ts-banform' },
				field( 'IP or CIDR', h( 'input', { id: 'ts-ban-ip', name: 'ban_ip', type: 'text', value: form.ip, placeholder: '203.0.113.5 or 203.0.113.0/24', onChange: ( e ) => setForm( { ...form, ip: e.target.value } ) } ), 'ts-ban-ip' ),
				field( 'Reason', h( 'input', { id: 'ts-ban-reason', name: 'ban_reason', type: 'text', value: form.reason, onChange: ( e ) => setForm( { ...form, reason: e.target.value } ) } ), 'ts-ban-reason' ),
				field( 'Type', h( 'select', { id: 'ts-ban-type', name: 'ban_type', value: form.type, onChange: ( e ) => setForm( { ...form, type: e.target.value } ) },
					h( 'option', { value: 'temporary' }, 'Temporary' ),
					h( 'option', { value: 'permanent' }, 'Permanent' )
				), 'ts-ban-type' ),
				// Basic view: a plain duration picker (this is the field most likely to confuse a
				// non-technical owner — "3600" means nothing without doing the seconds math).
				// Advanced view keeps the raw seconds field power users actually want precise
				// control over.
				form.type === 'temporary' && viewMode !== 'advanced' && field( 'Ban duration', h( 'select', {
					id: 'ts-ban-duration', name: 'ban_duration', value: String( form.ttl ),
					onChange: ( e ) => setForm( { ...form, ttl: Number( e.target.value ) } ),
				},
					h( 'option', { value: '3600' }, '1 hour' ),
					h( 'option', { value: '86400' }, '1 day' ),
					h( 'option', { value: '604800' }, '1 week' )
				), 'ts-ban-duration' ),
				form.type === 'temporary' && viewMode === 'advanced' && field( 'TTL (seconds)', h( 'input', { id: 'ts-ban-ttl', name: 'ban_ttl', type: 'number', value: form.ttl, onChange: ( e ) => setForm( { ...form, ttl: Number( e.target.value ) } ) } ), 'ts-ban-ttl' ),
				h( Button, { variant: 'primary', disabled: busy, onClick: addBan }, busy ? 'Adding…' : 'Add ban' )
			)
		),

		h(
			Card,
			{ title: 'Active bans', actions: bans ? h( Badge, { tone: 'neutral' }, bans.total ) : null },
			! bans ? ( bansError ? h( LoadError, { message: bansError, onRetry: loadBans } ) : h( Spinner, null ) )
				: ( bans.items && bans.items.length
					? h( 'table', { className: 'ts-table' },
							h( 'thead', null, h( 'tr', null,
								h( 'th', null, 'IP / CIDR' ), h( 'th', null, 'Reason' ), h( 'th', null, 'Type' ),
								h( 'th', null, 'Source' ), h( 'th', null, 'Expires' ), h( 'th', null, '' )
							) ),
							h( 'tbody', null, bans.items.map( ( b ) =>
								h( 'tr', { key: b.id },
									h( 'td', null, b.cidr || b.ip ),
									h( 'td', null, b.reason ),
									h( 'td', null, h( Badge, { tone: b.type === 'permanent' ? 'danger' : 'warning' }, b.type ) ),
									h( 'td', null, b.source ),
									h( 'td', null, b.expires_at || '—' ),
									h( 'td', null, h( Button, { variant: 'ghost', onClick: () => removeBan( b.ip ) }, 'Remove' ) )
								) ) )
					  )
					: h( EmptyState, { icon: '✅', title: 'No active bans', hint: 'No IPs are currently blocked.' } ) ),
				bans && bans.total > BANS_PER_PAGE && h( 'div', { className: 'ts-pager', style: { display: 'flex', gap: '10px', alignItems: 'center', marginTop: '10px' } },
					h( Button, { variant: 'ghost', disabled: bansOffset <= 0, onClick: () => loadBans( Math.max( 0, bansOffset - BANS_PER_PAGE ) ) }, '← Prev' ),
					h( 'span', { className: 'ts-muted' },
						( bansOffset + 1 ) + '–' + Math.min( bansOffset + BANS_PER_PAGE, bans.total ) + ' of ' + bans.total
					),
					h( Button, { variant: 'ghost', disabled: bansOffset + BANS_PER_PAGE >= bans.total, onClick: () => loadBans( bansOffset + BANS_PER_PAGE ) }, 'Next →' )
				)
		)
	);

	function addBanQuick( ip ) {
		setForm( { ip, reason: 'Repeat offender', type: 'temporary', ttl: 3600 } );
		store.toast( 'IP filled into the ban form below.', 'info' );
	}

	// One auto-drafted virtual-patch suggestion (see PatchSuggester). Never applied on its
	// own — Approve/Dismiss/Submit are explicit reviews.
	function suggestionItem( f ) {
		let s;
		try {
			s = JSON.parse( f.suggested_patch );
		} catch ( e ) {
			return null;
		}
		if ( ! s || ! s.rule ) return null;

		const rule = s.rule;
		const status = f.patch_status || '';
		const busyKey = ( a ) => 'patch:' + a + ':' + f.id;

		return h( 'li', { key: f.id, className: 'ts-modlist__item ts-patch-suggestion' },
			h( 'div', { className: 'ts-patch-suggestion__box' },
				h( Badge, { tone: 'high' === s.confidence ? 'success' : 'warning' }, s.confidence + ' confidence' ),
				// Identical rules drafted from several sink lines arrive collapsed into one
				// queue item (see ScannerModule::dedupe_suggestions) — show how many it covers.
				f.duplicate_count > 1 && h( Fragment, null, ' ', h( Badge, { tone: 'neutral' }, '×' + f.duplicate_count + ' findings' ) ),
				' ',
				h( 'span', { className: 'ts-muted', title: f.path }, rule.slug ),
				h( 'div', { style: { margin: '4px 0' } },
					rule.require_auth
						? h( Fragment, null, 'Requires ', h( 'code', null, rule.require_cap || 'login' ), ' on ', h( 'code', null, rule.path_regex || rule.slug + ' (route not resolved — plugin-wide)' ) )
						: h( Fragment, null, 'Blocks param ', h( 'code', null, rule.param ), ' on ', h( 'code', null, rule.path_regex || rule.slug + ' (route not resolved — plugin-wide)' ) )
				),
				h( 'div', { className: 'ts-muted' }, s.reason ),
				h( 'div', { style: { marginTop: '8px' } },
					status === 'rejected' ? h( Badge, { tone: 'neutral' }, 'Dismissed' )
						: status === 'submitted' ? h( Fragment, null,
							h( Badge, { tone: 'success' }, 'Applied locally — live now' ), ' ',
							h( Badge, { tone: 'success' }, 'Submitted to cloud' )
						)
						: status === 'approved' ? h( Fragment, null,
							h( Badge, { tone: 'success' }, 'Applied locally — live now' ),
							' ',
							h( Button, {
								variant: 'default',
								disabled: !! patchBusy,
								// Consent already given (the common way to land in 'approved' rather
								// than 'submitted' is the inline auto-submit-on-approve attempt
								// failing) → retry submit_cloud directly, no need to ask again.
								// Consent not yet given → same consent-prompt flow as before.
								onClick: () => ( consentGiven ? patchAction( f, 'submit_cloud' ) : setConsentPromptFor( f ) ),
								title: 'Shares this rule with LicenseKit so it can be reviewed and redistributed to other sites running the same plugin.' + ( consentGiven ? '' : ' Asks for anonymous data-sharing consent first.' ),
							}, patchBusy === busyKey( 'submit_cloud' ) ? 'Submitting…' : ( consentGiven ? 'Retry Submit to Cloud' : 'Submit to Cloud' ) )
						)
						: h( Fragment, null,
							h( Button, { variant: 'primary', disabled: !! patchBusy, onClick: () => patchAction( f, 'approve' ) }, patchBusy === busyKey( 'approve' ) ? 'Applying…' : 'Apply locally' ),
							' ',
							h( Button, { variant: 'ghost', disabled: !! patchBusy, onClick: () => patchAction( f, 'reject' ) }, 'Dismiss' )
						)
				)
			)
		);
	}

	// The originating scan finding for an active rule, if any (hand-added rules have none) —
	// looked up by rule id so the Active tab can also surface cloud-submission state, which
	// lives on the finding (patch_status), not the CustomVirtualPatches rule itself. Suggested/
	// Dismissed only cover the not-yet-decided and rejected states; 'approved'/'submitted' are
	// findings whose rule already moved to Active, so their cloud status belongs here instead.
	function findingForRule( ruleId ) {
		return ( suggestions || [] ).find( ( f ) => {
			try {
				return JSON.parse( f.suggested_patch ).rule.id === ruleId;
			} catch ( e ) {
				return false;
			}
		} );
	}

	// One already-applied virtual patch (approved suggestion or hand-added), with an
	// enable/disable toggle and a permanent-remove action. Disabling keeps the rule around
	// (and out of prepend/waf-config.php + the merged Standard-Mode ruleset) so it can be
	// re-enabled later without having to re-approve the original suggestion.
	function virtualPatchItem( rule ) {
		const scope = rule.require_auth
			? 'Requires ' + ( rule.require_cap || 'login' ) + ' on ' + ( rule.path_regex || rule.slug + ' (plugin-wide)' )
			: 'Blocks param ' + rule.param + ' on ' + ( rule.path_regex || rule.slug + ' (plugin-wide)' );
		const busy = ( a ) => patchBusy === 'vp-' + a + ':' + rule.id;
		const finding = findingForRule( rule.id );
		const cloudStatus = finding ? ( finding.patch_status || 'approved' ) : null;
		// Bundled (shipped with the plugin) and feed (synced from LicenseKit's cloud `patches`
		// dataset) rules have no CustomVirtualPatches record — only 'local' ones (hand-added or
		// an approved scanner suggestion) can be permanently removed; the other two can only be
		// toggled on/off (see FirewallModule::set_virtual_patch_disabled()).
		const origin = rule.origin || 'local';
		const originLabel = { local: 'Local', bundled: 'Bundled', feed: 'Cloud feed' }[ origin ] || origin;

		return h( 'li', { key: rule.id, className: 'ts-modlist__item ts-patch-suggestion' },
			h( 'div', { className: 'ts-patch-suggestion__box' },
				h( Badge, { tone: rule.enabled ? 'success' : 'neutral' }, rule.enabled ? 'Enabled' : 'Disabled' ),
				' ',
				h( Badge, { tone: 'neutral' }, originLabel ),
				rule.require_auth && h( Fragment, null, ' ', h( Badge, { tone: 'info' }, 'Auth gate' ) ),
				' ',
				h( 'span', { className: 'ts-muted' }, rule.slug ),
				h( 'div', { style: { margin: '4px 0' } }, scope ),
				rule.desc && h( 'div', { className: 'ts-muted' }, rule.desc ),
				h( 'div', { style: { marginTop: '8px', display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' } },
					h( Toggle, {
						checked: !! rule.enabled,
						disabled: busy( 'toggle' ),
						onChange: ( enabled ) => toggleVirtualPatch( rule, enabled ),
						label: rule.enabled ? 'Enabled' : 'Disabled',
					} ),
					'local' === origin
						? h( Button, { variant: 'ghost', disabled: !! patchBusy, onClick: () => deleteVirtualPatch( rule ) }, busy( 'delete' ) ? 'Removing…' : 'Remove' )
						: h( 'span', { className: 'ts-muted', title: 'bundled' === origin ? 'Ships with the plugin — can be disabled but not removed.' : 'Synced from the cloud patches feed — can be disabled but not removed.' }, 'Not removable' ),
					'submitted' === cloudStatus && h( Badge, { tone: 'success' }, 'Submitted to cloud' ),
					'approved' === cloudStatus && h( Fragment, null,
						h( Badge, { tone: 'neutral' }, 'Not submitted to cloud' ),
						h( Button, {
							variant: 'default',
							disabled: !! patchBusy,
							onClick: () => ( consentGiven ? patchAction( finding, 'submit_cloud' ) : setConsentPromptFor( finding ) ),
							title: 'Shares this rule with LicenseKit so it can be reviewed and redistributed to other sites running the same plugin.' + ( consentGiven ? '' : ' Asks for anonymous data-sharing consent first.' ),
						}, patchBusy === 'patch:submit_cloud:' + finding.id ? 'Submitting…' : ( consentGiven ? 'Retry Submit to Cloud' : 'Submit to Cloud' ) )
					)
				)
			)
		);
	}
}

/** A suggestion still awaiting a review action (approve/reject/submit_cloud). */
function pendingOnly( f ) {
	return ! f.patch_status;
}

/** A suggestion the admin explicitly declined — never became a virtual patch at all. */
function dismissedOnly( f ) {
	return f.patch_status === 'rejected';
}

/**
 * Suggested / Active / Disabled / Dismissed are kept as four separate tabs rather than
 * merging Disabled into Dismissed: they're different data (Disabled rules already live in
 * CustomVirtualPatches and re-enable with one click; Dismissed suggestions never became a
 * rule and there's no "un-reject" path back), so collapsing them would hide that distinction.
 */
function patchTabs( suggestions, virtualPatches ) {
	const count = ( list, pred ) => ( list ? list.filter( pred ).length : null );
	const label = ( name, n ) => name + ( null === n ? '' : ` (${ n })` );
	return [
		{ key: 'suggested', label: label( 'Suggested', count( suggestions, pendingOnly ) ) },
		{ key: 'active', label: label( 'Active', count( virtualPatches, ( r ) => r.enabled ) ) },
		{ key: 'disabled', label: label( 'Disabled', count( virtualPatches, ( r ) => ! r.enabled ) ) },
		{ key: 'dismissed', label: label( 'Dismissed', count( suggestions, dismissedOnly ) ) },
	];
}

/** Shared loading/empty/list rendering for each Virtual Patches tab. */
function renderPatchList( items, predicate, renderItem, empty ) {
	if ( ! items ) {
		return h( Spinner, null );
	}
	const filtered = items.filter( predicate );
	if ( filtered.length === 0 ) {
		return h( EmptyState, empty );
	}
	return h( 'ul', { className: 'ts-modlist' }, filtered.map( ( item ) => renderItem( item ) ) );
}

function field( label, control, id ) {
	return h( 'div', { className: 'ts-field' }, h( 'label', { htmlFor: id }, label ), control );
}

function settingRow( label, hint, checked, onChange ) {
	return h(
		'div',
		{ className: 'ts-row' },
		h(
			'div',
			{ className: 'ts-row__label' },
			h( 'span', { className: 'ts-row__name' }, h( 'strong', null, label ) ),
			h( 'span', { className: 'ts-hint' }, hint )
		),
		h( 'div', { className: 'ts-row__control' }, h( Toggle, { checked, onChange } ) )
	);
}

/**
 * Compact, inline requests/window editor for one bot rule's row in the Bot Rules table — saves
 * on blur, same as NumberRow, but two fields side by side since table cells are tight on space.
 * Shows a reset-to-default (↺) button only when this signature currently has a real override
 * (rule.rate_limit_custom), so the common case (everyone shares the default tier) stays clean.
 */
function BotRateCell( { rule, onSaved } ) {
	const store = useStore();
	const [ requests, setRequests ] = useState( String( rule.rate_limit_requests ) );
	const [ windowSec, setWindowSec ] = useState( String( rule.rate_limit_window ) );
	const [ busy, setBusy ] = useState( false );

	useEffect( () => {
		setRequests( String( rule.rate_limit_requests ) );
		setWindowSec( String( rule.rate_limit_window ) );
	}, [ rule.rate_limit_requests, rule.rate_limit_window ] );

	const save = async () => {
		const req = Math.max( 1, parseInt( requests, 10 ) || 0 );
		const win = Math.max( 1, parseInt( windowSec, 10 ) || 0 );
		setRequests( String( req ) );
		setWindowSec( String( win ) );
		if ( req === rule.rate_limit_requests && win === rule.rate_limit_window ) {
			return; // No actual change — skip the round trip.
		}
		setBusy( true );
		try {
			await api.post( '/firewall/bot-rules/rate-limit', { signature: rule.signature, requests: req, window: win } );
			store.toast( 'Rate limit updated for ' + rule.signature + '.', 'success' );
			onSaved();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( false );
		}
	};

	const resetToDefault = async () => {
		setBusy( true );
		try {
			await api.post( '/firewall/bot-rules/rate-limit', { signature: rule.signature, clear: true } );
			store.toast( rule.signature + ' reset to the shared default.', 'success' );
			onSaved();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( false );
		}
	};

	return h( 'div', { style: { display: 'flex', gap: '4px', alignItems: 'center' } },
		h( 'input', {
			id: 'ts-bot-rate-req-' + rule.id, name: 'bot_rate_requests_' + rule.id,
			type: 'number', min: '1', value: requests, disabled: busy,
			onChange: ( e ) => setRequests( e.target.value ), onBlur: save,
			style: { width: '60px' },
		} ),
		h( 'span', { className: 'ts-muted', style: { fontSize: '11px' } }, '/' ),
		h( 'input', {
			id: 'ts-bot-rate-win-' + rule.id, name: 'bot_rate_window_' + rule.id,
			type: 'number', min: '1', value: windowSec, disabled: busy,
			onChange: ( e ) => setWindowSec( e.target.value ), onBlur: save,
			style: { width: '50px' },
		} ),
		h( 'span', { className: 'ts-muted', style: { fontSize: '11px' } }, 's' ),
		rule.rate_limit_custom && h( Button, {
			variant: 'ghost', disabled: busy, onClick: resetToDefault,
			title: 'Reset to the shared default tier',
		}, '↺' )
	);
}

/**
 * A settingRow-style row for a numeric field, saved on blur rather than per-keystroke. `id`
 * follows the `module.key` convention (e.g. "firewall.bruteforce_max") so the Settings page's
 * deep-link/highlight mechanism can also target this same field when it's reached from there.
 */
function NumberRow( { id, label, hint, value, suffix, onCommit } ) {
	const [ local, setLocal ] = useState( String( value ) );
	useEffect( () => { setLocal( String( value ) ); }, [ value ] );

	const commit = () => {
		const n = Math.max( 0, parseInt( local, 10 ) || 0 );
		setLocal( String( n ) );
		if ( n !== value ) onCommit( n );
	};

	return h(
		'div',
		{ className: 'ts-row' },
		h(
			'div',
			{ className: 'ts-row__label' },
			h( 'label', { htmlFor: id }, h( 'span', { className: 'ts-row__name' }, h( 'strong', null, label ) ) ),
			h( 'span', { className: 'ts-hint' }, hint )
		),
		h( 'div', { className: 'ts-row__control', style: { display: 'flex', gap: '6px', alignItems: 'center' } },
			h( 'input', {
				id,
				name: id,
				type: 'number',
				min: '0',
				value: local,
				onChange: ( e ) => setLocal( e.target.value ),
				onBlur: commit,
				onKeyDown: ( e ) => { if ( 'Enter' === e.key ) e.target.blur(); },
				style: { width: '90px' },
			} ),
			suffix && h( 'span', { className: 'ts-muted' }, suffix )
		)
	);
}
