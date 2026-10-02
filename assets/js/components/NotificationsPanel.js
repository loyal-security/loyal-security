/**
 * Notifications panel — configure alerts, review what was sent, and mute noisy event types.
 *
 * Three tabs:
 *   • Settings — email channel, thresholds, throttle, quiet hours.
 *   • History  — every alert that was dispatched, each expandable into plain-language
 *                guidance ("what it means / is this a false positive / what to do").
 *   • Muted    — event types you've silenced, with one-click un-mute.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, Toggle, EmptyState, severityTone, ConfirmDialog, Modal } from './ui.js';
import { useStore } from '../store.js';
import { eventTypeMeta, relativeTime } from '../events.js';
import { ProGate } from './ProGate.js';

const CATEGORIES = [
	[ 'waf',           'Firewall / WAF' ],
	[ 'auth',          'Authentication' ],
	[ 'scan',          'Scanner' ],
	[ 'integrity',     'Integrity (FIM)' ],
	[ 'incident',      'Incident response' ],
	[ 'hardening',     'Hardening' ],
	[ 'settings',      'Settings changes' ],
	[ 'wp',            'WordPress lifecycle' ],
];

const SEVERITY_OPTIONS = [
	{ value: 10, label: 'Info (all events)' },
	{ value: 20, label: 'Notice and above' },
	{ value: 30, label: 'Warning and above' },
	{ value: 40, label: 'Critical only' },
];

/** Severity choices for the incident-routing integrations (PagerDuty / OpsGenie). */
const CHANNEL_META = {
	email:     { icon: '📧', label: 'Email' },
	webhook:   { icon: '🔗', label: 'Webhook' },
	pagerduty: { icon: '📟', label: 'PagerDuty' },
	opsgenie:  { icon: '🚨', label: 'OpsGenie' },
};

function channelMeta( channel ) {
	return CHANNEL_META[ channel ] || { icon: '•', label: channel || 'Channel' };
}

function SectionHeader( { title, badge } ) {
	return h(
		'div',
		{ className: 'ts-notif-section-head' },
		h( 'h3', { className: 'ts-notif-section-title' }, title ),
		badge && h( Badge, { tone: badge.tone }, badge.label )
	);
}

function FieldRow( { label, hint, children, id } ) {
	return h(
		'div',
		{ className: 'ts-notif-field' },
		h(
			'label',
			{ className: 'ts-notif-field__label', htmlFor: id },
			label,
			hint && h( 'span', { className: 'ts-notif-field__hint' }, hint )
		),
		h( 'div', { className: 'ts-notif-field__control' }, children )
	);
}

export function NotificationsPanel() {
	const store  = useStore();
	const [ tab,      setTab      ] = useState( 'settings' );
	const [ settings, setSettings ] = useState( null );
	const [ status,   setStatus   ] = useState( null );
	const [ busy,     setBusy     ] = useState( '' );
	// Bumped on every (re)load so the settings form remounts — its text/number/time inputs are
	// uncontrolled (defaultValue), so after a failed save + rollback load() they would otherwise
	// keep displaying the rejected value instead of the restored server value.
	const [ formVersion, setFormVersion ] = useState( 0 );
	// Lifted here (rather than into renderSettings, a plain helper function conditionally called
	// only when tab === 'settings') so this hook fires unconditionally on every render — a hook
	// inside a conditionally-invoked function would violate the Rules of Hooks and misfire on
	// tab switches.
	const [ channelsModalOpen, setChannelsModalOpen ] = useState( false );

	const load = async () => {
		const [ se, st ] = await Promise.all( [
			api.get( '/settings' ),
			api.get( '/notifications/status' ),
		] );
		setSettings( se.notifications || {} );
		setStatus( st );
		setFormVersion( ( v ) => v + 1 );
	};

	useEffect( () => {
		load().catch( ( e ) => store.toast( e.message, 'error' ) );
	}, [] );

	const save = async ( patch ) => {
		const next = { ...settings, ...patch };
		setSettings( next );
		try {
			await api.post( '/settings/notifications', next );
			store.toast( 'Notification settings saved.', 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
			load(); // rollback optimistic update
		}
	};

	const toggleCat = ( cat, checked ) => {
		const cats = Array.isArray( settings.email_categories ) ? [ ...settings.email_categories ] : [];
		const next = checked ? [ ...cats, cat ] : cats.filter( ( c ) => c !== cat );
		save( { email_categories: next } );
	};

	const testEmail = async () => {
		setBusy( 'email' );
		try {
			const res = await api.post( '/notifications/test-email', {} );
			store.toast( `Test email sent to ${ res.sent_to }.`, 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	/* ---- Mute list (shared across tabs; source of truth is settings) ---- */
	const muted = Array.isArray( settings && settings.muted_events ) ? settings.muted_events : [];

	const setMutedList = ( list ) => setSettings( ( s ) => ( { ...( s || {} ), muted_events: list } ) );

	const mute = async ( type ) => {
		try {
			const res = await api.post( '/notifications/mute', { type } );
			setMutedList( res.muted );
			store.toast( `Muted “${ type }”. You won’t be alerted about this again.`, 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	const unmute = async ( type ) => {
		try {
			const res = await api.post( '/notifications/unmute', { type } );
			setMutedList( res.muted );
			store.toast( `Un-muted “${ type }”.`, 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	if ( ! settings ) {
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	const TABS = [
		{ key: 'settings', label: 'Settings' },
		{ key: 'history',  label: 'History' + ( status && status.history_count ? ` (${ status.history_count })` : '' ) },
		{ key: 'muted',    label: 'Muted' + ( muted.length ? ` (${ muted.length })` : '' ) },
	];

	return h(
		Fragment,
		null,
		h(
			'div',
			{ className: 'ts-tabs' },
			TABS.map( ( t ) =>
				h(
					'button',
					{
						key: t.key,
						type: 'button',
						className: 'ts-tab' + ( tab === t.key ? ' is-active' : '' ),
						onClick: () => setTab( t.key ),
					},
					t.label
				)
			)
		),

		tab === 'settings' && h( Fragment, { key: formVersion }, renderSettings( { settings, status, busy, save, toggleCat, testEmail, channelsModalOpen, setChannelsModalOpen } ) ),
		tab === 'history'  && h( HistoryTab, { store, muted, onMute: mute, onUnmute: unmute } ),
		tab === 'muted'    && h( MutedTab,   { muted, onUnmute: unmute } )
	);
}

/* ==================================================================== *
 * Settings tab (previous single-page layout, unchanged behaviour)
 * ==================================================================== */

function renderSettings( { settings, status, busy, save, toggleCat, testEmail, channelsModalOpen, setChannelsModalOpen } ) {
	const emailTo = settings.email_to || '';
	const emailCats = Array.isArray( settings.email_categories ) ? settings.email_categories : [];
	const throttleMax = settings.throttle_max ?? 10;
	const throttleWindow = settings.throttle_window ?? 3600;
	const emailMinSev = settings.email_min_severity ?? 30;

	const quietEnabled = !! settings.quiet_hours_enabled;
	const quietStart   = settings.quiet_start || '23:00';
	const quietEnd     = settings.quiet_end || '07:00';

	const emailSent   = status ? status.email_sent   : 0;
	const throttleMax2 = status ? status.throttle_max : throttleMax;

	return h(
		Fragment,
		null,

		/* ---- Module-level toggle ---------------------------------------- */
		h(
			Card,
			{
				title: '🔔 Notifications',
				actions: h(
					Toggle,
					{
						checked: !! settings.enabled,
						onChange: ( v ) => save( { enabled: v } ),
						label: settings.enabled ? 'Enabled' : 'Disabled',
					}
				),
			},
			h(
				'p',
				{ className: 'ts-notif-intro' },
				'Receive real-time email alerts when security events are detected.'
			),
			status && h(
				'div',
				{ className: 'ts-notif-counters' },
				h( Badge, { tone: emailSent >= throttleMax2 && throttleMax2 > 0 ? 'warning' : 'neutral' },
					`Email: ${ emailSent } / ${ throttleMax2 > 0 ? throttleMax2 : '∞' } sent (current window)`
				)
			)
		),

		/* ---- Channels & rules summary + popup --------------------------- */
		h(
			Card,
			{
				title: '⚙️ Notification Channels & Rules',
				actions: h( Button, { variant: 'primary', onClick: () => setChannelsModalOpen( true ) }, 'Manage channels' ),
			},
			h( 'p', { className: 'ts-notif-intro', style: { marginTop: 0 } },
				'Email alerts, throttle and quiet hours.'
			),
			h( 'div', { style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
				h( Badge, { tone: settings.email_enabled ? 'success' : 'neutral' }, 'Email: ' + ( settings.email_enabled ? 'On' : 'Off' ) ),
				h( Badge, { tone: quietEnabled ? 'success' : 'neutral' }, 'Quiet hours: ' + ( quietEnabled ? 'On' : 'Off' ) )
			)
		),

		h( Modal, {
			open: channelsModalOpen,
			onClose: () => setChannelsModalOpen( false ),
			title: 'Notification Channels & Rules',
			icon: '⚙️',
			size: 'lg',
		},

		/* ---- Email channel --------------------------------------------- */
		h(
			Card,
			{
				title: '📧 Email alerts',
				actions: h(
					Toggle,
					{
						checked: !! settings.email_enabled,
						onChange: ( v ) => save( { email_enabled: v } ),
						label: settings.email_enabled ? 'On' : 'Off',
					}
				),
			},

			h(
				FieldRow,
				{ label: 'Recipient email', hint: 'Leave blank to use the admin email address.', id: 'ts-notif-email-to' },
				h( 'input', {
					id: 'ts-notif-email-to',
					name: 'email_to',
					type: 'email',
					className: 'ts-input',
					defaultValue: emailTo,
					placeholder: status ? status.email_to : 'admin@example.com',
					onBlur: ( e ) => save( { email_to: e.target.value.trim() } ),
				} )
			),

			h(
				FieldRow,
				{ label: 'Minimum severity', id: 'ts-notif-email-sev' },
				h(
					'select',
					{
						id: 'ts-notif-email-sev',
						name: 'email_min_severity',
						className: 'ts-select',
						value: emailMinSev,
						onChange: ( e ) => save( { email_min_severity: Number( e.target.value ) } ),
					},
					SEVERITY_OPTIONS.map( ( o ) =>
						h( 'option', { key: o.value, value: o.value }, o.label )
					)
				)
			),

			h(
				FieldRow,
				{
					label: 'Event categories',
					hint: 'Select which categories trigger an email. Leave all unchecked to receive every event above the threshold.',
				},
				h(
					'div',
					{ className: 'ts-notif-cats' },
					CATEGORIES.map( ( [ cat, label ] ) =>
						h(
							'label',
							{ key: cat, className: 'ts-notif-cat', htmlFor: 'ts-notif-email-cat-' + cat },
							h( 'input', {
								id: 'ts-notif-email-cat-' + cat,
								name: 'email_cat_' + cat,
								type: 'checkbox',
								checked: emailCats.includes( cat ),
								onChange: ( e ) => toggleCat( cat, e.target.checked ),
							} ),
							' ',
							label
						)
					)
				)
			),

			h(
				'div',
				{ className: 'ts-card__footer' },
				h(
					Button,
					{
						variant: 'secondary',
						disabled: busy === 'email',
						onClick: testEmail,
					},
					busy === 'email' ? h( Spinner, null ) : '📤 Send test email'
				)
			)
		),

		/* ---- Webhook / incident-routing channels (Loyal Security Pro) ---- */
		h( ProGate, {
			feature: 'notifications.webhook',
			title: 'Webhook & incident-routing alerts',
			bullets: [
				'Slack, Discord or any HTTPS webhook',
				'PagerDuty (Events API v2) and OpsGenie incident routing',
				'Per-channel minimum severity',
			],
		} ),

		/* ---- Throttle --------------------------------------------------- */
		h(
			Card,
			{ title: '⏱️ Alert throttle' },
			h(
				'p',
				{ className: 'ts-notif-intro' },
				'Prevents alert storms. When the limit is reached the counter resets after the window expires.'
			),
			h(
				FieldRow,
				{ label: 'Max alerts per window', hint: '0 = unlimited.', id: 'ts-notif-throttle-max' },
				h( 'input', {
					id: 'ts-notif-throttle-max',
					name: 'throttle_max',
					type: 'number',
					className: 'ts-input ts-input--short',
					defaultValue: throttleMax,
					min: 0,
					max: 1000,
					onBlur: ( e ) => save( { throttle_max: Number( e.target.value ) } ),
				} )
			),
			h(
				FieldRow,
				{ label: 'Window (seconds)', hint: '3600 = 1 hour.', id: 'ts-notif-throttle-window' },
				h( 'input', {
					id: 'ts-notif-throttle-window',
					name: 'throttle_window',
					type: 'number',
					className: 'ts-input ts-input--short',
					defaultValue: throttleWindow,
					min: 60,
					max: 86400,
					onBlur: ( e ) => save( { throttle_window: Number( e.target.value ) } ),
				} )
			)
		),

		/* ---- Quiet hours ----------------------------------------------- */
		h(
			Card,
			{
				title: '🌙 Quiet hours',
				actions: h( Toggle, {
					checked: quietEnabled,
					onChange: ( v ) => save( { quiet_hours_enabled: v } ),
					label: quietEnabled ? 'On' : 'Off',
				} ),
			},
			h( 'p', { className: 'ts-notif-intro' },
				'Suppress non-critical alerts during the configured window. ',
				h( 'strong', null, 'CRITICAL alerts bypass quiet hours.' )
			),
			h(
				FieldRow,
				{ label: 'Quiet from', id: 'ts-notif-quiet-start' },
				h( 'input', {
					id: 'ts-notif-quiet-start',
					name: 'quiet_start',
					type: 'time',
					className: 'ts-input ts-input--short',
					defaultValue: quietStart,
					onBlur: ( e ) => save( { quiet_start: e.target.value } ),
				} )
			),
			h(
				FieldRow,
				{ label: 'Until', id: 'ts-notif-quiet-end' },
				h( 'input', {
					id: 'ts-notif-quiet-end',
					name: 'quiet_end',
					type: 'time',
					className: 'ts-input ts-input--short',
					defaultValue: quietEnd,
					onBlur: ( e ) => save( { quiet_end: e.target.value } ),
				} )
			)
		)
		)
	);
}

/* ==================================================================== *
 * History tab
 * ==================================================================== */

const STATUS_META = {
	sent:    { tone: 'success', label: 'Sent' },
	failed:  { tone: 'danger',  label: 'Failed' },
	skipped: { tone: 'neutral', label: 'Skipped' },
};

function HistoryTab( { store, muted, onMute, onUnmute } ) {
	const [ data,    setData    ] = useState( null );
	const [ loading, setLoading ] = useState( true );
	const [ expanded, setExpanded ] = useState( null );
	const [ filters, setFilters ] = useState( { channel: '', status: '', page: 1, per_page: 25 } );
	const [ confirmClear, setConfirmClear ] = useState( false );
	const [ clearing, setClearing ] = useState( false );

	const load = async ( f ) => {
		setLoading( true );
		try {
			const params = {};
			Object.keys( f ).forEach( ( k ) => {
				if ( f[ k ] !== '' && f[ k ] !== 0 ) params[ k ] = f[ k ];
			} );
			setData( await api.get( '/notifications/history', params ) );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setLoading( false );
		}
	};

	useEffect( () => {
		load( filters );
	}, [ filters.channel, filters.status, filters.page ] );

	const clearHistory = async () => {
		setClearing( true );
		try {
			await api.post( '/notifications/history/clear', {} );
			store.toast( 'Notification history cleared.', 'success' );
			setFilters( { ...filters, page: 1 } );
			load( { ...filters, page: 1 } );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setClearing( false );
			setConfirmClear( false );
		}
	};

	const totalPages = data ? Math.max( 1, Math.ceil( data.total / data.per_page ) ) : 1;
	const isMuted = ( type ) => muted.includes( type );

	return h(
		Card,
		{
			title: 'Sent notifications',
			actions: data && data.total
				? h( Button, { variant: 'ghost', disabled: clearing, onClick: () => setConfirmClear( true ) }, clearing ? h( Spinner, null ) : '🗑 Clear history' )
				: null,
		},
		h( ConfirmDialog, {
			open: confirmClear,
			title: 'Clear notification history?',
			message: 'Permanently deletes every sent-notification record shown here. This cannot be undone.',
			confirmLabel: 'Clear History',
			busy: clearing,
			onCancel: () => setConfirmClear( false ),
			onConfirm: clearHistory,
		} ),
		h(
			'p',
			{ className: 'ts-notif-intro' },
			'Every alert Loyal Security has dispatched. Expand a row to see what it means, whether it might be a false positive, and how to fix it.'
		),
		h(
			'div',
			{ className: 'ts-filters' },
			h( 'select', { id: 'ts-notif-hist-channel', name: 'history_channel', value: filters.channel, onChange: ( e ) => setFilters( { ...filters, channel: e.target.value, page: 1 } ) },
				h( 'option', { value: '' }, 'All channels' ),
				Object.keys( CHANNEL_META ).map( ( c ) => h( 'option', { key: c, value: c }, CHANNEL_META[ c ].label ) )
			),
			h( 'select', { id: 'ts-notif-hist-status', name: 'history_status', value: filters.status, onChange: ( e ) => setFilters( { ...filters, status: e.target.value, page: 1 } ) },
				h( 'option', { value: '' }, 'Any status' ),
				h( 'option', { value: 'sent' }, 'Sent' ),
				h( 'option', { value: 'failed' }, 'Failed' ),
				h( 'option', { value: 'skipped' }, 'Skipped' )
			)
		),

		loading && ! data
			? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
			: ! data || ! data.items.length
				? h( EmptyState, { icon: '🔔', title: 'No notifications yet', hint: 'Alerts you receive will be listed here so you can review and act on them.' } )
				: h( Fragment, null,
					h( 'table', { className: 'ts-table' },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'When' ),
							h( 'th', null, 'Alert' ),
							h( 'th', null, 'Channel' ),
							h( 'th', null, 'Status' ),
							h( 'th', null, '' )
						) ),
						h( 'tbody', null, data.items.map( ( row ) => {
							const g   = row.guide || {};
							const cm  = channelMeta( row.channel );
							const sm  = STATUS_META[ row.status ] || { tone: 'neutral', label: row.status };
							const open = expanded === row.id;
							return h( Fragment, { key: row.id },
								h( 'tr', null,
									h( 'td', { title: row.created_at }, relativeTime( row.created_at ) ),
									h( 'td', null,
										h( 'div', { className: 'ts-evt' },
											h( 'span', { className: 'ts-evt__icon', 'aria-hidden': 'true' }, g.icon || '🔔' ),
											h( 'span', { className: 'ts-evt__text' },
												h( 'span', { className: 'ts-evt__title' },
													g.title || row.subject || row.event_type,
													isMuted( row.event_type ) && h( Badge, { tone: 'neutral' }, 'Muted' )
												),
												h( 'code', { className: 'ts-evt__code' }, row.event_type )
											)
										)
									),
									h( 'td', null, `${ cm.icon } ${ cm.label }` ),
									h( 'td', null, h( Badge, { tone: sm.tone }, sm.label ) ),
									h( 'td', null, h( Button, { variant: 'ghost', onClick: () => setExpanded( open ? null : row.id ) }, open ? '−' : '+' ) )
								),
								open && h( 'tr', { className: 'ts-detail' },
									h( 'td', { colSpan: 5 },
										h( GuideDetail, {
											row,
											guide: g,
											muted: isMuted( row.event_type ),
											onMute: () => onMute( row.event_type ),
											onUnmute: () => onUnmute( row.event_type ),
											store,
										} )
									)
								)
							);
						} ) )
					),
					h( 'div', { className: 'ts-pager' },
						h( Button, { disabled: data.page <= 1, onClick: () => setFilters( { ...filters, page: data.page - 1 } ) }, '‹ Prev' ),
						h( 'span', null, `Page ${ data.page } / ${ totalPages } · ${ data.total } sent` ),
						h( Button, { disabled: data.page >= totalPages, onClick: () => setFilters( { ...filters, page: data.page + 1 } ) }, 'Next ›' )
					)
				)
	);
}

/**
 * Return the label for the false-positive whitelist button given an event type + raw context,
 * or null when no automated whitelist action is available for that type.
 */
function fpButtonLabel( eventType, context ) {
	const ctx = context || {};
	switch ( eventType ) {
		case 'http.ajax.nopriv':
			return ctx.action ? `Whitelist AJAX action "${ ctx.action }"` : null;
		case 'waf.block':
		case 'waf.bruteforce':
		case 'waf.ddos':
		case 'waf.ratelimit':
		case 'waf.bot.block':
			return ctx.ip ? `Whitelist IP ${ ctx.ip }` : null;
		default:
			return null;
	}
}

function fpWhitelistedLabel( fp ) {
	if ( ! fp ) return null;
	switch ( fp.action ) {
		case 'whitelisted_ajax_action':
			return `✅ AJAX action "${ fp.value }" is whitelisted — future calls won't trigger alerts.`;
		case 'whitelisted_ip':
			return `✅ IP ${ fp.value } is whitelisted — it bypasses all firewall checks.`;
		default:
			return '✅ Whitelisted.';
	}
}

/**
 * The expandable body for one history row: plain-language guidance + facts + actions.
 */
function GuideDetail( { row, guide, muted, onMute, onUnmute, store } ) {
	const facts = Array.isArray( guide.facts ) ? guide.facts : [];
	const fixes = Array.isArray( guide.fix ) ? guide.fix : [];

	const [ fpResult,  setFpResult  ] = useState( row.false_positive || null );
	const [ fpBusy,    setFpBusy    ] = useState( false );

	const ctx    = row.context || {};
	const fpLabel = fpResult ? null : fpButtonLabel( row.event_type, ctx );

	const handleFalsePositive = async () => {
		setFpBusy( true );
		try {
			const res = await api.post( '/notifications/false-positive', {
				event_type: row.event_type,
				context:    ctx,
			} );
			setFpResult( res );
			if ( store ) {
				store.toast( res.description || 'Whitelisted.', 'success' );
			}
		} catch ( e ) {
			if ( store ) store.toast( e.message, 'error' );
		} finally {
			setFpBusy( false );
		}
	};

	return h(
		'div',
		{ className: 'ts-incident ts-guide' },

		h( 'div', { className: 'ts-guide__sev' },
			h( Badge, { tone: severityTone( row.severity ) }, guide.severity_label || row.severity_label || 'info' )
		),

		guide.meaning && h( 'div', { className: 'ts-guide__block' },
			h( 'h4', null, 'What this means' ),
			h( 'p', null, guide.meaning )
		),

		guide.legit && h( 'div', { className: 'ts-guide__block' },
			h( 'h4', null, 'Is this normal, or a false positive?' ),
			h( 'p', null, guide.legit )
		),

		fixes.length ? h( 'div', { className: 'ts-guide__block' },
			h( 'h4', null, 'What to do' ),
			h( 'ol', { className: 'ts-guide__steps' }, fixes.map( ( s, i ) => h( 'li', { key: i }, s ) ) )
		) : null,

		facts.length ? h( 'div', { className: 'ts-guide__block' },
			h( 'h4', null, 'Details' ),
			h( 'dl', { className: 'ts-incident__grid' },
				facts.map( ( f, i ) => h( 'div', { key: i, className: 'ts-incident__pair' },
					h( 'dt', null, f.label ),
					h( 'dd', null, f.value )
				) )
			)
		) : null,

		h( 'div', { className: 'ts-guide__actions' },
			h( 'a', { href: '#/logs', className: 'ts-btn ts-btn--secondary' }, 'Open audit log' ),

			/* False-positive / whitelist action */
			fpResult
				? h( 'span', { className: 'ts-guide__fp-done' }, fpWhitelistedLabel( fpResult ) )
				: fpLabel
					? h( Button, {
						variant: 'secondary',
						disabled: fpBusy,
						onClick: handleFalsePositive,
						title: 'Mark as a false positive and whitelist in the firewall',
					}, fpBusy ? '…' : `✅ ${ fpLabel }` )
					: null,

			/* Mute / un-mute */
			muted
				? h( Button, { variant: 'default', onClick: onUnmute }, '🔔 Un-mute this alert type' )
				: h( Button, { variant: 'default', onClick: onMute, title: 'Stop receiving alerts of this type on every channel' }, '🔕 Ignore alerts like this' )
		)
	);
}

/* ==================================================================== *
 * Muted tab
 * ==================================================================== */

function MutedTab( { muted, onUnmute } ) {
	if ( ! muted.length ) {
		return h(
			Card,
			{ title: 'Muted alert types' },
			h( EmptyState, {
				icon: '🔕',
				title: 'Nothing muted',
				hint: 'When an alert is too noisy, use “Ignore alerts like this” from the History tab. Muted types stop e-mailing you but are still recorded in the audit log.',
			} )
		);
	}

	return h(
		Card,
		{ title: 'Muted alert types' },
		h( 'p', { className: 'ts-notif-intro' },
			'These event types will not trigger a notification on any channel. They are still written to the audit log.'
		),
		h( 'ul', { className: 'ts-muted-list' },
			muted.map( ( type ) => {
				const m = eventTypeMeta( type );
				return h( 'li', { key: type, className: 'ts-muted-item' },
					h( 'span', { className: 'ts-muted-item__icon', 'aria-hidden': 'true' }, m.icon ),
					h( 'span', { className: 'ts-muted-item__text' },
						h( 'span', { className: 'ts-muted-item__label' }, m.label ),
						h( 'code', { className: 'ts-evt__code' }, type )
					),
					h( Button, { variant: 'ghost', onClick: () => onUnmute( type ) }, 'Un-mute' )
				);
			} )
		)
	);
}
