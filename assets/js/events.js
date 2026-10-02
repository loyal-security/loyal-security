/**
 * Event humanization layer.
 *
 * Turns raw event types (e.g. `waf.block`) and the structured context recorded with them
 * into something an average site owner can read: a plain-language title, a one-sentence
 * explanation of *what happened and why it matters*, an icon, and a worded severity.
 *
 * Shared by the Dashboard activity feed and the Audit Log viewer so both speak the same
 * language. Pure functions, no dependencies — safe to import anywhere.
 */

/**
 * Friendly descriptions for WAF attack categories (mirrors the `category` field in
 * data/waf-signatures.php). `label` is the attack's common name; `blurb` explains, in
 * lay terms, what the attacker was trying to do.
 */
const ATTACK_CATEGORIES = {
	sqli:      { label: 'SQL injection',        blurb: 'an attempt to tamper with or steal data from the site database by smuggling a malicious query' },
	xss:       { label: 'Cross-site scripting', blurb: 'an attempt to inject malicious JavaScript that would run in visitors’ browsers' },
	traversal: { label: 'Directory traversal',  blurb: 'an attempt to break out of the web folder and read files it shouldn’t reach' },
	lfi:       { label: 'Local file inclusion',  blurb: 'an attempt to make the site load a sensitive local file' },
	rfi:       { label: 'Remote file inclusion', blurb: 'an attempt to pull in and execute a file hosted on an attacker’s server' },
	rce:       { label: 'Remote code execution', blurb: 'an attempt to run arbitrary commands on your server' },
	php:       { label: 'PHP code injection',    blurb: 'an attempt to inject and execute PHP code' },
	proto:     { label: 'Protocol abuse',        blurb: 'a malformed or abusive request crafted to confuse the web server' },
	scanner:   { label: 'Vulnerability scan',    blurb: 'an automated tool probing the site for known weaknesses' },
};

const ATTACK_FALLBACK = { label: 'Malicious request', blurb: 'a request that matched a known attack pattern' };

/**
 * Friendly descriptions for malware/integrity *finding* categories (mirrors the `category`
 * field in data/malware-signatures.php and the integrity engine). `what` names the threat;
 * `off` explains, in lay terms, why it’s dangerous if left in place.
 */
const THREAT_CATEGORIES = {
	backdoor:    { label: 'Backdoor', what: 'Code that gives an attacker a hidden way back into your site.', off: 'Left in place, an attacker can return and re-infect the site at any time, even after you change passwords.' },
	webshell:    { label: 'Web shell', what: 'A script that lets an attacker run commands or browse files through the browser.', off: 'Grants remote control of your server — file theft, defacement, sending spam, or attacking other sites.' },
	obfuscation: { label: 'Obfuscated code', what: 'Code deliberately scrambled (base64/eval) to hide what it really does.', off: 'Legitimate code rarely hides itself; this is a strong sign of injected malware that should be reviewed.' },
	injection:   { label: 'Code injection', what: 'Malicious code inserted into an otherwise normal file.', off: 'Can redirect visitors, steal data, or load further malware on every page view.' },
	suspicious:  { label: 'Suspicious code', what: 'A pattern often associated with malware (e.g. remote downloads, dangerous functions).', off: 'May be benign, but warrants a look — attackers use these building blocks.' },
	integrity:   { label: 'Modified file', what: 'A core/plugin/theme file that no longer matches its official version.', off: 'Unexpected changes to trusted files are a classic backdoor technique.' },
};

const THREAT_FALLBACK = { label: 'Potential threat', what: 'A file or database entry that matched a detection signature.', off: 'Review the file; if you didn’t put this code there, quarantine it.' };

/** Where in the request a payload was found, in plain words. */
const SOURCE_LABELS = {
	query:  'URL query parameter',
	post:   'form field',
	body:   'request body field',
	cookie: 'cookie',
	header: 'header',
	uri:    'URL path',
	path:   'URL path',
};

/**
 * Base metadata for every known event type: an icon and a human label. Some entries are
 * refined further by describeEvent() using the event's context (e.g. the attack category).
 */
const EVENT_META = {
	// Firewall / WAF.
	'waf.block':       { icon: '🛡️', label: 'Attack blocked' },
	'waf.vpatch':      { icon: '🩹', label: 'Known exploit blocked' },
	'waf.bruteforce':  { icon: '🔨', label: 'Brute-force attack blocked' },
	'waf.ddos':        { icon: '🌊', label: 'Traffic flood blocked' },
	'waf.ratelimit':   { icon: '🚦', label: 'Rate limit triggered' },
	'waf.query_cardinality': { icon: '🧩', label: 'Filter-combination abuse blocked' },
	'waf.geo.block':   { icon: '🌍', label: 'Request from blocked country' },
	'waf.bot.block':   { icon: '🤖', label: 'Malicious bot blocked' },
	'waf.ban.added':   { icon: '⛔', label: 'IP address banned' },
	'waf.ban.removed': { icon: '✅', label: 'IP ban lifted' },

	// Authentication.
	'auth.login.success':     { icon: '🔓', label: 'Successful sign-in' },
	'auth.login.failed':      { icon: '🔑', label: 'Failed sign-in attempt' },
	'auth.logout':            { icon: '🚪', label: 'Signed out' },
	'auth.2fa.enrolled':      { icon: '🔐', label: 'Two-factor enabled' },
	'auth.2fa.failed':        { icon: '🔐', label: 'Two-factor check failed' },
	'auth.2fa.success':       { icon: '🔐', label: 'Two-factor verified' },
	'auth.password.rejected': { icon: '🔑', label: 'Weak password rejected' },
	'auth.session.destroyed': { icon: '🚪', label: 'Session ended' },

	// Scanner / integrity.
	'scan.started':      { icon: '🔬', label: 'Malware scan started' },
	'scan.completed':    { icon: '🔬', label: 'Malware scan finished' },
	'scan.finding':      { icon: '🦠', label: 'Malware detected' },
	'integrity.changed': { icon: '📝', label: 'Core/plugin file changed' },

	// Incident response.
	'incident.quarantine.add':     { icon: '🧪', label: 'File quarantined' },
	'incident.quarantine.restore': { icon: '♻️', label: 'File restored from quarantine' },
	'incident.recovered':          { icon: '🛟', label: 'Files recovered' },
	'incident.permissions.reset':  { icon: '🔧', label: 'File permissions reset' },

	// Hardening / settings.
	'hardening.applied':  { icon: '🛠️', label: 'Hardening applied' },
	'hardening.reverted': { icon: '↩️', label: 'Hardening reverted' },
	'settings.changed':   { icon: '⚙️', label: 'Settings changed' },

	// WordPress lifecycle.
	'wp.plugin.activated':   { icon: '🔌', label: 'Plugin activated' },
	'wp.plugin.deactivated': { icon: '🔌', label: 'Plugin deactivated' },
	'wp.plugin.installed':   { icon: '📦', label: 'Plugin installed' },
	'wp.theme.switched':     { icon: '🎨', label: 'Theme switched' },
	'wp.user.created':       { icon: '👤', label: 'User account created' },
	'wp.user.role':          { icon: '👑', label: 'User role changed' },
	'wp.core.updated':       { icon: '⬆️', label: 'WordPress core updated' },
};

const SEVERITY_LABELS = { 40: 'Critical', 30: 'Warning', 20: 'Notice', 10: 'Info' };

// Sentinel case classification/status — a different enum namespace from EVENT_META above
// (these describe an AI-analyst verdict, not a logged event type), so they get their own
// small maps rather than being forced through eventTypeMeta().
const CLASSIFICATION_LABELS = { malicious: 'Malicious', suspicious: 'Suspicious', benign: 'Benign' };
const CASE_STATUS_LABELS = {
	pending: 'Collecting', analyzing: 'Analyzing', verdict: 'Needs review',
	actioned: 'Actioned', false_positive: 'False positive', dismissed: 'Dismissed',
};

/** Worded label for a Sentinel case's classification (malicious/suspicious/benign). */
export function classificationLabel( classification ) {
	return CLASSIFICATION_LABELS[ classification ] || humanizeType( classification );
}

/** Worded label for a Sentinel case's status. */
export function caseStatusLabel( status ) {
	return CASE_STATUS_LABELS[ status ] || humanizeType( status );
}

/**
 * Friendly icon + label for a bare event type (no context needed). Handy for aggregate
 * views like "Blocks by type" that group by event_type alone.
 *
 * @param {string} type Event type, e.g. "waf.block".
 * @return {{icon:string,label:string}}
 */
export function eventTypeMeta( type ) {
	return EVENT_META[ type ] || { icon: '•', label: humanizeType( type ) };
}

/**
 * Friendly metadata for a malware/integrity finding category, including help text shaped
 * for the InfoTip ({ what, off }).
 *
 * @param {string} category e.g. "backdoor", "webshell", "integrity".
 * @return {{label:string,what:string,off:string}}
 */
export function threatMeta( category ) {
	return THREAT_CATEGORIES[ category ] || THREAT_FALLBACK;
}

/** Worded severity (e.g. "Critical") from the numeric level. */
export function severityLabel( severity ) {
	const n = Number( severity );
	if ( n >= 40 ) return SEVERITY_LABELS[ 40 ];
	if ( n >= 30 ) return SEVERITY_LABELS[ 30 ];
	if ( n >= 20 ) return SEVERITY_LABELS[ 20 ];
	return SEVERITY_LABELS[ 10 ];
}

/** Turn an unknown dotted event type into a Title Cased fallback label. */
function humanizeType( type ) {
	return String( type || 'Event' )
		.replace( /[._]/g, ' ' )
		.replace( /\b\w/g, ( c ) => c.toUpperCase() );
}

function sourceLabel( source ) {
	return SOURCE_LABELS[ String( source || '' ).toLowerCase() ] || 'request';
}

/**
 * Describe an event for display.
 *
 * @param {object} ev Event row ({ event_type, severity, context, ip, ... }).
 * @return {{icon:string,title:string,summary:string,sevLabel:string}}
 */
export function describeEvent( ev ) {
	const type = ( ev && ev.event_type ) || '';
	const ctx  = ev && ev.context && typeof ev.context === 'object' ? ev.context : {};
	const meta = EVENT_META[ type ] || { icon: '•', label: humanizeType( type ) };

	let title   = meta.label;
	let summary = '';

	switch ( type ) {
		case 'waf.block': {
			const cat = ATTACK_CATEGORIES[ ctx.category ] || ATTACK_FALLBACK;
			const onlyDetected = !! ctx.detection_only;
			title = cat.label + ( onlyDetected ? ' detected' : ' attack blocked' );
			const m = Array.isArray( ctx.matches ) && ctx.matches.length ? ctx.matches[ 0 ] : null;
			const where = m && m.param ? ` Spotted in the “${ m.param }” ${ sourceLabel( m.source ) }.` : '';
			const verb = onlyDetected
				? 'was detected but allowed through (detection-only mode)'
				: 'was identified and blocked before it reached your site';
			summary = `A ${ cat.label } attempt — ${ cat.blurb } — ${ verb }.${ where }`;
			break;
		}
		case 'waf.vpatch': {
			const rule = ctx.rule || ( ctx.rule && ctx.rule.id ) || '';
			title = 'Known vulnerability exploit blocked';
			summary = 'A request matched a virtual patch shielding a known-vulnerable plugin or theme, and was blocked'
				+ ( rule ? ` (patch ${ ruleId( rule ) }).` : '.' );
			break;
		}
		case 'waf.bruteforce':
			title = 'Brute-force login attack blocked';
			summary = 'Repeated failed sign-in attempts from this address crossed the lockout threshold'
				+ ( ctx.username ? ` (targeting “${ ctx.username }”)` : '' ) + ', so it was locked out.';
			break;
		case 'waf.ddos':
			title = 'Traffic flood blocked';
			summary = 'An abnormal burst of requests from this address was throttled to keep the site responsive'
				+ ( ctx.reason ? ` (${ ctx.reason }).` : '.' );
			break;
		case 'waf.ratelimit':
			title = 'Too many requests — rate limited';
			summary = 'This address sent more requests than allowed in a short window'
				+ ( ctx.count ? ` (${ ctx.count } requests)` : '' ) + ' and was temporarily slowed down.';
			break;
		case 'waf.query_cardinality':
			title = 'Filter-combination abuse blocked';
			summary = 'This address requested an unusually high number of distinct filter/search combinations in a short window'
				+ ( ctx.count ? ` (${ ctx.count } combinations)` : '' ) + ' — a pattern typical of a bot enumerating a faceted-search or archive page rather than a real visitor browsing.';
			break;
		case 'waf.geo.block':
			title = 'Request from a blocked country';
			summary = 'A request was blocked because it came from a country you’ve chosen to restrict'
				+ ( ctx.reason ? ` (${ ctx.reason }).` : '.' );
			break;
		case 'waf.bot.block':
			title = 'Malicious bot blocked';
			summary = 'An automated client identified as a bad bot was blocked'
				+ ( ctx.reason ? ` (${ ctx.reason }).` : '.' );
			break;
		case 'waf.ban.added':
			title = 'IP address banned';
			summary = `${ ev.ip || 'An address' } was added to the ban list`
				+ ( ctx.reason ? ` — ${ ctx.reason }.` : '.' )
				+ ( ctx.type ? ` (${ ctx.type } ban)` : '' );
			break;
		case 'scan.finding':
			title = 'Malware detected';
			summary = 'The scanner flagged a file matching a known malware or web-shell signature. Review it under Quarantine.';
			break;
		case 'integrity.changed':
			title = 'Monitored file changed';
			summary = ( ctx.changed ? `${ ctx.changed } core/plugin file(s) ` : 'A core or plugin file ' )
				+ 'differ from the official checksums — this can indicate tampering.';
			break;
		case 'incident.quarantine.add':
			title = 'Suspicious file quarantined';
			summary = 'A flagged file was moved to secure, non-executable storage so it can no longer run'
				+ ( ctx.path ? `: ${ shortPath( ctx.path ) }` : '.' );
			break;
		case 'auth.login.failed':
			title = 'Failed sign-in attempt';
			summary = 'Someone tried to sign in with the wrong credentials'
				+ ( ctx.username ? ` for “${ ctx.username }”.` : '.' );
			break;
		case 'auth.2fa.failed':
			title = 'Two-factor check failed';
			summary = 'A correct password was given but the two-factor code was wrong — the sign-in was stopped.';
			break;
		case 'wp.user.role':
			title = 'User role changed';
			summary = 'A user account’s role was changed — watch for unexpected escalations to Administrator.';
			break;
		default:
			summary = '';
	}

	return { icon: meta.icon, title, summary, sevLabel: severityLabel( ev && ev.severity ) };
}

/** A virtual-patch rule may be a string id or an object — normalize to an id string. */
function ruleId( rule ) {
	if ( rule && typeof rule === 'object' ) return rule.id || rule.name || JSON.stringify( rule );
	return String( rule );
}

/** Trim long filesystem paths to the trailing, meaningful part. */
function shortPath( path ) {
	const p = String( path );
	const parts = p.split( /[\\/]/ );
	return parts.length > 3 ? '…/' + parts.slice( -3 ).join( '/' ) : p;
}

/**
 * Build a structured, human-readable detail list for an event's incident report.
 * Returns an array of { label, value } rows ready to render. Skips empty values.
 *
 * @param {object} ev Event row with decoded context.
 * @return {Array<{label:string,value:string}>}
 */
export function incidentDetails( ev ) {
	const ctx  = ev && ev.context && typeof ev.context === 'object' ? ev.context : {};
	const rows = [];
	const push = ( label, value ) => {
		if ( value !== undefined && value !== null && value !== '' ) rows.push( { label, value: String( value ) } );
	};

	push( 'Source IP', ev.ip );
	push( 'When', ev.created_at );
	push( 'Method', ev.method );
	push( 'Target URL', ev.request_uri );

	if ( ctx.category ) {
		const cat = ATTACK_CATEGORIES[ ctx.category ];
		push( 'Attack type', cat ? cat.label : ctx.category );
	}
	push( 'Anomaly score', ctx.score );
	push( 'Triggered rule', ctx.rule ? ruleId( ctx.rule ) : '' );
	if ( ctx.detection_only ) push( 'Mode', 'Detection only (not blocked)' );
	push( 'Reason', ctx.reason );
	push( 'Failed attempts', ctx.count );
	push( 'Targeted user', ctx.username );
	push( 'File', ctx.path ? shortPath( ctx.path ) : '' );
	push( 'User agent', ev.user_agent );

	return rows;
}

/**
 * The individual signature matches behind a WAF block (the strongest forensic evidence):
 * which rule fired, where, and a short description. Empty array when not applicable.
 *
 * @param {object} ev Event row with decoded context.
 * @return {Array<{rule:string,where:string,category:string,score:(number|string),desc:string}>}
 */
export function attackMatches( ev ) {
	const ctx = ev && ev.context && typeof ev.context === 'object' ? ev.context : {};
	if ( ! Array.isArray( ctx.matches ) ) return [];
	return ctx.matches.map( ( m ) => ( {
		rule:     m.rule || '',
		where:    m.param ? `${ m.param } (${ sourceLabel( m.source ) })` : sourceLabel( m.source ),
		category: ( ATTACK_CATEGORIES[ m.category ] || {} ).label || m.category || '',
		score:    m.score != null ? m.score : '',
		desc:     m.desc || '',
	} ) );
}

/** Human-friendly relative time, e.g. "3 min ago". Falls back to the raw string. */
export function relativeTime( iso ) {
	if ( ! iso ) return '';
	// Events are stored as UTC ("Y-m-d H:i:s"); normalize to ISO so Date parses as UTC.
	const ts = Date.parse( String( iso ).replace( ' ', 'T' ) + 'Z' );
	if ( Number.isNaN( ts ) ) return String( iso );
	const diff = Math.round( ( Date.now() - ts ) / 1000 );
	if ( diff < 45 ) return 'just now';
	if ( diff < 90 ) return '1 min ago';
	if ( diff < 3600 ) return `${ Math.round( diff / 60 ) } min ago`;
	if ( diff < 7200 ) return '1 hour ago';
	if ( diff < 86400 ) return `${ Math.round( diff / 3600 ) } hours ago`;
	if ( diff < 172800 ) return 'yesterday';
	return `${ Math.round( diff / 86400 ) } days ago`;
}
