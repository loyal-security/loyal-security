/**
 * Plain-language help for every setting, so a non-expert can *decide*.
 *
 * Each entry answers three questions in lay terms:
 *   what — what the setting actually controls.
 *   on   — what happens when it's enabled / set (the protective effect).
 *   off  — how leaving it off or misconfigured can be abused by an attacker (the risk).
 *
 * Keys are `<moduleId>.<settingKey>` (e.g. `firewall.threshold`). The Hardening panel also
 * looks up its wp-config constants here by `hardening.<CONSTANT>`. Unknown keys simply get
 * no icon — add an entry to document a new setting.
 */
export const SETTINGS_HELP = {
	/* ----------------------------------------------------------------- Firewall (WAF). */
	'firewall.enabled': {
		what: 'The Web Application Firewall — inspects every incoming request for attack patterns before WordPress handles it.',
		on: 'Malicious requests (SQL injection, cross-site scripting, file inclusion, etc.) are detected and blocked.',
		off: 'Your site has no request filtering. Known exploit attempts reach WordPress and your plugins directly.',
	},
	'firewall.detection_only': {
		what: 'A “monitor but don’t block” mode for the firewall.',
		on: 'Attacks are logged but allowed through — useful for a few days to confirm the firewall isn’t blocking real visitors before you trust it.',
		off: 'Normal protection: detected attacks are actually blocked. This is the recommended setting for a live site.',
	},
	'firewall.threshold': {
		what: 'The anomaly-score limit. Each suspicious pattern in a request adds points; the request is blocked once the total reaches this number.',
		on: 'A lower number is stricter (blocks sooner); a higher number is more lenient. 12 is a balanced default.',
		off: 'Set too high and real attacks slip under the bar; set too low and legitimate requests may be blocked (false positives).',
	},
	'firewall.block_status': {
		what: 'The HTTP status code returned to a blocked request (e.g. 403 Forbidden).',
		on: '403 is standard for “blocked”. Some operators use 406 or 444 to give scanners less information.',
		off: 'A misleading code can confuse legitimate tools or, conversely, tell an attacker exactly what stopped them.',
	},
	'firewall.whitelist_admins': {
		what: 'Skips the heuristic firewall checks for logged-in administrators.',
		on: 'Prevents the firewall from ever blocking a trusted admin doing legitimate work (active IP bans still apply to everyone).',
		off: 'Admins are subject to the same rules — safer, but a power user pasting code/SQL into a legitimate field could trip a block.',
	},
	'firewall.trust_proxy': {
		what: 'Whether to read the visitor’s real IP from proxy headers (X-Forwarded-For) instead of the direct connection.',
		on: 'Required when you sit behind Cloudflare, a load balancer, or a reverse proxy — otherwise every visitor looks like the proxy’s IP.',
		off: 'If you ARE behind a proxy and leave this off, bans and rate-limits apply to the wrong IP. If you are NOT behind a trusted proxy, turning this on lets attackers spoof their IP via a forged header.',
	},
	'firewall.trusted_proxies': {
		what: 'The list of proxy/CDN IP addresses (or CIDR ranges) you actually trust to set the X-Forwarded-For header.',
		on: 'Only these sources are believed when resolving the real client IP, so the header can’t be spoofed by random visitors.',
		off: 'Empty + “trust proxy” on means any client can forge their IP and evade bans. Fill in your CDN/load-balancer ranges.',
	},
	'firewall.disabled_rules': {
		what: 'Firewall signature IDs you have explicitly switched off.',
		on: 'Use this to silence a specific rule that causes a false positive on your site.',
		off: 'Every disabled rule is a gap. Remove an ID here once the underlying false positive is fixed to restore full coverage.',
	},
	'firewall.allow_params': {
		what: 'Request parameter names that are exempt from inspection (allow-listed).',
		on: 'Handy when a legitimate field (e.g. a code editor or rich-text body) naturally contains characters the firewall flags.',
		off: 'Anything listed here is a blind spot — an attacker who knows the parameter name can smuggle a payload through it. Keep this list short.',
	},
	'firewall.rate_limit_enabled': {
		what: 'Caps how many requests a single IP can make in a time window.',
		on: 'Throttles scrapers, scanners, and credential-stuffing tools that hammer the site rapidly.',
		off: 'A single IP can send unlimited requests, enabling aggressive scanning, content scraping, and login brute-forcing.',
	},
	'firewall.rate_limit_requests': {
		what: 'The maximum number of requests allowed per IP within the rate-limit window.',
		on: 'Lower is stricter. 240 per window suits a normal browsing visitor.',
		off: 'Too high lets abuse through; too low can throttle legitimate users on shared/office IPs.',
	},
	'firewall.rate_limit_window': {
		what: 'The length of the rate-limit window, in seconds.',
		on: 'The request cap is counted over this many seconds (e.g. 240 requests per 60 seconds).',
		off: 'A very long window can lock out a busy legitimate user; a very short one weakens the limit.',
	},
	'firewall.bruteforce_max': {
		what: 'How many failed logins from one IP are allowed before it is locked out.',
		on: 'A low number (e.g. 5) stops password-guessing attacks quickly.',
		off: 'Set too high and attackers get many guesses; too low and a forgetful real user gets locked out.',
	},
	'firewall.bruteforce_window': {
		what: 'The time window (seconds) over which failed logins are counted.',
		on: 'Failures within this window add up toward the lockout threshold.',
		off: 'A long window is stricter (failures “remembered” longer); too short lets attackers reset their count by waiting.',
	},
	'firewall.bruteforce_lockout': {
		what: 'How long (seconds) an IP is locked out after too many failed logins.',
		on: 'A longer lockout (e.g. 1800 = 30 min) makes brute-forcing impractically slow.',
		off: 'A very short lockout barely slows an attacker; a very long one inconveniences a locked-out legitimate user.',
	},
	'firewall.ddos_enabled': {
		what: 'A burst shield that detects sudden floods of requests from one source.',
		on: 'Temporarily bans IPs that spike far above normal traffic, absorbing small denial-of-service bursts.',
		off: 'A single source can flood the site with a rapid burst and degrade performance for everyone.',
	},
	'firewall.ddos_burst': {
		what: 'The number of requests in the burst window that triggers the DDoS shield.',
		on: 'Crossing this many requests in the burst window flags the IP as a flood.',
		off: 'Too high misses real floods; too low may ban legitimate spikes (e.g. a page with many assets).',
	},
	'firewall.ddos_window': {
		what: 'The burst-detection window, in seconds.',
		on: 'Requests are counted over this short window to spot a flood.',
		off: 'Tune together with the burst count — a mismatched window makes the shield too twitchy or too slow.',
	},
	'firewall.ddos_ban': {
		what: 'How long (seconds) a flood source is banned.',
		on: 'A longer ban keeps an attacking IP out while the burst subsides.',
		off: 'Too short and the flood resumes immediately; too long risks holding a legitimate spike IP.',
	},
	'firewall.block_empty_ua': {
		what: 'Blocks requests that send no User-Agent (browser identity) string.',
		on: 'Filters out lazy bots and scripts, most of which omit a User-Agent.',
		off: 'Leaving it off (default) avoids blocking rare legitimate tools/monitors that don’t set a User-Agent.',
	},
	'firewall.custom_bad_agents': {
		what: 'Extra User-Agent substrings to block (one per line), on top of the built-in bad-bot list.',
		on: 'Add the signatures of bots/scrapers you specifically want to keep out.',
		off: 'Only the built-in list applies. A niche scraper hitting your site won’t be blocked until you add it here.',
	},
	'firewall.geo_mode': {
		what: 'Country-based access control: off, allow-list only, or block-list.',
		on: '“allow” lets in only the countries you list; “block” keeps out the countries you list.',
		off: '“off” means no geographic filtering. Misconfiguring “allow” with an empty list can lock out your whole audience — set the countries first.',
	},
	'firewall.geo_countries': {
		what: 'The list of two-letter country codes the geo rule applies to.',
		on: 'Works with the geo mode above to allow or block these countries.',
		off: 'An empty list with mode “allow” blocks everyone; with mode “block” it blocks no one. Always pair this with the mode.',
	},
	'firewall.virtual_patching': {
		what: 'Shields known-vulnerable third-party plugins/themes with targeted rules until you can update them.',
		on: 'Blocks requests matching published exploits even before the vendor’s patch is installed.',
		off: 'A site running an outdated, vulnerable plugin is exposed to its public exploit until the plugin itself is updated.',
	},

	/* --------------------------------------------------------------------- Hardening. */
	'hardening.enabled': {
		what: 'The hardening module — removes WordPress’s riskier default behaviours and information leaks.',
		on: 'Applies the runtime protections below (version hiding, XML-RPC, REST limits, etc.).',
		off: 'WordPress runs with its permissive defaults, exposing more surface for reconnaissance and attack.',
	},
	'hardening.obfuscate_version': {
		what: 'Hides the WordPress version from your pages and asset URLs.',
		on: 'Attackers can’t trivially see which version you run, making it harder to target version-specific exploits.',
		off: 'Your exact WP version is published in the page source, letting bots match it to known vulnerabilities.',
	},
	'hardening.disable_xmlrpc': {
		what: 'Disables xmlrpc.php, a legacy remote API.',
		on: 'Closes a classic brute-force amplification and DDoS-reflection endpoint that most modern sites never use.',
		off: 'xmlrpc.php stays open — attackers can test hundreds of passwords per request and abuse pingback for reflection attacks.',
	},
	'hardening.disable_pingback': {
		what: 'Removes pingback methods and the X-Pingback header.',
		on: 'Stops your site from being used as a reflector in distributed denial-of-service attacks against others.',
		off: 'Your site can be weaponised to flood third parties, and you may be blamed for the traffic.',
	},
	'hardening.restrict_rest_users': {
		what: 'Hides the /wp-json/wp/v2/users REST endpoint from anonymous callers.',
		on: 'Stops attackers from listing your usernames via the REST API to seed password-guessing.',
		off: 'Anyone can fetch your list of usernames, which is the first half of a login brute-force.',
	},
	'hardening.restrict_rest_cors': {
		what: 'WordPress core reflects any requesting website back in Access-Control-Allow-Origin (with credentials allowed) for every REST API call, unconditionally.',
		on: 'Only your own site — plus any origins you explicitly trust below — can read REST API responses using a logged-in visitor’s cookies. Everyone else’s browser is refused, even though core would normally let them in.',
		off: 'Any website on the internet can make cookie-authenticated requests to your REST API from a logged-in admin’s browser and read the response — a classic CORS misconfiguration.',
	},
	'hardening.restrict_rest_all': {
		what: 'Requires authentication for the *entire* REST API, not just the users endpoint.',
		on: 'Maximum lock-down of the API surface.',
		off: 'Leave off (default) unless you’re sure — turning it on can break the block editor, contact forms, and headless/integration features that rely on public REST calls.',
	},
	'hardening.block_author_enum': {
		what: 'Blocks the ?author=N trick that maps user IDs to login names.',
		on: 'Prevents another common route for discovering valid usernames.',
		off: 'Visiting ?author=1 reveals the admin’s login name, handing attackers a target account.',
	},
	'hardening.DISALLOW_FILE_EDIT': {
		what: 'Removes the built-in Appearance → Theme/Plugin File Editor from wp-admin.',
		on: 'Even a logged-in admin can no longer edit live PHP from the dashboard. Strongly recommended.',
		off: 'Anyone who gains admin access (stolen password, hijacked session) can paste a web shell straight into a theme file and run code on your server — no FTP required. This is one of the most common post-compromise escalation paths.',
	},
	'hardening.DISALLOW_FILE_MODS': {
		what: 'Blocks all plugin/theme installs, updates, and deletions from the dashboard.',
		on: 'A full lock-down: nothing can be installed or changed through wp-admin, ideal for tightly managed sites.',
		off: 'Off by default so you can update normally. When off, an attacker with admin access can upload a malicious plugin. (Note: this also blocks your own updates while on.)',
	},
	'hardening.FORCE_SSL_ADMIN': {
		what: 'Forces the admin area and login over HTTPS.',
		on: 'Passwords and session cookies are always encrypted in transit.',
		off: 'If your site is reachable over plain HTTP, logins can be sniffed on the network and sessions hijacked. Only enable once a valid SSL certificate is installed.',
	},

	/* ----------------------------------------------------------------------- Scanner. */
	'scanner.enabled': {
		what: 'The malware/file scanner — checks your files against known malware and web-shell signatures.',
		on: 'Surfaces backdoors, injected code, and suspicious files so you can quarantine them.',
		off: 'Malware planted by an attacker can persist unnoticed, re-infecting the site after cleanup.',
	},
	'scanner.max_file_size': {
		what: 'The largest file (in bytes) the scanner will read.',
		on: 'Skipping very large files keeps scans fast and avoids memory issues. 3 MB covers virtually all code files.',
		off: 'Set too low and a large infected file is skipped; too high and scans get slow and memory-hungry.',
	},
	'scanner.extensions': {
		what: 'Which file types are scanned (one extension per line).',
		on: 'Focuses on executable/script types where malware actually hides (php, js, phar, etc.).',
		off: 'Remove a risky extension here and infected files of that type won’t be examined. Keep php/phtml/phar listed.',
	},
	'scanner.scan_database': {
		what: 'Also scans database content (posts, options) for injected scripts and spam.',
		on: 'Catches malware that lives in the database rather than in files (e.g. injected redirect scripts).',
		off: 'Database-resident infections — a very common attack — go undetected even if your files are clean.',
	},
	'scanner.scheduled_scan': {
		what: 'Runs a full malware scan automatically once a week.',
		on: 'You get ongoing detection without remembering to scan manually.',
		off: 'Scans only happen when you click manually, so a fresh infection can sit undetected for a long time.',
	},
	'scanner.batch_size': {
		what: 'How many files are processed per scan batch.',
		on: 'Smaller batches are gentler on slow/shared hosting; larger batches finish faster on capable servers.',
		off: 'Too large can hit timeouts or exhaust memory on weak hosts; too small makes full scans drag on.',
	},

	/* --------------------------------------------------------------------- Integrity. */
	'integrity.enabled': {
		what: 'File Integrity Monitoring — compares your files to the official originals to detect tampering.',
		on: 'Flags any core/plugin/theme file that differs from the verified version published online.',
		off: 'Silent modifications to core or plugin files (a classic backdoor technique) go unnoticed.',
	},
	'integrity.verify_core': {
		what: 'Checks WordPress core files against the official WordPress.org checksums.',
		on: 'Detects any altered or extra file in wp-admin / wp-includes — the heart of your site.',
		off: 'An attacker can patch a core file to add a backdoor and you won’t be alerted.',
	},
	'integrity.verify_plugins': {
		what: 'Checks installed plugins against the checksums published on WordPress.org.',
		on: 'Detects tampering in plugin code, a frequent place for injected malware.',
		off: 'Modified plugin files (injected redirects, shells) aren’t flagged.',
	},
	'integrity.verify_themes': {
		what: 'Snapshots your themes and reports later changes against that baseline.',
		on: 'Alerts you when theme files change unexpectedly between scans.',
		off: 'Theme files — a common injection target (e.g. functions.php) — change without warning.',
	},
	'integrity.scheduled': {
		what: 'Runs integrity checks automatically on a schedule.',
		on: 'Continuous tamper detection without manual effort.',
		off: 'Tampering is only caught when you run a check by hand.',
	},

	/* ---------------------------------------------------------------------- Incident. */
	'incident.enabled': {
		what: 'Incident-response tools: quarantine, clean-file recovery, and permission reset.',
		on: 'Lets you neutralise and recover from a detected compromise from inside the dashboard.',
		off: 'You lose the one-click cleanup/recovery actions and must remediate infections manually.',
	},
	'incident.perm_dir_mode': {
		what: 'The permission mode applied to directories by the “reset permissions” tool (octal, e.g. 755).',
		on: '755 is the safe standard: owner can write, others can only read/traverse.',
		off: 'Looser modes (777) let any process write to your folders — a route for planting malware. Don’t loosen without reason.',
	},
	'incident.perm_file_mode': {
		what: 'The permission mode applied to files by the “reset permissions” tool (octal, e.g. 644).',
		on: '644 is the safe standard: owner can write, others read-only.',
		off: 'World-writable files (666/777) can be overwritten by other accounts on shared hosting, enabling tampering.',
	},

	/* ------------------------------------------------------------- Identity & Access. */
	'auth.enabled': {
		what: 'The identity module — two-factor auth, password policy, CAPTCHA, and session controls.',
		on: 'Enables the account-protection features below.',
		off: 'Logins rely solely on WordPress defaults, with no 2FA or password strength enforcement.',
	},
	'auth.force_2fa': {
		what: 'Requires two-factor authentication (an app code) for the selected roles.',
		on: 'Even if a password is stolen or guessed, an attacker still can’t log in without the second factor. The single most effective login defence.',
		off: 'A leaked or guessed password is all an attacker needs to take over an account.',
	},
	'auth.force_2fa_roles': {
		what: 'Which user roles must use two-factor authentication.',
		on: 'Target the high-value roles first (administrator, editor).',
		off: 'Roles left off this list can log in with a password alone — make sure administrator is always included.',
	},
	'auth.breach_check': {
		what: 'After a successful login, checks the password against the Have I Been Pwned list of passwords exposed in data breaches.',
		on: 'Only the first 5 characters of the password’s SHA-1 hash are sent to api.pwnedpasswords.com (k-anonymity) — never the password, the username or your site address. At most one check per user per day. A breached password triggers a warning; the login is never blocked.',
		off: 'No request is made. Users who reuse a leaked password get no warning.',
	},
	'backup.max_backups': {
		what: 'How many backups are kept. When a new backup is made, the oldest ones beyond this number are deleted.',
		on: 'More backups let you go further back in time, at the cost of disk space.',
		off: 'Keeping only one backup means a problem you notice late may already be in every copy you have.',
	},
	'traffic.capture_all': {
		what: 'Records every request to the site (not only security events) for the All Traffic view in Live Traffic.',
		on: 'You can watch every visit — human or bot, allowed or blocked — as it arrives. Requests are kept on this server only.',
		off: 'Nothing beyond security events is recorded; the All Traffic view stays empty.',
	},
	'traffic.buffer_size': {
		what: 'How many of the most recent requests Live Traffic keeps (50–5000). Older entries are overwritten.',
		on: 'A larger buffer keeps more history at the cost of a little disk space.',
		off: 'A small buffer only shows the last few minutes on a busy site.',
	},
	'traffic.skip_static': {
		what: 'Skips requests for static files (images, CSS, JavaScript) when recording all traffic.',
		on: 'The buffer holds page and API requests, which is what you usually want to see.',
		off: 'Every asset request is recorded too, so the buffer fills much faster.',
	},
	'threatintel.enabled': {
		what: 'Threat-intelligence updates: new firewall rules, malware signatures, virtual patches and the vulnerability (CVE) list for installed plugins and themes, downloaded from the Loyal Security feed service (licensekit.loyalsecuritywp.com).',
		on: 'Your protection keeps improving between plugin releases, and known-vulnerable plugins/themes are flagged. Requests send only the dataset name, the version you already have, and (for the vulnerability list) the folder names of installed plugins and themes — never your site address or any personal data.',
		off: 'No request is made to the feed service. The firewall and scanner keep working on the rules bundled with the plugin, but get no updates and vulnerability notices stop.',
	},
	'threatintel.auto_sync': {
		what: 'Whether feed updates are fetched automatically (twice a day, or hourly with a Loyal Security Pro subscription).',
		on: 'Updates arrive on their own. Each check sends only what is described under Threat Intelligence above.',
		off: 'Nothing is fetched automatically; use “Sync now” on the Threat Intel screen when you want an update.',
	},
	'auth.pw_min_length': {
		what: 'The minimum number of characters a user password must have.',
		on: 'Longer minimums (12+) dramatically increase the time needed to crack a password.',
		off: 'A low minimum allows weak, quickly-guessable passwords.',
	},
	'auth.pw_mixed_case': {
		what: 'Requires both upper- and lower-case letters in passwords.',
		on: 'Increases password complexity and resistance to guessing.',
		off: 'Users can pick simpler all-lowercase passwords that are easier to brute-force.',
	},
	'auth.pw_number': {
		what: 'Requires at least one digit in passwords.',
		on: 'Adds to password entropy.',
		off: 'Permits dictionary-word passwords with no numbers.',
	},
	'auth.pw_special': {
		what: 'Requires at least one symbol (e.g. !@#$) in passwords.',
		on: 'Further strengthens passwords against guessing and cracking.',
		off: 'Allows simpler passwords that fall faster to automated attacks.',
	},
	'auth.captcha_provider': {
		what: 'Adds a CAPTCHA challenge to the login form (Cloudflare Turnstile or Google reCAPTCHA v3).',
		on: 'Blocks automated login bots before they can even attempt a password.',
		off: '“none” leaves the login form open to scripted brute-force and credential-stuffing bots.',
	},
	'auth.captcha_site_key': {
		what: 'The public site key from your CAPTCHA provider.',
		on: 'Required for the CAPTCHA widget to load on your login form.',
		off: 'Without a valid key the CAPTCHA won’t appear, silently leaving logins unprotected.',
	},
	'auth.captcha_secret_key': {
		what: 'The private/secret key from your CAPTCHA provider (kept server-side).',
		on: 'Required to verify CAPTCHA responses. Stored as a secret and never shown back in full.',
		off: 'Without it, CAPTCHA responses can’t be validated and the check is ineffective.',
	},
	'auth.captcha_min_score': {
		what: 'For reCAPTCHA v3, the minimum “human” score (0–1) required to allow a login.',
		on: 'Higher is stricter. 0.5 is Google’s balanced default.',
		off: 'Set too high and real users get blocked; too low and bots scoring poorly still get through.',
	},
	'auth.captcha_protect_login': {
		what: 'Whether the CAPTCHA challenge applies to the sign-in form specifically.',
		on: 'Stops scripted credential-stuffing and password-guessing against the login form — the highest-value target for this kind of attack.',
		off: 'The login form accepts submissions without a challenge, even though a provider is configured.',
	},
	'auth.captcha_protect_register': {
		what: 'Whether the CAPTCHA challenge applies to the user-registration form.',
		on: 'Stops automated fake-account creation and spam signups.',
		off: 'Anyone (or any bot) can submit the registration form without a challenge, even though a provider is configured.',
	},
	'auth.captcha_protect_lostpassword': {
		what: 'Whether the CAPTCHA challenge applies to the “lost your password” form.',
		on: 'Stops automated password-reset-request flooding, which can be used to spam a target inbox or probe which usernames/emails exist on the site.',
		off: 'The lost-password form accepts submissions without a challenge, even though a provider is configured.',
	},
	'auth.idle_timeout': {
		what: 'Automatically logs a user out after this many minutes of inactivity (0 = off).',
		on: 'Limits the window in which an unattended, logged-in session can be misused.',
		off: '0 means sessions never expire from inactivity — a walked-away-from or hijacked session stays valid indefinitely.',
	},
	'auth.block_concurrent': {
		what: 'Prevents the same account from being logged in from multiple places at once.',
		on: 'A new login ends older sessions, making a stolen session easier to detect and cut off.',
		off: 'An attacker using a stolen session can stay logged in alongside the real user, unnoticed.',
	},

	/* ----------------------------------------------------------------- Notifications. */
	'notifications.enabled': {
		what: 'The notifications module — sends alerts when security events occur.',
		on: 'You receive email alerts for attacks, blocked IPs, malware finds, and other events.',
		off: 'Security events happen silently. You only learn about issues by checking the dashboard manually.',
	},
	'notifications.email_enabled': {
		what: 'Sends alert emails to your chosen address when security events match the configured criteria.',
		on: 'You get an email at the address below whenever a qualifying event occurs.',
		off: 'No email alerts. Useful if you want to silence email noise and check the dashboard instead.',
	},
	'notifications.email_to': {
		what: 'The email address that receives security alert emails.',
		on: 'Alerts go here. Defaults to the site admin email if left blank.',
		off: 'Leave blank to use the WordPress admin email, or fill in a dedicated security inbox.',
	},
	'notifications.email_min_severity': {
		what: 'Only send email alerts for events at or above this severity level.',
		on: 'Higher thresholds mean fewer, more critical emails (e.g. 40 = major events only).',
		off: 'A low threshold can flood your inbox with low-priority events.',
	},
	'notifications.email_categories': {
		what: 'Only send emails for events in these categories (e.g. waf, auth, scanner). Leave empty for all.',
		on: 'Filters alert emails to the security areas you care about most.',
		off: 'An empty list means all categories are included — a wide net.',
	},
	'notifications.throttle_max': {
		what: 'Maximum number of alerts sent within the throttle window.',
		on: 'Prevents alert storms — if the site is under a prolonged attack, you get at most this many messages.',
		off: 'Without throttling, a coordinated attack can generate hundreds of alerts in minutes.',
	},
	'notifications.throttle_window': {
		what: 'The time window (seconds) over which the alert count is limited.',
		on: 'Alerts are capped at throttle_max per this window. 3600 = one hour.',
		off: 'A very short window means the cap resets quickly and alert storms can resume sooner.',
	},

	/* --------------------------------------------------------------------- Audit Log. */
	'audit.enabled': {
		what: 'The audit log — records security-relevant events (logins, blocks, changes).',
		on: 'Gives you the forensic trail needed to investigate incidents and prove the plugin is working.',
		off: 'No record of attacks, logins, or admin changes — you lose visibility and incident evidence.',
	},
	'audit.retention_days': {
		what: 'How many days of audit-log history to keep before old events are pruned.',
		on: 'Longer retention preserves more forensic history; shorter saves database space.',
		off: 'Too short and you lose the trail before you notice an incident; very long can grow the table large.',
	},

	/* ----------------------------------------------------------------- Sentinel AI. */
};

/** Look up help for a `module.key`. Returns null when undocumented. */
export function settingHelp( moduleId, key ) {
	return SETTINGS_HELP[ moduleId + '.' + key ] || null;
}
