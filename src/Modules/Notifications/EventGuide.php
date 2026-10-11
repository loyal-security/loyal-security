<?php
/**
 * Human guidance for security events.
 *
 * Turns a raw event type (e.g. `audit.option.critical`) plus its recorded context into
 * something a non-expert site owner can act on:
 *
 *   - title    A plain-language headline.
 *   - meaning  What actually happened and why it matters.
 *   - legit    When this is normal / how to tell a false positive from a real threat.
 *   - fix      Concrete next steps ("what to do").
 *   - facts    The event's context, decoded and relabelled for humans (no serialized blobs).
 *
 * This is the single source of truth shared by the e-mail template
 * ({@see Dispatcher::email_body()}) and the dashboard notification centre (exposed via
 * {@see \LoyalSecurity\Rest\Controllers\NotificationsController}). Keep it dependency-light
 * and side-effect-free.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Notifications;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;

/**
 * Static catalogue of per-event guidance plus a context humaniser.
 */
final class EventGuide {

	/**
	 * Friendly, human-readable labels for known context keys. Anything not listed is
	 * title-cased on the fly by {@see self::label_for_key()}.
	 *
	 * @var array<string, string>
	 */
	private const KEY_LABELS = array(
		'option'      => 'Setting changed',
		'preview'     => 'New value',
		'category'    => 'Attack type',
		'rule'        => 'Triggered rule',
		'score'       => 'Anomaly score',
		'reason'      => 'Reason',
		'count'       => 'Attempts',
		'username'    => 'Targeted username',
		'path'        => 'File',
		'user'        => 'User',
		'role'        => 'Role',
		'plugin'      => 'Source plugin',
		'theme'       => 'Theme',
		'note'        => 'Note',
		'changed'     => 'Files changed',
		'hooks'       => 'Scheduled tasks',
		'host'        => 'Host',
		'url'         => 'URL',
		'status_code' => 'HTTP status',
		'action'      => 'AJAX action',
		'registered'  => 'Action registered by a plugin',
		'ip'          => 'IP address',
		'ua'          => 'User agent',
	);

	/**
	 * Resolve full guidance for a single event.
	 *
	 * @param string               $type    Event type constant.
	 * @param array<string, mixed> $context Decoded context (associative array).
	 * @param int                  $severity Numeric severity.
	 * @return array{title:string,icon:string,severity_label:string,meaning:string,legit:string,fix:string[],facts:array<int,array{label:string,value:string}>}
	 */
	public static function for_event( string $type, array $context = array(), int $severity = 10 ): array {
		$entry = self::lookup( $type, $context );

		return array(
			'title'          => $entry['title'],
			'icon'           => $entry['icon'],
			'severity_label' => EventCatalog::severity_label( $severity ),
			'meaning'        => $entry['meaning'],
			'legit'          => $entry['legit'],
			'fix'            => $entry['fix'],
			'facts'          => self::humanize_context( $context ),
		);
	}

	/**
	 * Look up guidance by exact type, then by category prefix, then a generic fallback.
	 * Certain entries are refined with values pulled from the context.
	 *
	 * @param string               $type    Event type.
	 * @param array<string, mixed> $context Decoded context.
	 * @return array{title:string,icon:string,meaning:string,legit:string,fix:string[]}
	 */
	private static function lookup( string $type, array $context ): array {
		$map = self::map();

		if ( isset( $map[ $type ] ) ) {
			$entry = $map[ $type ];
		} else {
			$entry = self::category_fallback( $type );
		}

		// Context-aware refinement for the highest-noise events.
		if ( EventCatalog::CRITICAL_OPTION_CHANGED === $type ) {
			$option = isset( $context['option'] ) ? (string) $context['option'] : '';
			$entry  = self::refine_critical_option( $entry, $option );
		}

		if ( EventCatalog::NOPRIV_AJAX_CALL === $type ) {
			$entry = self::refine_nopriv_ajax( $entry, $context );
		}

		return $entry;
	}

	/**
	 * Refine the "critical option changed" guidance based on *which* option changed —
	 * the difference between "someone edited your admin e-mail" and "a plugin list changed"
	 * matters a lot to the reader.
	 *
	 * @param array{title:string,icon:string,meaning:string,legit:string,fix:string[]} $entry Base entry.
	 * @param string                                                                    $option Option key.
	 * @return array{title:string,icon:string,meaning:string,legit:string,fix:string[]}
	 */
	private static function refine_critical_option( array $entry, string $option ): array {
		$known = array(
			'siteurl'         => 'the site address (WordPress Address / Site Address)',
			'home'            => 'the site home URL',
			'admin_email'     => 'the site administrator e-mail',
			'active_plugins'  => 'the list of active plugins',
			'template'        => 'the active theme (parent template)',
			'stylesheet'      => 'the active theme (stylesheet)',
			'users_can_register' => 'the open-registration setting',
			'default_role'    => 'the default role for new users',
		);

		if ( isset( $known[ $option ] ) ) {
			$entry['title']   = 'Critical setting changed: ' . $option;
			$entry['meaning'] = sprintf(
				'A security-sensitive WordPress setting — %s — was just modified. Attackers change these to redirect traffic, hijack password-reset e-mails, or auto-activate a malicious plugin, so every change is reported.',
				$known[ $option ]
			);
		} elseif ( '' !== $option ) {
			$entry['title'] = 'Critical setting changed: ' . $option;
		}

		return $entry;
	}

	/**
	 * Make the nopriv-AJAX guidance specific to the actual action and whether it is registered.
	 *
	 * @param array{title:string,icon:string,meaning:string,legit:string,fix:string[]} $entry   Base entry.
	 * @param array<string,mixed>                                                       $context Decoded context.
	 * @return array{title:string,icon:string,meaning:string,legit:string,fix:string[]}
	 */
	private static function refine_nopriv_ajax( array $entry, array $context ): array {
		$action     = isset( $context['action'] ) ? (string) $context['action'] : '';
		$registered = isset( $context['registered'] ) ? (bool) $context['registered'] : null;

		if ( '' !== $action ) {
			$entry['title'] = $registered
				? sprintf( 'Unauthenticated AJAX call: %s (registered)', $action )
				: sprintf( 'Unregistered AJAX probe: %s', $action );
		}

		if ( null !== $registered ) {
			if ( $registered ) {
				// Registered calls only reach here when the admin enabled monitor_registered_nopriv_ajax.
				$entry['legit'] = sprintf(
					'The action "%s" IS registered by a plugin — this is an expected public endpoint. It appears here only because you enabled monitoring of all nopriv AJAX calls. You can whitelist this action to remove it from future alerts.',
					$action
				);
				array_unshift(
					$entry['fix'],
					sprintf( '✅ "%s" is registered — if it is a plugin feature you recognise, click "Whitelist this AJAX action" below.', $action )
				);
			} else {
				$entry['legit'] = sprintf(
					'🚨 The action "%s" is NOT registered by any active plugin. Nothing on your site should be responding to this — it is almost certainly a scanner or attacker probing for unprotected backdoors or previously removed plugins.',
					$action
				);
				array_unshift(
					$entry['fix'],
					sprintf( '🚨 "%s" has no handler — this is a probe. Check whether it repeats from the same IP and ban it if so.', $action )
				);
			}
		}

		return $entry;
	}

	/**
	 * The full per-type guidance catalogue.
	 *
	 * @return array<string, array{title:string,icon:string,meaning:string,legit:string,fix:string[]}>
	 */
	private static function map(): array {
		return array(

			/* ---- Critical option / settings changes ------------------------ */
			EventCatalog::CRITICAL_OPTION_CHANGED => array(
				'title'   => 'A critical setting was changed',
				'icon'    => '⚙️',
				'meaning' => 'A security-sensitive WordPress option was modified. These settings control who can log in, where the site lives, and which code runs, so unexpected changes can indicate a compromise.',
				'legit'   => 'This is almost always YOU or another administrator making a normal change (updating the admin e-mail, activating a plugin, editing site settings). It is a false positive if the timing lines up with something you just did in wp-admin.',
				'fix'     => array(
					'Check the "When" and user against your own recent activity — did you or a teammate just change a setting?',
					'Open the Audit Log and filter by this event to see the user account and IP behind the change.',
					'If you do NOT recognise it: change all administrator passwords, review Users for unfamiliar accounts, and run a full malware scan.',
					'If it was expected: you can safely mute this alert type from the notification centre.',
				),
			),
			EventCatalog::SUSPICIOUS_OPTION => array(
				'title'   => 'A setting was changed to a suspicious value',
				'icon'    => '⚠️',
				'meaning' => 'A WordPress option was updated with content that looks like injected code or a malicious redirect (e.g. a <script> tag or PHP in a value that should be plain text).',
				'legit'   => 'Rarely legitimate. Some page-builder or widget plugins do store markup in options — compare the value against what that plugin normally saves.',
				'fix'     => array(
					'Review the "New value" below — does it contain script tags, iframes, or encoded PHP?',
					'If it looks injected, restore the option to a known-good value and run a full malware scan.',
					'Check recently modified files under Scanner → Integrity for the source of the injection.',
				),
			),
			EventCatalog::SETTING_CHANGED => array(
				'title'   => 'Loyal Security settings changed',
				'icon'    => '🛠️',
				'meaning' => 'A setting inside Loyal Security itself was updated.',
				'legit'   => 'Normal whenever you adjust the plugin configuration.',
				'fix'     => array( 'No action needed unless you did not make this change — if so, review admin accounts.' ),
			),

			/* ---- Firewall / WAF -------------------------------------------- */
			EventCatalog::WAF_BLOCK => array(
				'title'   => 'An attack was blocked by the firewall',
				'icon'    => '🛡️',
				'meaning' => 'An incoming request matched a known attack pattern (such as SQL injection or cross-site scripting) and was blocked before it reached your site.',
				'legit'   => 'The request was already stopped, so your site was not harmed. False positives happen when a legitimate action (e.g. an admin pasting code into a post, or a plugin sending an unusual request) trips a rule.',
				'fix'     => array(
					'No action is required — the request was blocked automatically.',
					'If a legitimate user reports being blocked, note the IP and rule below and add an allow-rule under Firewall.',
					'Repeated attacks from one IP: consider a permanent ban under Firewall → Bans.',
				),
			),
			EventCatalog::WAF_BRUTEFORCE => array(
				'title'   => 'A brute-force login attack was blocked',
				'icon'    => '🔨',
				'meaning' => 'Someone tried many wrong passwords in a row and was locked out. This is an attempt to guess a login.',
				'legit'   => 'It can be a real user who forgot their password. Check the targeted username below — if it is a common name like "admin", it is almost certainly an attacker.',
				'fix'     => array(
					'No immediate action needed — the attacker was locked out.',
					'Ensure all admin accounts use strong, unique passwords and enable two-factor authentication.',
					'If attacks persist, enable a stricter lockout or CAPTCHA under Firewall / Login protection.',
				),
			),
			EventCatalog::WAF_DDOS => array(
				'title'   => 'A traffic flood was blocked',
				'icon'    => '🌊',
				'meaning' => 'An abnormal burst of requests from one source was throttled to keep your site responsive.',
				'legit'   => 'Aggressive but legitimate crawlers or a sudden traffic spike can look like this. Check the IP and user agent.',
				'fix'     => array(
					'Usually no action needed — the flood was already throttled.',
					'If it is a good bot (e.g. an uptime monitor), allow-list its IP under Firewall.',
				),
			),
			EventCatalog::WAF_VIRTUAL_PATCH => array(
				'title'   => 'A known vulnerability exploit was blocked',
				'icon'    => '🩹',
				'meaning' => 'A request tried to exploit a known vulnerability in a specific plugin or theme, and a virtual patch blocked it.',
				'legit'   => 'Almost never a false positive — these rules target very specific exploit payloads.',
				'fix'     => array(
					'Update the affected plugin/theme to its latest version as soon as possible.',
					'If no update exists, consider replacing or removing the vulnerable component.',
				),
			),
			EventCatalog::PATCH_GAP_PROTECTED => array(
				'title'   => 'Early virtual patch applied — update this plugin when you can',
				'icon'    => '🛡️',
				'meaning' => 'A plugin you have installed recently shipped a security fix, but this site is still on the older version. Loyal Security deployed an early virtual patch that shields the vulnerability now — you are protected — but the real fix is only applied once you update the plugin itself.',
				'legit'   => 'This is expected right after a plugin releases a security update. It is informational, not an attack: no one has necessarily attacked your site yet.',
				'fix'     => array(
					'Update the named plugin to the fixed version at your convenience.',
					'The virtual patch stays active until you do, so there is no emergency — but updating removes the vulnerable code entirely.',
				),
			),

			/* ---- Authentication -------------------------------------------- */
			EventCatalog::LOGIN_FAILED => array(
				'title'   => 'A sign-in attempt failed',
				'icon'    => '🔑',
				'meaning' => 'Someone entered the wrong username or password.',
				'legit'   => 'Very common and usually harmless — most often a real user mistyping. Repeated failures for the same account point to a guessing attack.',
				'fix'     => array(
					'A single failure needs no action.',
					'Many failures in a short time: verify the account owner, and ensure brute-force protection is on under Firewall.',
				),
			),
			EventCatalog::USER_ADMIN_CREATED => array(
				'title'   => 'A new administrator account was created',
				'icon'    => '👑',
				'meaning' => 'A new user with full administrator privileges was added. Creating a rogue admin is one of the most common things an attacker does after breaking in.',
				'legit'   => 'Legitimate when you deliberately add a colleague. It is a red flag if you did not create it or do not recognise the username.',
				'fix'     => array(
					'Confirm you or a trusted teammate created this account (see the username below).',
					'If unexpected: delete the account immediately, change all admin passwords, and run a full malware scan.',
					'Review the Audit Log for how the account was created and from which IP.',
				),
			),
			EventCatalog::USER_ROLE_CHANGED => array(
				'title'   => 'A user role was changed',
				'icon'    => '👑',
				'meaning' => 'An existing account had its role changed. Escalating a low-privilege account to Administrator is a common attacker move.',
				'legit'   => 'Normal when you promote a team member. Suspicious if the change is to Administrator and you did not make it.',
				'fix'     => array(
					'Verify the change was intentional (see user and new role below).',
					'If not: revert the role, review the account, and change admin passwords.',
				),
			),

			/* ---- Scanner / integrity --------------------------------------- */
			EventCatalog::SCAN_FINDING => array(
				'title'   => 'Malware was detected',
				'icon'    => '🦠',
				'meaning' => 'The scanner found a file matching a known malware or web-shell signature.',
				'legit'   => 'Occasionally a security tool or a heavily-obfuscated-but-legitimate plugin trips a signature (a false positive). The file path below tells you what was flagged.',
				'fix'     => array(
					'Open Scanner → review the finding and inspect the flagged file.',
					'If it is malware, quarantine it from the Quarantine panel (reversible).',
					'If it is a known-good file, mark it as ignored in the Scanner so it stops being reported.',
				),
			),
			EventCatalog::INTEGRITY_CHANGED => array(
				'title'   => 'A core or plugin file was modified',
				'icon'    => '📝',
				'meaning' => 'A WordPress core, plugin, or theme file no longer matches its official version. Unexpected changes to trusted files are a classic sign of a backdoor.',
				'legit'   => 'Expected right after you update or edit a plugin/theme. Suspicious if no update happened recently.',
				'fix'     => array(
					'If you just updated something, this is expected — no action needed.',
					'Otherwise, review the changed files under Scanner → Integrity.',
					'Restore core files from Incident → Recovery, or reinstall the affected plugin.',
				),
			),

			/* ---- Incident -------------------------------------------------- */
			EventCatalog::QUARANTINE_ADD => array(
				'title'   => 'A suspicious file was quarantined',
				'icon'    => '🧪',
				'meaning' => 'A flagged file was moved to secure, non-executable storage so it can no longer run.',
				'legit'   => 'This is a protective action taken by the plugin. It is reversible.',
				'fix'     => array(
					'Review the quarantined file under Quarantine.',
					'If it was a false positive, restore it from there; otherwise leave it quarantined or delete it.',
				),
			),

			/* ---- Hardening ------------------------------------------------- */
			EventCatalog::SSRF_BLOCKED => array(
				'title'   => 'A server-side request forgery attempt was blocked',
				'icon'    => '🚫',
				'meaning' => 'Code tried to make your server fetch an internal or private address (a technique used to reach cloud metadata or internal services). It was blocked.',
				'legit'   => 'Rare false positives occur if a plugin legitimately fetches an internal URL. Check the URL/host below.',
				'fix'     => array(
					'Usually no action — the request was blocked.',
					'If a trusted plugin needs the blocked host, allow it under Hardening settings.',
				),
			),
			EventCatalog::HOST_INJECTION => array(
				'title'   => 'A forged Host header was detected',
				'icon'    => '🎭',
				'meaning' => 'A request arrived with a Host header that does not match your site. This is used for cache poisoning and password-reset poisoning.',
				'legit'   => 'Can be triggered by a misconfigured proxy or CDN. Verify the host below.',
				'fix'     => array(
					'If it is your CDN/proxy, add the hostname to your allowed hosts.',
					'Otherwise no action — the request was rejected.',
				),
			),
			EventCatalog::HONEYPOT_HIT => array(
				'title'   => 'A hidden trap (honeypot) was triggered',
				'icon'    => '🍯',
				'meaning' => 'Something interacted with a hidden trap that only automated bots find — a strong signal of malicious scanning.',
				'legit'   => 'Real users never see honeypot fields, so this is very rarely a false positive.',
				'fix'     => array( 'No action needed. Consider banning the IP if it keeps probing.' ),
			),

			/* ---- WordPress lifecycle --------------------------------------- */
			EventCatalog::PLUGIN_DEACTIVATED => array(
				'title'   => 'A plugin was deactivated',
				'icon'    => '🔌',
				'meaning' => 'A plugin was turned off. Attackers sometimes disable security plugins after getting in.',
				'legit'   => 'Normal when you manage plugins yourself.',
				'fix'     => array( 'If you did not deactivate it, re-activate it and review admin accounts.' ),
			),

			/* ---- Monitoring ------------------------------------------------ */
			EventCatalog::SITE_DOWN => array(
				'title'   => 'Your site appears to be down',
				'icon'    => '📉',
				'meaning' => 'The uptime monitor could not reach your site.',
				'legit'   => 'Can be a brief hosting hiccup or maintenance rather than an attack.',
				'fix'     => array(
					'Open your site in a browser to confirm.',
					'If it is down, check with your host; if it is up, this may have been a transient network blip.',
				),
			),
			EventCatalog::SITE_RECOVERED => array(
				'title'   => 'Your site is back online',
				'icon'    => '📈',
				'meaning' => 'The uptime monitor can reach your site again after a previous outage.',
				'legit'   => 'Informational — the outage is over.',
				'fix'     => array( 'No action needed.' ),
			),

			/* ---- Threat intelligence --------------------------------------- */
			EventCatalog::THREATINTEL_VULN_FOUND => array(
				'title'   => 'A vulnerable component was found on your site',
				'icon'    => '🧬',
				'meaning' => 'Threat intelligence matched an installed plugin/theme against a known vulnerability (CVE).',
				'legit'   => 'This is a real advisory, not a false positive — though the vulnerability may not be actively exploited yet.',
				'fix'     => array(
					'Update the named component to a patched version.',
					'If no fix exists, consider removing it until one is released; a virtual patch from the threat-intelligence feed blocks known exploit requests meanwhile.',
				),
			),

			/* ---- HTTP / suspicious ----------------------------------------- */
			EventCatalog::NOPRIV_AJAX_CALL => array(
				'title'   => 'An unregistered AJAX endpoint was probed',
				'icon'    => '📡',
				'meaning' => 'A logged-out visitor called an admin-ajax.php endpoint that no plugin on your site has registered. Normal plugin features (WooCommerce cart, contact forms, etc.) are always registered — so calling an unregistered action is a strong signal of a scanner or attacker probing for unprotected backdoors.',
				'legit'   => 'Rarely a false positive. Registered plugin endpoints are filtered out automatically, so if you see this alert it means nothing on your site should be responding to this action name. The most common source is automated scanners testing known action names.',
				'fix'     => array(
					'Check the "AJAX action" in Details — does the name match a plugin you recently removed? If so, no action needed (stale request).',
					'If the same IP appears repeatedly or probes many different actions, ban it under Firewall → Bans.',
					'If a legitimate plugin uses an unusual action that is triggering this alert, click "Whitelist this AJAX action" below or check whether the plugin is still active.',
				),
			),
			EventCatalog::CSRF_ATTEMPT => array(
				'title'   => 'A possible cross-site request forgery was blocked',
				'icon'    => '🎯',
				'meaning' => 'A request failed its security token check, which can indicate a forged action submitted on a user\'s behalf.',
				'legit'   => 'Often a stale browser tab or an expired form rather than an attack.',
				'fix'     => array( 'If a user reports it, ask them to reload the page and try again. No action otherwise.' ),
			),

			/* ---- Intelligence ----------------------------------------------- */
			EventCatalog::IMPOSSIBLE_TRAVEL_DETECTED => array(
				'title'   => 'Impossible travel: sign-in from two distant places',
				'icon'    => '🧭',
				'meaning' => 'An account signed in from a country it could not have reached since its previous sign-in, which usually means someone else is using the password. Its sessions were signed out.',
				'legit'   => 'A VPN switching countries, a mobile network routing through another country, or travel with a long gap between sign-ins.',
				'fix'     => array( 'Ask the user whether both sign-ins were theirs.', 'If not, reset their password and turn on two-factor authentication for the account.' ),
			),
			EventCatalog::IP_REPUTATION_REFRESHED => array(
				'title'   => 'IP reputation list refreshed',
				'icon'    => '🧭',
				'meaning' => 'The list of addresses known for attacks was updated and its bans were applied.',
				'legit'   => 'Routine: it runs on a schedule.',
				'fix'     => array( 'No action needed.' ),
			),
			EventCatalog::VIRTUAL_PATCH_AUTO_APPLIED => array(
				'title'   => 'A virtual patch was applied automatically',
				'icon'    => '🩹',
				'meaning' => 'A firewall rule that blocks attacks on a known vulnerability in one of your plugins was switched on automatically.',
				'legit'   => 'Expected when a vulnerability is published for something you run.',
				'fix'     => array( 'Update the affected plugin when a fixed version is available; the patch can then be removed.' ),
			),

			/* ---- Notifications self-test ----------------------------------- */
			EventCatalog::NOTIFICATION_TEST => array(
				'title'   => 'Test notification',
				'icon'    => '🔔',
				'meaning' => 'This is a test message you triggered from the notification settings.',
				'legit'   => 'Expected — it confirms your notification channel works.',
				'fix'     => array( 'No action needed. If you received this, your alerts are configured correctly.' ),
			),
		);
	}

	/**
	 * Category-level fallback keyed on the leading segment of the dotted type. Used when a
	 * specific type has no bespoke entry, so unknown/new events still read sensibly.
	 *
	 * @param string $type Event type.
	 * @return array{title:string,icon:string,meaning:string,legit:string,fix:string[]}
	 */
	private static function category_fallback( string $type ): array {
		$prefix = explode( '.', $type )[0];

		$fallbacks = array(
			'waf'         => array( '🛡️', 'The firewall flagged a request', 'A request matched a firewall rule. If the request was blocked, your site was protected.', 'False positives are possible for unusual but legitimate traffic.', array( 'Review the details below; no action is needed if the request was blocked.' ) ),
			'auth'        => array( '🔑', 'An authentication event occurred', 'Something happened around signing in or account security.', 'Most auth events are routine.', array( 'Review the user and IP; investigate only if it looks unfamiliar.' ) ),
			'scan'        => array( '🔬', 'A scanner event occurred', 'The malware/integrity scanner reported activity.', 'Findings can occasionally be false positives.', array( 'Open the Scanner panel for details.' ) ),
			'integrity'   => array( '📝', 'A monitored file changed', 'A tracked file differs from its known-good baseline.', 'Expected after updates.', array( 'Review changed files under Scanner → Integrity.' ) ),
			'incident'    => array( '🚑', 'An incident-response action ran', 'The plugin took (or reversed) a protective action.', 'These are actions taken on your behalf and are reversible.', array( 'Review the Incident/Quarantine panel.' ) ),
			'hardening'   => array( '🛠️', 'A hardening rule fired', 'A defensive hardening rule blocked or flagged a request.', 'Occasional false positives from misconfigured proxies/plugins.', array( 'Review the details; allow-list a trusted source if needed.' ) ),
			'settings'    => array( '⚙️', 'A setting changed', 'A configuration value was modified.', 'Normal when you change settings yourself.', array( 'Confirm you made the change.' ) ),
			'wp'          => array( '🔧', 'A WordPress change occurred', 'A plugin, theme, user, or core change was recorded.', 'Normal during routine site management.', array( 'Confirm the change was expected.' ) ),
			'audit'       => array( '📋', 'A noteworthy change was audited', 'A security-relevant change was recorded in the audit trail.', 'Often routine administration.', array( 'Review the Audit Log for who and when.' ) ),
			'threatintel' => array( '🧬', 'A threat-intelligence event occurred', 'The threat-intel feed reported something relevant to your site.', 'Advisories are real but may not be actively exploited.', array( 'Update or mitigate the named component.' ) ),
			'intel'       => array( '🧭', 'A threat-intelligence event occurred', 'A reputation or intelligence signal was recorded.', 'Informational in most cases.', array( 'Review the details below.' ) ),
			'monitoring'  => array( '📡', 'A monitoring event occurred', 'Site monitoring reported a status change.', 'Can be transient network conditions.', array( 'Confirm the site status in a browser.' ) ),
			'http'        => array( '🌐', 'A suspicious HTTP request was flagged', 'A request looked abnormal and was recorded.', 'Some plugins generate unusual-looking traffic legitimately.', array( 'Review the request details below.' ) ),
			'under_attack' => array( '🚨', 'Under-Attack Mode changed', 'Emergency Under-Attack Mode was toggled.', 'Expected when you enable/disable it.', array( 'Confirm the change was intentional.' ) ),
			'telemetry'   => array( 'ℹ️', 'A telemetry event occurred', 'Anonymous, opt-in telemetry activity was recorded.', 'Informational only.', array( 'No action needed.' ) ),
			'reporting'   => array( '📊', 'A report was generated', 'A scheduled report or digest was produced.', 'Routine.', array( 'No action needed.' ) ),
		);

		if ( isset( $fallbacks[ $prefix ] ) ) {
			[ $icon, $title, $meaning, $legit, $fix ] = $fallbacks[ $prefix ];
			return array( 'title' => $title, 'icon' => $icon, 'meaning' => $meaning, 'legit' => $legit, 'fix' => $fix );
		}

		return array(
			'title'   => 'A security event was recorded',
			'icon'    => '🔔',
			'meaning' => 'Loyal Security recorded an event on your site.',
			'legit'   => 'Review the details below to judge whether it is expected.',
			'fix'     => array( 'Open the Audit Log for full context.' ),
		);
	}

	/* ------------------------------------------------------------------ *
	 * Context humaniser
	 * ------------------------------------------------------------------ */

	/**
	 * Turn a raw context array into a list of human-readable {label, value} rows.
	 * Serialized PHP blobs and nested arrays are summarised rather than dumped, and
	 * over-long values are truncated so an e-mail never shows `a:24:{i:...}`.
	 *
	 * @param array<string, mixed> $context Decoded context.
	 * @return array<int, array{label:string,value:string}>
	 */
	public static function humanize_context( array $context ): array {
		$rows = array();
		foreach ( $context as $key => $value ) {
			$rows[] = array(
				'label' => self::label_for_key( (string) $key ),
				'value' => self::stringify_value( (string) $key, $value ),
			);
		}
		return $rows;
	}

	/**
	 * Friendly label for a context key.
	 */
	private static function label_for_key( string $key ): string {
		if ( isset( self::KEY_LABELS[ $key ] ) ) {
			return self::KEY_LABELS[ $key ];
		}
		return ucwords( str_replace( array( '_', '.' ), ' ', $key ) );
	}

	/**
	 * Render a single context value as a short, safe, human string.
	 *
	 * @param string $key   Context key (used for value-specific handling).
	 * @param mixed  $value Raw value.
	 */
	private static function stringify_value( string $key, $value ): string {
		// Give the boolean "registered" field a more informative label than "yes/no".
		if ( 'registered' === $key ) {
			return $value ? 'Yes — a plugin on this site handles this action' : 'No — no plugin claims this action (suspicious)';
		}

		// The critical-option "preview" is often a serialized blob (esp. the cron array).
		if ( 'preview' === $key && is_string( $value ) ) {
			$decoded = self::maybe_decode_blob( $value );
			if ( null !== $decoded ) {
				return $decoded;
			}
		}

		if ( is_bool( $value ) ) {
			return $value ? 'yes' : 'no';
		}
		if ( is_scalar( $value ) || null === $value ) {
			$str = (string) $value;
			// A scalar might itself be serialized data captured elsewhere.
			$decoded = self::maybe_decode_blob( $str );
			if ( null !== $decoded ) {
				return $decoded;
			}
			return self::truncate( $str );
		}
		if ( is_array( $value ) ) {
			// A short list renders inline; a large/associative array is summarised.
			$is_list = array_keys( $value ) === range( 0, count( $value ) - 1 );
			if ( $is_list && count( $value ) <= 8 ) {
				return self::truncate( implode( ', ', array_map( array( self::class, 'flatten_scalar' ), $value ) ) );
			}
			return sprintf( '%d item(s)', count( $value ) );
		}
		return self::truncate( (string) wp_json_encode( $value ) );
	}

	/**
	 * If a string is (or contains) serialized PHP data, decode it and return a short human
	 * summary; otherwise return null so the caller keeps the original string.
	 *
	 * Handles the specific pain point from the field report: a truncated serialized cron
	 * array (`a:24:{i:...}`) becomes "Scheduled-tasks list (24 entries): hook_a, hook_b, …".
	 *
	 * @param string $value Candidate value.
	 * @return string|null Human summary, or null when the value is not serialized data.
	 */
	private static function maybe_decode_blob( string $value ): ?string {
		$trimmed = trim( $value );
		if ( '' === $trimmed || ! preg_match( '/^(a|O|s|i|b|d):/', $trimmed ) ) {
			return null;
		}

		// The value is frequently truncated (preview caps at ~200 chars), which breaks
		// unserialize(). Fall back to a structural summary in that case.
		$data = @unserialize( $trimmed, array( 'allowed_classes' => false ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- display-only decode of a logged option preview; allowed_classes=false means no object can ever be instantiated.
		if ( false !== $data || 'b:0;' === $trimmed ) {
			return self::summarize_serialized( $data );
		}

		// Truncated blob: describe it structurally so it is not shown as gibberish.
		$hooks = self::extract_string_keys( $trimmed );
		if ( $hooks ) {
			return sprintf( 'Serialized data (truncated). Includes: %s …', self::truncate( implode( ', ', $hooks ), 160 ) );
		}
		return 'Serialized data (truncated) — open the Audit Log to view the full value.';
	}

	/**
	 * Summarise a successfully-unserialized value for humans.
	 *
	 * @param mixed $data Unserialized value.
	 */
	private static function summarize_serialized( $data ): string {
		if ( is_array( $data ) ) {
			// Cron-array shape: top-level keys are timestamps whose children are hook names.
			$hooks = array();
			foreach ( $data as $child ) {
				if ( is_array( $child ) ) {
					foreach ( array_keys( $child ) as $hook ) {
						if ( is_string( $hook ) ) {
							$hooks[ $hook ] = true;
						}
					}
				}
			}
			if ( $hooks ) {
				$names = array_slice( array_keys( $hooks ), 0, 8 );
				return sprintf(
					'Scheduled-tasks list (%d entr%s). Tasks: %s%s',
					count( $data ),
					count( $data ) === 1 ? 'y' : 'ies',
					self::truncate( implode( ', ', $names ), 200 ),
					count( $hooks ) > count( $names ) ? ', …' : ''
				);
			}
			return sprintf( 'List with %d item(s).', count( $data ) );
		}
		if ( is_scalar( $data ) || null === $data ) {
			return self::truncate( (string) $data );
		}
		return 'Structured value (see Audit Log for detail).';
	}

	/**
	 * Best-effort extraction of string keys from a raw (possibly truncated) serialized
	 * string — used to name the scheduled hooks inside a truncated cron blob.
	 *
	 * @return string[]
	 */
	private static function extract_string_keys( string $serialized ): array {
		if ( ! preg_match_all( '/s:\d+:"([^"]{2,64})"/', $serialized, $m ) ) {
			return array();
		}
		$candidates = array();
		foreach ( $m[1] as $s ) {
			// Skip the internal cron hashes and obvious non-hook tokens.
			if ( 'schedule' === $s || 'args' === $s || 'interval' === $s || preg_match( '/^[0-9a-f]{32}$/', $s ) ) {
				continue;
			}
			$candidates[ $s ] = true;
			if ( count( $candidates ) >= 8 ) {
				break;
			}
		}
		return array_keys( $candidates );
	}

	/**
	 * Flatten a scalar (or short array) for inline listing.
	 *
	 * @param mixed $v Value.
	 */
	private static function flatten_scalar( $v ): string {
		if ( is_scalar( $v ) || null === $v ) {
			return (string) $v;
		}
		return '[…]';
	}

	/**
	 * Truncate a string to a readable length with an ellipsis.
	 */
	private static function truncate( string $value, int $limit = 220 ): string {
		$value = trim( preg_replace( '/\s+/', ' ', $value ) ?? $value );
		if ( function_exists( 'mb_strlen' ) ? mb_strlen( $value ) > $limit : strlen( $value ) > $limit ) {
			$value = ( function_exists( 'mb_substr' ) ? mb_substr( $value, 0, $limit ) : substr( $value, 0, $limit ) ) . '…';
		}
		return $value;
	}
}
