<?php
/**
 * Catalogue of audit event types and their default severities.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Audit;

defined( 'ABSPATH' ) || exit;

/**
 * Central registry of event type constants. Using constants (not an enum) keeps the
 * code compatible with the pragmatic PHP 8.0 target.
 */
final class EventCatalog {

	/* Severity levels (numeric for easy comparison/sorting). */
	public const SEV_INFO     = 10;
	public const SEV_NOTICE   = 20;
	public const SEV_WARNING  = 30;
	public const SEV_CRITICAL = 40;

	/* Authentication. */
	public const LOGIN_SUCCESS   = 'auth.login.success';
	public const LOGIN_FAILED    = 'auth.login.failed';
	public const LOGIN_BLOCKED   = 'auth.login.blocked';
	public const LOGOUT          = 'auth.logout';
	public const TWOFA_ENROLLED  = 'auth.2fa.enrolled';
	public const TWOFA_DISABLED  = 'auth.2fa.disabled';
	public const TWOFA_FAILED    = 'auth.2fa.failed';
	public const TWOFA_SUCCESS   = 'auth.2fa.success';
	public const PASSWORD_REJECTED = 'auth.password.rejected';
	public const SESSION_DESTROYED = 'auth.session.destroyed';
	public const BREACHED_PASSWORD_DETECTED = 'auth.breach.detected';
	public const DEVICE_TRUSTED         = 'auth.device.trusted';
	public const DEVICE_TRUST_REVOKED   = 'auth.device.trust_revoked';
	public const PASSKEY_REGISTERED     = 'auth.passkey.registered';
	public const PASSKEY_REMOVED        = 'auth.passkey.removed';
	public const PASSKEY_LOGIN_SUCCESS  = 'auth.passkey.login_success';
	public const PASSKEY_LOGIN_FAILED   = 'auth.passkey.login_failed';

	/* Firewall / WAF. */
	public const WAF_BLOCK        = 'waf.block';
	public const WAF_RATE_LIMIT   = 'waf.ratelimit';
	public const WAF_BRUTEFORCE   = 'waf.bruteforce';
	public const WAF_BAN_ADDED    = 'waf.ban.added';
	public const WAF_BAN_REMOVED  = 'waf.ban.removed';
	public const WAF_GEO_BLOCK    = 'waf.geo.block';
	public const GEO_BLOCK_ADDED  = 'waf.geo.escalation';
	public const WAF_BOT_BLOCK    = 'waf.bot.block';
	public const WAF_DDOS         = 'waf.ddos';
	public const WAF_QUERY_CARDINALITY = 'waf.query_cardinality';
	public const WAF_VIRTUAL_PATCH = 'waf.vpatch';
	public const PATCH_GAP_PROTECTED = 'waf.patchgap.protected';

	/* Scanner / integrity. */
	public const SCAN_STARTED     = 'scan.started';
	public const SCAN_COMPLETED   = 'scan.completed';
	public const SCAN_FINDING     = 'scan.finding';
	public const INTEGRITY_CHANGED = 'integrity.changed';

	/* Incident. */
	public const QUARANTINE_ADD   = 'incident.quarantine.add';
	public const FILE_QUARANTINED = 'incident.quarantine.add'; // Alias of QUARANTINE_ADD for auto-quarantine callers.
	public const QUARANTINE_RESTORE = 'incident.quarantine.restore';
	public const FILE_RECOVERED   = 'incident.recovered';
	public const PERMISSIONS_RESET = 'incident.permissions.reset';
	public const CORE_REPAIRED    = 'incident.core.repaired';
	public const PLUGIN_REPAIRED  = 'incident.plugin.repaired';
	public const FILE_FIX_APPLIED = 'incident.filefix.applied';
	public const FILE_FIX_REVERTED = 'incident.filefix.reverted';
	public const REPAIR_AUTO_ROLLED_BACK = 'incident.repair.autorollback';
	public const FILE_DELETED      = 'incident.file.deleted';
	public const FILE_DELETE_REVERTED = 'incident.file.delete.reverted';
	public const BACKUP_CREATED   = 'incident.backup.created';
	public const BACKUP_RESTORED  = 'incident.backup.restored';
	public const BACKUP_STORAGE_HIGH = 'incident.backup.storage_high';
	public const CLEANUP_STARTED   = 'incident.cleanup.started';
	public const CLEANUP_COMPLETED = 'incident.cleanup.completed';
	public const CLEANUP_NEEDS_REVIEW = 'incident.cleanup.manual_review';

	/* Hardening / settings. */
	public const HARDENING_APPLIED = 'hardening.applied';
	public const HARDENING_REVERTED = 'hardening.reverted';
	public const SETTING_CHANGED   = 'settings.changed';
	public const CRITICAL_OPTION_CHANGED = 'audit.option.critical';
	public const SSRF_BLOCKED            = 'hardening.ssrf.blocked';
	public const HOST_INJECTION          = 'hardening.host_injection';
	public const XMLRPC_PROBE            = 'hardening.xmlrpc.probe';
	public const XMLRPC_MULTICALL        = 'hardening.xmlrpc.multicall';
	public const REST_LEARNING           = 'hardening.rest.learning';
	public const CORS_BLOCKED            = 'hardening.cors.blocked';
	public const LOGIN_URL_ENABLED       = 'hardening.login_url.enabled';
	public const LOGIN_URL_DISABLED      = 'hardening.login_url.disabled';
	public const LOGIN_URL_PROBE_BLOCKED = 'hardening.login_url.probe_blocked';
	public const AUTHOR_ENUM_BLOCKED     = 'hardening.author_enum.blocked';
	public const EXPOSURE_FINDING        = 'hardening.exposure.finding';

	/* Content / spam. */
	public const POST_CREATED          = 'audit.post.created';
	public const POST_SUSPICIOUS       = 'audit.post.suspicious';
	public const COMMENT_BULK_INSERT   = 'audit.comment.bulk_insert';
	public const COMMENT_SUSPICIOUS    = 'audit.comment.suspicious_url';
	public const MAIL_BULK_SEND        = 'audit.mail.bulk_send';
	public const MAIL_SUSPICIOUS       = 'audit.mail.suspicious';

	/* WordPress lifecycle. */
	public const PLUGIN_ACTIVATED   = 'wp.plugin.activated';
	public const PLUGIN_DEACTIVATED = 'wp.plugin.deactivated';
	public const PLUGIN_INSTALLED   = 'wp.plugin.installed';
	public const THEME_SWITCHED     = 'wp.theme.switched';
	public const USER_CREATED       = 'wp.user.created';
	public const USER_ROLE_CHANGED  = 'wp.user.role';
	public const USER_ADMIN_CREATED = 'wp.user.admin_created';
	public const USER_DELETED        = 'wp.user.deleted';
	public const CORE_UPDATED       = 'wp.core.updated';

	/* Notifications. */
	public const NOTIFICATION_SENT  = 'notifications.sent';
	public const NOTIFICATION_TEST  = 'notifications.test';

	/* Emergency / Under Attack Mode. */
	public const EVENT_UNDER_ATTACK_ENABLED  = 'under_attack.enabled';
	public const EVENT_UNDER_ATTACK_DISABLED = 'under_attack.disabled';

	/* Threat Intelligence. */
	public const THREATINTEL_SYNCED      = 'threatintel.synced';
	public const THREATINTEL_SYNC_FAILED = 'threatintel.sync.failed';
	public const THREATINTEL_VULN_FOUND  = 'threatintel.vuln.found';
	public const IP_REPUTATION_REFRESHED = 'intel.reputation.refreshed';
	public const IMPOSSIBLE_TRAVEL_DETECTED = 'intel.travel.detected';
	public const VIRTUAL_PATCH_AUTO_APPLIED = 'intel.vpatch.auto_applied';

	/* Sentinel AI — cloud-assisted analysis + autonomous response. */
	public const SENTINEL_CASE_OPENED    = 'sentinel.case.opened';
	public const SENTINEL_VERDICT         = 'sentinel.verdict';
	public const SENTINEL_ACTION_TAKEN    = 'sentinel.action.taken';
	public const SENTINEL_ACTION_QUEUED   = 'sentinel.action.queued';
	public const SENTINEL_ACTION_REVERSED = 'sentinel.action.reversed';
	public const SENTINEL_FALSE_POSITIVE  = 'sentinel.false_positive';
	public const SENTINEL_RATE_LIMITED    = 'sentinel.rate_limited';

	/* Reporting. */
	public const DIGEST_SENT = 'reporting.digest.sent';

	/* Agency. */
	public const WHITELABEL_AUTO_DISABLED = 'agency.whitelabel.auto_disabled';

	/* Bypass telemetry (anonymous, opt-in). */
	public const TELEMETRY_CONSENT_CHANGED = 'telemetry.consent.changed';
	public const TELEMETRY_REPORT_QUEUED   = 'telemetry.report.queued';
	public const TELEMETRY_REPORT_SENT     = 'telemetry.report.sent';

	/* Monitoring (uptime). */
	public const SITE_DOWN      = 'monitoring.site.down';
	public const SITE_RECOVERED = 'monitoring.site.recovered';

	/* Unauthenticated / suspicious HTTP. */
	public const NOPRIV_AJAX_CALL  = 'http.ajax.nopriv';
	public const CRON_SCHEDULED    = 'wp.cron.scheduled';
	public const CSRF_ATTEMPT      = 'http.csrf.attempt';
	public const OPEN_REDIRECT     = 'http.redirect.open';
	public const SUSPICIOUS_OPTION = 'audit.option.suspicious';

	/* Hardening. */
	public const HONEYPOT_HIT      = 'hardening.honeypot_hit';

	/**
	 * Map a severity constant to a label.
	 */
	public static function severity_label( int $severity ): string {
		switch ( $severity ) {
			case self::SEV_CRITICAL:
				return 'critical';
			case self::SEV_WARNING:
				return 'warning';
			case self::SEV_NOTICE:
				return 'notice';
			default:
				return 'info';
		}
	}

	/**
	 * Default severity for a given event type.
	 */
	public static function default_severity( string $type ): int {
		$critical = array(
			self::WAF_BLOCK,
			self::WAF_BRUTEFORCE,
			self::WAF_DDOS,
			self::WAF_VIRTUAL_PATCH,
			self::SCAN_FINDING,
			self::INTEGRITY_CHANGED,
			self::QUARANTINE_ADD,
			self::USER_ROLE_CHANGED,
			self::FILE_FIX_REVERTED,
			self::FILE_DELETE_REVERTED,
			self::REPAIR_AUTO_ROLLED_BACK,
			self::THREATINTEL_VULN_FOUND,
			self::EVENT_UNDER_ATTACK_ENABLED,
			self::IMPOSSIBLE_TRAVEL_DETECTED,
			self::HONEYPOT_HIT,
			self::USER_ADMIN_CREATED,
			self::CRITICAL_OPTION_CHANGED,
			self::SSRF_BLOCKED,
			self::SITE_DOWN,
			self::EXPOSURE_FINDING,
			self::SENTINEL_ACTION_TAKEN,
		);
		$warning  = array(
			self::LOGIN_FAILED,
			self::LOGIN_BLOCKED,
			self::TWOFA_FAILED,
			self::PASSKEY_LOGIN_FAILED,
			self::BREACHED_PASSWORD_DETECTED,
			self::WAF_RATE_LIMIT,
			self::WAF_QUERY_CARDINALITY,
			self::WAF_GEO_BLOCK,
			self::GEO_BLOCK_ADDED,
			self::WAF_BOT_BLOCK,
			self::WAF_BAN_ADDED,
			self::PASSWORD_REJECTED,
			self::PLUGIN_DEACTIVATED,
			self::CORE_REPAIRED,
			self::PLUGIN_REPAIRED,
			self::FILE_FIX_APPLIED,
			self::FILE_DELETED,
			self::BACKUP_RESTORED,
			self::BACKUP_STORAGE_HIGH,
			self::CLEANUP_COMPLETED,
			self::EVENT_UNDER_ATTACK_DISABLED,
			self::VIRTUAL_PATCH_AUTO_APPLIED,
			self::NOPRIV_AJAX_CALL,
			self::CSRF_ATTEMPT,
			self::OPEN_REDIRECT,
			self::SUSPICIOUS_OPTION,
			self::USER_DELETED,
			self::HOST_INJECTION,
			self::XMLRPC_MULTICALL,
			self::POST_SUSPICIOUS,
			self::COMMENT_BULK_INSERT,
			self::COMMENT_SUSPICIOUS,
			self::MAIL_BULK_SEND,
			self::MAIL_SUSPICIOUS,
			self::SITE_RECOVERED,
			self::AUTHOR_ENUM_BLOCKED,
			self::LOGIN_URL_PROBE_BLOCKED,
			self::SENTINEL_VERDICT,
			self::SENTINEL_ACTION_REVERSED,
			self::SENTINEL_RATE_LIMITED,
		);
		$notice   = array(
			self::SENTINEL_CASE_OPENED,
			self::SENTINEL_ACTION_QUEUED,
			self::SENTINEL_FALSE_POSITIVE,
			self::CLEANUP_NEEDS_REVIEW,
			self::IP_REPUTATION_REFRESHED,
			self::DIGEST_SENT,
			self::TELEMETRY_CONSENT_CHANGED,
			self::TELEMETRY_REPORT_QUEUED,
			self::TELEMETRY_REPORT_SENT,
			self::REST_LEARNING,
			self::LOGIN_URL_ENABLED,
			self::LOGIN_URL_DISABLED,
		);

		if ( in_array( $type, $critical, true ) ) {
			return self::SEV_CRITICAL;
		}
		if ( in_array( $type, $warning, true ) ) {
			return self::SEV_WARNING;
		}
		if ( in_array( $type, $notice, true ) ) {
			return self::SEV_NOTICE;
		}
		return self::SEV_INFO;
	}
}
