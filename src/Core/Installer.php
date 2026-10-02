<?php
/**
 * Database schema installer and migration runner.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Creates and maintains the plugin's custom tables via dbDelta. A stored schema version
 * drives idempotent upgrades.
 */
class Installer {

	private const VERSION_OPTION = 'totalsecwp_db_version';

	/**
	 * Create/upgrade all tables if the stored version is behind.
	 */
	public static function maybe_install(): void {
		$installed = get_option( self::VERSION_OPTION, '' );
		if ( TOTALSECWP_DB_VERSION === $installed ) {
			return;
		}
		self::install();
		Cron::clear_retired_events();
		Assets::remove_legacy_htaccess();
		update_option( self::VERSION_OPTION, TOTALSECWP_DB_VERSION, true );
	}

	/**
	 * Run dbDelta for every table definition.
	 */
	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$prefix  = $wpdb->prefix . 'totalsecwp_';

		$queries = array();

		// Audit events.
		$queries[] = "CREATE TABLE {$prefix}events (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type VARCHAR(64) NOT NULL DEFAULT '',
			severity SMALLINT UNSIGNED NOT NULL DEFAULT 10,
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			ip VARCHAR(45) NOT NULL DEFAULT '',
			method VARCHAR(10) NOT NULL DEFAULT '',
			request_uri VARCHAR(512) NOT NULL DEFAULT '',
			user_agent VARCHAR(512) NOT NULL DEFAULT '',
			context LONGTEXT NULL,
			proxy_headers TEXT NULL,
			created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY ip (ip),
			KEY user_id (user_id),
			KEY created_at (created_at)
		) {$charset};";

		// IP bans (temporary + permanent).
		$queries[] = "CREATE TABLE {$prefix}bans (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ip VARCHAR(45) NOT NULL DEFAULT '',
			cidr VARCHAR(50) NULL,
			reason VARCHAR(191) NOT NULL DEFAULT '',
			type VARCHAR(20) NOT NULL DEFAULT 'temporary',
			source VARCHAR(40) NOT NULL DEFAULT 'manual',
			hits INT UNSIGNED NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			expires_at DATETIME NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY ip (ip),
			KEY expires_at (expires_at),
			KEY type (type)
		) {$charset};";

		// Login attempts (brute-force tracking).
		$queries[] = "CREATE TABLE {$prefix}login_attempts (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ip VARCHAR(45) NOT NULL DEFAULT '',
			username VARCHAR(191) NOT NULL DEFAULT '',
			success TINYINT(1) NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			KEY ip (ip),
			KEY created_at (created_at)
		) {$charset};";

		// Scan findings.
		$queries[] = "CREATE TABLE {$prefix}scan_findings (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			scan_id VARCHAR(40) NOT NULL DEFAULT '',
			path TEXT NOT NULL,
			rule VARCHAR(120) NOT NULL DEFAULT '',
			category VARCHAR(40) NOT NULL DEFAULT '',
			severity SMALLINT UNSIGNED NOT NULL DEFAULT 10,
			line INT UNSIGNED NOT NULL DEFAULT 0,
			snippet TEXT NULL,
			score INT NOT NULL DEFAULT 0,
			status VARCHAR(20) NOT NULL DEFAULT 'open',
			suggested_patch LONGTEXT NULL,
			patch_status VARCHAR(20) NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			KEY scan_id (scan_id),
			KEY severity (severity),
			KEY status (status)
		) {$charset};";

		// Scan state (resume/progress).
		$queries[] = "CREATE TABLE {$prefix}scan_state (
			scan_id VARCHAR(40) NOT NULL,
			type VARCHAR(30) NOT NULL DEFAULT 'full',
			status VARCHAR(20) NOT NULL DEFAULT 'queued',
			total_files INT UNSIGNED NOT NULL DEFAULT 0,
			scanned_files INT UNSIGNED NOT NULL DEFAULT 0,
			findings INT UNSIGNED NOT NULL DEFAULT 0,
			`cursor` TEXT NULL,
			started_at DATETIME NULL,
			updated_at DATETIME NULL,
			finished_at DATETIME NULL,
			PRIMARY KEY  (scan_id),
			KEY status (status)
		) {$charset};";

		// Quarantine manifest.
		$queries[] = "CREATE TABLE {$prefix}quarantine (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			original_path TEXT NOT NULL,
			stored_path TEXT NOT NULL,
			hash CHAR(64) NOT NULL DEFAULT '',
			size BIGINT UNSIGNED NOT NULL DEFAULT 0,
			reason VARCHAR(191) NOT NULL DEFAULT '',
			finding_id BIGINT UNSIGNED NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'quarantined',
			created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			KEY status (status)
		) {$charset};";

		// File integrity baseline.
		// source: was VARCHAR(20) until TOTALSECWP_DB_VERSION 1.1.0 — too short for
		// 'theme:' . $stylesheet (e.g. 'theme:twentytwentyfive' is 22 chars). wpdb::insert()
		// rejected the overlong value and logged a DB error that nothing checked, so
		// Baseline::snapshot() silently recorded zero rows for every theme while still
		// reporting a nonzero count to the caller — dbDelta widens the column on upgrade.
		$queries[] = "CREATE TABLE {$prefix}integrity_baseline (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			path VARCHAR(255) NOT NULL DEFAULT '',
			hash CHAR(64) NOT NULL DEFAULT '',
			source VARCHAR(64) NOT NULL DEFAULT 'core',
			slug VARCHAR(120) NOT NULL DEFAULT '',
			version VARCHAR(40) NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			KEY path (path(191)),
			KEY source (source)
		) {$charset};";

		// Two-factor secrets (encrypted) + hashed backup codes.
		$queries[] = "CREATE TABLE {$prefix}twofa (
			user_id BIGINT UNSIGNED NOT NULL,
			secret TEXT NOT NULL,
			backup_codes TEXT NULL,
			enabled TINYINT(1) NOT NULL DEFAULT 0,
			confirmed_at DATETIME NULL,
			last_used INT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY  (user_id)
		) {$charset};";

		// Sent-notification history (what alerts were dispatched, to which channel).
		$queries[] = "CREATE TABLE {$prefix}notifications (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			event_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			event_type VARCHAR(64) NOT NULL DEFAULT '',
			severity SMALLINT UNSIGNED NOT NULL DEFAULT 10,
			channel VARCHAR(20) NOT NULL DEFAULT '',
			recipient VARCHAR(191) NOT NULL DEFAULT '',
			subject VARCHAR(255) NOT NULL DEFAULT '',
			summary VARCHAR(1000) NOT NULL DEFAULT '',
			status VARCHAR(20) NOT NULL DEFAULT 'sent',
			created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			KEY event_type (event_type),
			KEY channel (channel),
			KEY status (status),
			KEY created_at (created_at)
		) {$charset};";

		// Active sessions tracking.
		$queries[] = "CREATE TABLE {$prefix}sessions (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			token CHAR(64) NOT NULL DEFAULT '',
			ip VARCHAR(45) NOT NULL DEFAULT '',
			user_agent VARCHAR(255) NOT NULL DEFAULT '',
			last_activity DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			created_at DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			KEY user_id (user_id),
			KEY token (token)
		) {$charset};";

		// CSP violation reports. Grouped by (directive, blocked_uri) via the unique key so a
		// noisy/repeated violation bumps `hits` instead of adding a row per occurrence — this
		// bounds table size independently of the age-based retention pruned in Cron::prune_logs().
		$queries[] = "CREATE TABLE {$prefix}csp_violations (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			directive VARCHAR(60) NOT NULL DEFAULT '',
			blocked_uri VARCHAR(500) NOT NULL DEFAULT '',
			doc_uri VARCHAR(500) NOT NULL DEFAULT '',
			referrer VARCHAR(500) NOT NULL DEFAULT '',
			hits INT UNSIGNED NOT NULL DEFAULT 1,
			first_seen DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			last_seen DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY group_key (directive, blocked_uri(191)),
			KEY last_seen (last_seen)
		) {$charset};";

		foreach ( $queries as $sql ) {
			dbDelta( $sql );
		}
	}
}
