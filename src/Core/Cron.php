<?php
/**
 * Scheduled task registration.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Owns the plugin's WP-Cron events: malware scans, audit-log pruning, ban garbage
 * collection, and integrity-checksum refresh. Hook callbacks are attached by the relevant
 * modules; this class only schedules/unschedules.
 */
class Cron {

	public const SCAN             = 'totalsecwp_cron_scan';
	public const PRUNE_LOGS       = 'totalsecwp_cron_prune_logs';
	public const GC_BANS          = 'totalsecwp_cron_gc_bans';
	public const REFRESH_SUMS     = 'totalsecwp_cron_refresh_checksums';
	public const THREATINTEL_SYNC = 'totalsecwp_threatintel_sync';

	/**
	 * Events scheduled by earlier versions that nothing in this plugin handles any more.
	 *
	 * @var string[]
	 */
	private const RETIRED_EVENTS = array(
		'totalsecwp_reputation_flush',
		'totalsecwp_sentinel_analyze',
		'totalsecwp_sentinel_profile',
	);

	/**
	 * Register a custom weekly schedule and hook prune/gc callbacks shared across modules.
	 */
	public function register_hooks(): void {
		add_filter( 'cron_schedules', array( __CLASS__, 'add_schedules' ) );
		add_action( self::PRUNE_LOGS, array( $this, 'prune_logs' ) );
		add_action( self::GC_BANS, array( $this, 'gc_bans' ) );
	}

	/**
	 * Add a weekly interval (WordPress ships hourly/twicedaily/daily only on older cores).
	 * Static so it can be hooked defensively during activation before boot runs.
	 *
	 * @param array<string, array> $schedules Existing schedules.
	 * @return array<string, array>
	 */
	public static function add_schedules( array $schedules ): array {
		// Events are scheduled while plugins load, before `init`, and WordPress reads the
		// schedules then. Translations may only load from `init` on, so the labels (shown
		// only on admin screens, which run after `init`) stay untranslated until then.
		$translate = did_action( 'init' ) > 0;
		if ( ! isset( $schedules['weekly'] ) ) {
			$schedules['weekly'] = array(
				'interval' => WEEK_IN_SECONDS,
				'display'  => $translate ? __( 'Once Weekly', 'loyal-security' ) : 'Once Weekly',
			);
		}
		if ( ! isset( $schedules['totalsecwp_5min'] ) ) {
			$schedules['totalsecwp_5min'] = array(
				'interval' => 5 * MINUTE_IN_SECONDS,
				'display'  => $translate ? __( 'Every 5 Minutes (Loyal Security)', 'loyal-security' ) : 'Every 5 Minutes (Loyal Security)',
			);
		}
		return $schedules;
	}

	/**
	 * Schedule all recurring events (idempotent).
	 */
	public static function schedule_all(): void {
		// Ensure the custom 'weekly' recurrence is known even when called during
		// activation, before the instance hooks are attached.
		if ( ! has_filter( 'cron_schedules', array( __CLASS__, 'add_schedules' ) ) ) {
			add_filter( 'cron_schedules', array( __CLASS__, 'add_schedules' ) );
		}

		// self::SCAN (the weekly automatic scan) is scheduled by ScannerModule, which follows
		// the "Scheduled Scan" setting.
		$events = array(
			self::PRUNE_LOGS       => 'daily',
			self::GC_BANS          => 'hourly',
			self::REFRESH_SUMS     => 'weekly',
			self::THREATINTEL_SYNC => self::threatintel_recurrence(),
		);
		foreach ( $events as $hook => $recurrence ) {
			if ( ! wp_next_scheduled( $hook ) ) {
				wp_schedule_event( time() + HOUR_IN_SECONDS, $recurrence, $hook );
			}
		}
	}

	/**
	 * Unschedule events that earlier versions registered and nothing handles any more.
	 */
	public static function clear_retired_events(): void {
		foreach ( self::RETIRED_EVENTS as $hook ) {
			if ( wp_next_scheduled( $hook ) ) {
				wp_unschedule_hook( $hook );
			}
		}
	}

	/**
	 * How often the threat-intelligence sync runs: twice a day by default.
	 */
	public static function threatintel_recurrence(): string {
		/**
		 * Filters the threat-intelligence sync schedule.
		 *
		 * @param string $recurrence A registered cron schedule name. Default 'twicedaily'.
		 */
		$recurrence = (string) apply_filters( 'totalsecwp_threatintel_sync_recurrence', 'twicedaily' );
		return isset( wp_get_schedules()[ $recurrence ] ) ? $recurrence : 'twicedaily';
	}

	/**
	 * Reschedule the threat-intelligence sync event on {@see Cron::threatintel_recurrence()}.
	 */
	public static function reschedule_threatintel(): void {
		$hook = self::THREATINTEL_SYNC;
		$ts   = wp_next_scheduled( $hook );
		if ( $ts ) {
			wp_unschedule_event( $ts, $hook );
		}
		wp_schedule_event( time() + HOUR_IN_SECONDS, self::threatintel_recurrence(), $hook );
	}

	/**
	 * Clear every scheduled event owned by the plugin — the core events above plus the
	 * recurring/single events modules schedule themselves (telemetry flush, CSP notify,
	 * queued jobs, …).
	 * All plugin hooks share the `totalsecwp_` prefix, so sweep the cron array rather than
	 * maintaining a hook list that drifts as modules are added.
	 */
	public static function unschedule_all(): void {
		$crons = _get_cron_array();
		$hooks = array();
		if ( is_array( $crons ) ) {
			foreach ( $crons as $bucket ) {
				if ( ! is_array( $bucket ) ) {
					continue;
				}
				foreach ( array_keys( $bucket ) as $hook ) {
					if ( is_string( $hook ) && 0 === strpos( $hook, 'totalsecwp_' ) ) {
						$hooks[ $hook ] = true;
					}
				}
			}
		}
		foreach ( array_keys( $hooks ) as $hook ) {
			wp_unschedule_hook( $hook ); // Clears all occurrences regardless of args.
		}
	}

	/**
	 * Delete audit events older than the configured retention window.
	 */
	public function prune_logs(): void {
		global $wpdb;
		$days  = (int) apply_filters( 'totalsecwp_log_retention_days', 90 );
		$table = $wpdb->prefix . 'totalsecwp_events';
		$wpdb->query( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"DELETE FROM %i WHERE created_at < %s", $table,
				gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS )
			)
		);

		// login_attempts otherwise grows without bound (one row per failed login, forever) —
		// BruteForce only ever COUNTs a short recent window (minutes), and the status screen
		// reads the last 24h, so anything older than the retention below is dead weight that
		// slows the per-failed-login COUNT(*) as the table reaches millions of rows.
		$attempts_days = (int) apply_filters( 'totalsecwp_login_attempts_retention_days', 30 );
		$attempts      = $wpdb->prefix . 'totalsecwp_login_attempts';
		$wpdb->query( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"DELETE FROM %i WHERE created_at < %s", $attempts,
				gmdate( 'Y-m-d H:i:s', time() - max( 1, $attempts_days ) * DAY_IN_SECONDS )
			)
		);

		// CSP violation reports: grouping by (directive, blocked_uri) at write time already
		// bounds row count, but a long-idle site would otherwise keep stale rows forever.
		$csp_days = (int) apply_filters( 'totalsecwp_csp_violations_retention_days', 90 );
		$csp      = $wpdb->prefix . 'totalsecwp_csp_violations';
		$wpdb->query( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"DELETE FROM %i WHERE last_seen < %s", $csp,
				gmdate( 'Y-m-d H:i:s', time() - max( 1, $csp_days ) * DAY_IN_SECONDS )
			)
		);
	}

	/**
	 * Remove expired temporary bans.
	 */
	public function gc_bans(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'totalsecwp_bans';
		$wpdb->query( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"DELETE FROM %i WHERE type = %s AND expires_at IS NOT NULL AND expires_at < %s", $table,
				'temporary',
				gmdate( 'Y-m-d H:i:s' )
			)
		);
	}
}
