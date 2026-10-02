<?php
/**
 * Security Health Score — an A–F grade summarising the site's security posture.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Plugin;

/**
 * Computes a 0–100 health score (and an A–F grade) from a small set of posture checks:
 * which protective modules are enabled, scan recency, and open critical findings. Each check
 * independently subtracts from a perfect 100.
 */
class HealthScore {

	/** Rolling daily score history, used only to show a trend arrow — capped, not a full log. */
	private const HISTORY_OPTION = 'totalsecwp_score_history';

	/** Keep enough history for a month-over-month view later; today only the 7-day trend reads it. */
	private const HISTORY_MAX_DAYS = 35;

	/**
	 * Compute the score, grade, and the underlying checks.
	 *
	 * @return array{score:int,grade:string,checks:array<int,array{id:string,label:string,pass:bool,impact:int}>,trend:?int}
	 */
	public function compute(): array {
		$checks = array(
			$this->module_check( 'firewall', __( 'Web Application Firewall enabled', 'loyal-security' ), 20 ),
			$this->module_check( 'auth', __( 'Two-factor authentication available', 'loyal-security' ), 15 ),
			$this->module_check( 'hardening', __( 'System hardening enabled', 'loyal-security' ), 10 ),
			$this->recent_scan_check(),
			$this->critical_findings_check(),
			$this->module_check( 'integrity', __( 'Core integrity monitoring enabled', 'loyal-security' ), 10 ),
			$this->module_check( 'backup', __( 'Backups configured', 'loyal-security' ), 10 ),
		);

		/**
		 * Filters the health-score checks before the score is totalled.
		 *
		 * @since 1.0.0
		 *
		 * @param array<int,array{id:string,label:string,pass:bool,impact:int}> $checks Checks list.
		 */
		$checks = apply_filters( 'totalsecwp_health_score_checks', $checks );

		$score = 100;
		foreach ( $checks as $check ) {
			if ( empty( $check['pass'] ) ) {
				$score -= (int) $check['impact'];
			}
		}
		$score = max( 0, min( 100, $score ) );

		$this->maybe_snapshot( $score );

		return array(
			'score'  => $score,
			'grade'  => $this->grade( $score ),
			'checks' => array_values( $checks ),
			'trend'  => $this->trend( $score ),
		);
	}

	/**
	 * Append today's score to the rolling history, at most once per calendar day (UTC). Called
	 * from compute() itself rather than a dedicated cron — same "lazy, self-healing" pattern
	 * used elsewhere in this plugin (e.g. the WAF kernel resync check): whichever request
	 * happens to be the first of the day pays a single cheap option write, every other request
	 * that day is a no-op.
	 */
	private function maybe_snapshot( int $score ): void {
		$history = get_option( self::HISTORY_OPTION, array() );
		if ( ! is_array( $history ) ) {
			$history = array();
		}
		$today = gmdate( 'Y-m-d' );
		$last  = end( $history );
		if ( is_array( $last ) && $today === ( $last['date'] ?? '' ) ) {
			return;
		}
		$history[] = array( 'date' => $today, 'score' => $score );
		if ( count( $history ) > self::HISTORY_MAX_DAYS ) {
			$history = array_slice( $history, -self::HISTORY_MAX_DAYS );
		}
		update_option( self::HISTORY_OPTION, $history, false );
	}

	/**
	 * Change versus the closest snapshot that is at least 7 days old, or null when there isn't
	 * one yet (a fresh install, or one younger than a week, has nothing to compare against —
	 * the dashboard hides the trend arrow entirely in that case rather than showing a
	 * misleading zero).
	 */
	private function trend( int $current ): ?int {
		$history = get_option( self::HISTORY_OPTION, array() );
		if ( ! is_array( $history ) || empty( $history ) ) {
			return null;
		}
		$cutoff   = time() - ( 7 * DAY_IN_SECONDS );
		$baseline = null;
		foreach ( $history as $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry['date'], $entry['score'] ) ) {
				continue;
			}
			$ts = strtotime( (string) $entry['date'] . ' 00:00:00 UTC' );
			// Walk oldest→newest, keep advancing while still ≥7 days old, so we end up with the
			// entry CLOSEST to (but not inside) the 7-day window — the most accurate baseline.
			if ( $ts && $ts <= $cutoff ) {
				$baseline = (int) $entry['score'];
			}
		}
		return null === $baseline ? null : ( $current - $baseline );
	}

	/**
	 * Build a check that passes when the given module is enabled.
	 *
	 * @return array{id:string,label:string,pass:bool,impact:int}
	 */
	private function module_check( string $module_id, string $label, int $impact ): array {
		return array(
			'id'     => $module_id . '_enabled',
			'label'  => $label,
			'pass'   => $this->module_enabled( $module_id ),
			'impact' => $impact,
		);
	}

	/**
	 * Whether a module exists and reports itself enabled.
	 */
	private function module_enabled( string $module_id ): bool {
		if ( ! class_exists( Plugin::class ) ) {
			return false;
		}
		$module = Plugin::instance()->module( $module_id );
		return $module ? $module->is_enabled() : false;
	}

	/**
	 * Passes when a scan completed within the last 7 days.
	 *
	 * @return array{id:string,label:string,pass:bool,impact:int}
	 */
	private function recent_scan_check(): array {
		$history = get_option( 'totalsecwp_scan_history', array() );
		$pass    = false;

		if ( is_array( $history ) && ! empty( $history[0] ) && is_array( $history[0] ) ) {
			$completed = isset( $history[0]['completed_at'] ) ? strtotime( (string) $history[0]['completed_at'] . ' UTC' ) : 0;
			if ( $completed && $completed >= ( time() - ( 7 * DAY_IN_SECONDS ) ) ) {
				$pass = true;
			}
		}

		return array(
			'id'     => 'recent_scan',
			'label'  => __( 'Malware scan run in the last 7 days', 'loyal-security' ),
			'pass'   => $pass,
			'impact' => 15,
		);
	}

	/**
	 * Passes when there are no open findings at warning severity or above.
	 *
	 * @return array{id:string,label:string,pass:bool,impact:int}
	 */
	private function critical_findings_check(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'totalsecwp_scan_findings';

		$open_critical = (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE severity >= %d AND status = %s", $table,
				30,
				'open'
			)
		);

		return array(
			'id'     => 'no_open_critical',
			'label'  => __( 'No unresolved critical findings', 'loyal-security' ),
			'pass'   => 0 === $open_critical,
			'impact' => 20,
		);
	}

	/**
	 * Map a numeric score onto an A–F grade.
	 *
	 * Public so other surfaces (e.g. {@see \TotalSecurityWP\Admin\AdminBarScore}) that display a
	 * cached score can derive the same grade rather than duplicating (and risking drifting from)
	 * these thresholds.
	 */
	public function grade( int $score ): string {
		if ( $score >= 90 ) {
			return 'A';
		}
		if ( $score >= 75 ) {
			return 'B';
		}
		if ( $score >= 60 ) {
			return 'C';
		}
		if ( $score >= 45 ) {
			return 'D';
		}
		return 'F';
	}
}
