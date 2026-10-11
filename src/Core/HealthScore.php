<?php
/**
 * Security Health Score — an A–F grade summarising the site's security posture.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Core;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Plugin;

/**
 * Computes a 0–100 health score (and an A–F grade) from a small set of posture checks: which
 * protective modules are enabled, open malware findings, whether setup was completed and whether
 * two-factor is enforced. Each failing check subtracts its impact from a perfect 100.
 *
 * This is the only place the score is calculated. The dashboard, the admin-bar badge, WP-CLI and
 * Pro's Hub reporter all read it, so a site never shows two different grades.
 */
class HealthScore {

	/** Rolling daily score history, used only to show a trend arrow — capped, not a full log. */
	private const HISTORY_OPTION = 'loyalsec_score_history';

	/** Keep enough history for a month-over-month view later; today only the 7-day trend reads it. */
	private const HISTORY_MAX_DAYS = 35;

	/**
	 * Compute the score, grade, and the underlying checks.
	 *
	 * Each check carries the dashboard route that fixes it (`route`, plus `highlight` for a
	 * specific setting) so the dashboard can turn failing checks into recommendations. A check
	 * with impact 0 is advice only and does not lower the score.
	 *
	 * @return array{score:int,grade:string,checks:array<int,array{id:string,label:string,pass:bool,impact:int,route:string,highlight?:string}>,trend:?int}
	 */
	public function compute(): array {
		$checks = array();

		if ( class_exists( Plugin::class ) ) {
			foreach ( Plugin::instance()->modules() as $id => $module ) {
				$checks[] = array(
					'id'        => $id . '_enabled',
					/* translators: %s: module title */
					'label'     => sprintf( __( 'The %s module is disabled — enable it for full protection.', 'loyal-security' ), $module->title() ),
					'pass'      => $module->is_enabled(),
					'impact'    => 10,
					'route'     => 'settings',
					'highlight' => $id . '.enabled',
				);
			}
		}

		$open_findings = $this->count_rows( 'scan_findings', 'open' );
		$checks[]      = array(
			'id'     => 'no_open_findings',
			'label'  => __( 'Unresolved malware findings detected. Review and remediate them.', 'loyal-security' ),
			'pass'   => 0 === $open_findings,
			'impact' => min( 30, $open_findings * 5 ),
			'route'  => 'scanner',
		);

		$quarantined = $this->count_rows( 'quarantine', 'quarantined' );
		$checks[]    = array(
			'id'     => 'quarantine_reviewed',
			/* translators: %d quarantined file count */
			'label'  => sprintf( _n( '%d quarantined file is awaiting review.', '%d quarantined files are awaiting review.', $quarantined, 'loyal-security' ), $quarantined ),
			'pass'   => 0 === $quarantined,
			'impact' => 0,
			'route'  => 'quarantine',
		);

		$checks[] = array(
			'id'     => 'setup_complete',
			'label'  => __( 'Complete the setup wizard to deploy the optimized firewall.', 'loyal-security' ),
			'pass'   => (bool) get_option( 'loyalsec_setup_complete', false ),
			'impact' => 10,
			'route'  => 'wizard',
		);

		// This scores the *enforcement* toggle, which requires every admin/editor to enroll — not
		// whether the current user personally has. It's surfaced directly on the 2FA panel
		// (ForceTwoFactorCard in TwoFactorSetup.js), so the recommendation lands somewhere with
		// the actual control on it.
		$force_2fa = false;
		if ( class_exists( Plugin::class ) ) {
			$force_2fa = (bool) Plugin::instance()->container()->make( 'settings' )->get( 'auth', 'force_2fa', false );
		}
		$checks[] = array(
			'id'     => 'force_2fa',
			'label'  => __( 'Enforce two-factor authentication for administrators.', 'loyal-security' ),
			'pass'   => $force_2fa,
			'impact' => 8,
			'route'  => '2fa',
		);

		/**
		 * Filters the health-score checks before the score is totalled.
		 *
		 * @since 1.0.0
		 *
		 * @param array<int,array{id:string,label:string,pass:bool,impact:int}> $checks Checks list.
		 */
		$checks = apply_filters( 'loyalsec_health_score_checks', $checks );

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
	 * Count rows in one of the plugin's tables with the given status.
	 */
	private function count_rows( string $table, string $status ): int {
		global $wpdb;
		return (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table, counted live for the score.
			$wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE status = %s', $wpdb->prefix . 'loyalsec_' . $table, $status )
		);
	}

	/**
	 * Map a numeric score onto an A–F grade.
	 *
	 * Public so other surfaces (e.g. {@see \LoyalSecurity\Admin\AdminBarScore}) that display a
	 * cached score can derive the same grade rather than duplicating (and risking drifting from)
	 * these thresholds.
	 */
	public function grade( int $score ): string {
		if ( $score >= 90 ) {
			return 'A';
		}
		if ( $score >= 80 ) {
			return 'B';
		}
		if ( $score >= 65 ) {
			return 'C';
		}
		if ( $score >= 50 ) {
			return 'D';
		}
		return 'F';
	}
}
