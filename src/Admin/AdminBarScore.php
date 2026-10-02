<?php
/**
 * Admin-bar security score indicator.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Admin;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\HealthScore;

/**
 * Adds a small "🛡 A–F" node to the WordPress admin bar (front-end and back-end) showing the
 * site's current Security Health Score grade. Visible only to users with
 * the management capability. The numeric score is cached in a 30-minute transient so the node
 * does not recompute the posture checks (including a DB query) on every single page load, but
 * the cache is invalidated immediately on any event that could move the score — see
 * {@see AdminBarScore::invalidate_cache()} — so it never drifts far from the live value shown
 * on the dashboard and sidebar (both of which call {@see HealthScore::compute()} uncached).
 */
class AdminBarScore {

	/** Transient that caches the most recently computed health score. */
	private const CACHE_KEY = 'totalsecwp_health_score_cache';

	/** Cache lifetime for the score (30 minutes) — an upper bound; real changes invalidate sooner. */
	private const CACHE_TTL = 30 * MINUTE_IN_SECONDS;

	public function register_hooks(): void {
		add_action( 'admin_bar_menu', array( $this, 'add_node' ), 99 );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_style' ) );

		// Every settings change, scan completion, and finding status change (quarantine, fix,
		// ignore, whitelist, new finding, ...) logs an audit event through this generic hook —
		// it's the single choke point for "something HealthScore::compute() reads has changed".
		add_action( 'totalsecwp_event_logged', array( $this, 'invalidate_cache' ) );
	}

	/**
	 * Drop the cached score so the next admin-bar render recomputes it. Hooked to every audit
	 * event rather than pattern-matching event types — cheap (one transient recompute, not on
	 * the hot request path) and safer than trying to keep an allowlist of "score-affecting"
	 * event types in sync with {@see HealthScore::compute()} as checks are added.
	 */
	public function invalidate_cache(): void {
		delete_transient( self::CACHE_KEY );
	}

	/**
	 * Style the grade node by attaching a few rules to core's admin-bar stylesheet.
	 */
	public function enqueue_style(): void {
		if ( ! is_admin_bar_showing() || ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) ) {
			return;
		}
		// Matches the app's --ts-good/--ts-mid/--ts-bad tokens (assets/css/admin.css) — the same
		// three values the dashboard uses, so a score reads the same color anywhere it appears.
		wp_add_inline_style(
			'admin-bar',
			'#wpadminbar #wp-toolbar #wp-admin-bar-totalsecwp-score .ab-icon{margin-top:2px}'
			. '#wpadminbar #wp-toolbar #wp-admin-bar-totalsecwp-score span.ab-label{font-weight:600}'
			. '#wpadminbar #wp-toolbar #wp-admin-bar-totalsecwp-score span.totalsecwp-grade--good{color:#16a34a}'
			. '#wpadminbar #wp-toolbar #wp-admin-bar-totalsecwp-score span.totalsecwp-grade--mid{color:#d97706}'
			. '#wpadminbar #wp-toolbar #wp-admin-bar-totalsecwp-score span.totalsecwp-grade--bad{color:#dc2626}'
		);
	}

	/**
	 * Register the score node.
	 *
	 * @param \WP_Admin_Bar $bar The admin-bar instance.
	 */
	public function add_node( $bar ): void {
		if ( ! ( $bar instanceof \WP_Admin_Bar ) ) {
			return;
		}
		// Only privileged users see (and can act on) the score.
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$score = $this->cached_score();
		$grade = ( new HealthScore() )->grade( $score );
		$title = sprintf(
			'<span class="ab-icon" aria-hidden="true">&#128737;</span>'
				. '<span class="ab-label %1$s">%2$s</span>',
			esc_attr( 'totalsecwp-grade--' . $this->tone( $score ) ),
			esc_html( $grade )
		);

		$bar->add_node(
			array(
				'id'    => 'totalsecwp-score',
				'title' => $title,
				'href'  => esc_url( admin_url( 'admin.php?page=loyal-security' ) ),
				'meta'  => array(
					'title' => sprintf(
						/* translators: %1$s: brand name, %2$s: letter grade, %3$d: numeric score. */
						__( '%1$s: grade %2$s (%3$d/100)', 'loyal-security' ),
						\TotalSecurityWP\Support\Brand::name(),
						$grade,
						$score
					),
				),
			)
		);
	}

	/**
	 * Return the cached numeric score, recomputing and caching it on a miss.
	 */
	private function cached_score(): int {
		$cached = get_transient( self::CACHE_KEY );
		if ( false !== $cached ) {
			return (int) $cached;
		}

		$result = ( new HealthScore() )->compute();
		$score  = (int) ( $result['score'] ?? 0 );

		set_transient( self::CACHE_KEY, $score, self::CACHE_TTL );
		return $score;
	}

	/**
	 * Pick a traffic-light tone for the grade badge (styled in enqueue_style()).
	 */
	private function tone( int $score ): string {
		if ( $score >= 80 ) {
			return 'good';
		}
		if ( $score >= 60 ) {
			return 'mid';
		}
		return 'bad';
	}
}
