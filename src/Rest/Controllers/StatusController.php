<?php
/**
 * Security status / score endpoint.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Core\HealthScore;
use TotalSecurityWP\Core\OnboardingChecklist;
use TotalSecurityWP\Core\SafeBrowsing;
use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Plugin;
use WP_REST_Request;

/**
 * Aggregates module health into a single dashboard payload: an overall security score,
 * per-module status, key counters, and the most recent critical events.
 */
class StatusController extends AbstractController {

	public function register_routes(): void {
		register_rest_route(
			$this->namespace(),
			'/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_status' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/status/health-score',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'health_score' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/status/onboarding',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'onboarding' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/status/onboarding/dismiss',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'dismiss_onboarding' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/status/license',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'license' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/status/safe-browsing',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'safe_browsing' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/status/safe-browsing/check',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'safe_browsing_check' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);
	}

	/**
	 * Free: A–F security health score.
	 */
	public function health_score( WP_REST_Request $request ) {
		return $this->ok( ( new HealthScore() )->compute() );
	}

	/**
	 * Free: onboarding checklist state.
	 */
	public function onboarding( WP_REST_Request $request ) {
		$checklist = new OnboardingChecklist();
		return $this->ok(
			array(
				'dismissed' => $checklist->is_dismissed(),
				'percent'   => $checklist->completion_percent(),
				'steps'     => $checklist->get_steps(),
			)
		);
	}

	/**
	 * Free: dismiss the onboarding banner.
	 */
	public function dismiss_onboarding( WP_REST_Request $request ) {
		( new OnboardingChecklist() )->dismiss();
		return $this->ok( array( 'dismissed' => true ) );
	}

	/**
	 * Whether the separate Pro plugin is active. The dashboard uses this only to word its
	 * pointers to Pro; nothing in the free plugin is enabled or disabled by it.
	 */
	public function license( WP_REST_Request $request ) {
		$tier = $this->container->make( 'pro_status' )->tier();

		return $this->ok(
			array(
				'tier'      => $tier,
				'activated' => 'pro' === $tier,
			)
		);
	}

	/**
	 * Free: last cached Safe Browsing result.
	 */
	public function safe_browsing( WP_REST_Request $request ) {
		return $this->ok( ( new SafeBrowsing() )->last_result() );
	}

	/**
	 * Free: run a fresh Safe Browsing check against the site's home URL.
	 */
	public function safe_browsing_check( WP_REST_Request $request ) {
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		$key      = (string) $settings->get( 'hardening', 'safe_browsing_api_key', '' );

		return $this->ok( ( new SafeBrowsing() )->check( $key, home_url() ) );
	}

	public function get_status( WP_REST_Request $request ) {
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		$plugin   = Plugin::instance();

		$modules = array();
		foreach ( $plugin->modules() as $id => $module ) {
			$modules[] = array(
				'id'      => $id,
				'title'   => $module->title(),
				'enabled' => $module->is_enabled(),
			);
		}

		$counters = $this->counters();
		$score    = $this->score( $modules, $counters, $settings );

		return $this->ok(
			array(
				'version'         => TOTALSECWP_VERSION,
				'score'           => $score['score'],
				'grade'           => $score['grade'],
				'score_trend'     => $this->score_trend( $score['score'] ),
				'recommendations' => $score['recommendations'],
				'setup_complete'  => (bool) get_option( 'totalsecwp_setup_complete', false ),
				'modules'         => $modules,
				'counters'        => $counters,
				'recent_events'   => $this->recent_critical_events(),
			)
		);
	}

	/**
	 * Headline counters used by the dashboard cards.
	 *
	 * @return array<string, int>
	 */
	private function counters(): array {
		global $wpdb;
		$p = $wpdb->prefix . 'totalsecwp_';

		$active_bans = (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'totalsecwp_'), not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE type = %s OR expires_at IS NULL OR expires_at > %s", $p . 'bans',
				'permanent',
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		$open_findings = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'open'", $p . 'scan_findings' ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'totalsecwp_'), not user input; no other value to bind.
		$quarantined   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'quarantined'", $p . 'quarantine' ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'totalsecwp_'), not user input; no other value to bind.

		$blocks_24h = (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'totalsecwp_'), not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE event_type LIKE %s AND created_at > %s", $p . 'events',
				'waf.%',
				gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS )
			)
		);

		$failed_logins_24h = (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'totalsecwp_'), not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE success = 0 AND created_at > %s", $p . 'login_attempts',
				gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS )
			)
		);

		// Installed plugins currently shielded by an early virtual patch (patch-gap protection).
		// Guarded so the dashboard status never fails if ThreatIntel is unavailable.
		$patch_gap = 0;
		if ( class_exists( \TotalSecurityWP\Modules\ThreatIntel\PatchGap::class ) ) {
			try {
				$patch_gap = (int) ( ( new \TotalSecurityWP\Modules\ThreatIntel\PatchGap() )->summary()['count'] ?? 0 );
			} catch ( \Throwable $e ) {
				$patch_gap = 0;
			}
		}

		return array(
			'active_bans'       => $active_bans,
			'open_findings'     => $open_findings,
			'quarantined'       => $quarantined,
			'waf_blocks_24h'    => $blocks_24h,
			'failed_logins_24h' => $failed_logins_24h,
			'patch_gap'         => $patch_gap,
		);
	}

	/**
	 * Compute a 0–100 security score and human recommendations.
	 *
	 * @param array<int, array> $modules  Module status list.
	 * @param array<string,int> $counters Counters.
	 * @param Settings          $settings Settings repo.
	 * @return array{score:int,grade:string,recommendations:array<int,array{text:string,action:string,route:string}>}
	 */
	private function score( array $modules, array $counters, Settings $settings ): array {
		$score           = 100;
		$recommendations = array();

		foreach ( $modules as $m ) {
			if ( ! $m['enabled'] ) {
				$score -= 10;
				$recommendations[] = $this->rec(
					sprintf(
						/* translators: module title */
						__( 'The %s module is disabled — enable it for full protection.', 'loyal-security' ),
						$m['title']
					),
					__( 'Open settings', 'loyal-security' ),
					'settings',
					$m['id'] . '.enabled'
				);
			}
		}

		if ( $counters['open_findings'] > 0 ) {
			$score            -= min( 30, $counters['open_findings'] * 5 );
			$recommendations[] = $this->rec(
				__( 'Unresolved malware findings detected. Review and remediate them.', 'loyal-security' ),
				__( 'Review findings', 'loyal-security' ),
				'scanner'
			);
		}

		if ( $counters['quarantined'] > 0 ) {
			$recommendations[] = $this->rec(
				/* translators: %d quarantined file count */
				sprintf( _n( '%d quarantined file is awaiting review.', '%d quarantined files are awaiting review.', $counters['quarantined'], 'loyal-security' ), $counters['quarantined'] ),
				__( 'Open quarantine', 'loyal-security' ),
				'quarantine'
			);
		}

		if ( ! get_option( 'totalsecwp_setup_complete', false ) ) {
			$score            -= 10;
			$recommendations[] = $this->rec(
				__( 'Complete the setup wizard to deploy the optimized firewall.', 'loyal-security' ),
				__( 'Run setup wizard', 'loyal-security' ),
				'wizard'
			);
		}

		if ( ! (bool) $settings->get( 'auth', 'force_2fa', false ) ) {
			$score            -= 8;
			// This scores the *enforcement* toggle, which requires every admin/editor to
			// enroll — not whether the current user personally has. It's surfaced directly on
			// the 2FA panel (ForceTwoFactorCard in TwoFactorSetup.js), not just buried in the
			// generic Settings page, precisely so this recommendation lands somewhere with the
			// actual control on it.
			$recommendations[] = $this->rec(
				__( 'Enforce two-factor authentication for administrators.', 'loyal-security' ),
				__( 'Enforce 2FA', 'loyal-security' ),
				'2fa'
			);
		}

		$score = max( 0, min( 100, $score ) );

		$grade = 'A';
		if ( $score < 50 ) {
			$grade = 'F';
		} elseif ( $score < 65 ) {
			$grade = 'D';
		} elseif ( $score < 80 ) {
			$grade = 'C';
		} elseif ( $score < 90 ) {
			$grade = 'B';
		}

		return array(
			'score'           => $score,
			'grade'           => $grade,
			'recommendations' => array_values( $recommendations ),
		);
	}

	/** Rolling daily snapshot of the dashboard's own score, used only for the trend arrow. */
	private const SCORE_HISTORY_OPTION = 'totalsecwp_dashboard_score_history';

	private const SCORE_HISTORY_MAX_DAYS = 35;

	/**
	 * Change vs. the closest daily snapshot at least 7 days old, or null when there isn't one
	 * yet (a new install, or one under a week old). Snapshots itself at most once per calendar
	 * day (UTC) as a side effect of being called — same lazy, self-healing pattern the plugin
	 * already uses elsewhere (e.g. the WAF kernel resync check) rather than a dedicated cron.
	 */
	private function score_trend( int $current ): ?int {
		$history = get_option( self::SCORE_HISTORY_OPTION, array() );
		if ( ! is_array( $history ) ) {
			$history = array();
		}

		$today = gmdate( 'Y-m-d' );
		$last  = end( $history );
		if ( ! is_array( $last ) || $today !== ( $last['date'] ?? '' ) ) {
			$history[] = array( 'date' => $today, 'score' => $current );
			if ( count( $history ) > self::SCORE_HISTORY_MAX_DAYS ) {
				$history = array_slice( $history, -self::SCORE_HISTORY_MAX_DAYS );
			}
			update_option( self::SCORE_HISTORY_OPTION, $history, false );
		}

		$cutoff   = time() - ( 7 * DAY_IN_SECONDS );
		$baseline = null;
		foreach ( $history as $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry['date'], $entry['score'] ) ) {
				continue;
			}
			$ts = strtotime( (string) $entry['date'] . ' 00:00:00 UTC' );
			// Walk oldest→newest, keep advancing while still ≥7 days old, so we land on the
			// entry CLOSEST to (but not inside) the 7-day window.
			if ( $ts && $ts <= $cutoff ) {
				$baseline = (int) $entry['score'];
			}
		}
		return null === $baseline ? null : ( $current - $baseline );
	}

	/**
	 * Build a recommendation with an actionable link to the panel that resolves it.
	 *
	 * @param string $highlight Optional "module.key" settings field to scroll to and highlight
	 *                          once the target panel loads (see SettingsForm.js's highlight
	 *                          mechanism). Omit when the recommendation just needs the panel
	 *                          itself, not a specific field within it.
	 * @return array{text:string,action:string,route:string,highlight?:string}
	 */
	private function rec( string $text, string $action, string $route, string $highlight = '' ): array {
		$rec = array( 'text' => $text, 'action' => $action, 'route' => $route );
		if ( '' !== $highlight ) {
			$rec['highlight'] = $highlight;
		}
		return $rec;
	}

	/**
	 * Most recent critical/warning events for the activity feed.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function recent_critical_events(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'totalsecwp_events';
		$rows  = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT id, event_type, severity, ip, method, request_uri, user_agent, context, created_at FROM %i WHERE severity >= %d ORDER BY id DESC LIMIT 10", $table,
				30
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		// Decode context + add a worded severity so the dashboard can render a readable
		// incident report instead of a raw event code and a bare number.
		foreach ( $rows as &$row ) {
			$row['context']        = isset( $row['context'] ) ? json_decode( (string) $row['context'], true ) : null;
			$row['severity']       = (int) $row['severity'];
			$row['severity_label'] = EventCatalog::severity_label( $row['severity'] );
		}
		unset( $row );

		return $rows;
	}
}
