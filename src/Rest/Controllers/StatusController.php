<?php
/**
 * Security status / score endpoint.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Core\Settings;
use LoyalSecurity\Core\HealthScore;
use LoyalSecurity\Core\OnboardingChecklist;
use LoyalSecurity\Core\SafeBrowsing;
use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Plugin;
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
		$plugin = Plugin::instance();

		$modules = array();
		foreach ( $plugin->modules() as $id => $module ) {
			$modules[] = array(
				'id'      => $id,
				'title'   => $module->title(),
				'enabled' => $module->is_enabled(),
			);
		}

		$counters = $this->counters();
		$score    = $this->score();

		return $this->ok(
			array(
				'version'         => LOYALSEC_VERSION,
				'score'           => $score['score'],
				'grade'           => $score['grade'],
				'score_trend'     => $score['trend'],
				'recommendations' => $score['recommendations'],
				'setup_complete'  => (bool) get_option( 'loyalsec_setup_complete', false ),
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
		$p = $wpdb->prefix . 'loyalsec_';

		$active_bans = (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'loyalsec_'), not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE type = %s OR expires_at IS NULL OR expires_at > %s", $p . 'bans',
				'permanent',
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		$open_findings = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'open'", $p . 'scan_findings' ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'loyalsec_'), not user input; no other value to bind.
		$quarantined   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'quarantined'", $p . 'quarantine' ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'loyalsec_'), not user input; no other value to bind.

		$blocks_24h = (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'loyalsec_'), not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE event_type LIKE %s AND created_at > %s", $p . 'events',
				'waf.%',
				gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS )
			)
		);

		$failed_logins_24h = (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- $p is a fixed table-prefix shorthand ($wpdb->prefix . 'loyalsec_'), not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE success = 0 AND created_at > %s", $p . 'login_attempts',
				gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS )
			)
		);

		// Installed plugins currently shielded by an early virtual patch (patch-gap protection).
		// Guarded so the dashboard status never fails if ThreatIntel is unavailable.
		$patch_gap = 0;
		if ( class_exists( \LoyalSecurity\Modules\ThreatIntel\PatchGap::class ) ) {
			try {
				$patch_gap = (int) ( ( new \LoyalSecurity\Modules\ThreatIntel\PatchGap() )->summary()['count'] ?? 0 );
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
	 * The shared health score ({@see HealthScore}) plus a recommendation for each failing check.
	 *
	 * @return array{score:int,grade:string,trend:?int,recommendations:array<int,array{text:string,action:string,route:string}>}
	 */
	private function score(): array {
		$health  = ( new HealthScore() )->compute();
		$actions = array(
			'settings'   => __( 'Open settings', 'loyal-security' ),
			'scanner'    => __( 'Review findings', 'loyal-security' ),
			'quarantine' => __( 'Open quarantine', 'loyal-security' ),
			'wizard'     => __( 'Run setup wizard', 'loyal-security' ),
			'2fa'        => __( 'Enforce 2FA', 'loyal-security' ),
		);

		$recommendations = array();
		foreach ( $health['checks'] as $check ) {
			if ( ! empty( $check['pass'] ) || empty( $check['route'] ) ) {
				continue;
			}
			$route             = (string) $check['route'];
			$recommendations[] = $this->rec(
				(string) $check['label'],
				$actions[ $route ] ?? __( 'Open', 'loyal-security' ),
				$route,
				(string) ( $check['highlight'] ?? '' )
			);
		}

		return array(
			'score'           => $health['score'],
			'grade'           => $health['grade'],
			'trend'           => $health['trend'],
			'recommendations' => $recommendations,
		);
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
		$table = $wpdb->prefix . 'loyalsec_events';
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
