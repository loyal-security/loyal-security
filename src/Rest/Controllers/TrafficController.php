<?php
/**
 * Live Traffic REST controller.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Modules\Traffic\TrafficBuffer;
use TotalSecurityWP\Modules\Traffic\TrafficModule;
use TotalSecurityWP\Modules\Traffic\UserAgentParser;
use TotalSecurityWP\Plugin;
use WP_REST_Request;

/**
 * Endpoints:
 *   GET  /traffic/stream   — Paginated all-traffic buffer with filters and payload detail.
 *   GET  /traffic/summary  — Stats from the same buffer.
 *   POST /traffic/block    — Block an IP at the firewall.
 *   POST /traffic/unblock  — Remove an IP ban.
 *   GET  /traffic/ua-parse — Parse a UA string (diagnostic helper).
 *   POST /traffic/clear    — Clear the traffic buffer.
 */
class TrafficController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route(
			$ns,
			'/traffic/stream',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'stream' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/traffic/summary',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'summary' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/traffic/block',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'block_ip' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/traffic/unblock',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'unblock_ip' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/traffic/ua-parse',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'ua_parse' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/traffic/clear',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'clear_buffer' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* Handlers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Read from the all-traffic circular buffer with filters.
	 */
	public function stream( WP_REST_Request $request ) {
		$module = Plugin::instance()->module( 'traffic' );
		if ( ! ( $module instanceof TrafficModule ) ) {
			return $this->ok( array( 'items' => array(), 'total' => 0, 'page' => 1, 'per_page' => 100, 'server_time' => time(), 'capture_off' => true ) );
		}

		$filters = array(
			'since'      => max( 0, (int) $request->get_param( 'since' ) ),
			'limit'      => min( 500, max( 1, (int) ( $request->get_param( 'limit' ) ?: 500 ) ) ),
			'page'       => max( 1, (int) ( $request->get_param( 'page' ) ?: 1 ) ),
			'method'     => sanitize_text_field( (string) ( $request->get_param( 'method' ) ?: '' ) ),
			'ip'         => sanitize_text_field( (string) ( $request->get_param( 'ip' ) ?: '' ) ),
			'ua_type'    => sanitize_text_field( (string) ( $request->get_param( 'ua_type' ) ?: '' ) ),
			'event_type' => sanitize_text_field( (string) ( $request->get_param( 'event_type' ) ?: '' ) ),
			'search'     => sanitize_text_field( (string) ( $request->get_param( 'search' ) ?: '' ) ),
		);

		$result                = $module->buffer()->query( $filters );
		$result['capture_off'] = ! $module->capture_enabled();

		return $this->ok( $result );
	}

	/**
	 * Traffic summary stats.
	 *   Aggregates from the all-traffic buffer while "Capture All" is on; otherwise falls back to
	 *   the events table.
	 */
	public function summary( WP_REST_Request $request ) {
		$window = max( 300, min( 86400, (int) ( $request->get_param( 'window' ) ?: 3600 ) ) );
		$since  = time() - $window;

		$module = Plugin::instance()->module( 'traffic' );
		if ( $module instanceof TrafficModule && $module->capture_enabled() ) {
			return $this->ok( $module->buffer()->summary( $since ) );
		}

		// All-traffic recording is off: compute from the security-events table.
		return $this->ok( $this->events_summary( $since ) );
	}


	/** Block an IP at the firewall (permanent ban). */
	public function block_ip( WP_REST_Request $request ) {
		$ip = sanitize_text_field( (string) ( $request->get_param( 'ip' ) ?: '' ) );
		if ( ! $ip ) {
			return $this->fail( 'missing_ip', __( 'IP address is required.', 'loyal-security' ), 400 );
		}

		global $wpdb;
		$now = current_time( 'mysql', true );
		$wpdb->replace( // phpcs:ignore WordPress.DB
			$wpdb->prefix . 'totalsecwp_bans',
			array(
				'ip'         => $ip,
				'reason'     => sanitize_text_field( (string) ( $request->get_param( 'reason' ) ?: 'Blocked from Live Traffic monitor' ) ),
				'type'       => 'permanent',
				'source'     => 'manual',
				'hits'       => 0,
				'created_at' => $now,
				'expires_at' => null,
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', null )
		);

		return $this->ok( array( 'blocked' => $ip ) );
	}

	/** Remove an IP ban. */
	public function unblock_ip( WP_REST_Request $request ) {
		$ip = sanitize_text_field( (string) ( $request->get_param( 'ip' ) ?: '' ) );
		if ( ! $ip ) {
			return $this->fail( 'missing_ip', __( 'IP address is required.', 'loyal-security' ), 400 );
		}

		global $wpdb;
		$wpdb->delete( $wpdb->prefix . 'totalsecwp_bans', array( 'ip' => $ip ), array( '%s' ) ); // phpcs:ignore WordPress.DB

		return $this->ok( array( 'unblocked' => $ip ) );
	}

	/** Parse and classify a User-Agent string. */
	public function ua_parse( WP_REST_Request $request ) {
		$ua = (string) ( $request->get_param( 'ua' ) ?: '' );
		return $this->ok( UserAgentParser::parse( $ua ) );
	}

	/** Clear the Live Traffic buffer. */
	public function clear_buffer( WP_REST_Request $request ) {
		$module = Plugin::instance()->module( 'traffic' );
		if ( $module instanceof TrafficModule ) {
			$module->buffer()->clear();
		}

		return $this->ok( array( 'cleared' => true ) );
	}

	/* ------------------------------------------------------------------ */
	/* Private helpers                                                      */
	/* ------------------------------------------------------------------ */

	/** Compute summary stats from the audit events table (security events only). */
	private function events_summary( int $since ): array {
		global $wpdb;
		$table    = $wpdb->prefix . 'totalsecwp_events';
		$since_dt = gmdate( 'Y-m-d H:i:s', $since );

		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE created_at >= %s", $table, $since_dt ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; $since_dt is bound via prepare().

		$blocked = (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE created_at >= %s AND severity >= 30", $table,
				$since_dt
			)
		);

		$top_ip_rows = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT ip, COUNT(*) AS cnt FROM %i WHERE created_at >= %s AND ip != '' GROUP BY ip ORDER BY cnt DESC LIMIT 10", $table,
				$since_dt
			),
			ARRAY_A
		);
		$top_ips = is_array( $top_ip_rows ) ? array_map(
			static fn( $r ) => array( 'ip' => $r['ip'], 'count' => (int) $r['cnt'] ),
			$top_ip_rows
		) : array();

		$top_uri_rows = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT request_uri, COUNT(*) AS cnt FROM %i WHERE created_at >= %s AND request_uri != '' GROUP BY request_uri ORDER BY cnt DESC LIMIT 10", $table,
				$since_dt
			),
			ARRAY_A
		);
		$top_uris = is_array( $top_uri_rows ) ? array_map(
			static fn( $r ) => array( 'uri' => $r['request_uri'], 'count' => (int) $r['cnt'] ),
			$top_uri_rows
		) : array();

		$type_rows = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT event_type, COUNT(*) AS cnt FROM %i WHERE created_at >= %s GROUP BY event_type ORDER BY cnt DESC LIMIT 20", $table,
				$since_dt
			),
			ARRAY_A
		);
		$event_types = is_array( $type_rows ) ? array_map(
			static fn( $r ) => array( 'type' => $r['event_type'], 'count' => (int) $r['cnt'] ),
			$type_rows
		) : array();

		// Minute-granularity timeline: counts per minute, last 60 minutes.
		$tl_rows = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT DATE_FORMAT(created_at, '%%Y-%%m-%%dT%%H:%%i:00') AS bucket, COUNT(*) AS cnt"
				. " FROM %i"
				. ' WHERE created_at >= %s'
				. ' GROUP BY bucket'
				. ' ORDER BY bucket ASC', $table,
				$since_dt
			),
			ARRAY_A
		);
		$timeline = array();
		if ( is_array( $tl_rows ) ) {
			foreach ( $tl_rows as $r ) {
				$ts               = (int) strtotime( (string) $r['bucket'] );
				$timeline[ $ts ]  = (int) $r['cnt'];
			}
		}

		$elapsed_min = max( 1, ( time() - $since ) / 60 );

		return array(
			'total'         => $total,
			'blocked'       => $blocked,
			'bots'          => 0,
			'req_per_min'   => round( $total / $elapsed_min, 2 ),
			'top_ips'       => array_values( $top_ips ),
			'top_uris'      => array_values( $top_uris ),
			'event_types'   => array_values( $event_types ),
			'top_countries' => array(),
			'methods'       => array(),
			'timeline'      => $timeline,
		);
	}
}
