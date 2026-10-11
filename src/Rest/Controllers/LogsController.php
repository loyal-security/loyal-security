<?php
/**
 * Audit log REST controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Modules\Audit\LogRepository;
use LoyalSecurity\Modules\Audit\EventCatalog;
use WP_REST_Request;

/**
 * Serves the audit log with filtering/pagination and CSV export.
 */
class LogsController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route(
			$ns,
			'/logs',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_logs' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/logs/types',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_types' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/logs/export',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'export' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/logs/login-activity',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'login_activity' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		// Live traffic monitor — free tier (WAF/auth events only, capped at 50).
		register_rest_route(
			$ns,
			'/logs/live',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_live' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		// Summary: top IPs, event-type counts, events/min (free, from events table).
		register_rest_route(
			$ns,
			'/logs/summary',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_summary' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);
	}

	/**
	 * Event types surfaced by the free live monitor (WAF + auth security signals).
	 *
	 * @return string[]
	 */
	private function live_event_types(): array {
		$types = array(
			EventCatalog::WAF_BLOCK,
			EventCatalog::WAF_RATE_LIMIT,
			EventCatalog::WAF_BRUTEFORCE,
			EventCatalog::WAF_BAN_ADDED,
			EventCatalog::WAF_GEO_BLOCK,
			EventCatalog::LOGIN_FAILED,
			EventCatalog::LOGIN_BLOCKED,
		);

		/**
		 * Filter the event types shown by the free live traffic monitor.
		 *
		 * @since 1.0.0
		 *
		 * @param string[] $types Event-type constants.
		 */
		return (array) apply_filters( 'loyalsec_live_event_types', $types );
	}

	/**
	 * Shared query for the live monitor. Returns enriched rows.
	 *
	 * @param int           $since_id  Last-seen event ID (0 = initial load; returns up to
	 *                                 $limit events from the past 24 h, newest-first).
	 * @param int           $limit     Row cap.
	 * @param string[]|null $types     Restrict to these event types, or null for all.
	 * @param string        $ip        Optional IP filter.
	 * @param string        $search    Optional full-text search (URI / UA / context).
	 * @return array<int, array<string, mixed>>
	 */
	private function query_live( int $since_id, int $limit, ?array $types, string $ip = '', string $search = '' ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'loyalsec_events';

		// Polling (since_id > 0) fetches only newer rows; the initial load shows the last 24 h so
		// the panel isn't blank on a quiet site. Optional filters are switched off by an empty
		// value and the type list is matched as a comma-delimited list (INSTR, portable to SQLite
		// unlike FIND_IN_SET), so the statement is a fixed string.
		$since_24h = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$type_list = $types ? implode( ',', str_replace( ',', '', array_map( 'strval', $types ) ) ) : '';
		$like      = '' === $search ? '' : '%' . $wpdb->esc_like( $search ) . '%';

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live monitor poll.
			$wpdb->prepare(
				'SELECT id, event_type, ip, method, request_uri, user_agent, severity, context, created_at FROM %i'
				. ' WHERE ( ( %d > 0 AND id > %d ) OR ( %d = 0 AND created_at > %s ) )'
				. ' AND ( %s = \'\' OR INSTR( CONCAT( \',\', %s, \',\' ), CONCAT( \',\', event_type, \',\' ) ) > 0 )'
				. ' AND ( %s = \'\' OR ip = %s )'
				. ' AND ( %s = \'\' OR request_uri LIKE %s OR user_agent LIKE %s OR context LIKE %s )'
				. ' ORDER BY id DESC LIMIT %d',
				$table,
				$since_id, $since_id, $since_id, $since_24h,
				$type_list, $type_list,
				$ip, $ip,
				$like, $like, $like, $like,
				$limit
			),
			ARRAY_A
		);

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Free live traffic monitor: recent WAF/auth security events.
	 * Returns enriched rows: method, severity_label, country, ua_family, ua_type.
	 */
	public function get_live( WP_REST_Request $request ) {
		$since_id = max( 0, (int) $request->get_param( 'since' ) );
		$limit    = min( 50, max( 1, (int) ( $request->get_param( 'limit' ) ?: 50 ) ) );
		$ip       = sanitize_text_field( (string) ( $request->get_param( 'ip' ) ?: '' ) );
		$search   = sanitize_text_field( (string) ( $request->get_param( 'search' ) ?: '' ) );
		// Guard: URLSearchParams sends the literal string "undefined" when a JS filter is empty.
		if ( 'undefined' === $ip )     $ip     = '';
		if ( 'undefined' === $search ) $search = '';

		$rows  = $this->query_live( $since_id, $limit, $this->live_event_types(), $ip, $search );
		$items = $this->enrich_rows( $rows );

		return $this->ok(
			array(
				'items'       => $items,
				'server_time' => time(),
				'count'       => count( $items ),
			)
		);
	}

	/**
	 * Lightweight summary: top IPs, event type breakdown, events/min for the Live Traffic stat bar.
	 */
	public function get_summary( WP_REST_Request $request ) {
		global $wpdb;
		$table  = $wpdb->prefix . 'loyalsec_events';
		$window = max( 300, min( 86400, (int) ( $request->get_param( 'window' ) ?: 3600 ) ) );
		$since  = gmdate( 'Y-m-d H:i:s', time() - $window );

		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE created_at >= %s", $table, $since ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; $since is bound via prepare().

		$blocked = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE created_at >= %s AND severity >= 30", $table, $since ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; $since is bound via prepare().

		$top_ip_rows = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT ip, COUNT(*) AS cnt FROM %i WHERE created_at >= %s AND ip != '' GROUP BY ip ORDER BY cnt DESC LIMIT 5", $table,
				$since
			),
			ARRAY_A
		);
		$top_ips = is_array( $top_ip_rows )
			? array_map( static fn( $r ) => array( 'ip' => $r['ip'], 'count' => (int) $r['cnt'] ), $top_ip_rows )
			: array();

		$type_rows = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT event_type, COUNT(*) AS cnt FROM %i WHERE created_at >= %s GROUP BY event_type ORDER BY cnt DESC LIMIT 10", $table,
				$since
			),
			ARRAY_A
		);
		$event_types = is_array( $type_rows )
			? array_map( static fn( $r ) => array( 'type' => $r['event_type'], 'count' => (int) $r['cnt'] ), $type_rows )
			: array();

		$elapsed_min = max( 1, $window / 60 );

		return $this->ok(
			array(
				'total'        => $total,
				'blocked'      => $blocked,
				'req_per_min'  => round( $total / $elapsed_min, 2 ),
				'top_ips'      => array_values( $top_ips ),
				'event_types'  => array_values( $event_types ),
				'server_time'  => time(),
			)
		);
	}

	/**
	 * Last 10 login-related events (success / failure / blocked) for the dashboard timeline.
	 */
	public function login_activity( WP_REST_Request $request ) {
		global $wpdb;
		$table = $wpdb->prefix . 'loyalsec_events';
		$types = array(
			EventCatalog::LOGIN_SUCCESS,
			EventCatalog::LOGIN_FAILED,
			EventCatalog::LOGIN_BLOCKED,
		);

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live login activity.
			$wpdb->prepare(
				'SELECT event_type, severity, ip, context, created_at FROM %i WHERE INSTR( CONCAT( \',\', %s, \',\' ), CONCAT( \',\', event_type, \',\' ) ) > 0 ORDER BY id DESC LIMIT 10',
				$table,
				implode( ',', $types )
			),
			ARRAY_A
		);

		$items = array();
		foreach ( (array) $rows as $row ) {
			$context  = json_decode( (string) ( $row['context'] ?? '' ), true );
			$username = is_array( $context ) && isset( $context['username'] ) ? (string) $context['username'] : '';
			$items[]  = array(
				'type'       => (string) $row['event_type'],
				'ip'         => (string) ( $row['ip'] ?? '' ),
				'username'   => $username,
				'created_at' => (string) ( $row['created_at'] ?? '' ),
				'severity'   => (int) ( $row['severity'] ?? 0 ),
			);
		}

		return $this->ok( array( 'items' => $items ) );
	}

	/**
	 * Normalise and enrich raw DB rows for the live monitor response.
	 *
	 * @param  array<int,array<string,mixed>> $rows Raw rows from query_live().
	 * @return list<array<string,mixed>>
	 */
	private function enrich_rows( array $rows ): array {
		$items = array();
		foreach ( $rows as $row ) {
			$ctx    = json_decode( (string) ( $row['context'] ?? '' ), true );
			$ctx    = is_array( $ctx ) ? $ctx : array();
			$sev    = (int) ( $row['severity'] ?? 0 );
			$ua_raw = (string) ( $row['user_agent'] ?? '' );

			// Lightweight UA classification (no external library).
			$ua_lower  = strtolower( $ua_raw );
			$ua_type   = 'unknown';
			$ua_family = '';
			if ( str_contains( $ua_lower, 'googlebot' ) || str_contains( $ua_lower, 'bingbot' ) || str_contains( $ua_lower, 'baiduspider' ) || str_contains( $ua_lower, 'yandexbot' ) ) {
				$ua_type   = 'crawler';
				$ua_family = str_contains( $ua_lower, 'googlebot' ) ? 'Googlebot' : ( str_contains( $ua_lower, 'bingbot' ) ? 'Bingbot' : 'Bot' );
			} elseif ( str_contains( $ua_lower, 'bot' ) || str_contains( $ua_lower, 'spider' ) || str_contains( $ua_lower, 'crawler' ) ) {
				$ua_type = 'bot';
			} elseif ( str_contains( $ua_lower, 'curl/' ) || str_contains( $ua_lower, 'python' ) || str_contains( $ua_lower, 'go-http-client' ) ) {
				$ua_type = 'bot';
			} elseif ( str_contains( $ua_lower, 'mozilla/5.0' ) && ( str_contains( $ua_lower, 'applewebkit' ) || str_contains( $ua_lower, 'gecko/' ) ) ) {
				$ua_type = 'human';
				if ( preg_match( '/Firefox\//i', $ua_raw ) ) {
					$ua_family = 'Firefox';
				} elseif ( preg_match( '/Edg\//i', $ua_raw ) ) {
					$ua_family = 'Edge';
				} elseif ( preg_match( '/Chrome\//i', $ua_raw ) ) {
					$ua_family = 'Chrome';
				} elseif ( preg_match( '/Safari\//i', $ua_raw ) ) {
					$ua_family = 'Safari';
				}
			}

			$item = array(
				'id'             => (int) ( $row['id'] ?? 0 ),
				'event_type'     => (string) ( $row['event_type'] ?? '' ),
				'ip'             => (string) ( $row['ip'] ?? '' ),
				'method'         => strtoupper( (string) ( $row['method'] ?? 'GET' ) ),
				'request_uri'    => (string) ( $row['request_uri'] ?? '' ),
				'user_agent'     => $ua_raw,
				'ua_type'        => $ua_type,
				'ua_family'      => $ua_family,
				'severity'       => $sev,
				'severity_label' => EventCatalog::severity_label( $sev ),
				'created_at'     => (string) ( $row['created_at'] ?? '' ),
				'country'        => isset( $ctx['country'] ) ? (string) $ctx['country'] : ( isset( $ctx['country_code'] ) ? (string) $ctx['country_code'] : null ),
			);

			$items[] = $item;
		}
		return $items;
	}

	/**
	 * The audit log's configured retention, in days — everything the site keeps is viewable and
	 * exportable.
	 */
	private function audit_retention_days(): int {
		$module = \LoyalSecurity\Plugin::instance()->module( 'audit' );
		$days   = $module instanceof \LoyalSecurity\Modules\Audit\AuditModule
			? (int) $module->setting_public( 'log_retention_days', 90 )
			: 90;
		return max( 1, $days );
	}

	private function filters( WP_REST_Request $request ): array {
		return array(
			'search'       => (string) $request->get_param( 'search' ),
			'type'         => (string) $request->get_param( 'type' ),
			'ip'           => (string) $request->get_param( 'ip' ),
			'country'      => strtoupper( (string) $request->get_param( 'country' ) ),
			'min_severity' => (int) $request->get_param( 'min_severity' ),
			'page'         => (int) ( $request->get_param( 'page' ) ?: 1 ),
			'per_page'     => (int) ( $request->get_param( 'per_page' ) ?: 50 ),
		);
	}

	public function get_logs( WP_REST_Request $request ) {
		$filters                   = $this->filters( $request );
		$filters['since_days'] = $this->audit_retention_days();
		$result                = ( new LogRepository() )->query( $filters );

		// Strip absolute server paths from event context (scan/quarantine/repair events store an
		// absolute `path`) so the audit log never exposes the site's filesystem layout.
		if ( ! empty( $result['items'] ) && is_array( $result['items'] ) ) {
			$result['items'] = array_map(
				function ( $row ) {
					if ( isset( $row['context'] ) && is_array( $row['context'] ) ) {
						$row['context'] = $this->mask_paths_deep( $row['context'] );
					}
					return $row;
				},
				$result['items']
			);
		}
		return $this->ok( $result );
	}

	public function get_types( WP_REST_Request $request ) {
		return $this->ok( ( new LogRepository() )->types() );
	}

	/**
	 * Stream a CSV download.
	 */
	/**
	 * CSV export of the filtered audit log. Returned as JSON (`filename` + `content`) and saved
	 * as a file by the dashboard, so this endpoint never streams raw output.
	 */
	public function export( WP_REST_Request $request ) {
		$filters               = $this->filters( $request );
		$filters['since_days'] = $this->audit_retention_days();

		return $this->ok(
			array(
				'filename' => 'loyal-security-audit-' . gmdate( 'Ymd-His' ) . '.csv',
				'mime'     => 'text/csv',
				'content'  => ( new LogRepository() )->export_csv( $filters ),
			)
		);
	}
}
