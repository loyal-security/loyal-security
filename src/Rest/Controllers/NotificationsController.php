<?php
/**
 * Notifications REST controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Modules\Notifications\Dispatcher;
use LoyalSecurity\Modules\Notifications\NotificationLog;
use LoyalSecurity\Modules\Notifications\EventGuide;
use LoyalSecurity\Modules\Audit\Logger;
use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Core\Settings;
use LoyalSecurity\Plugin;
use WP_REST_Request;

/**
 * REST endpoints for the Notifications module.
 *
 * Routes:
 *   POST /notifications/test-email     — send a test email immediately
 *   GET  /notifications/status         — throttle counter + history summary
 *   GET  /notifications/history        — paginated sent-notification history (with guidance)
 *   POST /notifications/history/clear  — clear the history
 *   POST /notifications/mute           — mute an event type
 *   POST /notifications/unmute         — un-mute an event type
 *   GET  /notifications/guide          — resolved guidance for a single event type
 */
class NotificationsController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route(
			$ns,
			'/notifications/history',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_history' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/notifications/history/clear',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'clear_history' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/notifications/mute',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'mute' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/notifications/unmute',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'unmute' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/notifications/guide',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_guide' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/notifications/false-positive',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'mark_false_positive' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/notifications/test-email',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'test_email' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/notifications/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_status' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);
	}

	public function test_email( WP_REST_Request $request ) {
		$module = Plugin::instance()->module( 'notifications' );
		if ( ! $module ) {
			return $this->fail( 'module_disabled', __( 'Notifications module is not active.', 'loyal-security' ), 503 );
		}

		/** @var \LoyalSecurity\Modules\Notifications\NotificationsModule $module */
		$dispatcher = new Dispatcher( $module );
		$sent       = $dispatcher->send_test_email();

		if ( ! $sent ) {
			return $this->fail(
				'mail_failed',
				__( 'wp_mail() returned false. Check your server mail configuration.', 'loyal-security' ),
				500
			);
		}

		$to = (string) $module->get_setting( 'email_to', '' ) ?: (string) get_option( 'admin_email' );
		return $this->ok( array( 'sent_to' => $to ) );
	}

	public function get_status( WP_REST_Request $request ) {
		$module = Plugin::instance()->module( 'notifications' );
		if ( ! $module ) {
			return $this->ok( array( 'active' => false ) );
		}

		/** @var \LoyalSecurity\Modules\Notifications\NotificationsModule $module */
		$email_count   = (int) get_transient( 'loyalsec_notif_throttle_email' );
		$max           = (int) $module->get_setting( 'throttle_max', 10 );
		$to            = (string) $module->get_setting( 'email_to', '' ) ?: (string) get_option( 'admin_email' );

		return $this->ok(
			array(
				'active'        => true,
				'email_to'      => $to,
				'throttle_max'  => $max,
				'email_sent'    => $email_count,
				'history_count' => ( new NotificationLog() )->count(),
				'muted'         => array_values( (array) $module->get_setting( 'muted_events', array() ) ),
			)
		);
	}

	/* ------------------------------------------------------------------ *
	 * History
	 * ------------------------------------------------------------------ */

	/**
	 * Paginated sent-notification history, each row enriched with plain-language guidance
	 * (title, meaning, false-positive note, remediation steps, decoded facts).
	 */
	public function get_history( WP_REST_Request $request ) {
		$log    = new NotificationLog();
		$result = $log->query(
			array(
				'channel'  => (string) $request->get_param( 'channel' ),
				'type'     => (string) $request->get_param( 'type' ),
				'status'   => (string) $request->get_param( 'status' ),
				'page'     => (int) $request->get_param( 'page' ) ?: 1,
				'per_page' => (int) $request->get_param( 'per_page' ) ?: 25,
			)
		);

		// Batch-load the original audit context for the rows on this page so the guidance
		// can show the real facts (which option changed, which IP, etc.).
		$contexts = $this->load_contexts( wp_list_pluck( $result['items'], 'event_id' ) );

		// Pre-load whitelist state for false-positive badges (one settings read).
		$settings     = $this->container->make( 'settings' );
		$ajax_wl      = array_values( array_filter( (array) $settings->get( 'firewall', 'ajax_action_whitelist', array() ) ) );
		$ip_wl        = array_values( array_filter( (array) $settings->get( 'firewall', 'ip_whitelist', array() ) ) );

		foreach ( $result['items'] as &$row ) {
			$eid                   = (int) $row['event_id'];
			$ctx                   = $contexts[ $eid ] ?? array();
			$row['guide']          = EventGuide::for_event( (string) $row['event_type'], $ctx, (int) $row['severity'] );
			$row['context']        = $ctx; // Raw context forwarded to the false-positive endpoint.
			$row['false_positive'] = $this->get_whitelist_status( (string) $row['event_type'], $ctx, $ajax_wl, $ip_wl );
		}
		unset( $row );

		$module          = Plugin::instance()->module( 'notifications' );
		$result['muted'] = $module ? array_values( (array) $module->get_setting( 'muted_events', array() ) ) : array();

		return $this->ok( $result );
	}

	/**
	 * Fetch decoded context for a set of audit-event ids in one query.
	 *
	 * @param array<int, mixed> $ids Event ids.
	 * @return array<int, array<string, mixed>> id => decoded context.
	 */
	private function load_contexts( array $ids ): array {
		global $wpdb;

		$ids = array_values( array_unique( array_filter( array_map( 'intval', $ids ) ) ) );
		if ( empty( $ids ) ) {
			return array();
		}

		$table        = Logger::table();
		// Integer ids: match as a comma-delimited list (INSTR, portable to SQLite unlike
		// FIND_IN_SET) so the statement stays a fixed string.
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- per-request context lookup.
			$wpdb->prepare( 'SELECT id, context FROM %i WHERE INSTR( CONCAT( \',\', %s, \',\' ), CONCAT( \',\', id, \',\' ) ) > 0', $table, implode( ',', $ids ) ),
			ARRAY_A
		);

		$out = array();
		foreach ( (array) $rows as $r ) {
			$decoded              = json_decode( (string) $r['context'], true );
			$out[ (int) $r['id'] ] = is_array( $decoded ) ? $decoded : array();
		}
		return $out;
	}

	/**
	 * Clear the entire sent-notification history.
	 */
	public function clear_history( WP_REST_Request $request ) {
		$removed = ( new NotificationLog() )->clear();
		return $this->ok( array( 'cleared' => $removed ) );
	}

	/* ------------------------------------------------------------------ *
	 * Mute / un-mute
	 * ------------------------------------------------------------------ */

	/**
	 * Add an event type to the mute list (no more alerts of this kind on any channel).
	 */
	public function mute( WP_REST_Request $request ) {
		$type = $this->clean_type( $request );
		if ( '' === $type ) {
			return $this->fail( 'invalid_type', __( 'A valid event type is required.', 'loyal-security' ), 400 );
		}
		return $this->ok( array( 'muted' => $this->set_muted( $type, true ) ) );
	}

	/**
	 * Remove an event type from the mute list.
	 */
	public function unmute( WP_REST_Request $request ) {
		$type = $this->clean_type( $request );
		if ( '' === $type ) {
			return $this->fail( 'invalid_type', __( 'A valid event type is required.', 'loyal-security' ), 400 );
		}
		return $this->ok( array( 'muted' => $this->set_muted( $type, false ) ) );
	}

	/* ------------------------------------------------------------------ *
	 * False-positive / whitelist resolution
	 * ------------------------------------------------------------------ */

	/**
	 * Mark a specific alert as a false positive and apply the appropriate firewall
	 * whitelist action (e.g. whitelist an AJAX action, add an IP to the allow-list).
	 * The action taken depends on the event type; unknown types fall back to muting.
	 */
	public function mark_false_positive( WP_REST_Request $request ) {
		$body       = $request->get_json_params() ?: array();
		$event_type = isset( $body['event_type'] ) ? sanitize_text_field( (string) $body['event_type'] ) : '';
		$context    = isset( $body['context'] ) && is_array( $body['context'] ) ? $body['context'] : array();

		if ( '' === $event_type ) {
			return $this->fail( 'invalid_type', __( 'event_type is required.', 'loyal-security' ), 400 );
		}

		$result = $this->apply_false_positive( $event_type, $context );
		if ( is_wp_error( $result ) ) {
			return $this->fail( $result->get_error_code(), $result->get_error_message(), 400 );
		}

		$logger = $this->container->make( 'logger' );
		$logger->log(
			EventCatalog::SETTING_CHANGED,
			array(
				'module'     => 'notifications',
				'action'     => 'false_positive',
				'event_type' => $event_type,
				'resolution' => $result['action'],
				'value'      => $result['value'],
			)
		);

		return $this->ok( $result );
	}

	/**
	 * Dispatch to the correct whitelist action for a given event type.
	 *
	 * @param string               $event_type EventCatalog constant.
	 * @param array<string, mixed> $context    Decoded event context.
	 * @return array{action:string,value:string,description:string}|\WP_Error
	 */
	private function apply_false_positive( string $event_type, array $context ) {
		switch ( $event_type ) {

			case EventCatalog::NOPRIV_AJAX_CALL:
				$action = isset( $context['action'] ) ? sanitize_key( (string) $context['action'] ) : '';
				if ( '' === $action ) {
					return new \WP_Error( 'no_action', __( 'AJAX action name not found in context.', 'loyal-security' ) );
				}
				return $this->whitelist_ajax_action( $action );

			case EventCatalog::WAF_BLOCK:
			case EventCatalog::WAF_BRUTEFORCE:
			case EventCatalog::WAF_DDOS:
			case EventCatalog::WAF_RATE_LIMIT:
			case EventCatalog::WAF_BOT_BLOCK:
				$ip = isset( $context['ip'] ) ? (string) $context['ip'] : '';
				if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return new \WP_Error( 'no_ip', __( 'A valid IP address was not found in the event context.', 'loyal-security' ) );
				}
				return $this->whitelist_ip( $ip );

			default:
				// Unknown type: fall back to muting the alert type.
				$muted = $this->set_muted( $event_type, true );
				return array(
					'action'      => 'muted',
					'value'       => $event_type,
					'description' => sprintf(
						/* translators: event type */
						__( 'Alerts of type "%s" are now muted. They will still be recorded in the audit log but will not send notifications.', 'loyal-security' ),
						$event_type
					),
					'muted'       => $muted,
				);
		}
	}

	/**
	 * Add an AJAX action name to the firewall's ajax_action_whitelist setting.
	 * Future unauthenticated calls to this action will not be logged.
	 *
	 * @return array{action:string,value:string,description:string}
	 */
	private function whitelist_ajax_action( string $action ): array {
		$settings = $this->container->make( 'settings' );
		$current  = array_values( array_unique( array_filter( (array) $settings->get( 'firewall', 'ajax_action_whitelist', array() ) ) ) );
		if ( ! in_array( $action, $current, true ) ) {
			$current[] = $action;
			$settings->update_module( 'firewall', array( 'ajax_action_whitelist' => $current ) );
		}
		return array(
			'action'      => 'whitelisted_ajax_action',
			'value'       => $action,
			'description' => sprintf(
				/* translators: AJAX action name */
				__( 'AJAX action "%s" is now whitelisted — it will no longer generate alerts. The feature on your site still works normally.', 'loyal-security' ),
				$action
			),
		);
	}

	/**
	 * Add an IP to the firewall's ip_whitelist setting.
	 * The IP will bypass all firewall checks on future requests.
	 *
	 * @return array{action:string,value:string,description:string}
	 */
	private function whitelist_ip( string $ip ): array {
		if ( \LoyalSecurity\Modules\Firewall\BanStore::is_proxy_address( $ip ) ) {
			return array(
				'action'      => 'refused_proxy_ip',
				'value'       => $ip,
				'description' => sprintf(
					/* translators: IP address */
					__( 'IP %s belongs to a proxy or CDN in front of your site (such as Cloudflare), so it was not allowlisted: that would let every visitor routed through it skip the firewall.', 'loyal-security' ),
					$ip
				),
			);
		}
		$settings = $this->container->make( 'settings' );
		$current  = array_values( array_unique( array_filter( (array) $settings->get( 'firewall', 'ip_whitelist', array() ) ) ) );
		if ( ! in_array( $ip, $current, true ) ) {
			$current[] = $ip;
			$settings->update_module( 'firewall', array( 'ip_whitelist' => $current ) );
		}
		return array(
			'action'      => 'whitelisted_ip',
			'value'       => $ip,
			'description' => sprintf(
				/* translators: IP address */
				__( 'IP %s has been added to the firewall whitelist. It will bypass all firewall checks on future requests.', 'loyal-security' ),
				$ip
			),
		);
	}

	/**
	 * Return a resolved whitelist record if the subject of this event is already whitelisted,
	 * so the history UI can show a "✅ Already whitelisted" badge instead of an action button.
	 *
	 * @param string   $type    Event type.
	 * @param string[] $ctx     Decoded event context.
	 * @param string[] $ajax_wl Current ajax_action_whitelist.
	 * @param string[] $ip_wl   Current ip_whitelist.
	 * @return array{action:string,value:string}|null
	 */
	private function get_whitelist_status( string $type, array $ctx, array $ajax_wl, array $ip_wl ): ?array {
		switch ( $type ) {
			case EventCatalog::NOPRIV_AJAX_CALL:
				$action = isset( $ctx['action'] ) ? (string) $ctx['action'] : '';
				if ( '' !== $action && in_array( $action, $ajax_wl, true ) ) {
					return array( 'action' => 'whitelisted_ajax_action', 'value' => $action );
				}
				return null;

			case EventCatalog::WAF_BLOCK:
			case EventCatalog::WAF_BRUTEFORCE:
			case EventCatalog::WAF_DDOS:
			case EventCatalog::WAF_RATE_LIMIT:
			case EventCatalog::WAF_BOT_BLOCK:
				$ip = isset( $ctx['ip'] ) ? (string) $ctx['ip'] : '';
				if ( '' !== $ip && in_array( $ip, $ip_wl, true ) ) {
					return array( 'action' => 'whitelisted_ip', 'value' => $ip );
				}
				return null;

			default:
				return null;
		}
	}

	/**
	 * Read, mutate, and persist the muted-events list. Returns the new list.
	 *
	 * @return string[]
	 */
	private function set_muted( string $type, bool $mute ): array {
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		$current  = array_values( array_filter( array_map( 'strval', (array) $settings->get( 'notifications', 'muted_events', array() ) ) ) );

		if ( $mute ) {
			if ( ! in_array( $type, $current, true ) ) {
				$current[] = $type;
			}
		} else {
			$current = array_values( array_diff( $current, array( $type ) ) );
		}

		$settings->update_module( 'notifications', array( 'muted_events' => $current ) );

		/** @var Logger $logger */
		$logger = $this->container->make( 'logger' );
		$logger->log(
			EventCatalog::SETTING_CHANGED,
			array( 'module' => 'notifications', 'action' => $mute ? 'mute' : 'unmute', 'event_type' => $type )
		);

		return $current;
	}

	/**
	 * Resolve guidance for a single event type (used by the UI for the muted list labels).
	 */
	public function get_guide( WP_REST_Request $request ) {
		$type = $this->clean_type( $request );
		if ( '' === $type ) {
			return $this->fail( 'invalid_type', __( 'A valid event type is required.', 'loyal-security' ), 400 );
		}
		return $this->ok( EventGuide::for_event( $type, array(), (int) EventCatalog::default_severity( $type ) ) );
	}

	/**
	 * Sanitise an incoming event-type parameter (JSON body or query).
	 */
	private function clean_type( WP_REST_Request $request ): string {
		$type = (string) $request->get_param( 'type' );
		if ( '' === $type ) {
			$body = $request->get_json_params();
			$type = is_array( $body ) && isset( $body['type'] ) ? (string) $body['type'] : '';
		}
		$type = preg_replace( '/[^a-z0-9_.]/', '', strtolower( $type ) ) ?? '';
		return substr( $type, 0, 64 );
	}
}
