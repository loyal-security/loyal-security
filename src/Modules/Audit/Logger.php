<?php
/**
 * Central audit logger — writes security-relevant events to a dedicated table.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Audit;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Support\Ip;

/**
 * The single write path for the audit trail. Resolved as a shared service so every
 * module can record events without coupling to the Audit module's internals.
 */
class Logger {

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * Fully-qualified events table name.
	 */
	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'totalsecwp_events';
	}

	/**
	 * Record an event.
	 *
	 * @param string               $type     One of {@see EventCatalog} constants.
	 * @param array<string, mixed> $context  Arbitrary structured context (stored as JSON).
	 * @param int|null             $severity Override severity; defaults from the catalogue.
	 * @return int Inserted row id (0 on failure).
	 */
	public function log( string $type, array $context = array(), ?int $severity = null ): int {
		global $wpdb;

		$severity = $severity ?? EventCatalog::default_severity( $type );
		$ip_headers  = \TotalSecurityWP\Support\RequestVars::ip_headers();
		$trust_proxy = (bool) $this->settings->get( 'firewall', 'trust_proxy', false );
		$proxies     = (array) $this->settings->get( 'firewall', 'trusted_proxies', array() );
		$ip          = Ip::client_ip( $ip_headers, $trust_proxy, $proxies );

		$user_id = function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0;

		$data = array(
			'event_type'  => $type,
			'severity'    => $severity,
			'user_id'     => $user_id,
			'ip'          => $ip,
			'request_uri' => mb_substr( \TotalSecurityWP\Support\RequestVars::uri(), 0, 512 ),
			'method'      => '' !== \TotalSecurityWP\Support\RequestVars::text( 'REQUEST_METHOD' ) ? \TotalSecurityWP\Support\RequestVars::method() : '',
			'user_agent'  => mb_substr( \TotalSecurityWP\Support\RequestVars::user_agent(), 0, 512 ),
			'context'     => wp_json_encode( $this->scrub( $context ) ),
			'created_at'  => gmdate( 'Y-m-d H:i:s' ),
		);

		// Capture useful reverse-proxy headers for forensics.
		$fwd = array();
		foreach ( Ip::PROXY_HEADERS as $header ) {
			if ( ! empty( $ip_headers[ $header ] ) ) {
				$fwd[ $header ] = mb_substr( (string) $ip_headers[ $header ], 0, 255 );
			}
		}
		if ( $fwd ) {
			$data['proxy_headers'] = wp_json_encode( $fwd );
		}

		$ok = $wpdb->insert( self::table(), $data ); // phpcs:ignore WordPress.DB

		$id = $ok ? (int) $wpdb->insert_id : 0;

		/**
		 * Fires after an event is logged. Used for real-time alerting/notifications.
		 *
		 * @param string $type
		 * @param array  $data
		 * @param int    $id
		 */
		do_action( 'totalsecwp_event_logged', $type, $data, $id );

		return $id;
	}

	/**
	 * Remove obviously sensitive keys from context before persistence.
	 *
	 * @param array<string, mixed> $context Raw context.
	 * @return array<string, mixed>
	 */
	private function scrub( array $context ): array {
		$blocked = array( 'pass', 'pwd', 'password', 'pass1', 'pass2', 'secret', 'token', 'nonce', 'auth_key' );
		foreach ( $context as $key => $value ) {
			foreach ( $blocked as $needle ) {
				if ( false !== stripos( (string) $key, $needle ) ) {
					$context[ $key ] = '***redacted***';
					continue 2;
				}
			}
			if ( is_string( $value ) && strlen( $value ) > 2000 ) {
				$context[ $key ] = substr( $value, 0, 2000 ) . '…';
			}
		}
		return $context;
	}
}
