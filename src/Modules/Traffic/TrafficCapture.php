<?php
/**
 * Shutdown-hook traffic capture (Live Traffic, all-traffic mode).
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Traffic;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Ip;

/**
 * Hooks to PHP's shutdown handler and writes one entry per request into the
 * circular TrafficBuffer. Only loaded by TrafficModule while the "Capture All" setting is
 * on. Skips our own REST polling endpoints to prevent recursion.
 *
 * Other modules (WAF, auth) can call TrafficCapture::annotate() before the
 * shutdown fires to attach their event context to the buffer entry.
 */
class TrafficCapture {

	/** Event context set by WAF/auth when they fire on this request. */
	private static ?array $security_context = null;

	private TrafficBuffer $buffer;

	/** Request start in milliseconds (set at construction time). */
	private int $started_ms;

	/** Static assets to skip in all-traffic mode (saves buffer space). */
	private const SKIP_EXTENSIONS = array( '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.webp', '.avif', '.mp4', '.pdf', '.zip' );

	public function __construct( TrafficBuffer $buffer ) {
		$this->buffer     = $buffer;
		$this->started_ms = (int) ( microtime( true ) * 1000 );
	}

	/* ------------------------------------------------------------------ */
	/* Annotation (called from WAF / auth modules)                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Called by WAF/auth when they fire a security event, so the buffer entry
	 * for the same request is annotated with the event context.
	 *
	 * @param string               $event_type EventCatalog constant.
	 * @param int                  $severity   Numeric severity.
	 * @param array<string, mixed> $ctx        Extra context (rule_id, decoded_payload …).
	 */
	public static function annotate( string $event_type, int $severity, array $ctx = array() ): void {
		self::$security_context = array(
			'event_type'      => $event_type,
			'severity'        => $severity,
			'rule_id'         => $ctx['rule_id'] ?? null,
			'rule_category'   => $ctx['rule_category'] ?? null,
			'decoded_payload' => $ctx['decoded_payload'] ?? null,
		);
	}

	/* ------------------------------------------------------------------ */
	/* Hook registration                                                    */
	/* ------------------------------------------------------------------ */

	public function register( bool $skip_static = true ): void {
		$skip = $skip_static;
		add_action(
			'shutdown',
			function () use ( $skip ) {
				$this->capture( $skip );
			},
			9999
		);
	}

	/* ------------------------------------------------------------------ */
	/* Capture                                                              */
	/* ------------------------------------------------------------------ */

	/** @internal Called on PHP shutdown via the registered closure above. */
	public function capture( bool $skip_static = true ): void {
		// Never capture CLI or cron — no meaningful HTTP context.
		if ( defined( 'DOING_CRON' ) && \DOING_CRON ) {
			return;
		}
		if ( defined( 'WP_CLI' ) && \WP_CLI ) {
			return;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : '/';

		// Skip our own REST polling so the buffer doesn't fill with internal calls.
		if ( str_contains( $uri, '/' . trim( rest_get_url_prefix(), '/' ) . '/' . TOTALSECWP_REST_NAMESPACE . '/' ) || str_contains( $uri, 'rest_route=/' . TOTALSECWP_REST_NAMESPACE ) ) {
			return;
		}

		// Optionally skip static assets.
		if ( $skip_static ) {
			$path = strtolower( strtok( $uri, '?' ) ?: $uri );
			foreach ( self::SKIP_EXTENSIONS as $ext ) {
				if ( str_ends_with( $path, $ext ) ) {
					return;
				}
			}
		}

		$method  = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		$ua      = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$referer = isset( $_SERVER['HTTP_REFERER'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_REFERER'] ) ) : '';

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Ip::client_ip() validates every candidate with filter_var( FILTER_VALIDATE_IP ) internally; nothing unvalidated is ever returned.
		$ip      = Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() );
		$status  = http_response_code();
		$elapsed = (int) ( microtime( true ) * 1000 ) - $this->started_ms;

		$parsed = UserAgentParser::parse( $ua );

		// Country may already be in context or come from a server variable (Cloudflare, etc.).
		$country = '';
		if ( isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
			$country = strtoupper( substr( sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_CF_IPCOUNTRY'] ) ), 0, 2 ) );
		}

		$sec = self::$security_context;

		$this->buffer->push(
			array(
				'ts'              => time(),
				'method'          => substr( $method, 0, 10 ),
				'uri'             => substr( $uri, 0, 500 ),
				'status'          => is_int( $status ) ? $status : 200,
				'ip'              => substr( $ip, 0, 45 ),
				'country'         => $country,
				'ua_type'         => $parsed['type'],
				'ua_family'       => $parsed['family'],
				'ua_os'           => $parsed['os'],
				'referer'         => substr( $referer, 0, 300 ),
				'response_ms'     => max( 0, $elapsed ),
				'event_type'      => $sec ? (string) $sec['event_type'] : 'request.normal',
				'severity'        => $sec ? (int) $sec['severity'] : 0,
				'rule_id'         => $sec ? $sec['rule_id'] : null,
				'rule_category'   => $sec ? $sec['rule_category'] : null,
				'decoded_payload' => $sec ? $sec['decoded_payload'] : null,
			)
		);
	}
}
