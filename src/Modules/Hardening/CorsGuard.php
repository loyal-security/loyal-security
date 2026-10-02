<?php
/**
 * REST API CORS hardening.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Audit\Logger;

/**
 * Replaces WordPress core's default REST API CORS handling.
 *
 * Core's rest_send_cors_headers() (wp-includes/rest-api.php) reflects whatever Origin a
 * request sends back into Access-Control-Allow-Origin and pairs it with
 * Access-Control-Allow-Credentials: true, for every REST route, unconditionally. That
 * combination lets any website on the internet make cookie-authenticated cross-origin
 * requests to the REST API from a logged-in visitor's browser and read the response --
 * exactly the pattern browsers' Same-Origin Policy exists to prevent.
 *
 * This guard removes core's callback and substitutes one that only reflects the origin
 * (and only sets Allow-Credentials) when the request's Origin is the site itself or an
 * admin-approved trusted origin. Every other origin gets no CORS headers at all: the
 * request still executes normally (CORS is a browser-side read restriction, not a
 * server-side authorization check, so non-browser API consumers are unaffected), but a
 * browser will refuse to let cross-origin JS read the response.
 */
class CorsGuard {

	/** @var string[] Extra trusted origins ("scheme://host[:port]"), beyond the site's own. */
	private array $allowlist;
	private ?Logger $logger;

	/**
	 * @param string[] $allowlist Trusted cross-origin callers, e.g. a companion app that
	 *                            legitimately needs to call this site's REST API from the
	 *                            browser (portal.example.com calling api.example.com, etc.).
	 */
	public function __construct( array $allowlist = array(), ?Logger $logger = null ) {
		$this->allowlist = array_values( array_filter( array_map( array( $this, 'normalize_origin' ), $allowlist ) ) );
		$this->logger    = $logger;
	}

	public function register(): void {
		// Core attaches rest_send_cors_headers() to rest_pre_serve_request during
		// rest_api_default_filters(), hooked on rest_api_init at the default priority (10).
		// Run after it so the remove_filter() below has something to find.
		add_action( 'rest_api_init', array( $this, 'replace_core_handler' ), 15 );
	}

	public function replace_core_handler(): void {
		remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );
		add_filter( 'rest_pre_serve_request', array( $this, 'send_headers' ) );
	}

	/**
	 * Mirrors rest_send_cors_headers()'s contract: emits headers as a side effect and
	 * returns $served untouched.
	 *
	 * @param mixed $served Whether the request has already been served.
	 * @return mixed
	 */
	public function send_headers( $served ) {
		$origin = get_http_origin();

		if ( ! $origin ) {
			if ( ! headers_sent() && 'GET' === \TotalSecurityWP\Support\RequestVars::method() && ! is_user_logged_in() ) {
				header( 'Vary: Origin', false );
			}
			return $served;
		}

		header( 'Vary: Origin', false );

		if ( ! $this->is_trusted( $origin ) ) {
			if ( null !== $this->logger ) {
				$this->logger->log(
					EventCatalog::CORS_BLOCKED,
					array(
						'origin' => $origin,
						'route'  => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : '',
					),
					EventCatalog::SEV_NOTICE
				);
			}
			return $served;
		}

		$safe_origin = 'null' === $origin ? $origin : sanitize_url( $origin );
		header( 'Access-Control-Allow-Origin: ' . $safe_origin );
		header( 'Access-Control-Allow-Methods: OPTIONS, GET, POST, PUT, PATCH, DELETE' );
		header( 'Access-Control-Allow-Credentials: true' );

		return $served;
	}

	private function is_trusted( string $origin ): bool {
		$origin = $this->normalize_origin( $origin );
		if ( '' === $origin ) {
			return false;
		}
		if ( $origin === $this->normalize_origin( home_url() ) ) {
			return true;
		}
		return in_array( $origin, $this->allowlist, true );
	}

	/**
	 * Reduce an origin to "scheme://host[:port]", lower-cased, for stable comparison.
	 */
	private function normalize_origin( string $origin ): string {
		$origin = untrailingslashit( strtolower( trim( $origin ) ) );
		$scheme = wp_parse_url( $origin, PHP_URL_SCHEME );
		$host   = wp_parse_url( $origin, PHP_URL_HOST );
		if ( ! $scheme || ! $host ) {
			return '';
		}
		$port = wp_parse_url( $origin, PHP_URL_PORT );
		return $scheme . '://' . $host . ( $port ? ':' . $port : '' );
	}
}
