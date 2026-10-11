<?php
/**
 * HTTP helper wrapping the WordPress HTTP API.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Thin convenience layer over wp_remote_* used by the integrity (WordPress.org checksum)
 * and captcha verification engines. Centralises timeouts and JSON decoding.
 */
final class Http {

	/**
	 * Default cap on how much of a response body wp_remote_* will ever buffer into memory,
	 * regardless of what the remote server actually sends. Added after a real incident: a
	 * ThreatIntel feed sync (the `cve` dataset, whose own client-side comment already
	 * anticipated this — "a server that doesn't yet support [scoping] simply ignores it and
	 * keeps returning everything") pulled back a response large enough to hit "PHP Fatal
	 * error: Allowed memory size exhausted" inside Requests' cURL transport — a fatal that is
	 * NOT a \Throwable and cannot be caught by any try/catch, taking down the entire site (not
	 * just the sync request) for the duration. The only real fix is preventing the oversized
	 * download from happening at all. `limit_response_size` is WordPress's own HTTP API
	 * mechanism for exactly this; applied here, class-wide, so no future caller of this shared
	 * helper — whatever remote endpoint it points at — can repeat this failure mode. 8 MB is
	 * generous for any signature/rule dataset this plugin syncs, while leaving comfortable
	 * headroom under a typical 128 MB memory_limit even after JSON-decoding overhead (a JSON
	 * string commonly expands 2-5x once parsed into PHP arrays).
	 */
	private const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

	/**
	 * User-agent for every request this plugin makes. Deliberately carries no site URL —
	 * WordPress's default user-agent appends the home URL, which would disclose the site to
	 * every service contacted (see the readme's "External services" section).
	 */
	public static function user_agent(): string {
		return 'LoyalSecurity/' . ( defined( 'LOYALSEC_VERSION' ) ? LOYALSEC_VERSION : '1.0' );
	}

	/**
	 * `sslverify` value for loopback requests to this same site (self-tests, background jobs,
	 * CSP and exposure scans). Follows core's `https_local_ssl_verify` filter, exactly as
	 * WordPress's own loopback requests do, so a site with a valid certificate can enable
	 * verification.
	 */
	public static function local_sslverify(): bool {
		/** This filter is documented in wp-includes/class-wp-http-streams.php */
		return (bool) apply_filters( 'https_local_ssl_verify', false );
	}

	/**
	 * GET a URL and return the decoded JSON body, or null on failure.
	 *
	 * @param string               $url  Target URL.
	 * @param array<string, mixed> $args Optional wp_remote_get args.
	 * @return array<mixed>|null
	 */
	public static function get_json( string $url, array $args = array() ): ?array {
		$body = self::get_body( $url, $args );
		if ( null === $body ) {
			return null;
		}
		$data = json_decode( $body, true );
		return is_array( $data ) ? $data : null;
	}

	/**
	 * GET a URL and return the raw body string, or null on failure.
	 *
	 * @param string               $url  Target URL.
	 * @param array<string, mixed> $args Optional args.
	 */
	public static function get_body( string $url, array $args = array() ): ?string {
		$defaults = array(
			'timeout'             => 15,
			'user-agent'          => self::user_agent(),
			'limit_response_size' => self::MAX_RESPONSE_BYTES,
		);
		$response = wp_remote_get( $url, array_merge( $defaults, $args ) );
		if ( is_wp_error( $response ) ) {
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			return null;
		}
		return (string) wp_remote_retrieve_body( $response );
	}

	/**
	 * POST form-urlencoded fields and return decoded JSON, or null on failure.
	 *
	 * Despite the name, this sends `$fields` as a raw array with no Content-Type header —
	 * wp_remote_post() defaults an array body to application/x-www-form-urlencoded. Kept
	 * exactly as-is: Captcha::verify_token() relies on this for Google reCAPTCHA's and
	 * Cloudflare Turnstile's `siteverify` endpoints, both of which specifically require
	 * form-urlencoded, not JSON — changing this would silently break CAPTCHA verification
	 * (worst case, lock out every legitimate login if verification always fails closed). Use
	 * {@see post_json_body()} for an endpoint that actually expects a JSON request body.
	 *
	 * @param string               $url    Target URL.
	 * @param array<string, mixed> $fields Body fields.
	 * @return array<mixed>|null
	 */
	public static function post_json( string $url, array $fields ): ?array {
		$response = wp_remote_post(
			$url,
			array(
				'timeout'             => 15,
				'user-agent'          => self::user_agent(),
				'limit_response_size' => self::MAX_RESPONSE_BYTES,
				'body'                => $fields,
			)
		);
		if ( is_wp_error( $response ) ) {
			return null;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		return is_array( $data ) ? $data : null;
	}

	/**
	 * POST an actual JSON request body (Content-Type: application/json) and return decoded
	 * JSON, or null on failure. Distinct from post_json() (which, despite its name, sends
	 * form-urlencoded — see its doc comment) — this is for endpoints that require a real JSON
	 * body, e.g. LicenseKit's `/sync` feed endpoint, matching the encoding
	 * PatchSubmissionClient already uses for `/patches/suggest`.
	 *
	 * Found via: the entire feed/ cache directory had never been created on a live site —
	 * every dataset (waf/malware/patches/cve) was failing to sync via FeedClient, not just
	 * one, which is what pointed at a transport-level mismatch rather than anything
	 * dataset-specific — FeedClient was the one caller of post_json() actually talking to a
	 * JSON-only endpoint.
	 *
	 * @param string               $url    Target URL.
	 * @param array<string, mixed> $fields Body fields, JSON-encoded before sending.
	 * @return array<mixed>|null
	 */
	public static function post_json_body( string $url, array $fields ): ?array {
		$response = wp_remote_post(
			$url,
			array(
				'timeout'             => 15,
				'user-agent'          => self::user_agent(),
				'limit_response_size' => self::MAX_RESPONSE_BYTES,
				'headers'             => array( 'Content-Type' => 'application/json' ),
				'body'                => wp_json_encode( $fields ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return null;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		return is_array( $data ) ? $data : null;
	}
}
