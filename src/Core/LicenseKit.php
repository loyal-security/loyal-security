<?php
/**
 * LicenseKit API base + shared crypto + connection self-test.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Telemetry\BypassReporter;

/**
 * Single source of truth for the LicenseKit integration: the API base URL (derived from the one
 * configurable `TOTALSECWP_LICENSE_API_URL` constant), the canonical header hashes every endpoint
 * shares, and the two "did I wire it up correctly?" probes from the integration reference —
 * `GET /health` (liveness) and `POST /diagnostics` (one-call self-test).
 *
 * Keeping the base and the license-key hash here means feed, reputation, telemetry, and license
 * all point at the same deployment and hash the key identically — the two things the server dev
 * flagged as most commonly mis-wired.
 */
class LicenseKit {

	/** Host base (no /api/v1), from the single configurable constant. Empty if unset. */
	public static function host(): string {
		$host = defined( 'TOTALSECWP_LICENSE_API_URL' ) ? (string) \TOTALSECWP_LICENSE_API_URL : '';
		return rtrim( $host, '/' );
	}

	/** API base including the version segment, e.g. https://…/api/v1. Empty if unconfigured. */
	public static function api_base(): string {
		$host = self::host();
		return '' === $host ? '' : $host . '/api/v1';
	}

	/** Signature feed sync endpoint (§2). */
	public static function feed_url(): string {
		$base = self::api_base();
		return '' === $base ? '' : $base . '/sync';
	}

	/**
	 * Patch-suggestion submission endpoint — a site-derived virtual-patch rule (see
	 * PatchSuggester), not a hash. NOT YET IMPLEMENTED on the LicenseKit side as of 2026-07-04;
	 * see docs/licensekit-patch-suggestions.md for the proposed contract. PatchSubmissionClient
	 * fails open (no-op) until this responds.
	 */
	public static function patch_suggestion_endpoint(): string {
		$base = self::api_base();
		return '' === $base ? '' : $base . '/patches/suggest';
	}

	/**
	 * `GET /products/{slug}/pricing` — public, unauthenticated plan data for the Upgrade panel.
	 * Fetched server-side (this call), never proxied to the browser directly, so the dashboard
	 * never has to iframe or CORS-fetch LicenseKit's own site to show real prices.
	 *
	 * @return array{product?:array<string,mixed>,plans?:array<int,array<string,mixed>>,pricing_url?:string,checkout_url?:string}|null
	 */
	public static function pricing( string $item_slug ): ?array {
		$base = self::api_base();
		if ( '' === $base ) {
			return null;
		}
		$res = wp_remote_get( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$base . '/products/' . rawurlencode( $item_slug ) . '/pricing',
			array(
				'timeout'    => 10,
				'user-agent' => \TotalSecurityWP\Support\Http::user_agent(),
			)
		);
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return null;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		return is_array( $data ) ? $data : null;
	}

	/**
	 * Assemble the standard auth headers (install id, license-key hash, HMAC signature over the
	 * exact raw body) shared by every authenticated LicenseKit endpoint. Public so callers
	 * outside this class (e.g. PatchSubmissionClient) don't have to re-derive the same scheme.
	 *
	 * @return array<string, string>
	 */
	public static function auth_headers( string $raw_body, string $license_key = '' ): array {
		return self::reputation_headers( $raw_body, $license_key );
	}

	/**
	 * Canonical license-key hash for the `X-TotalSec-License` header. MUST be
	 * `sha256(strtoupper(trim(key)))` — exactly how the server stores `key_hash` — or the server
	 * does not recognise a valid subscription key.
	 */
	public static function license_key_hash( string $license_key ): string {
		return hash( 'sha256', strtoupper( trim( $license_key ) ) );
	}

	/**
	 * `GET /health` — unauthenticated liveness ping. Returns the decoded JSON
	 * (`{ ok, service, api, time }`) or null when the base URL is wrong / unreachable.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function health(): ?array {
		$base = self::api_base();
		if ( '' === $base ) {
			return null;
		}
		$res = wp_remote_get( $base . '/health', array( 'timeout' => 10, 'user-agent' => \TotalSecurityWP\Support\Http::user_agent() ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( is_wp_error( $res ) ) {
			return null;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		return is_array( $data ) ? $data : null;
	}

	/**
	 * `POST /diagnostics` — one-call integration self-test. Sends the same auth headers the
	 * reputation endpoints use (install id, license-key hash, and an HMAC over the exact raw body
	 * when a secret is provisioned) plus `{ timestamp }`. The server never rejects (always 200)
	 * and reports which link is wrong (install / signature / license / clock skew).
	 *
	 * @param string $license_key Feed subscription key (may be empty).
	 * @return array{ok:bool,base:string,status:int,health:?array<string,mixed>,diagnostics:?array<string,mixed>,error:?string}
	 */
	public static function connection_test( string $license_key = '' ): array {
		$base   = self::api_base();
		$result = array(
			'ok'          => false,
			'base'        => $base,
			'status'      => 0,
			'health'      => null,
			'diagnostics' => null,
			'error'       => null,
		);

		if ( '' === $base ) {
			$result['error'] = 'not_configured';
			return $result;
		}

		// Liveness first — a failure here means the base URL is wrong or unreachable.
		$result['health'] = self::health();

		$raw     = (string) wp_json_encode( array( 'timestamp' => time() ) );
		$headers = self::reputation_headers( $raw, $license_key );

		$res = wp_remote_post( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$base . '/diagnostics',
			array(
				'timeout'    => 12,
				'user-agent' => \TotalSecurityWP\Support\Http::user_agent(),
				'headers'    => $headers,
				'body'    => $raw,
			)
		);
		if ( is_wp_error( $res ) ) {
			$result['error'] = $res->get_error_message();
			return $result;
		}

		$result['status']      = (int) wp_remote_retrieve_response_code( $res );
		$data                  = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		$result['diagnostics'] = is_array( $data ) ? $data : null;
		$result['ok']          = is_array( $data );

		return $result;
	}

	/**
	 * Assemble the reputation/diagnostics auth headers, signing the exact raw body when a
	 * telemetry secret has been provisioned (unsigned is accepted pre-cutover).
	 *
	 * @return array<string, string>
	 */
	private static function reputation_headers( string $raw_body, string $license_key ): array {
		$headers = array(
			'Content-Type'       => 'application/json',
			'X-TotalSec-Install' => BypassReporter::install_id(),
		);
		if ( '' !== $license_key ) {
			$headers['X-TotalSec-License'] = self::license_key_hash( $license_key );
		}
		$secret = (string) get_option( 'totalsecwp_telemetry_secret', '' );
		if ( '' !== $secret ) {
			$headers['X-TotalSec-Sig'] = hash_hmac( 'sha256', $raw_body, $secret );
		}
		return $headers;
	}
}
