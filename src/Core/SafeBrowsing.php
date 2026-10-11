<?php
/**
 * Safe Browsing Check — query the Google Safe Browsing Lookup API v4.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Checks a URL against Google Safe Browsing v4 (`threatMatches:find`) to detect whether the
 * site is flagged for malware, social engineering, or unwanted software.
 * Results are cached in a transient for 6 hours to stay within API quota.
 */
class SafeBrowsing {

	private const CACHE_KEY = 'loyalsec_safebrowse_cache';

	private const CACHE_TTL = 6 * HOUR_IN_SECONDS;

	private const ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

	/**
	 * Look up a URL against the Safe Browsing API.
	 *
	 * @param string $api_key Google API key.
	 * @param string $url     URL to check.
	 * @return array<string, mixed>
	 */
	public function check( string $api_key, string $url ): array {
		$api_key = trim( $api_key );
		if ( '' === $api_key ) {
			return array(
				'safe'  => null,
				'error' => __( 'API key not configured', 'loyal-security' ),
			);
		}

		$body = array(
			'client'     => array(
				'clientId'      => 'loyal-security',
				'clientVersion' => '1.0',
			),
			'threatInfo' => array(
				'threatTypes'      => array( 'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE' ),
				'platformTypes'    => array( 'ANY_PLATFORM' ),
				'threatEntryTypes' => array( 'URL' ),
				'threatEntries'    => array(
					array( 'url' => $url ),
				),
			),
		);

		$response = wp_remote_post(
			add_query_arg( 'key', rawurlencode( $api_key ), self::ENDPOINT ),
			array(
				'timeout'    => 15,
				'user-agent' => \LoyalSecurity\Support\Http::user_agent(),
				'headers'    => array( 'Content-Type' => 'application/json' ),
				'body'       => wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'safe'  => null,
				'error' => $response->get_error_message(),
			);
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			return array(
				'safe'  => null,
				/* translators: %d HTTP status code */
				'error' => sprintf( __( 'Safe Browsing API error (HTTP %d).', 'loyal-security' ), $code ),
			);
		}

		$data    = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		$matches = ( is_array( $data ) && ! empty( $data['matches'] ) && is_array( $data['matches'] ) )
			? $data['matches']
			: array();

		$result = array(
			'safe'       => empty( $matches ),
			'threats'    => array_values( $matches ),
			'checked_at' => time(),
		);

		set_transient( self::CACHE_KEY, $result, self::CACHE_TTL );

		return $result;
	}

	/**
	 * The last cached result, or an empty array if none.
	 *
	 * @return array<string, mixed>
	 */
	public function last_result(): array {
		$cached = get_transient( self::CACHE_KEY );
		return is_array( $cached ) ? $cached : array();
	}
}
