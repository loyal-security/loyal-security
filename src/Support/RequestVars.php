<?php
/**
 * Sanitized access to request server variables.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Every `$_SERVER` read made from WordPress context goes through here, so each value is
 * unslashed and sanitized exactly once, at the point it's read, with the function that fits it.
 *
 * {@see Ip} deliberately stays free of WordPress functions (the pre-WordPress firewall uses it
 * too), so it takes an array — callers pass {@see ip_headers()} rather than the raw superglobal.
 */
final class RequestVars {

	/** Geo headers set by CDNs in front of the site. */
	private const GEO_HEADERS = array( 'HTTP_CF_IPCOUNTRY', 'HTTP_CLOUDFRONT_VIEWER_COUNTRY', 'HTTP_X_GEO_COUNTRY' );

	/**
	 * A single server variable as sanitized plain text ('' when absent or not a scalar).
	 */
	public static function text( string $key ): string {
		if ( ! isset( $_SERVER[ $key ] ) || ! is_scalar( $_SERVER[ $key ] ) ) {
			return '';
		}
		return sanitize_text_field( wp_unslash( (string) $_SERVER[ $key ] ) );
	}

	/**
	 * The variables {@see Ip::client_ip()} reads: REMOTE_ADDR plus the forwarded-for headers it
	 * only honours from configured trusted proxies. Absent headers are omitted.
	 *
	 * @return array<string, string>
	 */
	public static function ip_headers(): array {
		$out = array();
		foreach ( array_merge( array( 'REMOTE_ADDR' ), Ip::PROXY_HEADERS ) as $key ) {
			$value = self::text( $key );
			if ( '' !== $value ) {
				$out[ $key ] = $value;
			}
		}
		return $out;
	}

	/**
	 * CDN country headers for geo-blocking. Absent headers are omitted.
	 *
	 * @return array<string, string>
	 */
	public static function geo_headers(): array {
		$out = array();
		foreach ( self::GEO_HEADERS as $key ) {
			$value = self::text( $key );
			if ( '' !== $value ) {
				$out[ $key ] = $value;
			}
		}
		return $out;
	}

	/**
	 * The request URI (path + query). URL-sanitized rather than text-sanitized so
	 * percent-encoding — often the interesting part of a logged attack — is preserved.
	 */
	public static function uri(): string {
		if ( ! isset( $_SERVER['REQUEST_URI'] ) || ! is_scalar( $_SERVER['REQUEST_URI'] ) ) {
			return '';
		}
		return esc_url_raw( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) );
	}

	/** Upper-cased HTTP method ('GET' when absent). */
	public static function method(): string {
		$method = strtoupper( sanitize_key( self::text( 'REQUEST_METHOD' ) ) );
		return '' === $method ? 'GET' : $method;
	}

	/** The User-Agent header. */
	public static function user_agent(): string {
		return self::text( 'HTTP_USER_AGENT' );
	}

	/** The Referer header. */
	public static function referer(): string {
		if ( ! isset( $_SERVER['HTTP_REFERER'] ) || ! is_scalar( $_SERVER['HTTP_REFERER'] ) ) {
			return '';
		}
		return esc_url_raw( wp_unslash( (string) $_SERVER['HTTP_REFERER'] ) );
	}
}
