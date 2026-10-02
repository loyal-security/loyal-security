<?php
/**
 * IP address utilities — parsing, CIDR matching, and proxy-aware client resolution.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Stateless helpers for working with IPv4/IPv6 addresses. No WordPress dependency,
 * so the WAF prepend layer can use it too.
 */
final class Ip {

	/**
	 * Headers that may carry the real client IP behind a reverse proxy / CDN.
	 * Only trusted when explicitly enabled, to prevent spoofing.
	 */
	public const PROXY_HEADERS = array(
		'HTTP_CF_CONNECTING_IP', // Cloudflare.
		'HTTP_TRUE_CLIENT_IP',   // Akamai / Cloudflare Enterprise.
		'HTTP_X_REAL_IP',        // Nginx.
		'HTTP_X_FORWARDED_FOR',  // Generic (comma list, left-most = client).
	);

	/**
	 * Resolve the client IP from a $_SERVER-like array.
	 *
	 * @param array       $server          Server superglobal (or copy).
	 * @param bool        $trust_proxy     Whether to honour forwarded headers.
	 * @param string[]    $trusted_proxies CIDR list of proxies allowed to set headers.
	 * @return string Best-effort client IP, or '0.0.0.0' if none valid.
	 */
	public static function client_ip( array $server, bool $trust_proxy = false, array $trusted_proxies = array() ): string {
		$remote = isset( $server['REMOTE_ADDR'] ) ? trim( (string) $server['REMOTE_ADDR'] ) : '';

		// Forwarded headers are honoured ONLY when the direct peer (REMOTE_ADDR) is a configured
		// trusted proxy. An empty trusted_proxies list no longer means "trust everyone": doing so
		// let any client spoof X-Forwarded-For to rotate their apparent IP (evading bans and
		// rate-limits) or to pin a victim's IP (getting a legitimate visitor banned). With no
		// trusted ranges we fall through to REMOTE_ADDR — the only value an attacker cannot forge.
		// (Admin\Notices warns when trust_proxy is on but no ranges are set, so this fallback is
		// visible rather than a silent behaviour change.)
		if ( $trust_proxy && ! empty( $trusted_proxies ) && self::in_ranges( $remote, $trusted_proxies ) ) {
			foreach ( self::PROXY_HEADERS as $header ) {
				if ( empty( $server[ $header ] ) ) {
					continue;
				}
				$candidate = (string) $server[ $header ];
				if ( false !== strpos( $candidate, ',' ) ) {
					$parts     = explode( ',', $candidate );
					$candidate = trim( $parts[0] );
				}
				if ( self::is_valid( $candidate ) ) {
					return $candidate;
				}
			}
		}

		return self::is_valid( $remote ) ? $remote : '0.0.0.0';
	}

	/**
	 * Validate an IP address (v4 or v6).
	 */
	public static function is_valid( string $ip ): bool {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Test whether an IP falls within any of the given CIDR ranges or exact IPs.
	 *
	 * @param string   $ip     Candidate IP.
	 * @param string[] $ranges List of CIDR strings or plain IPs.
	 */
	public static function in_ranges( string $ip, array $ranges ): bool {
		foreach ( $ranges as $range ) {
			$range = trim( $range );
			if ( '' === $range ) {
				continue;
			}
			if ( false === strpos( $range, '/' ) ) {
				if ( $ip === $range ) {
					return true;
				}
				continue;
			}
			if ( self::cidr_match( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Match an IP against a single CIDR block (handles v4 and v6).
	 */
	public static function cidr_match( string $ip, string $cidr ): bool {
		[ $subnet, $bits ] = array_pad( explode( '/', $cidr, 2 ), 2, null );

		if ( null === $bits ) {
			return $ip === $subnet;
		}

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bits      = (int) $bits;
		$whole     = intdiv( $bits, 8 );
		$remainder = $bits % 8;

		if ( $whole > 0 && 0 !== substr_compare( $ip_bin, $subnet_bin, 0, $whole ) ) {
			return false;
		}

		if ( $remainder > 0 ) {
			$mask     = chr( 0xff << ( 8 - $remainder ) & 0xff );
			$ip_byte  = ord( $ip_bin[ $whole ] ) & ord( $mask );
			$net_byte = ord( $subnet_bin[ $whole ] ) & ord( $mask );
			if ( $ip_byte !== $net_byte ) {
				return false;
			}
		}

		return true;
	}
}
