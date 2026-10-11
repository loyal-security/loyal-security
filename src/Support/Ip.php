<?php
/**
 * IP address utilities — parsing, CIDR matching, and proxy-aware client resolution.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Support;

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
	 * Cloudflare's published edge ranges (https://www.cloudflare.com/ips/, checked 2026-10-10).
	 * Bundled rather than fetched so resolving an IP never makes a remote request. Only a
	 * request whose direct peer is inside these ranges has its CF-Connecting-IP believed.
	 */
	public const CLOUDFLARE_RANGES = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * The proxy trust actually applied, from the firewall settings: the configured trusted
	 * proxies when "Trust proxy" is on, plus Cloudflare's ranges when "Trust Cloudflare" is on.
	 *
	 * @param bool     $trust_proxy      Firewall "trust_proxy" setting.
	 * @param string[] $trusted_proxies  Firewall "trusted_proxies" setting.
	 * @param bool     $trust_cloudflare Firewall "trust_cloudflare" setting.
	 * @return array{0: bool, 1: string[]} Arguments for {@see client_ip()}.
	 */
	public static function effective_trust( bool $trust_proxy, array $trusted_proxies, bool $trust_cloudflare ): array {
		$ranges = $trust_proxy ? array_values( array_filter( array_map( 'trim', array_map( 'strval', $trusted_proxies ) ) ) ) : array();
		if ( $trust_cloudflare ) {
			$ranges = array_values( array_unique( array_merge( $ranges, self::CLOUDFLARE_RANGES ) ) );
		}
		return array( ! empty( $ranges ), $ranges );
	}

	/**
	 * Whether an address belongs to Cloudflare's edge.
	 */
	public static function is_cloudflare( string $ip ): bool {
		return self::is_valid( $ip ) && self::in_ranges( $ip, self::CLOUDFLARE_RANGES );
	}

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
	 * Whether an address is internal: loopback, private or reserved. Nobody on the internet can
	 * connect from one, so a request from it was relayed by something on the host's own network.
	 */
	public static function is_internal( string $ip ): bool {
		return self::is_valid( $ip ) && false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Whether the resolved visitor address is really an unconfigured proxy: the request came from
	 * an internal address (a load balancer, a container's ingress, nginx in front of Apache) and
	 * carries a forwarding header, and that proxy is not in Trusted proxies, so every visitor
	 * shares its address. IP-keyed decisions (bans, rate limits, sign-in lockouts, the admin
	 * allowlist) must not be taken on it, or one visitor's limit applies to everyone.
	 *
	 * @param string               $resolved The address the firewall resolved for this request.
	 * @param array<string, mixed> $server   Server variables (REMOTE_ADDR and the forwarding headers).
	 */
	public static function behind_unknown_proxy( string $resolved, array $server ): bool {
		$remote = trim( (string) ( $server['REMOTE_ADDR'] ?? '' ) );
		if ( '' === $resolved || $resolved !== $remote || ! self::is_internal( $remote ) ) {
			return false;
		}
		return ! empty( $server['HTTP_X_FORWARDED_FOR'] ) || ! empty( $server['HTTP_X_REAL_IP'] );
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
	 * Build a lookup index from CIDR ranges and plain IPs: per address family, the ranges as
	 * sorted, merged [first, last] pairs of fixed-width hex, so {@see in_range_index()} can
	 * binary-search them. Checking an IP against thousands of ranges then takes a dozen string
	 * comparisons instead of one CIDR match per range on every request.
	 *
	 * @param string[] $ranges CIDR strings or plain IPs.
	 * @return array{v4: array<int, array{0: string, 1: string}>, v6: array<int, array{0: string, 1: string}>}
	 */
	public static function build_range_index( array $ranges ): array {
		$spans = array( 'v4' => array(), 'v6' => array() );
		foreach ( $ranges as $range ) {
			$span = self::range_span( trim( (string) $range ) );
			if ( null !== $span ) {
				$spans[ 4 === strlen( $span[0] ) ? 'v4' : 'v6' ][] = $span;
			}
		}
		$index = array( 'v4' => array(), 'v6' => array() );
		foreach ( $spans as $family => $list ) {
			usort( $list, static fn( $a, $b ) => strcmp( $a[0], $b[0] ) );
			$merged = array();
			foreach ( $list as $span ) {
				$last = count( $merged ) - 1;
				if ( $last >= 0 && strcmp( $span[0], $merged[ $last ][1] ) <= 0 ) {
					if ( strcmp( $span[1], $merged[ $last ][1] ) > 0 ) {
						$merged[ $last ][1] = $span[1];
					}
					continue;
				}
				$merged[] = $span;
			}
			foreach ( $merged as $span ) {
				$index[ $family ][] = array( bin2hex( $span[0] ), bin2hex( $span[1] ) );
			}
		}
		return $index;
	}

	/**
	 * Whether an IP falls inside an index from {@see build_range_index()}.
	 *
	 * @param string $ip    Candidate IP.
	 * @param array  $index The index.
	 */
	public static function in_range_index( string $ip, array $index ): bool {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an invalid address is simply "not in range".
		if ( false === $bin ) {
			return false;
		}
		$list = 4 === strlen( $bin ) ? ( $index['v4'] ?? array() ) : ( $index['v6'] ?? array() );
		$hex  = bin2hex( $bin );
		$lo   = 0;
		$hi   = count( $list ) - 1;
		while ( $lo <= $hi ) {
			$mid = ( $lo + $hi ) >> 1;
			if ( strcmp( $hex, (string) $list[ $mid ][0] ) < 0 ) {
				$hi = $mid - 1;
			} elseif ( strcmp( $hex, (string) $list[ $mid ][1] ) > 0 ) {
				$lo = $mid + 1;
			} else {
				return true;
			}
		}
		return false;
	}

	/**
	 * First and last address (binary) of a CIDR range or plain IP, or null if invalid.
	 *
	 * @return array{0: string, 1: string}|null
	 */
	private static function range_span( string $range ): ?array {
		if ( '' === $range ) {
			return null;
		}
		$parts = explode( '/', $range, 2 );
		$bin   = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid entries are skipped.
		if ( false === $bin ) {
			return null;
		}
		$width = strlen( $bin ) * 8;
		$bits  = isset( $parts[1] ) ? (int) $parts[1] : $width;
		if ( $bits < 0 || $bits > $width || ( isset( $parts[1] ) && ! ctype_digit( $parts[1] ) ) ) {
			return null;
		}
		$first = '';
		$last  = '';
		for ( $i = 0, $n = strlen( $bin ); $i < $n; $i++ ) {
			$keep   = max( 0, min( 8, $bits - $i * 8 ) );
			$mask   = ( 0xff << ( 8 - $keep ) ) & 0xff;
			$byte   = ord( $bin[ $i ] );
			$first .= chr( $byte & $mask );
			$last  .= chr( ( $byte & $mask ) | ( ~$mask & 0xff ) );
		}
		return array( $first, $last );
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
