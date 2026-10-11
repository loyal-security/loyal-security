<?php
/**
 * Geolocation / country-based blocking.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;
use LoyalSecurity\Support\Ip;

/**
 * Resolves a request's country and enforces an allow-list or block-list.
 *
 * A country header from a CDN (Cloudflare's CF-IPCountry, CloudFront's viewer country, or a
 * proxy's X-Geo-Country) is believed only when the request really came from that CDN or proxy:
 * anyone can send those headers straight to the server. Otherwise the client address is looked
 * up in the bundled table ({@see CountryTable}), so country rules work without any CDN.
 */
class GeoBlocker {

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * @return string|null Reason if the country is blocked, null otherwise.
	 */
	public function evaluate( string $ip, array $server ): ?string {
		$mode = (string) $this->settings->get( 'firewall', 'geo_mode', 'off' ); // off | allow | block
		if ( 'off' === $mode ) {
			return null;
		}

		$country = $this->country( $ip, $server );
		if ( '' === $country ) {
			return null; // Unknown — don't block to avoid false positives.
		}

		$list = array_map( 'strtoupper', (array) $this->settings->get( 'firewall', 'geo_countries', array() ) );

		if ( 'allow' === $mode ) {
			return in_array( $country, $list, true ) ? null : 'geo_not_allowed:' . $country;
		}
		// block mode.
		return in_array( $country, $list, true ) ? 'geo_blocked:' . $country : null;
	}

	/**
	 * Resolve an ISO country code for an IP ('' when unknown).
	 *
	 * @param string $ip     Client IP.
	 * @param array  $server Country headers of the current request ({@see RequestVars::geo_headers()}),
	 *                       or an empty array to use the table only (e.g. for a past event's IP).
	 */
	public function country( string $ip, array $server ): string {
		$code = $this->trusted_header_country( $server );
		if ( '' !== $code ) {
			return $code;
		}
		// A proxy's own address says where the proxy is, not the visitor: unknown.
		if ( BanStore::is_proxy_address( $ip ) ) {
			return '';
		}
		return CountryTable::lookup( $ip );
	}

	/**
	 * The country a CDN or proxy reported for this request, only when the request came from
	 * that CDN or proxy (checked against the direct connection's address).
	 *
	 * @param array $server Country headers of the current request.
	 */
	private function trusted_header_country( array $server ): string {
		if ( ! $server ) {
			return '';
		}
		$peer = \LoyalSecurity\Support\RequestVars::text( 'REMOTE_ADDR' );
		if ( '' === $peer ) {
			return '';
		}

		$headers = array();
		if ( Ip::is_cloudflare( $peer ) ) {
			$headers[] = 'HTTP_CF_IPCOUNTRY';
		}
		$proxies = array_filter( array_map( 'trim', array_map( 'strval', (array) $this->settings->get( 'firewall', 'trusted_proxies', array() ) ) ) );
		if ( $proxies && Ip::in_ranges( $peer, $proxies ) ) {
			$headers = array_merge( $headers, array( 'HTTP_CF_IPCOUNTRY', 'HTTP_CLOUDFRONT_VIEWER_COUNTRY', 'HTTP_X_GEO_COUNTRY' ) );
		}

		foreach ( array_unique( $headers ) as $h ) {
			if ( empty( $server[ $h ] ) ) {
				continue;
			}
			$code = strtoupper( substr( (string) $server[ $h ], 0, 2 ) );
			// XX = unknown and T1 = Tor (Cloudflare): fall through to the table.
			if ( 2 === strlen( $code ) && ctype_alpha( $code ) && 'XX' !== $code ) {
				return $code;
			}
		}
		return '';
	}
}
