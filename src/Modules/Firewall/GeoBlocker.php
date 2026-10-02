<?php
/**
 * Geolocation / country-based blocking.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Support\Ip;

/**
 * Resolves a request's country and enforces an allow-list or block-list. Country resolution
 * prefers CDN-provided headers (Cloudflare / CloudFront / Akamai) and falls back to an
 * optional bundled CIDR→country table when present.
 */
class GeoBlocker {

	private Settings $settings;

	/** @var array<int, array{0:string,1:string,2:string}>|null Cached CIDR table. */
	private static ?array $cidr_table = null;

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
	 * Resolve an ISO country code for an IP.
	 */
	public function country( string $ip, array $server ): string {
		// 1) CDN headers (most reliable when fronted by a CDN).
		$header_map = array(
			'HTTP_CF_IPCOUNTRY',            // Cloudflare.
			'HTTP_CLOUDFRONT_VIEWER_COUNTRY', // CloudFront.
			'HTTP_X_GEO_COUNTRY',
		);
		foreach ( $header_map as $h ) {
			if ( ! empty( $server[ $h ] ) ) {
				$code = strtoupper( substr( (string) $server[ $h ], 0, 2 ) );
				if ( ctype_alpha( $code ) && 'XX' !== $code ) {
					return $code;
				}
			}
		}

		// 2) Optional bundled CIDR table.
		return $this->lookup_cidr( $ip );
	}

	/**
	 * Lookup an IP in the optional bundled country CIDR table.
	 */
	private function lookup_cidr( string $ip ): string {
		if ( null === self::$cidr_table ) {
			$file             = TOTALSECWP_PATH . 'data/geo/country-cidr.php';
			self::$cidr_table = is_file( $file ) ? (array) include $file : array();
		}
		if ( empty( self::$cidr_table ) ) {
			return '';
		}
		foreach ( self::$cidr_table as $entry ) {
			// Each entry: [ cidr, country ].
			if ( isset( $entry[0], $entry[1] ) && Ip::cidr_match( $ip, $entry[0] ) ) {
				return strtoupper( (string) $entry[1] );
			}
		}
		return '';
	}
}
