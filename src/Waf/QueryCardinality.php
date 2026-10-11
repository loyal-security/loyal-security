<?php
/**
 * What the query-cardinality limiter counts.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * The limiter exists to stop a bot walking every filter or search combination of a page. Only
 * page views can do that, so this decides which requests count and what makes two of them
 * "different". Shared by Standard Mode and the Optimized-Mode prepend.
 *
 * Not counted:
 * - anything but GET/HEAD (form posts, checkouts, webhooks);
 * - AJAX and REST calls (admin-ajax.php, `?wc-ajax=`, `/wp-json/`, `?rest_route=`): a single
 *   page view fires several, each with its own query string;
 * - WP-Cron spawns.
 *
 * Tracking parameters (utm_*, gclid, fbclid, ...) are dropped before comparing, so one visitor
 * following several campaign links is not counted as browsing filters.
 */
class QueryCardinality {

	/** Query parameters that only carry campaign or click tracking. */
	private const TRACKING = array(
		'gclid', 'gbraid', 'wbraid', 'dclid', 'fbclid', 'msclkid', 'ttclid', 'twclid', 'li_fat_id',
		'mc_cid', 'mc_eid', '_ga', '_gl', 'igshid', 'yclid', 'srsltid',
	);

	/**
	 * The string compared between requests, or '' when the request is not counted.
	 *
	 * @param RequestContext $req         The request.
	 * @param string         $rest_prefix Path prefix of the REST API, e.g. "/wp-json/".
	 */
	public static function signature( RequestContext $req, string $rest_prefix = '/wp-json/' ): string {
		$method = strtoupper( $req->method );
		if ( 'GET' !== $method && 'HEAD' !== $method ) {
			return '';
		}
		$path = strtolower( $req->path );
		if ( '' !== $rest_prefix && false !== strpos( $path, strtolower( $rest_prefix ) ) ) {
			return '';
		}
		if ( '/admin-ajax.php' === substr( $path, -15 ) || '/wp-cron.php' === substr( $path, -12 ) ) {
			return '';
		}
		$get = $req->get;
		if ( isset( $get['wc-ajax'] ) || isset( $get['rest_route'] ) ) {
			return '';
		}
		foreach ( array_keys( $get ) as $name ) {
			$name = strtolower( (string) $name );
			if ( 0 === strpos( $name, 'utm_' ) || in_array( $name, self::TRACKING, true ) ) {
				unset( $get[ $name ] );
			}
		}
		if ( ! $get ) {
			return '';
		}
		self::ksort_deep( $get );
		return $path . '?' . http_build_query( $get );
	}

	/**
	 * Sort keys recursively so parameter order does not make two requests "different".
	 *
	 * @param array<mixed> $value Value to sort in place.
	 */
	private static function ksort_deep( array &$value ): void {
		ksort( $value );
		foreach ( $value as &$item ) {
			if ( is_array( $item ) ) {
				self::ksort_deep( $item );
			}
		}
	}
}
