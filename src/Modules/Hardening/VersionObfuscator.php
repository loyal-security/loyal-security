<?php
/**
 * WordPress version / fingerprint obfuscation.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Removes version fingerprints that help attackers target known-vulnerable versions: the
 * generator meta tag, readable version query strings on assets, and discovery links (RSD, WLW,
 * shortlink).
 *
 * Asset versions are replaced, not removed. The `ver` value is what makes browsers and CDNs
 * fetch a new copy after an update; deleting it left caches serving stale files for days behind
 * a CDN (an origin max-age of ten years is common). Each version becomes a short hash keyed with
 * this site's salts: the same version always gives the same hash, so caching still works, and
 * a new version gives a new hash, so caches fetch the new file. The salts mean a hash cannot be
 * looked up in a table built on another site.
 *
 * This stops casual fingerprinting only: a scanner can still identify a version by hashing the
 * contents of a core file.
 */
class VersionObfuscator {

	/** Length of the hash that replaces a version. */
	private const TOKEN_LENGTH = 10;

	public function register(): void {
		// Generator tag.
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );

		// Replace ?ver= on enqueued styles, scripts and script modules.
		add_filter( 'style_loader_src', array( $this, 'hash_version' ), 9999 );
		add_filter( 'script_loader_src', array( $this, 'hash_version' ), 9999 );
		add_filter( 'script_module_loader_src', array( $this, 'hash_version' ), 9999 );

		// Remove discovery/meta links.
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
		remove_action( 'wp_head', 'wp_shortlink_wp_head' );
		remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
	}

	/**
	 * Replace an asset URL's `ver` with its site-specific hash. wp-admin is left alone: it is
	 * only reachable after signing in, so hiding versions there protects nothing.
	 *
	 * @param mixed $src Asset URL.
	 * @return mixed
	 */
	public function hash_version( $src ) {
		if ( ! is_string( $src ) || '' === $src || false === strpos( $src, 'ver=' ) || is_admin() ) {
			return $src;
		}
		$query = (string) wp_parse_url( $src, PHP_URL_QUERY );
		if ( '' === $query ) {
			return $src;
		}
		parse_str( $query, $args );
		if ( ! isset( $args['ver'] ) || ! is_scalar( $args['ver'] ) || '' === (string) $args['ver'] ) {
			return $src;
		}
		return add_query_arg( 'ver', self::token( (string) $args['ver'] ), $src );
	}

	/**
	 * The hash that stands in for a version string.
	 */
	public static function token( string $version ): string {
		static $cache = array();
		if ( ! isset( $cache[ $version ] ) ) {
			$cache[ $version ] = substr( wp_hash( 'loyalsec-ver|' . $version ), 0, self::TOKEN_LENGTH );
		}
		return $cache[ $version ];
	}
}
