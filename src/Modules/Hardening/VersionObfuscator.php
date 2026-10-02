<?php
/**
 * WordPress version / fingerprint obfuscation.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Removes version fingerprints that help attackers target known-vulnerable versions: the
 * generator meta tag, version query strings on assets, and discovery links (RSD, WLW,
 * shortlink).
 */
class VersionObfuscator {

	public function register(): void {
		// Generator tag.
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );

		// Strip ?ver= from enqueued asset URLs (defeats core-version fingerprinting).
		add_filter( 'style_loader_src', array( $this, 'strip_version' ), 9999 );
		add_filter( 'script_loader_src', array( $this, 'strip_version' ), 9999 );

		// Remove discovery/meta links.
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
		remove_action( 'wp_head', 'wp_shortlink_wp_head' );
		remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
	}

	/**
	 * @param string $src Asset URL.
	 * @return string
	 */
	public function strip_version( $src ) {
		if ( $src && false !== strpos( (string) $src, 'ver=' ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}
}
