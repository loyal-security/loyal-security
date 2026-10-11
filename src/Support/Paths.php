<?php
/**
 * Filesystem locations of WordPress itself.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Support;

defined( 'ABSPATH' ) || exit;

/**
 * The single place this plugin resolves where WordPress keeps its own files.
 *
 * The plugin's own files are always located from its main file (`LOYALSEC_PATH`, i.e.
 * `plugin_dir_path( __FILE__ )`) and everything it writes lives under `wp_upload_dir()`. What
 * remains — and what this class is for — are locations a security plugin has to inspect or
 * repair *because they are WordPress's own*: the core files it verifies against WordPress.org
 * checksums and restores when tampered with, the root `.htaccess`/`.user.ini`/`wp-config.php`
 * its hardening and firewall deploy to, and the plugins/themes/mu-plugins/drop-ins directories
 * its malware scanner and integrity monitor cover. Where WordPress exposes a function for a
 * location it is used here (`wp_upload_dir()`, `get_theme_root()`); for the core root and the
 * content/plugins directories WordPress offers no function, so the constants core itself uses
 * for these exact paths are read here — once — and every other class goes through this one.
 */
final class Paths {

	/**
	 * WordPress root directory — where `wp-admin/`, `wp-includes/`, `wp-load.php` and the
	 * root `.htaccess` live. Always has a trailing slash.
	 */
	public static function root(): string {
		return trailingslashit( ABSPATH );
	}

	/** Memoized admin directory name — see {@see admin_name()}. */
	private static ?string $admin_name = null;

	/**
	 * The name of the core admin directory, without any path around it (normally `wp-admin`).
	 *
	 * WordPress exposes no constant for this one directory, so it is derived the way core
	 * itself addresses it: `admin_url()` relative to the install URL (`site_url()`). The
	 * literal is only reached when those URLs are not usable yet, or when the admin URL has
	 * been filtered to somewhere outside the install.
	 */
	public static function admin_name(): string {
		if ( null === self::$admin_name ) {
			if ( ! function_exists( 'admin_url' ) || ! function_exists( 'site_url' ) ) {
				return 'wp-admin'; // Called before WordPress is loaded; do not memoize.
			}
			$admin = wp_parse_url( admin_url( '/' ) );
			$site  = wp_parse_url( site_url( '/' ) );
			$seg   = '';

			// Only a URL on the install's own host says anything about a directory inside it.
			// `admin_url` can be filtered to another host entirely, and the scheme may differ
			// from the site's on its own (FORCE_SSL_ADMIN), which is not a reason to give up.
			$same_host = is_array( $admin ) && is_array( $site )
				&& '' !== (string) ( $site['host'] ?? '' )
				&& strtolower( (string) ( $admin['host'] ?? '' ) ) === strtolower( (string) ( $site['host'] ?? '' ) );

			if ( $same_host ) {
				$admin_path = (string) ( $admin['path'] ?? '' );
				$site_path  = (string) ( $site['path'] ?? '' );
				if ( '' !== $site_path && 0 === strpos( $admin_path, $site_path ) ) {
					$seg = trim( substr( $admin_path, strlen( $site_path ) ), '/' );
				}
			}

			// A single directory name, or nothing usable — never a nested or empty path.
			self::$admin_name = ( '' !== $seg && false === strpos( $seg, '/' ) ) ? $seg : 'wp-admin';
		}
		return self::$admin_name;
	}

	/** Core admin directory (no trailing slash). */
	public static function admin(): string {
		return self::root() . self::admin_name();
	}

	/** Core `wp-includes` directory (no trailing slash). */
	public static function includes(): string {
		return self::root() . WPINC;
	}

	/**
	 * The active `wp-config.php`, found the same way `wp-load.php` finds it: in the root, or
	 * one level above it when that copy isn't itself part of another WordPress install.
	 * Empty string when neither exists.
	 */
	public static function wp_config(): string {
		$in_root = self::root() . 'wp-config.php';
		if ( is_file( $in_root ) ) {
			return $in_root;
		}
		$parent = dirname( self::root() );
		if ( is_file( $parent . '/wp-config.php' ) && ! is_file( $parent . '/wp-settings.php' ) ) {
			return $parent . '/wp-config.php';
		}
		return '';
	}

	/** Content directory — home of drop-ins and the default `debug.log` (no trailing slash). */
	public static function content(): string {
		return untrailingslashit( WP_CONTENT_DIR );
	}

	/** Plugins directory (no trailing slash). */
	public static function plugins(): string {
		return untrailingslashit( WP_PLUGIN_DIR );
	}

	/** Directory of an installed plugin, by folder slug (no trailing slash). */
	public static function plugin( string $slug ): string {
		return self::plugins() . '/' . $slug;
	}

	/** Must-use plugins directory (no trailing slash). */
	public static function mu_plugins(): string {
		return untrailingslashit( WPMU_PLUGIN_DIR );
	}

	/** Themes directory (no trailing slash). */
	public static function themes(): string {
		return untrailingslashit( get_theme_root() );
	}

	/** Uploads base directory (no trailing slash). */
	public static function uploads(): string {
		$uploads = wp_upload_dir( null, false );
		return untrailingslashit( (string) ( $uploads['basedir'] ?? '' ) );
	}

	/**
	 * A path relative to the WordPress root, normalized to forward slashes — the form the
	 * dashboard displays and WordPress.org checksum lists use. Returns the normalized input
	 * unchanged when it isn't under the root.
	 */
	public static function relative( string $path ): string {
		$norm = wp_normalize_path( $path );
		$root = wp_normalize_path( self::root() );
		return 0 === strpos( $norm, $root ) ? ltrim( substr( $norm, strlen( $root ) ), '/' ) : $norm;
	}

	/**
	 * A short, server-path-free form of a filesystem path for display: relative to the
	 * WordPress root when inside it, otherwise relative to the parent of a relocated content
	 * directory (e.g. `content/uploads/x.php`). Null when the path is outside both, so callers
	 * can decide not to expose it.
	 */
	public static function display( string $path ): ?string {
		$norm = wp_normalize_path( trim( $path ) );
		$root = untrailingslashit( wp_normalize_path( self::root() ) );
		if ( '' !== $root && ( $norm === $root || 0 === strpos( $norm, $root . '/' ) ) ) {
			return ltrim( substr( $norm, strlen( $root ) ), '/' );
		}
		$content = wp_normalize_path( self::content() );
		if ( '' !== $content && 0 === strpos( $norm, $content . '/' ) ) {
			return basename( $content ) . '/' . ltrim( substr( $norm, strlen( $content ) ), '/' );
		}
		return null;
	}
}
