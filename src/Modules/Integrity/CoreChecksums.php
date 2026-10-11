<?php
/**
 * WordPress core file integrity verification.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Integrity;

defined( 'ABSPATH' ) || exit;

/**
 * Compares installed core files against the official WordPress.org checksums to detect
 * tampering (modified files), missing core files, and *unexpected* files planted in core
 * locations (the WP root, wp-admin, wp-includes) that are not part of the official
 * distribution. Uploaded content and wp-content are intentionally excluded (handled by
 * plugin/theme checks and the malware scanner).
 */
class CoreChecksums {

	/**
	 * Executable extensions worth flagging when found unexpectedly in a core location.
	 *
	 * @var string[]
	 */
	private const SCAN_EXTENSIONS = array( 'php', 'phtml', 'php5', 'php7', 'phps', 'phar', 'inc' );

	/**
	 * Files legitimately present in the WP root that are *not* in the checksum manifest
	 * (operator/installer-created), so they must not be reported as unknown.
	 *
	 * @var string[]
	 */
	private const ROOT_ALLOWLIST = array( 'wp-config.php' );

	/**
	 * Files that well-known plugins write into the WordPress root on purpose, keyed by file,
	 * with the plugin folder that writes them. Accepted only while that plugin is installed, so
	 * a leftover or a planted copy under the same name is still reported.
	 *
	 * @var array<string, string>
	 */
	private const PLUGIN_ROOT_FILES = array(
		'koko-analytics-collect.php' => 'koko-analytics',
		'wordfence-waf.php'          => 'wordfence',
	);

	/**
	 * Root files written by installed plugins (see PLUGIN_ROOT_FILES).
	 *
	 * @return string[]
	 */
	private function plugin_root_files(): array {
		$files = array();
		foreach ( self::PLUGIN_ROOT_FILES as $file => $plugin ) {
			if ( is_dir( trailingslashit( \LoyalSecurity\Support\Paths::plugins() ) . $plugin ) ) {
				$files[] = $file;
			}
		}
		/**
		 * Filters the files in the WordPress root that are expected although they are not part
		 * of WordPress, such as an analytics endpoint a plugin writes there.
		 *
		 * @since 1.5.1
		 *
		 * @param string[] $files File names relative to the WordPress root.
		 */
		return array_map( 'strval', (array) apply_filters( 'loyalsec_expected_root_files', $files ) );
	}

	/**
	 * Verify core files.
	 *
	 * @return array{checked:int,modified:string[],missing:string[],unknown:string[],error:string}
	 */
	public function verify(): array {
		global $wp_version, $wp_local_package;

		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$locale    = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$checksums = get_core_checksums( $wp_version, $locale );

		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			// Retry with default locale.
			$checksums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			return array( 'checked' => 0, 'modified' => array(), 'missing' => array(), 'unknown' => array(), 'error' => 'Could not fetch core checksums.' );
		}

		$modified = array();
		$missing  = array();
		$checked  = 0;

		foreach ( $checksums as $file => $md5 ) {
			// Skip wp-content (user-managed) and language files.
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$path = \LoyalSecurity\Support\Paths::root() . $file;
			if ( ! file_exists( $path ) ) {
				// Only treat genuinely required files as missing (ignore optional samples).
				if ( ! preg_match( '/(readme\.html|wp-config-sample\.php|license\.txt)$/i', $file ) ) {
					$missing[] = $file;
				}
				continue;
			}
			$checked++;
			if ( md5_file( $path ) !== $md5 ) {
				$modified[] = $file;
			}
		}

		return array(
			'checked'  => $checked,
			'modified' => $modified,
			'missing'  => $missing,
			'unknown'  => $this->find_unknown( $checksums ),
			'error'    => '',
		);
	}

	/**
	 * Find executable files present in core locations (WP root, wp-admin, wp-includes) that
	 * are absent from the official checksum manifest — i.e. files an attacker dropped that
	 * the malware scanner intentionally skips (it defers core locations to this check).
	 *
	 * @param array<string,string> $checksums Manifest keyed by relative path.
	 * @return string[] Relative paths of unexpected files.
	 */
	private function find_unknown( array $checksums ): array {
		// Set of every legitimate relative path, normalised to forward slashes.
		$known = array();
		foreach ( $checksums as $file => $md5 ) {
			$known[ $file ] = true;
		}
		foreach ( self::ROOT_ALLOWLIST as $file ) {
			$known[ $file ] = true;
		}
		foreach ( $this->plugin_root_files() as $file ) {
			$known[ $file ] = true;
		}

		$unknown = array();
		$abspath = untrailingslashit( wp_normalize_path( \LoyalSecurity\Support\Paths::root() ) );

		// Top-level WP root files only (do not recurse into wp-content/themes/plugins).
		$pattern = $abspath . '/*.{' . implode( ',', self::SCAN_EXTENSIONS ) . '}';
		foreach ( (array) glob( $pattern, GLOB_BRACE ) as $path ) {
			$rel = ltrim( str_replace( $abspath, '', wp_normalize_path( $path ) ), '/' );
			if ( '' !== $rel && ! isset( $known[ $rel ] ) ) {
				$unknown[] = $rel;
			}
		}

		// Core directories — recurse fully; the manifest lists every legitimate file here.
		$core_dirs = array(
			wp_normalize_path( \LoyalSecurity\Support\Paths::admin() ),
			wp_normalize_path( \LoyalSecurity\Support\Paths::includes() ),
		);
		foreach ( $core_dirs as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			$iter = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( ! $file->isFile() || ! in_array( strtolower( $file->getExtension() ), self::SCAN_EXTENSIONS, true ) ) {
					continue;
				}
				$rel = ltrim( str_replace( $abspath, '', wp_normalize_path( $file->getPathname() ) ), '/' );
				if ( '' !== $rel && ! isset( $known[ $rel ] ) ) {
					$unknown[] = $rel;
				}
			}
		}

		return $unknown;
	}
}
