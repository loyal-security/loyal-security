<?php
/**
 * Clean reinstall of WordPress core for the running version.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Support\Filesystem;

/**
 * Restores a pristine core: it downloads the official "no-content" package for the *exact*
 * installed version, then for every file in the WordPress.org checksum manifest overwrites
 * the live copy when it differs — but only after re-verifying the freshly downloaded bytes
 * against the published md5, so tampered downloads can never be written. Finally it removes
 * malware-dropped executable files that live inside the core directories (`wp-admin/`,
 * `wp-includes/`) but are absent from the manifest. `wp-content/`, `wp-config.php` and
 * web-root drop-ins are never touched; foreign files at the web root are reported, not deleted.
 */
class CoreRepair {

	/** Executable extensions that are auto-removed when found foreign inside core dirs. */
	private const CODE_EXT = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'pht', 'inc' );

	/**
	 * Core directories that are 100% core-owned and safe to prune foreign code from, as
	 * absolute paths. A method rather than a constant because the locations come from
	 * {@see \LoyalSecurity\Support\Paths}, which resolves them against this install.
	 *
	 * @return string[]
	 */
	private static function core_dirs(): array {
		return array(
			\LoyalSecurity\Support\Paths::admin(),
			\LoyalSecurity\Support\Paths::includes(),
		);
	}

	/**
	 * Run the repair.
	 *
	 * @param bool $remove_extras Whether to delete foreign code files in the core dirs.
	 * @return array{ok:bool,replaced:string[],removed:string[],reported_extras:string[],failed:string[],message:string}
	 */
	public function repair( bool $remove_extras = true ): array {
		global $wp_version;

		$out = array(
			'ok'              => false,
			'replaced'        => array(),
			'removed'         => array(),
			'reported_extras' => array(),
			'failed'          => array(),
			'message'         => '',
		);

		$manifest = $this->manifest();
		if ( empty( $manifest ) ) {
			$out['message'] = __( 'Could not fetch the official core checksums; aborting (nothing changed).', 'loyal-security' );
			return $out;
		}

		$provider  = new PackageProvider();
		$extracted = $provider->download_and_extract( $provider->core_zip_url( (string) $wp_version ) );
		if ( null === $extracted ) {
			$out['message'] = __( 'Could not download the clean core package from WordPress.org; aborting (nothing changed).', 'loyal-security' );
			return $out;
		}

		$clean = $provider->inner_dir( $extracted );
		if ( null === $clean ) {
			$provider->cleanup( $extracted );
			$out['message'] = __( 'Downloaded package looked malformed; aborting (nothing changed).', 'loyal-security' );
			return $out;
		}

		// 1) Restore modified/missing core files from the verified clean source.
		$allow = array();
		foreach ( $manifest as $rel => $md5 ) {
			$rel = ltrim( wp_normalize_path( $rel ), '/' );
			// wp-content is user-managed; never restore it from core.
			if ( '' === $rel || 0 === strpos( $rel, 'wp-content/' ) ) {
				continue;
			}
			$allow[ $rel ] = true;

			$live = \LoyalSecurity\Support\Paths::root() . $rel;
			if ( is_file( $live ) && md5_file( $live ) === $md5 ) {
				continue; // Already pristine.
			}

			$source = trailingslashit( $clean ) . $rel;
			if ( ! is_file( $source ) || md5_file( $source ) !== $md5 ) {
				$out['failed'][] = $rel; // Won't write unverified bytes.
				continue;
			}
			$contents = Filesystem::read( $source );
			if ( null === $contents || ! Filesystem::write( $live, $contents ) ) {
				$out['failed'][] = $rel;
				continue;
			}
			Filesystem::chmod( $live, 0644 );
			$out['replaced'][] = $rel;
		}

		// 2) Remove malware-dropped files from inside the core directories.
		if ( $remove_extras ) {
			foreach ( self::core_dirs() as $core_dir ) {
				$this->prune_foreign( $core_dir, $allow, $out );
			}
			// Web-root: report-only (legitimate user files live here).
			$this->report_root_extras( $allow, $out );
		}

		$provider->cleanup( $extracted );

		// 3) Confirm the site still loads.
		$health = ( new Loopback() )->check();
		if ( ! $health['ok'] ) {
			$out['message'] = __( 'Core files were restored, but the post-repair health check failed. Review the site immediately.', 'loyal-security' );
			$out['ok']      = false;
			return $out;
		}

		$out['ok'] = true;
		$out['message'] = sprintf(
			/* translators: 1: files restored, 2: files removed */
			__( 'Core repaired: %1$d file(s) restored, %2$d foreign file(s) removed.', 'loyal-security' ),
			count( $out['replaced'] ),
			count( $out['removed'] )
		);
		return $out;
	}

	/**
	 * Delete foreign executable files under a core directory (recursively), skipping the
	 * bundled language directory to avoid removing legitimate translation packs.
	 *
	 * @param array<string,bool> $allow Allowlist of manifest-relative paths.
	 * @param array<string,mixed> $out  Result accumulator (by reference).
	 */
	private function prune_foreign( string $dir, array $allow, array &$out ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$iter = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS )
		);
		foreach ( $iter as $item ) {
			if ( ! $item->isFile() ) {
				continue;
			}
			$rel = \LoyalSecurity\Support\Paths::relative( $item->getPathname() );
			if ( isset( $allow[ $rel ] ) ) {
				continue; // Legitimate core file.
			}
			// Preserve translation packs and other non-code assets shipped/added under core.
			if ( false !== strpos( $rel, '/languages/' ) ) {
				continue;
			}
			$ext = strtolower( $item->getExtension() );
			if ( in_array( $ext, self::CODE_EXT, true ) ) {
				if ( Filesystem::delete( $item->getPathname() ) ) {
					$out['removed'][] = $rel;
				} else {
					$out['failed'][] = $rel;
				}
			} else {
				$out['reported_extras'][] = $rel; // Non-code anomaly — surface, don't delete.
			}
		}
	}

	/**
	 * Collect (but never delete) unexpected top-level files at the web root.
	 *
	 * @param array<string,bool>  $allow Allowlist of manifest paths.
	 * @param array<string,mixed> $out   Result accumulator (by reference).
	 */
	private function report_root_extras( array $allow, array &$out ): void {
		// Files a normal install legitimately adds at the root.
		$known = array( 'wp-config.php', '.htaccess', '.htaccess.bak', 'robots.txt', 'php.ini', '.user.ini', 'web.config', 'sitemap.xml', 'sitemap.xml.gz' );

		$entries = glob( \LoyalSecurity\Support\Paths::root() . '*' );
		if ( ! is_array( $entries ) ) {
			return;
		}
		foreach ( $entries as $path ) {
			if ( ! is_file( $path ) ) {
				continue;
			}
			$name = basename( $path );
			if ( isset( $allow[ $name ] ) || in_array( $name, $known, true ) ) {
				continue;
			}
			$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
			if ( in_array( $ext, self::CODE_EXT, true ) ) {
				$out['reported_extras'][] = $name;
			}
		}
	}

	/**
	 * Authoritative core file manifest (relative path => md5) from WordPress.org.
	 *
	 * @return array<string,string>
	 */
	private function manifest(): array {
		global $wp_version, $wp_local_package;
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$locale = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$sums   = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $sums ) || empty( $sums ) ) {
			$sums = get_core_checksums( $wp_version, 'en_US' );
		}
		return is_array( $sums ) ? $sums : array();
	}
}
