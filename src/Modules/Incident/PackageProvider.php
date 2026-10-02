<?php
/**
 * Downloads and unpacks clean source packages from WordPress.org.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Modules\Integrity\PluginChecksums;
use TotalSecurityWP\Support\Filesystem;

/**
 * Resolves the canonical WordPress.org download URLs for the exact installed core/plugin
 * version and fetches them into a private temp area, verifying them only after extraction.
 * Everything is sourced over TLS from the official endpoints so the recovered code is
 * pristine, and temp artefacts are always cleaned up.
 */
class PackageProvider {

	/**
	 * Official "no-content" core build URL (core files only — no bundled themes/plugins),
	 * so syncing it over the install never disturbs wp-content.
	 */
	public function core_zip_url( string $version ): string {
		return 'https://downloads.wordpress.org/release/wordpress-' . rawurlencode( $version ) . '-no-content.zip';
	}

	/**
	 * Official plugin package URL for a specific version.
	 */
	public function plugin_zip_url( string $slug, string $version ): string {
		return 'https://downloads.wordpress.org/plugin/' . rawurlencode( $slug ) . '.' . rawurlencode( $version ) . '.zip';
	}

	/**
	 * True when the plugin/version is hosted on WordPress.org (i.e. a clean copy can be
	 * fetched). Premium/custom plugins return false and must be repaired by hand.
	 */
	public function plugin_on_wporg( string $slug, string $version ): bool {
		if ( '' === $slug || '.' === $slug || '' === $version ) {
			return false;
		}
		return null !== ( new PluginChecksums() )->verify_plugin( $slug, $version );
	}

	/**
	 * Download an archive and extract it.
	 *
	 * @return string|null Absolute path to the extracted directory, or null on failure.
	 *                     Caller must call {@see cleanup()} on the returned path when done.
	 */
	public function download_and_extract( string $url ): ?string {
		if ( ! function_exists( 'download_url' ) || ! function_exists( 'unzip_file' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		// Ensure WP_Filesystem is initialised for unzip_file().
		global $wp_filesystem;
		if ( ! $wp_filesystem ) {
			WP_Filesystem();
		}

		$zip = download_url( $url, 90 );
		if ( is_wp_error( $zip ) ) {
			return null;
		}

		$dest = $this->temp_dir();
		if ( '' === $dest ) {
			Filesystem::delete( $zip );
			return null;
		}

		$unzipped = unzip_file( $zip, $dest );
		Filesystem::delete( $zip );

		if ( is_wp_error( $unzipped ) ) {
			$this->cleanup( $dest );
			return null;
		}

		return $dest;
	}

	/**
	 * The single child directory of an extracted archive (WordPress and plugin zips wrap
	 * their payload in one top-level folder, e.g. `wordpress/` or `akismet/`).
	 */
	public function inner_dir( string $extracted ): ?string {
		$entries = glob( trailingslashit( $extracted ) . '*', GLOB_ONLYDIR );
		if ( is_array( $entries ) && 1 === count( $entries ) ) {
			return $entries[0];
		}
		// Fall back to the extraction root itself if the layout is flat.
		return is_dir( $extracted ) ? $extracted : null;
	}

	/**
	 * Recursively delete a temp extraction directory.
	 */
	public function cleanup( string $dir ): void {
		$base = $this->base_dir();
		// Guard: only ever delete inside our own repair-tmp area.
		if ( '' === $base || 0 !== strpos( wp_normalize_path( $dir ), wp_normalize_path( $base ) ) ) {
			return;
		}
		if ( ! is_dir( $dir ) ) {
			return;
		}
		Filesystem::delete_dir( $dir );
	}

	private function base_dir(): string {
		$storage = BanStore::storage_dir();
		return '' === $storage ? '' : $storage . '/repair-tmp';
	}

	private function temp_dir(): string {
		$base = $this->base_dir();
		if ( '' === $base ) {
			return '';
		}
		$dir = trailingslashit( $base ) . gmdate( 'YmdHis' ) . '_' . wp_generate_password( 8, false, false );
		if ( ! wp_mkdir_p( $dir ) ) {
			return '';
		}
		return $dir;
	}
}
