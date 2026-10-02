<?php
/**
 * One-click recovery of clean core files from WordPress.org.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Filesystem;
use TotalSecurityWP\Support\Http;
use TotalSecurityWP\Modules\Integrity\CoreChecksums;

/**
 * Restores tampered WordPress core files by fetching the pristine version from the official
 * WordPress SVN tag for the running version, verifying it against the published checksum
 * before overwriting.
 */
class Recovery {

	/**
	 * Recover a single core file (path relative to ABSPATH).
	 *
	 * @return array{ok:bool,message:string}
	 */
	public function recover_core_file( string $relative ): array {
		global $wp_version;

		$relative = ltrim( wp_normalize_path( $relative ), '/' );

		// Guard: only core paths, never wp-content.
		if ( 0 === strpos( $relative, 'wp-content/' ) || false !== strpos( $relative, '..' ) ) {
			return array( 'ok' => false, 'message' => __( 'Only core files can be recovered.', 'loyal-security' ) );
		}

		$url  = 'https://core.svn.wordpress.org/tags/' . rawurlencode( $wp_version ) . '/' . $relative;
		$body = Http::get_body( $url );
		if ( null === $body ) {
			return array( 'ok' => false, 'message' => __( 'Could not download the clean file from WordPress.org.', 'loyal-security' ) );
		}

		// Verify against the official checksum when available.
		$checksums = $this->checksums();
		if ( isset( $checksums[ $relative ] ) && md5( $body ) !== $checksums[ $relative ] ) {
			return array( 'ok' => false, 'message' => __( 'Downloaded file failed checksum verification; aborting.', 'loyal-security' ) );
		}

		$target = \TotalSecurityWP\Support\Paths::root() . $relative;
		if ( ! Filesystem::write( $target, $body ) ) {
			return array( 'ok' => false, 'message' => __( 'Could not write the recovered file (check permissions).', 'loyal-security' ) );
		}

		return array( 'ok' => true, 'message' => sprintf( /* translators: file path */ __( 'Recovered %s from WordPress.org.', 'loyal-security' ), $relative ) );
	}

	/**
	 * Recover all modified core files detected by the integrity check.
	 *
	 * @return array{ok:bool,recovered:string[],failed:string[]}
	 */
	public function recover_all_core(): array {
		$report    = ( new CoreChecksums() )->verify();
		$recovered = array();
		$failed    = array();

		foreach ( array_merge( $report['modified'], $report['missing'] ) as $file ) {
			$res = $this->recover_core_file( $file );
			if ( $res['ok'] ) {
				$recovered[] = $file;
			} else {
				$failed[] = $file;
			}
		}

		return array( 'ok' => true, 'recovered' => $recovered, 'failed' => $failed );
	}

	/**
	 * @return array<string, string> core file => md5.
	 */
	private function checksums(): array {
		global $wp_version, $wp_local_package;
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$sums = get_core_checksums( $wp_version, isset( $wp_local_package ) ? $wp_local_package : 'en_US' );
		return is_array( $sums ) ? $sums : array();
	}
}
