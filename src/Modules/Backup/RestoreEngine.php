<?php
/**
 * Backup restore engine (in-WordPress path).
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Backup;

defined( 'ABSPATH' ) || exit;

/**
 * Restores a backup created by {@see BackupEngine} from inside a working WordPress: extracts
 * the file archive back over ABSPATH (validating every entry stays within the site root to
 * defeat path traversal) and optionally re-imports the database dump. The standalone recovery
 * endpoint implements the same steps independently for the case where WordPress cannot boot.
 */
class RestoreEngine {

	private BackupStore $store;

	public function __construct( ?BackupStore $store = null ) {
		$this->store = $store ?? new BackupStore();
	}

	/**
	 * Restore a backup by id.
	 *
	 * @param bool $restore_files Restore the file archive.
	 * @param bool $restore_db    Restore the database dump (if present).
	 * @return array{ok:bool,message:string,files?:int,db?:array<string,mixed>}
	 */
	public function restore( string $id, bool $restore_files = true, bool $restore_db = true ): array {
		$manifest = $this->store->manifest( $id );
		if ( ! $manifest ) {
			return array( 'ok' => false, 'message' => __( 'Backup not found.', 'loyal-security' ) );
		}

		// Restoring a large archive + DB can exceed default limits; lift both for the job.
		if ( function_exists( 'set_time_limit' ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- restoring a large archive + DB dump can run well past default execution limits.
			@set_time_limit( 0 );
		}
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
		}

		$dir = $this->store->backup_dir( $id );

		$files = 0;
		if ( $restore_files ) {
			$zip = $dir . '/files.zip';
			if ( ! is_file( $zip ) ) {
				return array( 'ok' => false, 'message' => __( 'The file archive is missing from this backup.', 'loyal-security' ) );
			}
			$files = $this->extract_zip( $zip, \TotalSecurityWP\Support\Paths::root() );
			if ( $files < 0 ) {
				return array( 'ok' => false, 'message' => __( 'Could not extract the file archive.', 'loyal-security' ) );
			}
		}

		$db = array();
		if ( $restore_db && ! empty( $manifest['db_included'] ) ) {
			$sql_path = $dir . '/database.sql';
			if ( is_file( $sql_path ) ) {
				$expected = (string) ( $manifest['db_sha256'] ?? '' );
				if ( '' !== $expected && ! hash_equals( $expected, (string) \TotalSecurityWP\Support\Filesystem::sha256( $sql_path ) ) ) {
					return array( 'ok' => false, 'message' => __( 'The database dump does not match the checksum recorded when this backup was made, so it was not restored.', 'loyal-security' ), 'files' => $files );
				}
				// Stream-import so a large dump is never read whole into memory (OOM risk).
				$db = ( new DatabaseDump() )->import_file( $sql_path );
			}
		}

		$result = array(
			'ok'      => true,
			'message' => __( 'Restore complete.', 'loyal-security' ),
			'files'   => $files,
			'db'      => $db,
		);

		/**
		 * Filters the result of a completed restore (extension point, e.g. to replay data
		 * recorded after the backup was taken).
		 *
		 * @param array<string,mixed> $result   { ok, message, files, db }.
		 * @param array<string,mixed> $manifest The restored backup's manifest.
		 */
		$filtered = apply_filters( 'totalsecwp_restore_result', $result, $manifest );
		return is_array( $filtered ) ? $filtered : $result;
	}

	/**
	 * Safely extract a zip into $dest, rejecting any entry that would escape $dest.
	 * Returns the number of files written, or -1 on failure.
	 */
	private function extract_zip( string $zip_path, string $dest ): int {
		if ( ! class_exists( '\ZipArchive' ) ) {
			return -1;
		}
		$zip = new \ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			return -1;
		}
		$dest_real = wp_normalize_path( untrailingslashit( $dest ) );
		$written   = 0;

		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$name = (string) $zip->getNameIndex( $i );
			if ( '' === $name || $this->is_unsafe_entry( $name ) ) {
				continue;
			}
			$target = $dest_real . '/' . ltrim( wp_normalize_path( $name ), '/' );

			// Defence in depth: the resolved parent must remain within the destination root.
			$parent = dirname( $target );
			if ( ! $this->within( $dest_real, $parent ) ) {
				continue;
			}

			if ( '/' === substr( $name, -1 ) ) {
				if ( ! is_dir( $target ) ) {
					wp_mkdir_p( $target );
				}
				continue;
			}
			if ( ! is_dir( $parent ) ) {
				wp_mkdir_p( $parent );
			}
			$contents = $zip->getFromIndex( $i );
			if ( false !== $contents && false !== file_put_contents( $target, $contents ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
				$written++;
			}
		}
		$zip->close();
		return $written;
	}

	/**
	 * Reject absolute paths and any traversal segment.
	 */
	private function is_unsafe_entry( string $name ): bool {
		$norm = wp_normalize_path( $name );
		if ( 0 === strpos( $norm, '/' ) || preg_match( '#^[A-Za-z]:#', $norm ) ) {
			return true;
		}
		foreach ( explode( '/', $norm ) as $seg ) {
			if ( '..' === $seg ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether $child is the same as or inside $root (string-prefix on normalised paths).
	 */
	private function within( string $root, string $child ): bool {
		$root  = untrailingslashit( $root );
		$child = untrailingslashit( wp_normalize_path( $child ) );
		return $child === $root || 0 === strpos( $child, $root . '/' );
	}
}
