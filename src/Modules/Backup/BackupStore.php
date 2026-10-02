<?php
/**
 * Backup storage + manifest management.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Backup;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Firewall\BanStore;

/**
 * Owns the private, non-web-served directory where backups live and the per-backup manifest
 * files. Manifests are stored on disk (not just the database) so the standalone recovery
 * endpoint can enumerate and restore backups even when WordPress/the database is unavailable.
 */
class BackupStore {

	/**
	 * Absolute path to the backups root, provisioned with web-server denies and an index
	 * stub so it can never be browsed or its archives downloaded directly.
	 */
	public function dir(): string {
		$storage = BanStore::storage_dir();
		if ( '' === $storage ) {
			return '';
		}
		$dir = $storage . '/backups';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$this->harden( $dir );
		return $dir;
	}

	/**
	 * Drop deny rules so the archives are never web-accessible even if uploads/ is served.
	 */
	private function harden( string $dir ): void {
		$htaccess = $dir . '/.htaccess';
		if ( ! is_file( $htaccess ) ) {
			file_put_contents( $htaccess, "Order deny,allow\nDeny from all\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n", LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		$index = $dir . '/index.php';
		if ( ! is_file( $index ) ) {
			file_put_contents( $index, "<?php\n// Silence is golden.\n", LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		$webconfig = $dir . '/web.config';
		if ( ! is_file( $webconfig ) ) {
			file_put_contents( $webconfig, "<configuration>\n\t<system.webServer>\n\t\t<authorization>\n\t\t\t<deny users=\"*\" />\n\t\t</authorization>\n\t</system.webServer>\n</configuration>\n", LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	/**
	 * Path to one backup's directory (id is sanitised to a safe slug).
	 */
	public function backup_dir( string $id ): string {
		$id   = $this->safe_id( $id );
		$root = $this->dir();
		return ( '' === $root || '' === $id ) ? '' : $root . '/' . $id;
	}

	/**
	 * Allocate a new backup directory and return [id, path].
	 *
	 * @return array{0:string,1:string}
	 */
	public function allocate(): array {
		$id   = gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 8, false, false );
		$path = $this->backup_dir( $id );
		if ( '' !== $path ) {
			wp_mkdir_p( $path );
		}
		return array( $id, $path );
	}

	/**
	 * Write a manifest for a backup.
	 *
	 * @param array<string,mixed> $manifest Manifest data.
	 */
	public function write_manifest( string $id, array $manifest ): void {
		$path = $this->backup_dir( $id );
		if ( '' === $path ) {
			return;
		}
		file_put_contents( $path . '/manifest.json', wp_json_encode( $manifest ), LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/**
	 * Read one backup's manifest.
	 *
	 * @return array<string,mixed>|null
	 */
	public function manifest( string $id ): ?array {
		$path = $this->backup_dir( $id );
		if ( '' === $path || ! is_file( $path . '/manifest.json' ) ) {
			return null;
		}
		$data = json_decode( (string) file_get_contents( $path . '/manifest.json' ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		return is_array( $data ) ? $data : null;
	}

	/**
	 * List all backups newest-first.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function all(): array {
		$root = $this->dir();
		if ( '' === $root || ! is_dir( $root ) ) {
			return array();
		}
		$out = array();
		foreach ( (array) glob( $root . '/*', GLOB_ONLYDIR ) as $dir ) {
			$id       = basename( $dir );
			$manifest = $this->manifest( $id );
			if ( $manifest ) {
				$out[] = $manifest;
			}
		}
		usort( $out, static function ( $a, $b ) {
			return strcmp( (string) ( $b['created'] ?? '' ), (string) ( $a['created'] ?? '' ) );
		} );
		return $out;
	}

	/**
	 * Permanently delete a backup directory.
	 */
	public function delete( string $id ): bool {
		$path = $this->backup_dir( $id );
		if ( '' === $path || ! is_dir( $path ) ) {
			return false;
		}
		\TotalSecurityWP\Support\Filesystem::delete_dir( $path );
		return true;
	}

	/**
	 * Reduce backups to the most recent $keep, deleting older ones.
	 */
	public function prune( int $keep ): int {
		$all     = $this->all();
		$deleted = 0;
		foreach ( array_slice( $all, max( 0, $keep ) ) as $m ) {
			if ( isset( $m['id'] ) && $this->delete( (string) $m['id'] ) ) {
				$deleted++;
			}
		}
		return $deleted;
	}

	/**
	 * Constrain an id to a filesystem-safe slug (defeats path traversal).
	 */
	public function safe_id( string $id ): string {
		return (string) preg_replace( '/[^A-Za-z0-9_-]/', '', $id );
	}
}
