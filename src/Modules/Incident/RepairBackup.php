<?php
/**
 * Backup store for repair operations.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Support\Filesystem;

/**
 * Every destructive repair (a plugin reinstall, a single-file fix) snapshots the original
 * bytes here first, so any change is fully reversible. Backups live in a private,
 * non-web-served directory and are indexed in a small option-backed manifest. A separate
 * "pending" list records fixes that have not yet been health-checked, which {@see RepairGuard}
 * uses to auto-restore after a fatal error.
 */
class RepairBackup {

	private const MANIFEST = 'totalsecwp_repair_backups';
	private const PENDING  = 'totalsecwp_pending_repairs';

	/**
	 * Hard ceiling on retained backups (a safety net beyond the per-target policy). These are
	 * the safety snapshots taken automatically before a plugin reinstall or file fix; their job
	 * is only to make the *last* operation reversible, so a small cap is plenty.
	 */
	private const MAX = 20;

	private function dir(): string {
		$storage = BanStore::storage_dir();
		if ( '' === $storage ) {
			return '';
		}
		$dir = $storage . '/repair-backups';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		return $dir;
	}

	/**
	 * Snapshot a single file. Returns the backup id, or '' on failure.
	 */
	public function backup_file( string $path, string $label = '' ): string {
		$path = wp_normalize_path( $path );
		if ( ! is_file( $path ) ) {
			return '';
		}
		$dir = $this->dir();
		if ( '' === $dir ) {
			return '';
		}

		$id    = $this->new_id();
		$store = trailingslashit( $dir ) . $id . '.bak';

		$contents = Filesystem::read( $path );
		if ( null === $contents || ! Filesystem::write( $store, $contents ) ) {
			return '';
		}
		Filesystem::chmod( $store, 0600 );

		$this->record( $id, 'file', $path, $store, $label ?: basename( $path ), strlen( $contents ) );
		return $id;
	}

	/**
	 * Snapshot a whole directory tree (e.g. a plugin folder). Returns the backup id or ''.
	 */
	public function backup_tree( string $source, string $label ): string {
		$source = wp_normalize_path( untrailingslashit( $source ) );
		if ( ! is_dir( $source ) ) {
			return '';
		}
		$dir = $this->dir();
		if ( '' === $dir ) {
			return '';
		}

		$id      = $this->new_id();
		$store   = trailingslashit( $dir ) . $id;
		$payload = $store . '/payload';
		if ( ! wp_mkdir_p( $payload ) ) {
			return '';
		}

		if ( ! $this->copy_tree( $source, $payload ) ) {
			return '';
		}

		$this->record( $id, 'tree', $source, $payload, $label, $this->dir_size( $payload ) );
		return $id;
	}

	/**
	 * Back up a directory tree by *moving* it aside instead of copying it. On the same
	 * filesystem (the storage dir and the plugins dir normally share a volume) this is an
	 * instant rename rather than a multi-minute recursive PHP copy — which is what made large
	 * plugin reinstalls (e.g. WooCommerce) appear to hang. After this returns successfully the
	 * source path no longer exists; the caller is expected to write fresh files in its place.
	 * Returns the backup id, or '' if the move was not possible (caller should fall back to
	 * {@see self::backup_tree()}).
	 */
	public function backup_tree_move( string $source, string $label ): string {
		$source = wp_normalize_path( untrailingslashit( $source ) );
		if ( ! is_dir( $source ) ) {
			return '';
		}
		$dir = $this->dir();
		if ( '' === $dir ) {
			return '';
		}

		$id      = $this->new_id();
		$store   = trailingslashit( $dir ) . $id;
		$payload = $store . '/payload';
		if ( ! wp_mkdir_p( $store ) ) {
			return '';
		}

		// Measure before moving (source still exists), then attempt the atomic rename.
		$bytes = $this->dir_size( $source );
		if ( ! Filesystem::move( $source, $payload ) ) {
			Filesystem::delete_dir( $store, false ); // tidy the empty container
			return '';
		}

		$this->record( $id, 'tree', $source, $payload, $label, $bytes );
		return $id;
	}

	/**
	 * Restore a backup over its original location.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public function restore( string $id ): array {
		$row = $this->find( $id );
		if ( ! $row ) {
			return array( 'ok' => false, 'message' => __( 'Backup not found.', 'loyal-security' ) );
		}

		if ( 'file' === $row['type'] ) {
			$contents = Filesystem::read( $row['backup'] );
			if ( null === $contents || ! Filesystem::write( $row['target'], $contents ) ) {
				return array( 'ok' => false, 'message' => __( 'Could not restore the file.', 'loyal-security' ) );
			}
			return array( 'ok' => true, 'message' => __( 'File restored from backup.', 'loyal-security' ) );
		}

		// Tree restore: wipe the live directory and copy the snapshot back.
		if ( is_dir( $row['target'] ) ) {
			$this->delete_tree_contents( $row['target'] );
		} else {
			wp_mkdir_p( $row['target'] );
		}
		if ( ! $this->copy_tree( $row['backup'], $row['target'] ) ) {
			return array( 'ok' => false, 'message' => __( 'Could not restore the directory.', 'loyal-security' ) );
		}
		return array( 'ok' => true, 'message' => __( 'Directory restored from backup.', 'loyal-security' ) );
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public function list(): array {
		$rows = get_option( self::MANIFEST, array() );
		return is_array( $rows ) ? array_values( $rows ) : array();
	}

	/**
	 * Aggregate stats for the dashboard and the storage-size reminder.
	 *
	 * @return array{count:int,bytes:int,size_human:string}
	 */
	public function summary(): array {
		$rows  = $this->list();
		$bytes = 0;
		foreach ( $rows as $row ) {
			$bytes += (int) ( $row['bytes'] ?? 0 );
		}
		return array(
			'count'      => count( $rows ),
			'bytes'      => $bytes,
			'size_human' => size_format( $bytes, 1 ) ?: '0 B',
		);
	}

	/**
	 * Delete a single backup: remove its on-disk file/tree and drop it from the manifest.
	 */
	public function delete( string $id ): bool {
		$rows = $this->list();
		$kept = array();
		$hit  = false;
		foreach ( $rows as $row ) {
			if ( isset( $row['id'] ) && $row['id'] === $id ) {
				$this->delete_storage( $row );
				$hit = true;
				continue;
			}
			$kept[] = $row;
		}
		if ( $hit ) {
			$this->store_manifest( $kept );
		}
		return $hit;
	}

	/**
	 * Remove every repair backup (disk + manifest). Optional progress callback receives
	 * ( int $done, int $total, string $message ) so a background job can stream a plain-language
	 * activity feed to the dashboard.
	 *
	 * @param callable|null $progress fn(int $done, int $total, string $message): void
	 * @return array{deleted:int,freed:int,freed_human:string}
	 */
	public function clear_all( ?callable $progress = null ): array {
		$rows  = $this->list();
		$total = count( $rows );
		$freed = 0;
		$done  = 0;

		foreach ( $rows as $row ) {
			$freed += $this->delete_storage( $row );
			$done++;
			if ( $progress ) {
				$progress(
					$done,
					$total,
					sprintf(
						/* translators: 1: current item, 2: total items, 3: backup label */
						__( 'Deleting backup %1$d of %2$d: %3$s', 'loyal-security' ),
						$done,
						$total,
						(string) ( $row['label'] ?? $row['id'] ?? '' )
					)
				);
			}
		}

		delete_option( self::MANIFEST );
		return array(
			'deleted'     => $done,
			'freed'       => $freed,
			'freed_human' => size_format( $freed, 1 ) ?: '0 B',
		);
	}

	/* ------------------------------------------------------------------ *
	 * Pending repairs (used by the fatal-error guard).
	 * ------------------------------------------------------------------ */

	/**
	 * Flag a file as having a fix in flight, watched until $grace seconds from now. The
	 * {@see RepairGuard} auto-restores the backup if a fatal in this file fires before the
	 * grace window lapses, then prunes the entry once the fix has proven stable.
	 */
	public function mark_pending( string $path, string $backup_id, int $grace = 300 ): void {
		$pending = $this->pending();
		$pending[ wp_normalize_path( $path ) ] = array(
			'backup' => $backup_id,
			'until'  => time() + max( 30, $grace ),
		);
		$this->save_pending( $pending );
	}

	/**
	 * Clear a file's pending flag (e.g. after an explicit rollback).
	 */
	public function clear_pending( string $path ): void {
		$pending = $this->pending();
		unset( $pending[ wp_normalize_path( $path ) ] );
		$this->save_pending( $pending );
	}

	/**
	 * @return array<string,array{backup:string,until:int}> path => entry.
	 */
	public function pending(): array {
		$rows = get_option( self::PENDING, array() );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Persist the pending list (also used by the guard to prune lapsed entries). Mirrors the
	 * "is anything in-flight?" state into a flag *file* so the early watchdog in the main plugin
	 * bootstrap can decide whether to arm without a database query on every request.
	 *
	 * @param array<string,array{backup:string,until:int}> $pending Pending entries.
	 */
	public function save_pending( array $pending ): void {
		if ( empty( $pending ) ) {
			delete_option( self::PENDING );
			$this->set_pending_flag( false );
			return;
		}
		update_option( self::PENDING, $pending, false );
		$this->set_pending_flag( true );
	}

	/**
	 * Absolute path to the in-flight flag file (empty if storage is unavailable).
	 */
	public static function pending_flag_path(): string {
		$storage = BanStore::storage_dir();
		return '' === $storage ? '' : $storage . '/repair-pending.flag';
	}

	/**
	 * Cheap, DB-free check used by the early bootstrap watchdog.
	 */
	public static function pending_flag_exists(): bool {
		$path = self::pending_flag_path();
		return '' !== $path && is_file( $path );
	}

	private function set_pending_flag( bool $on ): void {
		$path = self::pending_flag_path();
		if ( '' === $path ) {
			return;
		}
		if ( $on ) {
			if ( ! is_file( $path ) ) {
				@file_put_contents( $path, (string) time() ); // phpcs:ignore WordPress
			}
			return;
		}
		if ( is_file( $path ) ) {
			Filesystem::delete( $path );
		}
	}

	/* ------------------------------------------------------------------ *
	 * Internals.
	 * ------------------------------------------------------------------ */

	private function new_id(): string {
		return gmdate( 'YmdHis' ) . '_' . wp_generate_password( 10, false, false );
	}

	private function record( string $id, string $type, string $target, string $backup, string $label, int $bytes = 0 ): void {
		$rows  = $this->list();
		$entry = array(
			'id'      => $id,
			'type'    => $type,
			'target'  => $target,
			'backup'  => $backup,
			'label'   => mb_substr( $label, 0, 191 ),
			'bytes'   => $bytes,
			'created' => gmdate( 'Y-m-d H:i:s' ),
		);

		// Retention policy: these are pre-operation safety snapshots, so only the most recent
		// backup of any given target needs to survive. Delete older snapshots of the SAME target
		// (and their bytes on disk) — this is what stops a folder like WooCommerce piling up a
		// fresh few-hundred-MB copy on every reinstall.
		$norm = wp_normalize_path( $target );
		$kept = array();
		foreach ( $rows as $row ) {
			if ( wp_normalize_path( (string) ( $row['target'] ?? '' ) ) === $norm ) {
				$this->delete_storage( $row );
				continue;
			}
			$kept[] = $row;
		}
		array_unshift( $kept, $entry );

		// Global safety cap: delete the on-disk payload of anything pruned beyond the ceiling
		// (the old code left these files on disk forever — the root cause of the pile-up).
		if ( count( $kept ) > self::MAX ) {
			foreach ( array_slice( $kept, self::MAX ) as $stale ) {
				$this->delete_storage( $stale );
			}
			$kept = array_slice( $kept, 0, self::MAX );
		}

		$this->store_manifest( $kept );

		/**
		 * Fires after a repair backup is recorded. Lets the incident module check whether the
		 * accumulated backup storage has crossed the admin-reminder threshold.
		 *
		 * @since 1.1.1
		 *
		 * @param array<string,mixed> $entry The new manifest entry.
		 */
		do_action( 'totalsecwp_repair_backup_recorded', $entry );
	}

	/**
	 * @param array<int,array<string,mixed>> $rows Manifest rows.
	 */
	private function store_manifest( array $rows ): void {
		if ( empty( $rows ) ) {
			delete_option( self::MANIFEST );
			return;
		}
		update_option( self::MANIFEST, array_values( $rows ), false );
	}

	/**
	 * Delete the on-disk payload behind a manifest row and return the bytes reclaimed.
	 *
	 * @param array<string,mixed> $row Manifest row.
	 */
	private function delete_storage( array $row ): int {
		$bytes  = (int) ( $row['bytes'] ?? 0 );
		$backup = (string) ( $row['backup'] ?? '' );
		if ( '' === $backup ) {
			return 0;
		}

		if ( 'tree' === ( $row['type'] ?? '' ) ) {
			// The backup path is "<dir>/<id>/payload"; remove the whole "<id>" container.
			$container = dirname( $backup );
			if ( is_dir( $container ) ) {
				Filesystem::delete_dir( $container, false );
			}
			return $bytes;
		}

		if ( is_file( $backup ) ) {
			if ( ! $bytes ) {
				$bytes = (int) filesize( $backup );
			}
			Filesystem::delete( $backup );
		}
		return $bytes;
	}

	/**
	 * Total size of a directory tree in bytes (best-effort; never throws).
	 */
	private function dir_size( string $dir ): int {
		if ( ! is_dir( $dir ) ) {
			return 0;
		}
		$bytes = 0;
		try {
			$it = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS )
			);
			foreach ( $it as $file ) {
				if ( $file->isFile() ) {
					$bytes += (int) $file->getSize();
				}
			}
		} catch ( \Throwable $e ) {
			return $bytes;
		}
		return $bytes;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	private function find( string $id ): ?array {
		foreach ( $this->list() as $row ) {
			if ( isset( $row['id'] ) && $row['id'] === $id ) {
				return $row;
			}
		}
		return null;
	}

	private function copy_tree( string $from, string $to ): bool {
		return Filesystem::copy_dir( $from, $to );
	}

	private function delete_tree_contents( string $dir ): void {
		Filesystem::delete_dir( $dir, true );
	}
}
