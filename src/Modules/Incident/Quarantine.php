<?php
/**
 * Safe file quarantine.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Support\Filesystem;

/**
 * Isolates suspicious files instead of deleting them: each file is moved into a private,
 * non-executable storage directory, its permissions are stripped, and a manifest row keeps
 * the mapping so the action is fully reversible.
 */
class Quarantine {

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'totalsecwp_quarantine';
	}

	private function dir(): string {
		$dir = BanStore::storage_dir() . '/quarantine';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		return $dir;
	}

	/**
	 * Quarantine a file.
	 *
	 * @param string   $path       Absolute path to the suspicious file.
	 * @param string   $reason     Reason.
	 * @param int|null $finding_id Related scan finding id.
	 * @return array{ok:bool,id?:int,message?:string}
	 */
	public function add( string $path, string $reason = '', ?int $finding_id = null ): array {
		$path = wp_normalize_path( $path );

		if ( ! is_file( $path ) ) {
			return array( 'ok' => false, 'message' => __( 'File not found.', 'loyal-security' ) );
		}
		// Refuse to quarantine our own files or obvious core bootstrap to avoid self-harm.
		if ( false !== strpos( $path, wp_normalize_path( TOTALSECWP_PATH ) ) ) {
			return array( 'ok' => false, 'message' => __( 'Refusing to quarantine plugin files.', 'loyal-security' ) );
		}

		$hash  = Filesystem::sha256( $path );
		$size  = (int) filesize( $path );
		$store = trailingslashit( $this->dir() ) . gmdate( 'YmdHis' ) . '_' . wp_generate_password( 8, false, false ) . '.quarantine';

		if ( ! Filesystem::move( $path, $store ) ) {
			return array( 'ok' => false, 'message' => __( 'Could not move the file (check permissions).', 'loyal-security' ) );
		}
		// Strip executable/readable bits.
		Filesystem::chmod( $store, 0400 );

		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'original_path' => $path,
				'stored_path'   => $store,
				'hash'          => $hash,
				'size'          => $size,
				'reason'        => mb_substr( $reason, 0, 191 ),
				'finding_id'    => $finding_id,
				'status'        => 'quarantined',
				'created_at'    => gmdate( 'Y-m-d H:i:s' ),
			)
		);

		return array( 'ok' => true, 'id' => (int) $wpdb->insert_id );
	}

	/**
	 * Restore a quarantined file to its original location.
	 */
	public function restore( int $id ): array {
		$row = $this->get( $id );
		if ( ! $row || 'quarantined' !== $row['status'] ) {
			return array( 'ok' => false, 'message' => __( 'Quarantine entry not found.', 'loyal-security' ) );
		}
		if ( ! Filesystem::move( $row['stored_path'], $row['original_path'] ) ) {
			return array( 'ok' => false, 'message' => __( 'Could not restore the file.', 'loyal-security' ) );
		}
		Filesystem::chmod( $row['original_path'], 0644 );

		global $wpdb;
		$wpdb->update( $this->table(), array( 'status' => 'restored' ), array( 'id' => $id ) ); // phpcs:ignore WordPress.DB

		// The file is back on disk and live again — its linked finding must reflect that.
		// Leaving it 'quarantined' showed a neutralized threat in the dashboard while the
		// (still unreviewed) file was actually executing again.
		$this->set_finding_status( $row, 'open' );
		return array( 'ok' => true );
	}

	/**
	 * Permanently delete a quarantined file.
	 */
	public function delete( int $id ): array {
		$row = $this->get( $id );
		if ( ! $row ) {
			return array( 'ok' => false, 'message' => __( 'Quarantine entry not found.', 'loyal-security' ) );
		}
		if ( is_file( $row['stored_path'] ) ) {
			Filesystem::delete( $row['stored_path'] );
		}
		global $wpdb;
		$wpdb->update( $this->table(), array( 'status' => 'deleted' ), array( 'id' => $id ) ); // phpcs:ignore WordPress.DB

		// The threat is permanently gone — close out the linked finding too.
		$this->set_finding_status( $row, 'resolved' );
		return array( 'ok' => true );
	}

	/**
	 * Permanently delete every currently-quarantined file (disk + manifest status). Returns the
	 * number cleared.
	 *
	 * @return array{ok:bool,deleted:int}
	 */
	public function clear(): array {
		global $wpdb;
		$deleted = 0;
		// list() is capped at 200 rows per call — page until the backlog is drained, or with
		// >200 quarantined files "Clear all" reported success while leaving the rest on disk.
		// Progress is guaranteed: every processed row leaves the 'quarantined' status even if
		// its stored file was already missing. The iteration cap is pure insurance against a
		// persistently failing status UPDATE re-serving the same page forever.
		$guard = 500;
		do {
			$rows = $this->list( 'quarantined' );
			foreach ( $rows as $row ) {
				$stored = (string) ( $row['stored_path'] ?? '' );
				if ( '' !== $stored && is_file( $stored ) ) {
					Filesystem::delete( $stored );
				}
				$wpdb->update( $this->table(), array( 'status' => 'deleted' ), array( 'id' => (int) $row['id'] ) ); // phpcs:ignore WordPress.DB
				$this->set_finding_status( $row, 'resolved' );
				$deleted++;
			}
		} while ( count( $rows ) > 0 && --$guard > 0 );
		return array( 'ok' => true, 'deleted' => $deleted );
	}

	/**
	 * Sync the scan finding linked to a quarantine row (if any) to a new status, so the
	 * findings list always reflects reality after a restore ('open' — the file is live again)
	 * or a permanent delete ('resolved').
	 *
	 * @param array<string, mixed> $row Quarantine manifest row.
	 */
	private function set_finding_status( array $row, string $status ): void {
		$finding_id = (int) ( $row['finding_id'] ?? 0 );
		if ( $finding_id <= 0 ) {
			return;
		}
		global $wpdb;
		$wpdb->update( // phpcs:ignore WordPress.DB
			$wpdb->prefix . 'totalsecwp_scan_findings',
			array( 'status' => $status ),
			array( 'id' => $finding_id )
		);
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public function get( int $id ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT * FROM %i WHERE id = %d", $this->table(), $id ),
			ARRAY_A
		);
		return $row ?: null;
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function list( string $status = 'quarantined' ): array {
		global $wpdb;
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT * FROM %i WHERE status = %s ORDER BY id DESC LIMIT 200", $this->table(), $status ),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : array();
	}
}
