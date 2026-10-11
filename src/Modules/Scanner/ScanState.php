<?php
/**
 * Scan progress/state persistence.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Reads/writes the resumable progress of a scan in the scan_state table.
 */
class ScanState {

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_scan_state';
	}

	public function create( string $scan_id, string $type, int $total ): void {
		global $wpdb;
		$wpdb->replace( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'scan_id'       => $scan_id,
				'type'          => $type,
				'status'        => 'running',
				'total_files'   => $total,
				'scanned_files' => 0,
				'findings'      => 0,
				'started_at'    => gmdate( 'Y-m-d H:i:s' ),
				'updated_at'    => gmdate( 'Y-m-d H:i:s' ),
			)
		);
	}

	public function progress( string $scan_id, int $scanned, int $findings ): void {
		global $wpdb;
		$wpdb->update( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'scanned_files' => $scanned,
				'findings'      => $findings,
				'updated_at'    => gmdate( 'Y-m-d H:i:s' ),
			),
			array( 'scan_id' => $scan_id )
		);
	}

	public function finish( string $scan_id, string $status = 'completed' ): void {
		global $wpdb;
		$wpdb->update( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'status'      => $status,
				'finished_at' => gmdate( 'Y-m-d H:i:s' ),
				'updated_at'  => gmdate( 'Y-m-d H:i:s' ),
			),
			array( 'scan_id' => $scan_id )
		);

		if ( 'completed' === $status ) {
			$this->record_history( $scan_id );
		}
	}

	/**
	 * Append a compact summary of a completed scan to the rolling history option.
	 *
	 * Stored in the autoloaded `loyalsec_scan_history` option as a list of up to 10 entries
	 * (oldest dropped first), so the dashboard can show recent scans without trawling the
	 * audit log. Findings are bucketed by severity.
	 */
	private function record_history( string $scan_id ): void {
		$row = $this->get( $scan_id );
		if ( ! $row ) {
			return;
		}

		global $wpdb;
		$findings_table = $wpdb->prefix . 'loyalsec_scan_findings';
		$buckets        = array( 'critical' => 0, 'warning' => 0, 'notice' => 0 );
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT severity, COUNT(*) AS n FROM %i WHERE scan_id = %s GROUP BY severity", $findings_table,
				$scan_id
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $r ) {
			$sev = (int) ( $r['severity'] ?? 0 );
			$n   = (int) ( $r['n'] ?? 0 );
			if ( $sev >= 40 ) {
				$buckets['critical'] += $n;
			} elseif ( $sev >= 30 ) {
				$buckets['warning'] += $n;
			} else {
				$buckets['notice'] += $n;
			}
		}

		$entry = array(
			'scan_id'       => $scan_id,
			'started_at'    => (string) ( $row['started_at'] ?? '' ),
			'completed_at'  => (string) ( $row['finished_at'] ?? gmdate( 'Y-m-d H:i:s' ) ),
			'files_scanned' => (int) ( $row['scanned_files'] ?? 0 ),
			'findings'      => $buckets,
		);

		$history = get_option( 'loyalsec_scan_history', array() );
		if ( ! is_array( $history ) ) {
			$history = array();
		}
		// Newest first; keep only the most recent 10.
		array_unshift( $history, $entry );
		$history = array_slice( $history, 0, 10 );

		update_option( 'loyalsec_scan_history', $history, true );
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public function get( string $scan_id ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT * FROM %i WHERE scan_id = %s", $this->table(), $scan_id ),
			ARRAY_A
		);
		return $row ?: null;
	}

	/**
	 * Latest scan (any status).
	 *
	 * @return array<string, mixed>|null
	 */
	public function latest(): ?array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM %i ORDER BY started_at DESC LIMIT 1", $this->table() ), ARRAY_A ); // phpcs:ignore WordPress.DB
		return $row ?: null;
	}
}
