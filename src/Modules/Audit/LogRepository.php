<?php
/**
 * Query/export/prune layer for the audit event table.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Audit;

defined( 'ABSPATH' ) || exit;

/**
 * Read-side repository for the audit log: filtered pagination, CSV export, and pruning.
 */
class LogRepository {

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_events';
	}

	/**
	 * Filtered, paginated query.
	 *
	 * @param array<string, mixed> $filters search|type|min_severity|ip|page|per_page.
	 * @return array{items:array<int,array<string,mixed>>,total:int,page:int,per_page:int}
	 */
	public function query( array $filters ): array {
		global $wpdb;

		// Every filter is always present in the SQL and switched off by an empty value, so the
		// statement itself is a fixed string and every value is bound by prepare(). A
		// comma-separated type list (deep links group several event types under one bucket)
		// matches as a comma-delimited list lookup (INSTR on ",list," for ",value,", which unlike
		// FIND_IN_SET also runs on SQLite); a single type is the one-item case of the same thing.
		$types = array_filter( array_map( 'sanitize_text_field', array_map( 'trim', explode( ',', (string) ( $filters['type'] ?? '' ) ) ) ) );
		$types = implode( ',', str_replace( ',', '', $types ) );

		$min_severity = max( 0, (int) ( $filters['min_severity'] ?? 0 ) );
		$ip           = (string) ( $filters['ip'] ?? '' );

		$cc            = strtoupper( (string) ( $filters['country'] ?? '' ) );
		$country_like  = '' === $cc ? '' : '%"country":"' . $wpdb->esc_like( $cc ) . '"%';
		$country_like2 = '' === $cc ? '' : '%"country_code":"' . $wpdb->esc_like( $cc ) . '"%';

		$search = (string) ( $filters['search'] ?? '' );
		$like   = '' === $search ? '' : '%' . $wpdb->esc_like( $search ) . '%';

		$since_days = max( 0, (int) ( $filters['since_days'] ?? 0 ) );
		$since      = $since_days > 0 ? gmdate( 'Y-m-d H:i:s', time() - $since_days * DAY_IN_SECONDS ) : '1970-01-01 00:00:00';

		// Dashboard pages are capped at 200 rows; a CSV export may take up to 5000 in one go.
		$per_page = max( 1, min( empty( $filters['export'] ) ? 200 : 5000, (int) ( $filters['per_page'] ?? 50 ) ) );
		$page     = max( 1, (int) ( $filters['page'] ?? 1 ) );
		$offset   = ( $page - 1 ) * $per_page;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live audit-log reads; caching would show stale security events.
		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE ( %s = \'\' OR INSTR( CONCAT( \',\', %s, \',\' ), CONCAT( \',\', event_type, \',\' ) ) > 0 ) AND ( %d = 0 OR severity >= %d ) AND ( %s = \'\' OR ip = %s ) AND ( %s = \'\' OR context LIKE %s OR context LIKE %s ) AND ( %s = \'\' OR event_type LIKE %s OR request_uri LIKE %s OR user_agent LIKE %s OR context LIKE %s ) AND created_at >= %s',
				$this->table(),
				$types,
				$types,
				$min_severity,
				$min_severity,
				$ip,
				$ip,
				$country_like,
				$country_like,
				$country_like2,
				$like,
				$like,
				$like,
				$like,
				$like,
				$since
			)
		);

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE ( %s = \'\' OR INSTR( CONCAT( \',\', %s, \',\' ), CONCAT( \',\', event_type, \',\' ) ) > 0 ) AND ( %d = 0 OR severity >= %d ) AND ( %s = \'\' OR ip = %s ) AND ( %s = \'\' OR context LIKE %s OR context LIKE %s ) AND ( %s = \'\' OR event_type LIKE %s OR request_uri LIKE %s OR user_agent LIKE %s OR context LIKE %s ) AND created_at >= %s ORDER BY id DESC LIMIT %d OFFSET %d',
				$this->table(),
				$types,
				$types,
				$min_severity,
				$min_severity,
				$ip,
				$ip,
				$country_like,
				$country_like,
				$country_like2,
				$like,
				$like,
				$like,
				$like,
				$like,
				$since,
				$per_page,
				$offset
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		// Decode context for the client. Loop over the variable itself: a by-reference foreach
		// over a cast expression would only change a temporary copy.
		$rows = is_array( $rows ) ? $rows : array();
		foreach ( $rows as &$row ) {
			$row['context']       = isset( $row['context'] ) ? json_decode( (string) $row['context'], true ) : null;
			$row['proxy_headers'] = isset( $row['proxy_headers'] ) ? json_decode( (string) $row['proxy_headers'], true ) : null;
			$row['severity']      = (int) $row['severity'];
			$row['severity_label'] = EventCatalog::severity_label( $row['severity'] );
			$ctx             = is_array( $row['context'] ) ? $row['context'] : array();
			$row['country']  = isset( $ctx['country'] ) ? (string) $ctx['country'] : ( isset( $ctx['country_code'] ) ? (string) $ctx['country_code'] : null );
		}
		unset( $row );

		return array(
			'items'    => $rows,
			'total'    => $total,
			'page'     => $page,
			'per_page' => $per_page,
		);
	}

	/**
	 * Export matching rows as a CSV string.
	 *
	 * @param array<string, mixed> $filters Same filters as query() (pagination ignored).
	 */
	public function export_csv( array $filters ): string {
		$filters['per_page'] = 5000;
		$filters['page']     = 1;
		$filters['export']   = true;
		$result              = $this->query( $filters );

		$out = fopen( 'php://temp', 'r+' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- in-memory stream (php://temp, not a real file), required by fputcsv() for correct CSV quoting; WP_Filesystem has no CSV-writer equivalent.
		fputcsv( $out, array( 'id', 'time', 'type', 'severity', 'user_id', 'ip', 'country', 'method', 'uri', 'user_agent', 'context' ) );
		foreach ( $result['items'] as $row ) {
			fputcsv(
				$out,
				array(
					$row['id'],
					$row['created_at'],
					$row['event_type'],
					$row['severity_label'],
					$row['user_id'],
					$row['ip'],
					$row['country'],
					$row['method'],
					$row['request_uri'],
					$row['user_agent'],
					wp_json_encode( $row['context'] ),
				)
			);
		}
		rewind( $out );
		$csv = (string) stream_get_contents( $out );
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- matching close for the in-memory php://temp stream opened above.
		return $csv;
	}

	/**
	 * Prune events older than the audit module's configured `log_retention_days`.
	 */
	public function prune_to_limit(): void {
		global $wpdb;

		$module    = \LoyalSecurity\Plugin::instance()->module( 'audit' );
		$configured = $module instanceof AuditModule
			? (int) $module->setting_public( 'log_retention_days', 90 )
			: 90;

		$days = max( 1, $configured );

		$wpdb->query( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"DELETE FROM %i WHERE created_at < %s", $this->table(),
				gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS )
			)
		);
	}

	/**
	 * Distinct event types present (for filter dropdowns).
	 *
	 * @return string[]
	 */
	public function types(): array {
		global $wpdb;
		$rows = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT event_type FROM %i ORDER BY event_type ASC", $this->table() ) ); // phpcs:ignore WordPress.DB
		return is_array( $rows ) ? $rows : array();
	}
}
