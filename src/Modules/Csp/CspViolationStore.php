<?php
/**
 * CSP violation report store.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Csp;

defined( 'ABSPATH' ) || exit;

/**
 * DB-backed store for browser-reported CSP violations ({@see CspController::receive_report()}).
 *
 * Repeat violations of the same (directive, blocked-uri) pair are grouped into a single row
 * with a `hits` counter and a `last_seen`/`last doc_uri` update, rather than one row per
 * report — a single noisy/repeated resource can otherwise generate unbounded rows. Age-based
 * retention on top of that is pruned daily by {@see \TotalSecurityWP\Core\Cron::prune_logs()}.
 */
class CspViolationStore {

	/** Column max lengths — mirror the schema in Installer::install(). */
	private const MAX_LEN = 500;

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'totalsecwp_csp_violations';
	}

	/**
	 * Record (or bump the hit count of) a violation.
	 */
	public function record( string $directive, string $blocked_uri, string $doc_uri, string $referrer ): void {
		global $wpdb;

		$directive   = substr( $directive, 0, 60 );
		$blocked_uri = substr( $blocked_uri, 0, self::MAX_LEN );
		$doc_uri     = substr( $doc_uri, 0, self::MAX_LEN );
		$referrer    = substr( $referrer, 0, self::MAX_LEN );
		$now         = current_time( 'mysql', true );
		$table       = $this->table();

		$wpdb->query( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"INSERT INTO %i (directive, blocked_uri, doc_uri, referrer, hits, first_seen, last_seen)"
				. ' VALUES (%s, %s, %s, %s, 1, %s, %s)'
				. ' ON DUPLICATE KEY UPDATE hits = hits + 1, doc_uri = VALUES(doc_uri), referrer = VALUES(referrer), last_seen = VALUES(last_seen)', $table,
				$directive,
				$blocked_uri,
				$doc_uri,
				$referrer,
				$now,
				$now
			)
		);
	}

	/**
	 * Query violations with optional filters, newest (last seen) first.
	 *
	 * @param array{ directive?: string, search?: string, page?: int, per_page?: int } $args
	 * @return array{ items: array<int, array<string, mixed>>, total: int, page: int, per_page: int }
	 */
	public function query( array $args ): array {
		global $wpdb;
		$table = $this->table();

		$page     = max( 1, (int) ( $args['page'] ?? 1 ) );
		$per_page = max( 1, min( 200, (int) ( $args['per_page'] ?? 50 ) ) );
		$offset   = ( $page - 1 ) * $per_page;

		// Optional filters are switched off by an empty value, so the statement is a fixed string.
		$directive = (string) ( $args['directive'] ?? '' );
		$search    = (string) ( $args['search'] ?? '' );
		$like      = '' === $search ? '' : '%' . $wpdb->esc_like( $search ) . '%';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live violation log.
		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE ( %s = \'\' OR directive = %s ) AND ( %s = \'\' OR blocked_uri LIKE %s OR doc_uri LIKE %s )',
				$table, $directive, $directive, $like, $like, $like
			)
		);

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE ( %s = \'\' OR directive = %s ) AND ( %s = \'\' OR blocked_uri LIKE %s OR doc_uri LIKE %s ) ORDER BY last_seen DESC LIMIT %d OFFSET %d',
				$table, $directive, $directive, $like, $like, $like, $per_page, $offset
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		return array(
			'items'    => $rows ?: array(),
			'total'    => $total,
			'page'     => $page,
			'per_page' => $per_page,
		);
	}

	/**
	 * Distinct directives currently present, for the panel's filter dropdown.
	 *
	 * @return string[]
	 */
	public function distinct_directives(): array {
		global $wpdb;
		$table = $this->table();
		return array_map( 'strval', (array) $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT directive FROM %i ORDER BY directive ASC", $table ) ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; no other value to bind.
	}

	/**
	 * Fetch a single violation row by id.
	 *
	 * @return array<string, mixed>|null
	 */
	public function get( int $id ): ?array {
		global $wpdb;
		$table = $this->table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM %i WHERE id = %d", $table, $id ), ARRAY_A ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; $id is bound via prepare().
		return $row ?: null;
	}

	/** Delete every stored violation. */
	public function clear(): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "TRUNCATE TABLE %i", $this->table() ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Count violations (by row, not by hit count) last seen at or after a given timestamp —
	 * used to surface "N violations since Report-Only started" on the CSP panel.
	 */
	public function count_since( int $timestamp ): int {
		global $wpdb;
		$table = $this->table();
		$since = gmdate( 'Y-m-d H:i:s', $timestamp );
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE last_seen >= %s", $table, $since ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; $since is bound via prepare().
	}

	/**
	 * Delete rows not seen within the last N days. Called from the daily prune cron.
	 *
	 * @return int Number of rows deleted.
	 */
	public function prune_older_than( int $days ): int {
		if ( $days <= 0 ) {
			return 0;
		}
		global $wpdb;
		$table  = $this->table();
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM %i WHERE last_seen < %s", $table, $cutoff ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; $cutoff is bound via prepare().
	}
}
