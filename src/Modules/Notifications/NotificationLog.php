<?php
/**
 * Sent-notification history store.
 *
 * Records every alert Loyal Security actually dispatches (or attempts) so the notification
 * centre can show a delivery history: which event, on which channel, to whom, and whether it
 * succeeded. Backed by a dedicated table (`{$prefix}loyalsec_notifications`) created in
 * {@see \LoyalSecurity\Core\Installer}.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Notifications;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;

/**
 * Read/write layer for the notification-history table.
 */
class NotificationLog {

	public const STATUS_SENT    = 'sent';
	public const STATUS_FAILED  = 'failed';
	public const STATUS_SKIPPED = 'skipped';

	/**
	 * Fully-qualified table name.
	 */
	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_notifications';
	}

	/**
	 * Record a dispatch attempt.
	 *
	 * @param array{event_id?:int,event_type:string,severity?:int,channel:string,recipient?:string,subject?:string,summary?:string,status?:string} $row Row data.
	 * @return int Inserted id (0 on failure).
	 */
	public function record( array $row ): int {
		global $wpdb;

		$data = array(
			'event_id'   => (int) ( $row['event_id'] ?? 0 ),
			'event_type' => mb_substr( (string) ( $row['event_type'] ?? '' ), 0, 64 ),
			'severity'   => (int) ( $row['severity'] ?? EventCatalog::SEV_INFO ),
			'channel'    => mb_substr( (string) ( $row['channel'] ?? '' ), 0, 20 ),
			'recipient'  => mb_substr( (string) ( $row['recipient'] ?? '' ), 0, 191 ),
			'subject'    => mb_substr( (string) ( $row['subject'] ?? '' ), 0, 255 ),
			'summary'    => mb_substr( (string) ( $row['summary'] ?? '' ), 0, 1000 ),
			'status'     => mb_substr( (string) ( $row['status'] ?? self::STATUS_SENT ), 0, 20 ),
			'created_at' => gmdate( 'Y-m-d H:i:s' ),
		);

		$ok = $wpdb->insert( self::table(), $data ); // phpcs:ignore WordPress.DB

		return $ok ? (int) $wpdb->insert_id : 0;
	}

	/**
	 * Filtered, paginated history query.
	 *
	 * @param array<string, mixed> $filters channel|type|status|page|per_page.
	 * @return array{items:array<int,array<string,mixed>>,total:int,page:int,per_page:int}
	 */
	public function query( array $filters = array() ): array {
		global $wpdb;

		// Optional filters are switched off by an empty value, so the statement is a fixed string.
		$channel = (string) ( $filters['channel'] ?? '' );
		$type    = (string) ( $filters['type'] ?? '' );
		$status  = (string) ( $filters['status'] ?? '' );

		$per_page = max( 1, min( 100, (int) ( $filters['per_page'] ?? 25 ) ) );
		$page     = max( 1, (int) ( $filters['page'] ?? 1 ) );
		$offset   = ( $page - 1 ) * $per_page;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live notification history.
		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE ( %s = \'\' OR channel = %s ) AND ( %s = \'\' OR event_type = %s ) AND ( %s = \'\' OR status = %s )',
				$this->tbl(), $channel, $channel, $type, $type, $status, $status
			)
		);

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE ( %s = \'\' OR channel = %s ) AND ( %s = \'\' OR event_type = %s ) AND ( %s = \'\' OR status = %s ) ORDER BY id DESC LIMIT %d OFFSET %d',
				$this->tbl(), $channel, $channel, $type, $type, $status, $status, $per_page, $offset
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		// Loop over the variable itself: a by-reference foreach over a cast expression would only
		// change a temporary copy.
		$rows = is_array( $rows ) ? $rows : array();
		foreach ( $rows as &$r ) {
			$r['id']             = (int) $r['id'];
			$r['event_id']       = (int) $r['event_id'];
			$r['severity']       = (int) $r['severity'];
			$r['severity_label'] = EventCatalog::severity_label( (int) $r['severity'] );
		}
		unset( $r );

		return array(
			'items'    => $rows,
			'total'    => $total,
			'page'     => $page,
			'per_page' => $per_page,
		);
	}

	/**
	 * Total rows in the history table.
	 */
	public function count(): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i", $this->tbl() ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; no other value to bind, so there's nothing for prepare() to parameterize.
	}

	/**
	 * Delete all history rows. Returns the number of rows removed.
	 */
	public function clear(): int {
		global $wpdb;
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM %i", $this->tbl() ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->prefix, not user input; no other value to bind, so there's nothing for prepare() to parameterize.
	}

	/**
	 * Delete history older than $days days.
	 */
	public function prune( int $days ): void {
		global $wpdb;
		$days = max( 1, $days );
		$wpdb->query( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"DELETE FROM %i WHERE created_at < %s", $this->tbl(),
				gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS )
			)
		);
	}

	/**
	 * Local shorthand for the (escaped, prefix-only) table name in queries.
	 */
	private function tbl(): string {
		return self::table();
	}
}
