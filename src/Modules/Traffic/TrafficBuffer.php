<?php
/**
 * Circular flat-file traffic buffer — no database, no bloat.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Traffic;

defined( 'ABSPATH' ) || exit;

/**
 * Stores the last N HTTP requests in a JSON-Lines file under private storage.
 *
 * Design:
 * – Append-only writes (one JSON line per request) — fast, no full-file rewrite on each hit.
 * – Compaction happens automatically when the file exceeds MAX_FILE_BYTES; it trims to the
 *   cap, so the buffer never grows unboundedly.
 * – Reads are full-file (`file_get_contents`) because the cap keeps the file small (≤ ~2 MB).
 * – flock(LOCK_EX | LOCK_NB) on writes; if another request holds the lock the entry is simply
 *   skipped — fail-open, no site impact. Filesystems without locking still get every entry.
 */
class TrafficBuffer {

	private const DEFAULT_CAP    = 500;
	private const MAX_FILE_BYTES = 2 * 1024 * 1024; // compact when file hits 2 MB.

	private string $file;
	private int $cap;

	public function __construct( int $cap = self::DEFAULT_CAP ) {
		$this->cap  = max( 100, min( 2000, $cap ) );
		$this->file = self::buffer_path();
	}

	/* ------------------------------------------------------------------ */
	/* Public API                                                           */
	/* ------------------------------------------------------------------ */

	/** Push one entry onto the buffer (append + optional compact). */
	public function push( array $entry ): void {
		if ( '' === $this->file ) {
			return; // Uploads directory unavailable.
		}
		self::ensure_dir();

		if ( ! isset( $entry['id'] ) ) {
			$entry['id'] = uniqid( 'tx', true );
		}
		if ( ! isset( $entry['ts'] ) ) {
			$entry['ts'] = time();
		}

		$line = json_encode( $entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions
		$fh = fopen( $this->file, 'a' );
		if ( ! $fh ) {
			return;
		}
		// Skip the entry only when another request holds the lock. A filesystem without locking
		// (NFS, some shared hosts, WordPress Playground) fails flock() without $wouldblock, and
		// dropping every write there left Live Traffic permanently empty. One short line in
		// append mode is written whole even without the lock.
		$wouldblock = 0;
		// phpcs:ignore WordPress.WP.AlternativeFunctions
		$locked = flock( $fh, LOCK_EX | LOCK_NB, $wouldblock );
		if ( $locked || ! $wouldblock ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions
			fwrite( $fh, $line );
		}
		if ( $locked ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions
			flock( $fh, LOCK_UN );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions
		fclose( $fh );

		// Compact if file is too large (outside lock to minimise contention).
		clearstatcache( true, $this->file );
		if ( file_exists( $this->file ) && filesize( $this->file ) > self::MAX_FILE_BYTES ) {
			$this->compact();
		}
	}

	/**
	 * Query recent traffic with optional filters.
	 *
	 * Supported filters: since (unix ts), limit, page, method, ip, ua_type, event_type, search.
	 *
	 * @param  array<string,mixed> $filters
	 * @return array{items:list<array>,total:int,page:int,per_page:int,server_time:int}
	 */
	public function query( array $filters ): array {
		$all = $this->read_all();

		$since = max( 0, (int) ( $filters['since'] ?? 0 ) );
		if ( $since > 0 ) {
			$all = array_values( array_filter( $all, static fn( $e ) => (int) ( $e['ts'] ?? 0 ) > $since ) );
		}

		if ( ! empty( $filters['method'] ) ) {
			$m   = strtoupper( (string) $filters['method'] );
			$all = array_values( array_filter( $all, static fn( $e ) => ( $e['method'] ?? '' ) === $m ) );
		}

		if ( ! empty( $filters['ip'] ) ) {
			$ip  = (string) $filters['ip'];
			$all = array_values( array_filter( $all, static fn( $e ) => ( $e['ip'] ?? '' ) === $ip ) );
		}

		if ( ! empty( $filters['ua_type'] ) ) {
			$t   = (string) $filters['ua_type'];
			$all = array_values( array_filter( $all, static fn( $e ) => ( $e['ua_type'] ?? '' ) === $t ) );
		}

		if ( ! empty( $filters['event_type'] ) ) {
			$et  = (string) $filters['event_type'];
			$all = array_values( array_filter( $all, static fn( $e ) => ( $e['event_type'] ?? '' ) === $et ) );
		}

		if ( ! empty( $filters['search'] ) ) {
			$s   = strtolower( (string) $filters['search'] );
			$all = array_values(
				array_filter(
					$all,
					static fn( $e ) =>
						str_contains( strtolower( $e['uri'] ?? '' ), $s ) ||
						str_contains( strtolower( $e['ip'] ?? '' ), $s ) ||
						str_contains( strtolower( $e['ua_family'] ?? '' ), $s ) ||
						str_contains( strtolower( $e['event_type'] ?? '' ), $s ) ||
						str_contains( strtolower( $e['ua_os'] ?? '' ), $s )
				)
			);
		}

		$total    = count( $all );
		$limit    = max( 1, min( 500, (int) ( $filters['limit'] ?? 100 ) ) );
		$page     = max( 1, (int) ( $filters['page'] ?? 1 ) );
		$offset   = ( $page - 1 ) * $limit;
		$items    = array_slice( $all, $offset, $limit );

		return array(
			'items'       => array_values( $items ),
			'total'       => $total,
			'page'        => $page,
			'per_page'    => $limit,
			'server_time' => time(),
		);
	}

	/**
	 * Aggregate stats for entries newer than $since (default: last hour).
	 *
	 * @param  int $since Unix timestamp (0 → now - 1 hour).
	 * @return array<string,mixed>
	 */
	public function summary( int $since = 0 ): array {
		if ( $since <= 0 ) {
			$since = time() - HOUR_IN_SECONDS;
		}

		$all  = $this->read_all();
		$all  = array_filter( $all, static fn( $e ) => (int) ( $e['ts'] ?? 0 ) >= $since );
		$total = count( $all );

		$blocked   = 0;
		$bots      = 0;
		$ips       = array();
		$uris      = array();
		$countries = array();
		$methods   = array();
		$timeline  = array();

		foreach ( $all as $e ) {
			// Blocked = a security event on a request that was refused. A failed sign-in is a
			// warning too, but its page loaded normally.
			if ( (int) ( $e['severity'] ?? 0 ) >= 30 && (int) ( $e['status'] ?? 200 ) >= 400 ) {
				++$blocked;
			}
			$ua_t = $e['ua_type'] ?? '';
			if ( $ua_t && 'human' !== $ua_t && 'unknown' !== $ua_t ) {
				++$bots;
			}

			$ip = (string) ( $e['ip'] ?? '' );
			if ( $ip ) {
				$ips[ $ip ] = ( $ips[ $ip ] ?? 0 ) + 1;
			}

			$uri = strtok( (string) ( $e['uri'] ?? '' ), '?' );
			if ( $uri ) {
				$uris[ $uri ] = ( $uris[ $uri ] ?? 0 ) + 1;
			}

			$c = (string) ( $e['country'] ?? '' );
			if ( $c ) {
				$countries[ $c ] = ( $countries[ $c ] ?? 0 ) + 1;
			}

			$m = (string) ( $e['method'] ?? '' );
			if ( $m ) {
				$methods[ $m ] = ( $methods[ $m ] ?? 0 ) + 1;
			}

			// Minute-granularity timeline bucket.
			$ts     = (int) ( $e['ts'] ?? time() );
			$bucket = $ts - ( $ts % 60 );
			$timeline[ $bucket ] = ( $timeline[ $bucket ] ?? 0 ) + 1;
		}

		arsort( $ips );
		arsort( $uris );
		arsort( $countries );
		ksort( $timeline );

		$elapsed_min = max( 1, ( time() - $since ) / 60 );

		$to_list = static function ( array $map, string $key_name, string $val_name ) {
			$list = array();
			foreach ( $map as $k => $v ) {
				$list[] = array( $key_name => $k, $val_name => $v );
			}
			return array_values( array_slice( $list, 0, 10 ) );
		};

		return array(
			'total'         => $total,
			'blocked'       => $blocked,
			'bots'          => $bots,
			'req_per_min'   => round( $total / $elapsed_min, 1 ),
			'top_ips'       => $to_list( $ips, 'ip', 'count' ),
			'top_uris'      => $to_list( $uris, 'uri', 'count' ),
			'top_countries' => $to_list( $countries, 'country', 'count' ),
			'methods'       => $methods,
			'timeline'      => $timeline,
		);
	}

	/** Delete the buffer file. */
	public function clear(): void {
		if ( file_exists( $this->file ) ) {
			unlink( $this->file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	/* ------------------------------------------------------------------ */
	/* Static helpers                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Buffer file inside the plugin's private storage directory ('' when uploads is unavailable).
	 */
	public static function buffer_path(): string {
		$dir = \LoyalSecurity\Modules\Firewall\BanStore::storage_dir();
		return '' === $dir ? '' : $dir . '/traffic/buffer.jsonl';
	}

	public static function ensure_dir(): void {
		if ( '' === self::buffer_path() ) {
			return;
		}
		$dir = dirname( self::buffer_path() );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$htaccess = $dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Deny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		$index = $dir . '/index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php // Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	/* ------------------------------------------------------------------ */
	/* Internal                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Read all entries, newest first.
	 *
	 * @return list<array<string,mixed>>
	 */
	private function read_all(): array {
		if ( ! file_exists( $this->file ) ) {
			return array();
		}
		$content = file_get_contents( $this->file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $content ) {
			return array();
		}

		$lines = explode( "\n", trim( $content ) );
		$items = array();
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$item = json_decode( $line, true );
			if ( is_array( $item ) ) {
				$items[] = $item;
			}
		}
		// Reverse so newest is first (file is written oldest→newest).
		return array_reverse( $items );
	}

	/** Trim the buffer file down to the cap, keeping the most-recent entries. */
	private function compact(): void {
		$items   = $this->read_all(); // newest first
		$items   = array_slice( $items, 0, $this->cap );
		$content = '';
		foreach ( array_reverse( $items ) as $item ) { // write oldest→newest
			$content .= json_encode( $item, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n";
		}
		file_put_contents( $this->file, $content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}
}
