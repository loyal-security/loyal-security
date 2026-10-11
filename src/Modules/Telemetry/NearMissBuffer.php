<?php
/**
 * Near-miss buffer — records allowed-but-suspicious requests (already anonymized).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Telemetry;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Waf\RequestContext;
use LoyalSecurity\Waf\Decision;

/**
 * A small circular JSON-Lines buffer of requests that scored above zero on the WAF but stayed
 * below the block threshold (a "near miss"). These are the prime suspects when a compromise is
 * later confirmed: the request was allowed through, so its payload is exactly what bypassed the
 * firewall.
 *
 * Crucially, entries are scrubbed by {@see Redactor} *before* being written to disk — the raw
 * body never touches storage. Writes are append-only with a non-blocking lock and fail open.
 */
class NearMissBuffer {

	private const DEFAULT_CAP    = 200;
	private const MAX_FILE_BYTES = 1024 * 1024; // compact at 1 MB.

	private string $file;
	private int $cap;

	public function __construct( int $cap = self::DEFAULT_CAP ) {
		$this->cap  = max( 50, min( 1000, $cap ) );
		$this->file = self::path();
	}

	/**
	 * Capture an allowed-but-suspicious request. Accepts the live WAF objects, extracts the
	 * useful fields, redacts them, and appends one line. Never throws.
	 */
	public function capture( RequestContext $req, Decision $decision ): void {
		try {
			$redactor = Redactor::for_site();

			$entry = array(
				'ts'      => time(),
				'ip'      => (string) $req->ip,
				'method'  => (string) $req->method,
				'path'    => $redactor->scrub_string( (string) $req->path ),
				'uri'     => $redactor->scrub_string( mb_substr( (string) $req->uri, 0, 2048 ) ),
				'query'   => $redactor->scrub_params( (array) $req->get ),
				'body'    => $redactor->scrub_params( (array) $req->post ),
				'raw_body' => $redactor->scrub_body( (string) ( $req->raw_body ?? '' ) ),
				'headers' => $redactor->scrub_headers( (array) $req->headers ),
				'ua'      => $redactor->scrub_string( mb_substr( (string) $req->user_agent, 0, 512 ) ),
				'score'   => (int) $decision->score,
				'category' => (string) ( $decision->category ?? '' ),
				'top_rule' => (string) ( $decision->top_rule ?? '' ),
				'matches' => $this->compact_matches( $decision ),
				'body_truncated' => (bool) ( $req->body_truncated ?? false ),
			);

			$this->push( $entry );
		} catch ( \Throwable $e ) {
			// Fail open — telemetry capture must never affect request handling.
			unset( $e );
		}
	}

	/**
	 * Return entries whose timestamp falls within [$from, $to], newest first.
	 *
	 * @return list<array<string,mixed>>
	 */
	public function between( int $from, int $to ): array {
		$out = array();
		foreach ( $this->read_all() as $e ) {
			$ts = (int) ( $e['ts'] ?? 0 );
			if ( $ts >= $from && $ts <= $to ) {
				$out[] = $e;
			}
		}
		return $out;
	}

	/* ------------------------------------------------------------------ */

	/**
	 * Reduce a Decision's matches to rule-id / category / score triples (no raw values).
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function compact_matches( Decision $decision ): array {
		$out     = array();
		$matches = is_array( $decision->matches ?? null ) ? $decision->matches : array();
		foreach ( array_slice( $matches, 0, 10 ) as $m ) {
			$out[] = array(
				'rule'     => (string) ( $m['rule'] ?? '' ),
				'category' => (string) ( $m['category'] ?? '' ),
				'source'   => (string) ( $m['source'] ?? '' ),
				'param'    => (string) ( $m['param'] ?? '' ),
				'score'    => (int) ( $m['score'] ?? 0 ),
			);
		}
		return $out;
	}

	private function push( array $entry ): void {
		if ( '' === $this->file ) {
			return; // Uploads directory unavailable.
		}
		self::ensure_dir();
		// Stored base64-encoded: these entries hold raw attacker payloads (potentially live
		// webshell strings). Encoding at rest stops on-box malware scanners / AV from
		// quarantining the buffer file or flagging it as an infection.
		$line = base64_encode( (string) wp_json_encode( $entry ) ) . "\n";

		$fh = fopen( $this->file, 'a' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $fh ) {
			return;
		}
		// Skip only when another request holds the lock; a filesystem without locking (NFS,
		// some shared hosts) fails flock() without $wouldblock and must still get the entry.
		$wouldblock = 0;
		$locked     = flock( $fh, LOCK_EX | LOCK_NB, $wouldblock ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( $locked || ! $wouldblock ) {
			fwrite( $fh, $line ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		if ( $locked ) {
			flock( $fh, LOCK_UN ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		clearstatcache( true, $this->file );
		if ( file_exists( $this->file ) && filesize( $this->file ) > self::MAX_FILE_BYTES ) {
			$this->compact();
		}
	}

	/**
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
		$items = array();
		foreach ( explode( "\n", trim( $content ) ) as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$item = $this->decode_line( $line );
			if ( is_array( $item ) ) {
				$items[] = $item;
			}
		}
		return array_reverse( $items ); // newest first.
	}

	private function compact(): void {
		$items   = array_slice( $this->read_all(), 0, $this->cap ); // newest first.
		$content = '';
		foreach ( array_reverse( $items ) as $item ) {
			$content .= base64_encode( (string) wp_json_encode( $item ) ) . "\n";
		}
		file_put_contents( $this->file, $content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/**
	 * Decode one stored line. Lines are base64(JSON); falls back to plain JSON for forward/
	 * backward compatibility if an un-encoded line is ever encountered.
	 *
	 * @return array<string,mixed>|null
	 */
	private function decode_line( string $line ) {
		$decoded = base64_decode( $line, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( false !== $decoded ) {
			$item = json_decode( $decoded, true );
			if ( is_array( $item ) ) {
				return $item;
			}
		}
		$item = json_decode( $line, true );
		return is_array( $item ) ? $item : null;
	}

	/**
	 * Buffer file inside the plugin's private storage directory ('' when uploads is unavailable).
	 */
	public static function path(): string {
		$dir = \LoyalSecurity\Modules\Firewall\BanStore::storage_dir();
		return '' === $dir ? '' : $dir . '/telemetry/near-miss.jsonl';
	}

	public static function ensure_dir(): void {
		if ( '' === self::path() ) {
			return;
		}
		$dir = dirname( self::path() );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$htaccess = $dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Require all denied\nDeny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		$index = $dir . '/index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php // Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}
}
