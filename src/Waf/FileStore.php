<?php
/**
 * Flat-file ban + rate-limit state for the pre-WordPress WAF layer.
 *
 * The standalone prepend runs before WordPress (and thus before $wpdb is available), so
 * ban and rate state are kept in small files under the plugin's private storage dir. The
 * in-plugin BanStore (DB) syncs the authoritative ban list into `bans.json` here.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Waf;

use LoyalSecurity\Support\Ip;

defined( 'ABSPATH' ) || exit;

class FileStore {

	private string $dir;

	/** @var array<string, int>|null Cached ban map (ip => expiry epoch, 0 = permanent). */
	private ?array $bans = null;

	/** @var string[]|null Cached CIDR ban ranges. */
	private ?array $ban_ranges = null;

	/** @var array|null Sorted index of the ranges ({@see Ip::build_range_index()}), when the file has one. */
	private ?array $ban_index = null;

	/**
	 * @param string $dir Storage directory (created if missing).
	 */
	public function __construct( string $dir ) {
		$this->dir = rtrim( $dir, '/\\' );
		if ( ! is_dir( $this->dir ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- this WAF kernel class is shared with the pre-WordPress prepend bootstrapper; WP_Filesystem is unavailable there.
			@mkdir( $this->dir, 0750, true );
		}
		if ( ! is_dir( $this->dir . '/rate' ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- this WAF kernel class is shared with the pre-WordPress prepend bootstrapper; WP_Filesystem is unavailable there.
			@mkdir( $this->dir . '/rate', 0750, true );
		}
	}

	/* --------------------------------- Bans -------------------------------- */

	private function load_bans(): void {
		if ( null !== $this->bans ) {
			return;
		}
		$this->bans       = array();
		$this->ban_ranges = array();
		$this->ban_index  = null;
		$file             = $this->dir . '/bans.json';
		if ( ! is_file( $file ) ) {
			return;
		}
		$data = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! is_array( $data ) ) {
			return;
		}
		if ( isset( $data['ips'] ) && is_array( $data['ips'] ) ) {
			$this->bans = $data['ips'];
		}
		if ( isset( $data['ranges'] ) && is_array( $data['ranges'] ) ) {
			$this->ban_ranges = $data['ranges'];
		}
		if ( isset( $data['index']['v4'], $data['index']['v6'] ) && is_array( $data['index']['v4'] ) && is_array( $data['index']['v6'] ) ) {
			$this->ban_index = $data['index'];
		}
	}

	/**
	 * Is the IP currently banned (exact or CIDR, honouring expiry)?
	 */
	public function is_banned( string $ip ): bool {
		$this->load_bans();
		$now = time();

		if ( isset( $this->bans[ $ip ] ) ) {
			$exp = (int) $this->bans[ $ip ];
			if ( 0 === $exp || $exp > $now ) {
				return true;
			}
		}
		return $this->in_banned_range( $ip );
	}

	/**
	 * Is the IP inside a banned CIDR range? Binary search over the index written with the ban
	 * file; a file written by an older version (no index) falls back to checking each range.
	 */
	public function in_banned_range( string $ip ): bool {
		$this->load_bans();
		if ( ! $this->ban_ranges ) {
			return false;
		}
		if ( null !== $this->ban_index ) {
			return Ip::in_range_index( $ip, $this->ban_index );
		}
		return Ip::in_ranges( $ip, $this->ban_ranges );
	}

	/**
	 * Persist the authoritative ban list (called by the WP-side BanStore on change).
	 *
	 * @param array<string, int> $ips    Map of ip => expiry epoch (0 = permanent).
	 * @param string[]           $ranges CIDR ranges (permanent).
	 */
	public function write_bans( array $ips, array $ranges = array() ): bool {
		$this->bans       = $ips;
		$this->ban_ranges = $ranges;
		$this->ban_index  = Ip::build_range_index( $ranges );
		return false !== file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$this->dir . '/bans.json',
			json_encode( array( 'ips' => $ips, 'ranges' => $ranges, 'index' => $this->ban_index ) ),
			LOCK_EX
		);
	}

	/* ------------------------------ Rate limit ----------------------------- */

	/**
	 * Record a hit for an IP and report whether it now exceeds the limit within the window.
	 * Sliding-window counter persisted per-IP with file locking.
	 *
	 * @param string $ip     Client IP.
	 * @param int    $limit  Max requests within the window.
	 * @param int    $window Window length in seconds.
	 * @return array{exceeded:bool,count:int}
	 */
	public function hit_rate( string $ip, int $limit, int $window ): array {
		$now  = time();
		$file = $this->dir . '/rate/' . sha1( $ip ) . '.json';

		$fh = @fopen( $file, 'c+' ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
		if ( ! $fh ) {
			return array( 'exceeded' => false, 'count' => 0 );
		}
		@flock( $fh, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		$raw   = stream_get_contents( $fh );
		$stamps = json_decode( (string) $raw, true );
		if ( ! is_array( $stamps ) ) {
			$stamps = array();
		}
		// Prune outside the window and append now.
		$cutoff = $now - $window;
		$stamps = array_values( array_filter( $stamps, static fn( $t ) => (int) $t > $cutoff ) );
		$stamps[] = $now;

		$count = count( $stamps );

		// Cap stored entries to limit+overflow to bound file size.
		if ( $count > $limit + 50 ) {
			$stamps = array_slice( $stamps, -( $limit + 50 ) );
		}

		ftruncate( $fh, 0 );
		rewind( $fh );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- this WAF kernel class is shared with the pre-WordPress prepend bootstrapper; WP_Filesystem is unavailable there.
		fwrite( $fh, (string) json_encode( $stamps ) );
		@flock( $fh, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- this WAF kernel class is shared with the pre-WordPress prepend bootstrapper; WP_Filesystem is unavailable there.
		fclose( $fh );

		return array( 'exceeded' => $count > $limit, 'count' => $count );
	}

	/**
	 * Record a distinct signature for an IP within a window and report whether the IP has now
	 * accumulated more than $max DISTINCT signatures — not a request count like hit_rate(), a
	 * count of how many different combinations it's tried. Built for faceted-search/archive-page
	 * abuse: a bot walking every filter combination on a shop page looks nothing like a volume
	 * spike (each individual combination might be requested only once), so a plain rate limit
	 * misses it entirely; tracking the SET of distinct combinations catches it directly.
	 *
	 * Stored as `rate/qc-<sha1 ip>.json`, sharing the `rate/` directory (and its existing
	 * gc_rate() cleanup — that glob already matches any `*.json` in there) with hit_rate()'s
	 * per-IP counters, but keeping its own file since the two need different data shapes: a
	 * timestamp list there, a signature-hash => last-seen map here.
	 *
	 * @return array{exceeded:bool,count:int}
	 */
	public function hit_distinct( string $ip, string $signature, int $max, int $window ): array {
		if ( '' === $signature ) {
			return array( 'exceeded' => false, 'count' => 0 );
		}

		$now  = time();
		$file = $this->dir . '/rate/qc-' . sha1( $ip ) . '.json';

		$fh = @fopen( $file, 'c+' ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
		if ( ! $fh ) {
			return array( 'exceeded' => false, 'count' => 0 );
		}
		@flock( $fh, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		$raw  = stream_get_contents( $fh );
		$seen = json_decode( (string) $raw, true );
		if ( ! is_array( $seen ) ) {
			$seen = array();
		}

		// Prune anything outside the window, then record/refresh this signature.
		$cutoff = $now - $window;
		$seen   = array_filter( $seen, static fn( $ts ) => (int) $ts > $cutoff );
		$seen[ sha1( $signature ) ] = $now;

		// Bound the stored set so a genuine burst of distinct combinations (malicious or a very
		// active real shopper) can't grow this file unbounded — a generous cap well past $max,
		// since the point is catching the threshold being crossed, not storing every combination
		// forever. Evicts the oldest-seen signatures first once over the cap.
		if ( count( $seen ) > $max + 100 ) {
			asort( $seen );
			$seen = array_slice( $seen, -( $max + 100 ), null, true );
		}

		$count = count( $seen );

		ftruncate( $fh, 0 );
		rewind( $fh );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
		fwrite( $fh, (string) json_encode( $seen ) );
		@flock( $fh, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
		fclose( $fh );

		return array( 'exceeded' => $count > $max, 'count' => $count );
	}

	/**
	 * Garbage-collect stale rate files (called periodically by WP cron).
	 */
	public function gc_rate( int $max_age = 3600 ): void {
		$now   = time();
		$files = glob( $this->dir . '/rate/*.json' );
		if ( ! $files ) {
			return;
		}
		foreach ( $files as $f ) {
			if ( ( $now - (int) @filemtime( $f ) ) > $max_age ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				// phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.unlink_unlink -- this WAF kernel class is shared with the pre-WordPress prepend bootstrapper; WP_Filesystem is unavailable there.
				@unlink( $f );
			}
		}
	}

	/* --------------------------- Bot verification --------------------------- */

	/**
	 * Cached forward-confirmed-DNS verdict for an IP claiming to be a known good bot, or null if
	 * never checked or the cache entry has aged past $ttl. Pure read, no I/O beyond one file —
	 * the actual DNS lookup never happens here or anywhere in either mode's per-request
	 * inspection path; only a periodic WP-Cron job (Standard Mode only, registered
	 * unconditionally regardless of WAF mode) ever calls {@see store_bot_verdict()}.
	 */
	public function bot_verdict( string $ip, int $ttl ): ?bool {
		$file = $this->dir . '/verified-bots/' . sha1( $ip ) . '.json';
		if ( ! is_file( $file ) ) {
			return null;
		}
		$data = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! is_array( $data ) || ! isset( $data['checked_at'], $data['verified'] ) ) {
			return null;
		}
		if ( ( time() - (int) $data['checked_at'] ) > $ttl ) {
			return null;
		}
		return (bool) $data['verified'];
	}

	/**
	 * Persist a bot-verification verdict. Called only from the periodic verification cron —
	 * never from request-inspection code in either mode.
	 */
	public function store_bot_verdict( string $ip, bool $verified ): void {
		$dir = $this->dir . '/verified-bots';
		if ( ! is_dir( $dir ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
			@mkdir( $dir, 0750, true );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
		file_put_contents(
			$dir . '/' . sha1( $ip ) . '.json',
			(string) json_encode( array( 'verified' => $verified, 'checked_at' => time() ) ),
			LOCK_EX
		);
	}

	/**
	 * Queue an IP + matched-signature pair for background verification, deduped and bounded.
	 * Cheap and synchronous (one small locked file) — safe to call from the request path in
	 * both modes. The actual DNS lookup happens later, off the request path.
	 */
	/**
	 * @param string        $ip        Claimant IP.
	 * @param string        $signature UA signature that matched (for logging/display only).
	 * @param array<string> $suffixes  Trusted PTR-hostname suffixes to verify against — resolved
	 *                                 by the caller (builtin {@see \LoyalSecurity\Waf\BotSignatures::TRUSTED_SUFFIXES}
	 *                                 or an admin-provided custom suffix), snapshotted here rather
	 *                                 than re-resolved by the verification cron, so a rule edited
	 *                                 or deleted between queuing and verification can't change
	 *                                 what an already-queued claim gets checked against.
	 */
	public function queue_bot_verification( string $ip, string $signature, array $suffixes = array() ): void {
		$dir = $this->dir . '/verified-bots';
		if ( ! is_dir( $dir ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
			@mkdir( $dir, 0750, true );
		}
		$file = $dir . '/pending.json';
		$fh   = @fopen( $file, 'c+' ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
		if ( ! $fh ) {
			return;
		}
		@flock( $fh, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		$raw   = stream_get_contents( $fh );
		$queue = json_decode( (string) $raw, true );
		if ( ! is_array( $queue ) ) {
			$queue = array();
		}
		// Bound the queue so a burst of spoofed "good bot" UAs can't grow this file unbounded —
		// worst case some claims wait for the next cron run's next-200 batch to be queued.
		if ( ! isset( $queue[ $ip ] ) && count( $queue ) < 200 ) {
			$queue[ $ip ] = array( 'signature' => $signature, 'suffixes' => array_values( $suffixes ), 'queued_at' => time() );
		}

		ftruncate( $fh, 0 );
		rewind( $fh );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
		fwrite( $fh, (string) json_encode( $queue ) );
		@flock( $fh, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
		fclose( $fh );
	}

	/**
	 * Pop up to $max queued IPs pending bot verification (removes them from the queue as
	 * returned — the caller verifies each and stores its own verdict). Standard-Mode-cron-only.
	 *
	 * @return array<string, array{signature:string,suffixes:array<string>,queued_at:int}>
	 */
	public function pop_pending_bot_verifications( int $max = 20 ): array {
		$file = $this->dir . '/verified-bots/pending.json';
		$fh   = @fopen( $file, 'c+' ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
		if ( ! $fh ) {
			return array();
		}
		@flock( $fh, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		$raw   = stream_get_contents( $fh );
		$queue = json_decode( (string) $raw, true );
		if ( ! is_array( $queue ) ) {
			$queue = array();
		}
		$batch = array_slice( $queue, 0, $max, true );
		$rest  = array_diff_key( $queue, $batch );

		ftruncate( $fh, 0 );
		rewind( $fh );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
		fwrite( $fh, (string) json_encode( $rest ) );
		@flock( $fh, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- shared with the pre-WordPress prepend; WP_Filesystem is unavailable there.
		fclose( $fh );

		return $batch;
	}
}
