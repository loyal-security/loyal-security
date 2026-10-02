<?php
/**
 * Malware scanner module — orchestrates batched, resumable scans.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\AbstractModule;
use TotalSecurityWP\Core\Cron;
use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Modules\Firewall\PatchSuggester;
use TotalSecurityWP\Support\Filesystem;

/**
 * Drives scans in small batches so they fit within request/cron time limits and never
 * exhaust memory. The dashboard polls {@see run_batch()} until completion; a scheduled full
 * scan runs via WP-Cron.
 */
class ScannerModule extends AbstractModule {

	public function id(): string {
		return 'scanner';
	}

	public function title(): string {
		return __( 'Malware Scanner', 'loyal-security' );
	}

	public function default_settings(): array {
		return array(
			'enabled'              => true,
			'max_file_size'        => 3145728, // 3 MB.
			'extensions'           => array( 'php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'js' ),
			'scan_database'        => true,
			'scheduled_scan'       => true,
			'batch_size'           => 150,
		);
	}

	/** Single-event hook that drives an in-progress scan to completion in the background. */
	public const CONTINUE_HOOK = 'totalsecwp_scan_continue';

	public function register_hooks(): void {
		add_action( Cron::SCAN, array( $this, 'run_scheduled' ) );
		add_action( self::CONTINUE_HOOK, array( $this, 'continue_scan' ), 10, 1 );

		// Weekly automatic full scan ("Scheduled Scan" setting, on by default).
		add_action( 'init', array( $this, 'ensure_free_weekly_scan' ) );
	}

	/**
	 * Keep the weekly automatic scan scheduled while the "Scheduled Scan" setting is on, and
	 * unscheduled while it is off. Also replaces the daily event older versions scheduled.
	 */
	public function ensure_free_weekly_scan(): void {
		$want = $this->is_enabled() && (bool) $this->setting( 'scheduled_scan', true );
		$next = wp_next_scheduled( Cron::SCAN );

		if ( ! $want ) {
			if ( $next ) {
				wp_unschedule_hook( Cron::SCAN );
			}
			return;
		}

		$event = function_exists( 'wp_get_scheduled_event' ) ? wp_get_scheduled_event( Cron::SCAN ) : false;
		if ( $event && 'weekly' !== $event->schedule ) {
			wp_unschedule_hook( Cron::SCAN );
			$next = false;
		}
		if ( ! $next ) {
			if ( ! has_filter( 'cron_schedules', array( Cron::class, 'add_schedules' ) ) ) {
				add_filter( 'cron_schedules', array( Cron::class, 'add_schedules' ) );
			}
			wp_schedule_event( time() + DAY_IN_SECONDS, 'weekly', Cron::SCAN );
		}
	}

	/**
	 * Public logging shim so collaborators (e.g. ScheduledScanner) can record events
	 * through this module's audit logger without exposing the container.
	 *
	 * @param string               $type    Event type constant.
	 * @param array<string, mixed> $context Structured context.
	 * @param int|null             $severity Optional severity override.
	 */
	public function logger_log( string $type, array $context = array(), ?int $severity = null ): void {
		$this->logger()->log( $type, $context, $severity );
	}

	private function scans_dir(): string {
		$dir = BanStore::storage_dir() . '/scans';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		return $dir;
	}

	private function list_file( string $scan_id ): string {
		return $this->scans_dir() . '/' . preg_replace( '/[^a-z0-9_]/i', '', $scan_id ) . '.list';
	}

	private function findings_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'totalsecwp_scan_findings';
	}

	/**
	 * Begin a new scan: enumerate files and persist the work list.
	 *
	 * @param string $type full | content | uploads | core.
	 * @return array{scan_id:string,total:int,type:string}
	 */
	public function start( string $type = 'full' ): array {
		$scan_id = 'scan_' . gmdate( 'YmdHis' ) . '_' . wp_generate_password( 6, false, false );
		$walker  = new FileWalker( (array) $this->setting( 'extensions', array( 'php' ) ) );

		$list  = $this->list_file( $scan_id );
		$fh    = fopen( $list, 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$total = 0;
		if ( $fh ) {
			foreach ( $walker->roots_for( $type ) as $root ) {
				foreach ( $walker->walk( $root ) as $path ) {
					fwrite( $fh, $path . "\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- streaming write; loading the whole file-list into memory via WP_Filesystem would defeat the point for a large scan.
					$total++;
				}
			}
			fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- matching close for the streaming write above.
		}

		( new ScanState() )->create( $scan_id, $type, $total );
		$this->logger()->log( EventCatalog::SCAN_STARTED, array( 'scan_id' => $scan_id, 'type' => $type, 'total' => $total ) );

		// Schedule a background driver so the scan completes even if the browser tab that
		// started it is closed or reloaded. The dashboard also drives batches while open; the
		// two are safe to overlap (batch offsets derive from persisted progress and findings
		// are de-duplicated), and this is the fallback that guarantees completion.
		if ( ! wp_next_scheduled( self::CONTINUE_HOOK, array( $scan_id ) ) ) {
			wp_schedule_single_event( time() + 15, self::CONTINUE_HOOK, array( $scan_id ) );
		}

		return array( 'scan_id' => $scan_id, 'total' => $total, 'type' => $type );
	}

	/**
	 * Background driver (WP-Cron): advance a still-running scan within a time budget and
	 * reschedule itself until it completes. This makes scans resilient to the dashboard tab
	 * being closed mid-scan — progress persists in scan_state and is shown again on return.
	 */
	public function continue_scan( string $scan_id ): void {
		$state = new ScanState();
		$row   = $state->get( $scan_id );
		if ( ! $row || 'running' !== $row['status'] ) {
			return;
		}

		// Lift the execution limit for the cron driver so the host's default max_execution_time
		// (often 30s) doesn't kill the worker before its own 40s budget below. Best-effort —
		// disabled in some environments; the scan is resumable regardless.
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- long-running scan driver; lifts the host default execution limit so the batch loop below can use its own bounded budget.
		}

		$deadline = time() + 40;
		$progress = $row;
		do {
			$progress = $this->run_batch( $scan_id );
		} while ( 'running' === ( $progress['status'] ?? '' ) && time() < $deadline );

		if ( 'running' === ( $progress['status'] ?? '' ) ) {
			wp_schedule_single_event( time() + 10, self::CONTINUE_HOOK, array( $scan_id ) );
		}
	}

	/**
	 * Process the next batch of files. Returns the updated progress.
	 *
	 * @return array<string, mixed>
	 */
	public function run_batch( string $scan_id, ?int $batch_size = null ): array {
		$state = ( new ScanState() );

		// Overlap guard: the dashboard driver and the CONTINUE_HOOK cron worker can both call
		// this for the same scan. Without mutual exclusion both read the same cursor, scan the
		// same slice twice (wasted I/O), and the read-modify-write on the findings counter can
		// double-count or regress. add_option() is atomic (duplicate-key INSERT fails), unlike
		// get/set_transient. Non-blocking: the loser just reports current progress and keeps
		// polling while the holder advances the cursor. A stale lock (crashed worker) is stolen
		// after 120s so a scan can never wedge permanently.
		$lock = 'totalsecwp_scanlock_' . $scan_id;
		if ( ! add_option( $lock, (string) time(), '', 'no' ) ) {
			$held_since = (int) get_option( $lock );
			if ( $held_since && time() - $held_since < 120 ) {
				$row = $state->get( $scan_id );
				return $row ? array(
					'scan_id'       => $scan_id,
					'status'        => (string) $row['status'],
					'total_files'   => (int) $row['total_files'],
					'scanned_files' => (int) $row['scanned_files'],
					'findings'      => (int) $row['findings'],
				) : array( 'status' => 'unknown' );
			}
			update_option( $lock, (string) time(), 'no' );
		}

		try {
			$row = $state->get( $scan_id );
			if ( ! $row || 'running' !== $row['status'] ) {
				return $row ?: array( 'status' => 'unknown' );
			}

			$batch_size = $batch_size ?: (int) $this->setting( 'batch_size', 150 );
			$offset     = (int) $row['scanned_files'];
			$total      = (int) $row['total_files'];

			$paths = $this->read_list_slice( $scan_id, $offset, $batch_size );

			$scanner = $this->make_scanner();
			$max     = (int) $this->setting( 'max_file_size', 3145728 );

			$new_findings = 0;
			foreach ( $paths as $path ) {
				$findings = $scanner->scan_file( $path, $max );
				$new_findings += $this->store_findings( $scan_id, $findings );
			}

			$scanned        = min( $total, $offset + count( $paths ) );
			$total_findings = (int) $row['findings'] + $new_findings;
			$state->progress( $scan_id, $scanned, $total_findings );

			$done = ( $scanned >= $total ) || empty( $paths );
			if ( $done ) {
				// Optional database scan as the final step.
				if ( $this->setting( 'scan_database', true ) ) {
					$db_findings    = ( new DatabaseScanner() )->scan();
					$total_findings += $this->store_findings( $scan_id, $db_findings );
					$state->progress( $scan_id, $scanned, $total_findings );
				}
				$state->finish( $scan_id, 'completed' );
				Filesystem::delete( $this->list_file( $scan_id ) );
				$this->logger()->log( EventCatalog::SCAN_COMPLETED, array( 'scan_id' => $scan_id, 'findings' => $total_findings ) );
			}

			return array(
				'scan_id'       => $scan_id,
				'status'        => $done ? 'completed' : 'running',
				'total_files'   => $total,
				'scanned_files' => $scanned,
				'findings'      => $total_findings,
			);
		} finally {
			delete_option( $lock );
		}
	}

	/**
	 * Build a HeuristicScanner with the base malware signatures merged with any cached
	 * remote feed rules. Fail-open: remote merge errors are silently ignored.
	 */
	private function make_scanner(): HeuristicScanner {
		$base_file   = TOTALSECWP_PATH . 'data/malware-signatures.php';
		$base_data   = is_file( $base_file ) ? include $base_file : array();
		$base_rules  = isset( $base_data['rules'] ) && is_array( $base_data['rules'] ) ? $base_data['rules'] : array();
		$base_version = isset( $base_data['version'] ) ? (string) $base_data['version'] : '';

		try {
			if ( class_exists( \TotalSecurityWP\Modules\ThreatIntel\FeedStore::class ) ) {
				$remote = ( new \TotalSecurityWP\Modules\ThreatIntel\FeedStore() )->get_rules( 'malware' );
				if ( is_array( $remote ) && ! empty( $remote ) ) {
					$base_rules = array_merge( $base_rules, $remote );
				}
			}
		} catch ( \Throwable $e ) {
			// Fail open.
		}

		// Trust any file whose content provably matches an official WordPress.org plugin
		// release (same trust model already applied to core files in
		// HeuristicScanner::scan_file()) — this is what stops a heuristic false positive on
		// unmodified vendor code (e.g. WooCommerce) from re-appearing scan after scan, since a
		// reinstall alone can never "fix" code that was never actually different. Fail-open:
		// a checksum-API hiccup just means this scan runs without the trust allowlist.
		$allow_hashes = array();
		try {
			$allow_hashes = ( new \TotalSecurityWP\Modules\Integrity\PluginChecksums() )->official_hash_set();
		} catch ( \Throwable $e ) {
			// Fail open.
		}

		return new HeuristicScanner( new SignatureDb( $base_rules, $base_version ), null, $allow_hashes );
	}

	/**
	 * @return string[]
	 */
	private function read_list_slice( string $scan_id, int $offset, int $count ): array {
		$file = $this->list_file( $scan_id );
		if ( ! is_file( $file ) ) {
			return array();
		}
		$paths = array();
		$fh    = fopen( $file, 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $fh ) {
			return array();
		}
		$i = 0;
		while ( false !== ( $line = fgets( $fh ) ) ) {
			if ( $i >= $offset && $i < $offset + $count ) {
				$path = trim( $line );
				if ( '' !== $path ) {
					$paths[] = $path;
				}
			}
			$i++;
			if ( $i >= $offset + $count ) {
				break;
			}
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- matching close for the streaming line-by-line read above (fgets loop over a potentially large scan file-list).
		return $paths;
	}

	/**
	 * Persist findings; logs each as a critical event. Returns the count stored.
	 * Skips findings whose (path, rule, line) already exist as an open finding to
	 * prevent duplicate rows accumulating across repeated scans.
	 *
	 * @param Finding[] $findings Findings.
	 */
	private function store_findings( string $scan_id, array $findings ): int {
		global $wpdb;
		$table     = $this->findings_table();
		$whitelist = $this->whitelist();
		$n         = 0;
		foreach ( $findings as $f ) {
			// Suppress admin-whitelisted false positives so they never re-appear.
			if ( $whitelist->is_whitelisted( $f->path, $f->rule ) ) {
				continue;
			}
			// Skip re-inserting if an identical open finding already exists from a previous
			// scan — but if that existing row predates a PatchSuggester rule type it now
			// qualifies for (e.g. this exact case: mal-insecure-rest-surface/ajax-nopriv
			// gained suggest_auth_gate() after some sites already had this finding on file),
			// backfill the suggestion onto it. Without this, a finding recorded before a
			// PatchSuggester capability existed would sit un-reviewable forever: it's never
			// re-inserted (duplicate), so the original code path that attaches a suggestion
			// would never run for it again.
			$existing = $wpdb->get_row( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
				$wpdb->prepare(
					"SELECT id, suggested_patch FROM %i WHERE status = 'open' AND path = %s AND rule = %s AND line = %d LIMIT 1", $table,
					$f->path,
					$f->rule,
					(int) $f->line
				),
				ARRAY_A
			);
			if ( $existing ) {
				if ( '' === (string) $existing['suggested_patch'] ) {
					$suggestion = $this->suggest_for( $f );
					if ( null !== $suggestion ) {
						$wpdb->update( // phpcs:ignore WordPress.DB
							$table,
							array( 'suggested_patch' => (string) wp_json_encode( $suggestion ) ),
							array( 'id' => (int) $existing['id'] )
						);
					}
				}
				continue;
			}
			$f->suggested_patch = $this->suggest_for( $f );
			$wpdb->insert( $table, $f->to_row( $scan_id ) ); // phpcs:ignore WordPress.DB
			$f->id = (int) $wpdb->insert_id;
			$this->logger()->log(
				EventCatalog::SCAN_FINDING,
				array( 'path' => $f->path, 'rule' => $f->rule, 'score' => $f->score, 'line' => $f->line ),
				$f->severity
			);

			/**
			 * Fires once for each newly-recorded scan finding.
			 *
			 * @since 1.0.0
			 *
			 * @param Finding $f The persisted finding (its `id` is populated).
			 */
			do_action( 'totalsecwp_scan_finding', $f );

			/**
			 * Fires alongside `totalsecwp_scan_finding` for each newly recorded finding.
			 *
			 * @since 1.2.0
			 *
			 * @param Finding $f The persisted finding.
			 */
			do_action( 'totalsecwp_cloud_reputation_scanner', $f );
			$n++;
		}
		return $n;
	}

	/**
	 * Auto-draft a virtual-patch candidate for a finding, if its rule qualifies — never
	 * applied here, just computed for a human to review in the dashboard (see PatchSuggester).
	 * Shared by store_findings()'s new-insert and existing-row-backfill paths, and by
	 * ScannerController::finding_patch()'s refresh-before-acting step (public for that reason)
	 * — all three need the same up-to-date PatchSuggester output as its supported rule types
	 * and their shapes evolve.
	 *
	 * @return array{rule: array<string, mixed>, confidence: string, reason: string}|null
	 */
	public function suggest_for( Finding $f ): ?array {
		if ( str_starts_with( $f->rule, 'tainted-' ) ) {
			return ( new PatchSuggester() )->suggest( $f );
		}
		if ( in_array( $f->rule, array( 'mal-insecure-rest-surface', 'mal-insecure-ajax-nopriv' ), true ) ) {
			return ( new PatchSuggester() )->suggest_auth_gate( $f );
		}
		return null;
	}

	/**
	 * Findings list for the dashboard.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function findings( string $status = 'open', int $limit = 200 ): array {
		global $wpdb;
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT * FROM %i WHERE status = %s ORDER BY severity DESC, id DESC LIMIT %d", $this->findings_table(),
				$status,
				$limit
			),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			return array();
		}
		// Annotate file-system findings with whether the path still exists.
		foreach ( $rows as &$row ) {
			$path = (string) ( $row['path'] ?? '' );
			$row['file_missing'] = ( '' !== $path && ! $this->is_db_finding_path( $path ) && ! file_exists( $path ) );
		}
		unset( $row );
		return $rows;
	}

	/**
	 * Findings that carry an auto-drafted virtual-patch suggestion (see PatchSuggester),
	 * for the Firewall panel's review queue — a small, targeted subset of the (potentially
	 * very large) full findings list, since only tainted-sink rules ever get a suggestion.
	 *
	 * @param string $patch_status '' = all, or one of ''|approved|rejected|submitted to filter.
	 * @return array<int, array<string, mixed>>
	 */
	public function patch_suggestions( string $patch_status = '' ): array {
		global $wpdb;
		$table = $this->findings_table();
		// A still-pending suggestion rides its finding's lifecycle: once the finding is no
		// longer open (resolved by a re-check, ignored, whitelisted, quarantined), an
		// un-reviewed draft for it is stale noise and drops out of the queue. Reviewed rows
		// (approved/rejected/submitted) are kept regardless of finding status — they are the
		// audit trail the Dismissed tab and the Active tab's cloud-status lookup read.
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live review queue.
			$wpdb->prepare(
				"SELECT * FROM %i WHERE suggested_patch IS NOT NULL AND suggested_patch != '' AND ( patch_status != '' OR status = 'open' ) AND ( %s = '' OR patch_status = %s ) ORDER BY id DESC LIMIT 200",
				$table,
				$patch_status,
				$patch_status
			),
			ARRAY_A
		);

		return $this->dedupe_suggestions( is_array( $rows ) ? $rows : array() );
	}

	/**
	 * Collapse queue rows that drafted the SAME virtual-patch rule. The rule id is a hash of
	 * slug|param|rule-type, so N sink lines all tracing to one parameter produce N findings
	 * but one identical rule — e.g. WooCommerce's `status` param flagged in four places is
	 * one reviewable rule, not four queue items. A reviewed row (approved/rejected/submitted)
	 * wins over a pending duplicate, so a rule the admin already acted on never re-nags via
	 * a leftover sibling; among rows of equal standing the newest (first, given the id DESC
	 * ordering) wins. The survivor carries `duplicate_count` for the UI.
	 *
	 * @param array<int, array<string, mixed>> $rows Rows ordered newest-first.
	 * @return array<int, array<string, mixed>>
	 */
	private function dedupe_suggestions( array $rows ): array {
		$out     = array();
		$by_rule = array(); // Suggested rule id => index into $out.

		foreach ( $rows as $row ) {
			$decoded = json_decode( (string) ( $row['suggested_patch'] ?? '' ), true );
			$rule_id = is_array( $decoded ) && isset( $decoded['rule']['id'] ) ? (string) $decoded['rule']['id'] : '';
			if ( '' === $rule_id ) {
				$out[] = $row; // Undecodable — pass through untouched rather than guess.
				continue;
			}

			if ( ! isset( $by_rule[ $rule_id ] ) ) {
				$row['duplicate_count'] = 1;
				$out[]                  = $row;
				$by_rule[ $rule_id ]    = count( $out ) - 1;
				continue;
			}

			$i = $by_rule[ $rule_id ];
			if ( '' === (string) $out[ $i ]['patch_status'] && '' !== (string) ( $row['patch_status'] ?? '' ) ) {
				$row['duplicate_count'] = (int) $out[ $i ]['duplicate_count'];
				$out[ $i ]              = $row;
			}
			$out[ $i ]['duplicate_count']++;
		}

		return $out;
	}

	/**
	 * Update a finding's status (open|ignored|resolved|quarantined).
	 */
	public function set_finding_status( int $id, string $status ): bool {
		global $wpdb;
		return (bool) $wpdb->update( $this->findings_table(), array( 'status' => $status ), array( 'id' => $id ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Update a finding's auto-drafted-patch review status (''|approved|rejected|submitted).
	 */
	public function set_patch_status( int $id, string $status ): bool {
		global $wpdb;
		return (bool) $wpdb->update( $this->findings_table(), array( 'patch_status' => $status ), array( 'id' => $id ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Bulk-move every finding currently in $from to $to (e.g. open → ignored). Returns rows
	 * affected. Used by the "Ignore all" / "Whitelist all" dashboard actions.
	 */
	public function set_status_bulk( string $from, string $to ): int {
		global $wpdb;
		return (int) $wpdb->query( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"UPDATE %i SET status = %s WHERE status = %s", $this->findings_table(),
				$to,
				$from
			)
		);
	}

	/**
	 * The false-positive whitelist store.
	 */
	public function whitelist(): Whitelist {
		return new Whitelist();
	}

	/**
	 * Re-check every currently-open finding without running a full site scan — clears any that
	 * are no longer valid: the file is gone, it now matches an official WordPress.org release
	 * (see {@see make_scanner()}'s allow_hashes), or re-running the analyser on its current
	 * content no longer reproduces the same rule match (e.g. it was cleaned by hand, or a
	 * signature update no longer flags it). Database-row findings (post:/option:/etc.) have no
	 * single file to re-check and are left as-is.
	 *
	 * @return array{checked:int,resolved:int,kept:int}
	 */
	public function refresh_findings( int $limit = 500 ): array {
		$rows    = $this->findings( 'open', $limit );
		$checked = count( $rows );
		$resolved = 0;

		$allow_hashes = array();
		try {
			$allow_hashes = ( new \TotalSecurityWP\Modules\Integrity\PluginChecksums() )->official_hash_set();
		} catch ( \Throwable $e ) {
			// Fail open — refresh still runs, just without the checksum-trust shortcut.
		}

		$scanner = $this->make_scanner();

		foreach ( $rows as $row ) {
			$id   = (int) ( $row['id'] ?? 0 );
			$path = (string) ( $row['path'] ?? '' );
			if ( ! $id || '' === $path ) {
				continue;
			}

			// Stale: the file no longer exists on disk — no longer a threat.
			if ( ! empty( $row['file_missing'] ) ) {
				$this->set_finding_status( $id, 'resolved' );
				$resolved++;
				continue;
			}

			if ( $this->is_db_finding_path( $path ) ) {
				continue; // No single file to re-check; leave open for manual review.
			}

			if ( ! is_file( $path ) || ! is_readable( $path ) ) {
				continue; // Ambiguous — leave open rather than guess.
			}

			$content = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( false === $content ) {
				continue;
			}

			if ( $allow_hashes && isset( $allow_hashes[ hash( 'sha256', $content ) ] ) ) {
				$this->set_finding_status( $id, 'resolved' );
				$resolved++;
				continue;
			}

			// Re-run the analyser on the current content; if this finding's specific rule no
			// longer matches, it's stale (manually cleaned, or the signature itself changed).
			$fresh      = $scanner->analyse( $path, $content );
			$rule       = (string) ( $row['rule'] ?? '' );
			$still_open = false;
			foreach ( $fresh as $f ) {
				if ( $f->rule === $rule ) {
					$still_open = true;
					break;
				}
			}
			if ( ! $still_open ) {
				$this->set_finding_status( $id, 'resolved' );
				$resolved++;
				continue;
			}

			// The finding stands, but its auto-drafted patch suggestion may not:
			// PatchSuggester's criteria evolve (it now declines plugin-wide drafts for files
			// matching their official WordPress.org checksums), so re-draft from the fresh
			// analysis and let a now-null result clear the stored one — that's what actually
			// empties stale rows out of the Firewall panel's review queue. Only rows still
			// awaiting review are touched (reviewed ones are history), and only on an exact
			// (rule, line) match so a same-rule finding at another line — which carries a
			// different tainted param and would draft a different rule — can't overwrite it.
			if ( '' !== (string) ( $row['patch_status'] ?? '' ) || '' === (string) ( $row['suggested_patch'] ?? '' ) ) {
				continue;
			}
			foreach ( $fresh as $f ) {
				if ( $f->rule !== $rule || $f->line !== (int) ( $row['line'] ?? 0 ) ) {
					continue;
				}
				$suggestion = $this->suggest_for( $f );
				$encoded    = null === $suggestion ? '' : (string) wp_json_encode( $suggestion );
				if ( $encoded !== (string) $row['suggested_patch'] ) {
					$this->update_suggested_patch( $id, $suggestion );
				}
				break;
			}
		}

		return array( 'checked' => $checked, 'resolved' => $resolved, 'kept' => $checked - $resolved );
	}

	/**
	 * Whether a finding path is a database-row locator (post:/option:/user:/etc.) rather than a
	 * real filesystem path. Shared by {@see findings()} and {@see refresh_findings()}. Also covers
	 * `plugin:`/`core:` — the pseudo-paths VulnerabilityScanner::scan() writes for CVE findings
	 * (e.g. `plugin:woocommerce`, `core:wordpress`); without these, `file_exists()` on a
	 * non-existent literal path like that flagged them `file_missing`, and refresh_findings()
	 * auto-resolved otherwise-valid, still-applicable CVEs that then reappeared on the next CVE
	 * check.
	 */
	private function is_db_finding_path( string $path ): bool {
		foreach ( array( 'post:', 'option:', 'user:', 'theme:', 'comment:', 'usermeta:', 'mu:', 'dropin:', 'plugin:', 'core:' ) as $prefix ) {
			if ( str_starts_with( $path, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Fetch a single finding row.
	 *
	 * @return array<string, mixed>|null
	 */
	public function get_finding( int $id ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare( "SELECT * FROM %i WHERE id = %d", $this->findings_table(), $id ),
			ARRAY_A
		);
		return $row ?: null;
	}

	/**
	 * Overwrite a finding's stored suggestion — used when ScannerController::finding_patch()
	 * recomputes a stale one (drafted before PatchSuggester gained a field/rule type it now
	 * has) right before acting on it, so the refreshed shape sticks for future actions too,
	 * not just the current request. Passing null clears the draft entirely — used by
	 * {@see refresh_findings()} when PatchSuggester declines to re-draft one it previously
	 * produced (e.g. the file is now recognised as pristine official vendor code).
	 *
	 * @param array{rule: array<string, mixed>, confidence: string, reason: string}|null $suggestion
	 */
	public function update_suggested_patch( int $id, ?array $suggestion ): bool {
		global $wpdb;
		$updated = $wpdb->update( // phpcs:ignore WordPress.DB
			$this->findings_table(),
			array( 'suggested_patch' => null === $suggestion ? '' : (string) wp_json_encode( $suggestion ) ),
			array( 'id' => $id )
		);
		return false !== $updated;
	}

	/**
	 * Weekly automatic full scan (Cron::SCAN), driven in batches; a scan that doesn't finish
	 * within this cron run continues via CONTINUE_HOOK.
	 */
	public function run_scheduled(): void {
		/**
		 * Filters whether the built-in weekly scan runs. An add-on that schedules its own,
		 * more frequent scans can return false to avoid scanning twice.
		 *
		 * @param bool $run Default true.
		 */
		if ( ! apply_filters( 'totalsecwp_run_weekly_scan', true ) ) {
			return;
		}
		if ( ! $this->setting( 'scheduled_scan', true ) ) {
			return;
		}
		$start = $this->start( 'full' );
		$scan_id = $start['scan_id'];

		// Bounded loop so a runaway cron can't hang; remaining batches resume next cron.
		$deadline = time() + 50;
		do {
			$progress = $this->run_batch( $scan_id );
		} while ( 'running' === ( $progress['status'] ?? '' ) && time() < $deadline );
	}

}
