<?php
/**
 * Incident response module.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\AbstractModule;
use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Support\Filesystem;
use TotalSecurityWP\Support\JobStore;

/**
 * Exposes the quarantine, recovery, and permission-reset tools and records each action in
 * the audit log.
 */
class IncidentModule extends AbstractModule {

	public function id(): string {
		return 'incident';
	}

	public function title(): string {
		return __( 'Incident Response', 'loyal-security' );
	}

	/** Cron hooks for the async incident operations (dispatched from RepairController). */
	public const JOB_REPAIR_PLUGIN = 'totalsecwp_incident_repair_plugin';
	public const JOB_REPAIR_BULK   = 'totalsecwp_incident_repair_bulk';
	public const JOB_CLEAR_BACKUPS = 'totalsecwp_incident_clear_backups';

	public function default_settings(): array {
		return array(
			'enabled'                => true,
			'perm_dir_mode'          => 0755,
			'perm_file_mode'         => 0644,
			'auto_remove_core_extras' => true,
			'enable_file_fix'        => true,
			// Remind the admin to clear repair backups once they exceed this many bytes
			// (default 250 MB). One reinstall snapshot of a large plugin is easily this big.
			'backup_size_threshold'  => 250 * 1024 * 1024,
		);
	}

	public function register_hooks(): void {
		// Arm the fatal-error safety net so an in-flight file fix or plugin reinstall can self-heal.
		( new RepairGuard( $this->logger() ) )->arm();

		// Background drivers for the async repair / maintenance jobs. Each writes progress to the
		// JobStore so the dashboard can poll /jobs/{id} for a live, plain-language activity feed.
		add_action( self::JOB_REPAIR_PLUGIN, array( $this, 'run_repair_plugin_job' ), 10, 2 );
		add_action( self::JOB_REPAIR_BULK, array( $this, 'run_repair_bulk_job' ), 10, 2 );
		add_action( self::JOB_CLEAR_BACKUPS, array( $this, 'run_clear_backups_job' ), 10, 1 );

		// Watch backup storage growth and remind the admin to clear it once it crosses the
		// configured size threshold (fires right after each new snapshot is recorded).
		add_action( 'totalsecwp_repair_backup_recorded', array( $this, 'audit_backup_storage' ) );
	}

	public function quarantine(): Quarantine {
		return new Quarantine();
	}

	/**
	 * Resolve a finding path to an absolute filesystem path. Scanner findings already store
	 * an absolute path; integrity findings store one relative to the WordPress root (e.g.
	 * `hack.php`, `wp-admin/foo.php`), so anchor those on ABSPATH before any file operation.
	 */
	private function resolve_finding_path( string $path ): string {
		if ( '' === $path || path_is_absolute( $path ) ) {
			return $path;
		}
		return \TotalSecurityWP\Support\Paths::root() . ltrim( $path, '/\\' );
	}

	public function recovery(): Recovery {
		return new Recovery();
	}

	/**
	 * Quarantine a file and log it.
	 *
	 * @return array<string, mixed>
	 */
	public function quarantine_file( string $path, string $reason = '', ?int $finding_id = null ): array {
		$path = $this->resolve_finding_path( $path );
		$res  = $this->quarantine()->add( $path, $reason, $finding_id );
		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::QUARANTINE_ADD, array( 'path' => $path, 'id' => $res['id'] ?? 0 ) );
		}
		return $res;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function restore_file( int $id ): array {
		$res = $this->quarantine()->restore( $id );
		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::QUARANTINE_RESTORE, array( 'id' => $id ) );
		}
		return $res;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function recover_core(): array {
		$res = $this->recovery()->recover_all_core();
		$this->logger()->log( EventCatalog::FILE_RECOVERED, array( 'recovered' => count( $res['recovered'] ), 'failed' => count( $res['failed'] ) ) );
		return $res;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function reset_permissions( string $root = '' ): array {
		$reset = new PermissionsReset(
			(int) $this->setting( 'perm_dir_mode', 0755 ),
			(int) $this->setting( 'perm_file_mode', 0644 )
		);
		$result = $reset->apply( $root ?: \TotalSecurityWP\Support\Paths::root() );
		$this->logger()->log( EventCatalog::PERMISSIONS_RESET, $result );
		return $result;
	}

	/**
	 * Reinstall clean WordPress core for the running version.
	 *
	 * @return array<string, mixed>
	 */
	public function repair_core(): array {
		$res = ( new CoreRepair() )->repair( (bool) $this->setting( 'auto_remove_core_extras', true ) );
		if ( ! empty( $res['ok'] ) ) {
			$res['resolved'] = $this->resolve_core_findings();
		}
		$this->logger()->log(
			EventCatalog::CORE_REPAIRED,
			array(
				'replaced' => count( $res['replaced'] ?? array() ),
				'removed'  => count( $res['removed'] ?? array() ),
				'failed'   => count( $res['failed'] ?? array() ),
				'ok'       => ! empty( $res['ok'] ),
			)
		);
		return $res;
	}

	/**
	 * Mark open findings on core files as resolved after a successful core reinstall — the
	 * core tree is now verified clean against the official checksums.
	 *
	 * @return int Findings resolved.
	 */
	private function resolve_core_findings(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'totalsecwp_scan_findings';
		// Normalise separators so Windows-stored backslash paths match too.
		return (int) $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- bulk status update.
			$wpdb->prepare(
				"UPDATE %i SET status = 'resolved' WHERE status = 'open' AND ( REPLACE( path, '\\\\', '/' ) LIKE %s OR REPLACE( path, '\\\\', '/' ) LIKE %s )",
				$table,
				$wpdb->esc_like( wp_normalize_path( \TotalSecurityWP\Support\Paths::admin() ) . '/' ) . '%',
				$wpdb->esc_like( wp_normalize_path( \TotalSecurityWP\Support\Paths::includes() ) . '/' ) . '%'
			)
		);
	}

	/**
	 * List installed plugins split into auto-repairable vs manual-only.
	 *
	 * @return array<string, mixed>
	 */
	public function plugin_inventory(): array {
		return ( new PluginRepair() )->inventory();
	}

	/**
	 * Slugs of every installed plugin that can be auto-reinstalled from WordPress.org.
	 *
	 * @return array<int,string>
	 */
	public function plugin_inventory_slugs(): array {
		return ( new PluginRepair() )->repairable_slugs();
	}

	/**
	 * Verify a WordPress.org plugin against the official checksums and clear false positives:
	 * any open finding on a file whose hash matches the official copy is auto-resolved (it is
	 * provably the unmodified WordPress.org file, so the heuristic flag was a false positive).
	 * Findings on files that genuinely differ from the official copy are left open. This is the
	 * right tool for a freshly (re)installed plugin that is still showing flagged files — no
	 * pointless reinstall required.
	 *
	 * @return array{ok:bool,cleared:int,kept:int,message:string}
	 */
	public function verify_plugin_findings( string $slug ): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$version = '';
		foreach ( get_plugins() as $file => $data ) {
			if ( dirname( $file ) === $slug ) {
				$version = isset( $data['Version'] ) ? (string) $data['Version'] : '';
				break;
			}
		}
		if ( '.' === $slug || '' === $version ) {
			return array( 'ok' => false, 'cleared' => 0, 'kept' => 0, 'message' => __( 'This plugin can’t be verified against WordPress.org.', 'loyal-security' ) );
		}

		$modified = ( new \TotalSecurityWP\Modules\Integrity\PluginChecksums() )->verify_plugin( $slug, $version );
		if ( null === $modified ) {
			return array( 'ok' => false, 'cleared' => 0, 'kept' => 0, 'message' => __( 'No official checksums available for this plugin/version (premium or custom code).', 'loyal-security' ) );
		}

		// Normalised set of files that differ from the official copy.
		$plugin_dir   = wp_normalize_path( \TotalSecurityWP\Support\Paths::plugin( $slug ) );
		$modified_set = array();
		foreach ( $modified as $rel ) {
			$modified_set[ wp_normalize_path( $plugin_dir . '/' . ltrim( (string) $rel, '/' ) ) ] = true;
		}

		$scanner = \TotalSecurityWP\Plugin::instance()->module( 'scanner' );
		if ( ! $scanner instanceof \TotalSecurityWP\Modules\Scanner\ScannerModule ) {
			return array( 'ok' => false, 'cleared' => 0, 'kept' => 0, 'message' => __( 'The scanner module is unavailable.', 'loyal-security' ) );
		}

		$cleared = 0;
		$kept    = 0;
		foreach ( $scanner->findings( 'open', 1000 ) as $f ) {
			$path = wp_normalize_path( (string) ( $f['path'] ?? '' ) );
			// Only findings that live inside this plugin's directory.
			if ( '' === $path || 0 !== strpos( $path, trailingslashit( $plugin_dir ) ) ) {
				continue;
			}
			if ( isset( $modified_set[ $path ] ) ) {
				$kept++; // Genuinely differs from the official file — leave it for review.
				continue;
			}
			// Matches the official WordPress.org hash → false positive → resolve it.
			$scanner->set_finding_status( (int) $f['id'], 'resolved' );
			$cleared++;
		}

		$this->logger()->log(
			EventCatalog::PLUGIN_REPAIRED,
			array( 'slug' => $slug, 'verified' => true, 'cleared' => $cleared, 'kept' => $kept )
		);

		$message = $kept > 0
			? sprintf(
				/* translators: 1: cleared count, 2: remaining count */
				__( 'Verified against WordPress.org: cleared %1$d false positive(s); %2$d file(s) still differ from the official copy and were kept for review.', 'loyal-security' ),
				$cleared,
				$kept
			)
			: sprintf(
				/* translators: %d: cleared count */
				__( 'Verified clean against WordPress.org — cleared %d false positive(s). This plugin matches the official copy exactly.', 'loyal-security' ),
				$cleared
			);

		return array( 'ok' => true, 'cleared' => $cleared, 'kept' => $kept, 'message' => $message );
	}

	/**
	 * Group open findings into one-click repair actions (core / wp.org plugins).
	 *
	 * @return array<string, mixed>
	 */
	public function triage_findings(): array {
		return ( new FindingTriage() )->build();
	}

	/**
	 * Reinstall a WordPress.org plugin's clean code.
	 *
	 * @return array<string, mixed>
	 */
	public function repair_plugin( string $slug ): array {
		$res = ( new PluginRepair() )->repair( $slug );
		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::PLUGIN_REPAIRED, array( 'slug' => $slug ) );
		}
		return $res;
	}

	/**
	 * Best-effort clean of a single infected file (premium/custom code).
	 *
	 * @return array<string, mixed>
	 */
	public function fix_file( string $path, ?int $finding_id = null ): array {
		if ( ! $this->setting( 'enable_file_fix', true ) ) {
			return array( 'ok' => false, 'message' => __( 'Automatic file fixing is disabled.', 'loyal-security' ) );
		}

		$path = $this->resolve_finding_path( $path );
		$res  = ( new FileFix() )->attempt( $path, $finding_id );

		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::FILE_FIX_APPLIED, array( 'path' => $path, 'removed' => $res['removed'] ?? 0 ) );
			if ( $finding_id ) {
				$scanner = \TotalSecurityWP\Plugin::instance()->module( 'scanner' );
				if ( $scanner instanceof \TotalSecurityWP\Modules\Scanner\ScannerModule ) {
					$scanner->set_finding_status( $finding_id, 'resolved' );
				}
			}
		} elseif ( ! empty( $res['reverted'] ) ) {
			$this->logger()->log( EventCatalog::FILE_FIX_REVERTED, array( 'path' => $path ) );
		}

		return $res;
	}

	/**
	 * Permanently remove a file, guarded by a backup + loopback health check. If deleting the
	 * file breaks the site (a fatal on the front page or login), the backup is restored
	 * automatically — so a wrong call can never leave the site down. The backup is retained
	 * (listed in the Repair Center) so the deletion stays reversible.
	 *
	 * @return array<string, mixed>
	 */
	public function remove_file( string $path, ?int $finding_id = null ): array {
		$path = wp_normalize_path( $this->resolve_finding_path( $path ) );

		if ( ! is_file( $path ) ) {
			return array( 'ok' => false, 'message' => __( 'File not found.', 'loyal-security' ) );
		}
		// Never delete our own plugin files or wp-config.php.
		if ( false !== strpos( $path, wp_normalize_path( TOTALSECWP_PATH ) ) ) {
			return array( 'ok' => false, 'message' => __( 'Refusing to delete Loyal Security\'s own files.', 'loyal-security' ) );
		}
		if ( 'wp-config.php' === basename( $path ) ) {
			return array( 'ok' => false, 'message' => __( 'Refusing to delete wp-config.php.', 'loyal-security' ) );
		}

		$backups   = new RepairBackup();
		$backup_id = $backups->backup_file( $path, 'delete:' . basename( $path ) );
		if ( '' === $backup_id ) {
			return array( 'ok' => false, 'message' => __( 'Could not back up the file; aborting deletion for safety.', 'loyal-security' ) );
		}

		if ( ! Filesystem::delete( $path ) ) {
			return array( 'ok' => false, 'message' => __( 'Could not delete the file (check permissions).', 'loyal-security' ) );
		}

		// Verify the site still loads; restore immediately if the deletion broke it.
		$health = ( new Loopback() )->check();
		if ( ! $health['ok'] ) {
			$backups->restore( $backup_id );
			$this->logger()->log( EventCatalog::FILE_DELETE_REVERTED, array( 'path' => $path ) );
			return array(
				'ok'       => false,
				'reverted' => true,
				'message'  => __( 'Deleting this file broke the site, so it was automatically restored. Quarantine it instead.', 'loyal-security' ),
			);
		}

		$this->logger()->log( EventCatalog::FILE_DELETED, array( 'path' => $path, 'backup_id' => $backup_id ) );
		if ( $finding_id ) {
			$scanner = \TotalSecurityWP\Plugin::instance()->module( 'scanner' );
			if ( $scanner instanceof \TotalSecurityWP\Modules\Scanner\ScannerModule ) {
				$scanner->set_finding_status( $finding_id, 'resolved' );
			}
		}

		return array(
			'ok'        => true,
			'backup_id' => $backup_id,
			'message'   => __( 'File deleted. A backup was kept (restorable from the Repair Center) and the site verified healthy.', 'loyal-security' ),
		);
	}

	/**
	 * Non-executing inspection of a file: returns the source and a dry-run of what the
	 * surgical fixer would remove, for the dashboard code inspector.
	 *
	 * @return array<string, mixed>
	 */
	public function preview_fix( string $path ): array {
		$path = $this->resolve_finding_path( $path );
		return ( new FileFix() )->preview( $path );
	}

	/* ------------------------------------------------------------------ *
	 * Async jobs (dispatched from RepairController, run on WP-Cron).
	 * ------------------------------------------------------------------ */

	/**
	 * Queue a background job and kick WP-Cron so it starts immediately. Returns the job id the
	 * dashboard polls. Mirrors the BackupController pattern (async-first; a sync fallback lives
	 * in the controller for hosts where the loopback cron never fires).
	 *
	 * @param string             $hook Cron hook constant.
	 * @param string             $type Job type slug stored in the JobStore.
	 * @param array<int,mixed>   $args Extra cron args appended after the job id.
	 * @param array<string,mixed> $meta Extra JobStore metadata.
	 */
	public function dispatch_job( string $hook, string $type, array $args = array(), array $meta = array() ): string {
		$job_id = JobStore::create( $type, $meta );
		wp_schedule_single_event( time() - 1, $hook, array_merge( array( $job_id ), $args ) );

		// Non-blocking loopback so the queued event runs now instead of on the next page view.
		wp_remote_post(
			add_query_arg( 'doing_wp_cron', '1', site_url( '/' ) ),
			array( 'timeout' => 0.01, 'blocking' => false, 'sslverify' => \TotalSecurityWP\Support\Http::local_sslverify(), 'body' => array() )
		);

		return $job_id;
	}

	/**
	 * WP-Cron handler: reinstall a single WordPress.org plugin with live progress.
	 */
	public function run_repair_plugin_job( string $job_id, string $slug ): void {
		try {
			JobStore::progress( $job_id, 2, sprintf( /* translators: plugin slug */ __( 'Preparing to reinstall “%s”…', 'loyal-security' ), $slug ) );
			$res = ( new PluginRepair() )->repair(
				$slug,
				static function ( int $pct, string $msg ) use ( $job_id ): void {
					JobStore::progress( $job_id, max( 1, min( 99, $pct ) ), $msg );
				}
			);
			if ( ! empty( $res['ok'] ) ) {
				$this->logger()->log( EventCatalog::PLUGIN_REPAIRED, array( 'slug' => $slug ) );
				JobStore::complete( $job_id, $res['message'] ?? __( 'Plugin reinstalled.', 'loyal-security' ), $res );
			} else {
				JobStore::fail( $job_id, $res['message'] ?? __( 'Plugin repair failed.', 'loyal-security' ) );
			}
		} catch ( \Throwable $e ) {
			JobStore::fail( $job_id, $e->getMessage() );
		}
	}

	/**
	 * WP-Cron handler: reinstall many WordPress.org plugins in sequence with per-plugin progress.
	 *
	 * @param string            $job_id Job id.
	 * @param array<int,string> $slugs  Plugin slugs to reinstall.
	 */
	public function run_repair_bulk_job( string $job_id, array $slugs ): void {
		try {
			$slugs = array_values( array_filter( array_map( 'strval', $slugs ) ) );
			$total = count( $slugs );
			if ( 0 === $total ) {
				JobStore::complete( $job_id, __( 'Nothing to reinstall.', 'loyal-security' ), array( 'ok' => 0, 'failed' => 0, 'results' => array() ) );
				return;
			}

			$repair  = new PluginRepair();
			$ok      = 0;
			$failed  = 0;
			$results = array();

			foreach ( $slugs as $i => $slug ) {
				$base = (int) floor( ( $i / $total ) * 100 );
				$span = (int) floor( ( 1 / $total ) * 100 );
				JobStore::progress(
					$job_id,
					max( 1, min( 99, $base ) ),
					sprintf( /* translators: 1: index, 2: total, 3: slug */ __( 'Reinstalling %1$d of %2$d: %3$s…', 'loyal-security' ), $i + 1, $total, $slug )
				);

				$res = $repair->repair(
					$slug,
					static function ( int $pct, string $msg ) use ( $job_id, $base, $span ): void {
						$scaled = $base + (int) floor( ( $pct / 100 ) * $span );
						JobStore::progress( $job_id, max( 1, min( 99, $scaled ) ), $msg );
					}
				);

				if ( ! empty( $res['ok'] ) ) {
					$ok++;
					$this->logger()->log( EventCatalog::PLUGIN_REPAIRED, array( 'slug' => $slug, 'bulk' => true ) );
				} else {
					$failed++;
				}
				$results[] = array( 'slug' => $slug, 'ok' => ! empty( $res['ok'] ), 'message' => $res['message'] ?? '' );
			}

			JobStore::complete(
				$job_id,
				sprintf(
					/* translators: 1: succeeded, 2: failed */
					__( 'Reinstall finished — %1$d succeeded, %2$d failed.', 'loyal-security' ),
					$ok,
					$failed
				),
				array( 'ok' => $ok, 'failed' => $failed, 'results' => $results )
			);
		} catch ( \Throwable $e ) {
			JobStore::fail( $job_id, $e->getMessage() );
		}
	}

	/**
	 * WP-Cron handler: delete every repair backup with live progress.
	 */
	public function run_clear_backups_job( string $job_id ): void {
		try {
			JobStore::progress( $job_id, 3, __( 'Scanning saved backups…', 'loyal-security' ) );
			$res = ( new RepairBackup() )->clear_all(
				static function ( int $done, int $total, string $msg ) use ( $job_id ): void {
					$pct = $total > 0 ? (int) floor( ( $done / $total ) * 100 ) : 99;
					JobStore::progress( $job_id, max( 1, min( 99, $pct ) ), $msg );
				}
			);
			delete_option( 'totalsecwp_repair_backup_reminder' );
			JobStore::complete(
				$job_id,
				sprintf(
					/* translators: 1: count, 2: human-readable size */
					__( 'Cleared %1$d backup(s), freed %2$s.', 'loyal-security' ),
					(int) $res['deleted'],
					(string) $res['freed_human']
				),
				$res
			);
		} catch ( \Throwable $e ) {
			JobStore::fail( $job_id, $e->getMessage() );
		}
	}

	/* ------------------------------------------------------------------ *
	 * Backup management surface.
	 * ------------------------------------------------------------------ */

	/**
	 * Aggregate backup stats + the current reminder state for the dashboard.
	 *
	 * @return array<string,mixed>
	 */
	public function backups_summary(): array {
		$summary   = ( new RepairBackup() )->summary();
		$threshold = (int) $this->setting( 'backup_size_threshold', 250 * 1024 * 1024 );
		$summary['threshold']        = $threshold;
		$summary['threshold_human']  = size_format( $threshold, 1 ) ?: '0 B';
		$summary['over_threshold']   = $summary['bytes'] >= $threshold;
		return $summary;
	}

	/**
	 * Delete one repair backup.
	 */
	public function delete_backup( string $id ): bool {
		return ( new RepairBackup() )->delete( $id );
	}

	/**
	 * Synchronous clear-all (used as the controller's fallback when cron can't be kicked).
	 *
	 * @return array<string,mixed>
	 */
	public function clear_backups(): array {
		$res = ( new RepairBackup() )->clear_all();
		delete_option( 'totalsecwp_repair_backup_reminder' );
		return $res;
	}

	/**
	 * Check accumulated repair-backup storage against the configured threshold; when exceeded,
	 * record a (throttled) audit event the Notifications module routes, and persist a reminder
	 * the dashboard surfaces. Fired after each new snapshot via `totalsecwp_repair_backup_recorded`.
	 */
	public function audit_backup_storage(): void {
		$threshold = (int) $this->setting( 'backup_size_threshold', 250 * 1024 * 1024 );
		if ( $threshold <= 0 ) {
			return;
		}
		$summary = ( new RepairBackup() )->summary();
		if ( $summary['bytes'] < $threshold ) {
			return;
		}

		// Persist the reminder for the dashboard banner (cheap, non-autoloaded).
		update_option(
			'totalsecwp_repair_backup_reminder',
			array(
				'bytes'      => $summary['bytes'],
				'size_human' => $summary['size_human'],
				'count'      => $summary['count'],
				'at'         => gmdate( 'Y-m-d H:i:s' ),
			),
			false
		);

		// Throttle the alert event to once per day so a burst of reinstalls doesn't spam.
		if ( false === get_transient( 'totalsecwp_backup_storage_alerted' ) ) {
			set_transient( 'totalsecwp_backup_storage_alerted', 1, DAY_IN_SECONDS );
			$this->logger()->log(
				EventCatalog::BACKUP_STORAGE_HIGH,
				array(
					'size'       => $summary['size_human'],
					'count'      => $summary['count'],
					'threshold'  => size_format( $threshold, 1 ),
				)
			);
		}
	}

	/**
	 * Restore a repair backup by id.
	 *
	 * @return array<string, mixed>
	 */
	public function restore_backup( string $id ): array {
		$res = ( new RepairBackup() )->restore( $id );
		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::BACKUP_RESTORED, array( 'id' => $id ) );
		}
		return $res;
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function list_backups(): array {
		return ( new RepairBackup() )->list();
	}
}
