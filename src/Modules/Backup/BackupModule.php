<?php
/**
 * Backup & Recovery module.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Backup;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\AbstractModule;
use TotalSecurityWP\Core\Cron;
use TotalSecurityWP\Modules\Audit\EventCatalog;

/**
 * Coordinates on-demand and scheduled backups (files, or files + database), enforces a
 * retention cap, and owns the standalone-recovery secret. Restores are performed by
 * {@see RestoreEngine} (in-dashboard) or the hardened, runtime-generated standalone recovery
 * script (when WordPress cannot boot) — see {@see RecoveryAuth} and {@see RecoveryScriptTemplate}.
 */
class BackupModule extends AbstractModule {

	public function id(): string {
		return 'backup';
	}

	public function title(): string {
		return __( 'Backup & Recovery', 'loyal-security' );
	}

	/** Recurring cron hook that runs an automatic backup. */
	public const SCHEDULE_HOOK = 'totalsecwp_scheduled_backup';

	public function default_settings(): array {
		return array(
			'enabled'         => true,
			'include_db'      => true,
			'include_uploads' => true,
			'max_backups'     => 5,
			// Automatic backup cadence: 'none' | 'weekly' | 'daily' — free on every tier.
			'schedule'        => 'none',
		);
	}

	public function register_hooks(): void {
		add_action( Cron::PRUNE_LOGS, array( $this, 'enforce_retention' ) );
		add_action( 'totalsecwp_run_backup', array( $this, 'run_backup_job' ), 10, 3 );
		add_action( self::SCHEDULE_HOOK, array( $this, 'run_scheduled_backup' ) );

		// Keep the recurring-backup cron in lock-step with the `schedule` setting whenever it
		// is saved (and reconcile once per load in boot() as a safety net). Without this the
		// dashboard toggle changed a setting that nothing ever acted on.
		add_action( 'update_option_totalsecwp_settings', array( $this, 'sync_backup_schedule' ) );
	}

	public function boot(): void {
		// Provision the protected storage directory early so its denies exist before any
		// archive is written.
		( new BackupStore() )->dir();

		// Reconcile the automatic-backup cron with the stored cadence once per load (covers
		// installs whose setting predates this feature, and a Pro→Free downgrade that must drop
		// a daily schedule back to weekly).
		$this->sync_backup_schedule();
	}

	/**
	 * Effective automatic-backup cadence: 'none' | 'weekly' | 'daily'.
	 *
	 */
	private function effective_schedule(): string {
		$freq = (string) $this->setting( 'schedule', 'none' );
		if ( ! in_array( $freq, array( 'none', 'weekly', 'daily' ), true ) ) {
			$freq = 'none';
		}
		return $freq;
	}

	/**
	 * Align the recurring-backup cron event with {@see effective_schedule()}. Idempotent —
	 * safe to call on every load and on every settings save.
	 */
	public function sync_backup_schedule(): void {
		$freq     = $this->effective_schedule();
		$existing = wp_get_schedule( self::SCHEDULE_HOOK ); // false when not scheduled.

		if ( 'none' === $freq ) {
			if ( false !== $existing ) {
				wp_unschedule_hook( self::SCHEDULE_HOOK );
			}
			return;
		}

		if ( $existing === $freq ) {
			return; // Already scheduled at the right cadence.
		}
		if ( false !== $existing ) {
			wp_unschedule_hook( self::SCHEDULE_HOOK );
		}
		wp_schedule_event( time() + HOUR_IN_SECONDS, $freq, self::SCHEDULE_HOOK );
	}

	/**
	 * Cron callback: run an automatic backup honouring the module's scope settings. Dispatched
	 * through the same async job path as a dashboard-triggered backup so retention and logging
	 * behave identically.
	 */
	public function run_scheduled_backup(): void {
		if ( 'none' === $this->effective_schedule() ) {
			return; // Setting turned off between scheduling and firing.
		}
		$scope  = $this->setting( 'include_db', true ) ? 'full' : 'files';
		$job_id = \TotalSecurityWP\Support\JobStore::create( 'backup', array( 'scope' => $scope, 'scheduled' => true ) );
		$this->run_backup_job( $job_id, $scope, null );
	}

	/**
	 * WP-Cron handler for async backup jobs dispatched by BackupController.
	 * Writes progress to JobStore so the dashboard can poll /jobs/{id}.
	 *
	 * @param string    $job_id          Job id created by JobStore::create().
	 * @param string    $scope           'full' | 'files'.
	 * @param bool|null $include_uploads Null means "use module default".
	 */
	public function run_backup_job( string $job_id, string $scope, ?bool $include_uploads ): void {
		try {
			\TotalSecurityWP\Support\JobStore::progress( $job_id, 5, 'Getting ready…' );
			$uploads = null === $include_uploads ? (bool) $this->setting( 'include_uploads', true ) : $include_uploads;
			$engine  = new BackupEngine( new BackupStore() );
			$res     = $engine->create(
				$scope,
				$uploads,
				static function ( int $pct, string $step ) use ( $job_id ): void {
					\TotalSecurityWP\Support\JobStore::progress( $job_id, $pct, $step );
				}
			);
			if ( ! empty( $res['ok'] ) ) {
				$m    = $res['manifest'] ?? [];
				$size = $res['size_human'] ?? '';
				$this->logger()->log( EventCatalog::BACKUP_CREATED, array(
					'id'    => $m['id'] ?? '',
					'scope' => $scope,
					'files' => $m['files'] ?? 0,
					'db'    => ! empty( $m['db_included'] ),
				) );
				$this->enforce_retention();
				\TotalSecurityWP\Support\JobStore::complete(
					$job_id,
					'Backup complete' . ( $size ? ' — ' . $size : '' ),
					$m
				);
			} else {
				\TotalSecurityWP\Support\JobStore::fail( $job_id, $res['message'] ?? 'Backup failed.' );
			}
		} catch ( \Throwable $e ) {
			\TotalSecurityWP\Support\JobStore::fail( $job_id, $e->getMessage() );
		}
	}

	/**
	 * Create a backup honouring the module settings.
	 *
	 * @return array<string,mixed>
	 */
	public function create( ?string $scope = null, ?bool $include_uploads = null ): array {
		$scope    = $scope ?: ( $this->setting( 'include_db', true ) ? 'full' : 'files' );
		$uploads  = null === $include_uploads ? (bool) $this->setting( 'include_uploads', true ) : $include_uploads;
		$res      = ( new BackupEngine() )->create( $scope, $uploads );

		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::BACKUP_CREATED, array(
				'id'    => $res['manifest']['id'] ?? '',
				'scope' => $scope,
				'files' => $res['manifest']['files'] ?? 0,
				'db'    => ! empty( $res['manifest']['db_included'] ),
			) );
			( new BackupStore() )->prune( $this->retention_cap() );
		}
		return $res;
	}

	/**
	 * How many backups to keep (the `max_backups` setting). Single source of truth for every
	 * prune site, so the async dashboard job and the synchronous create() always agree.
	 */
	private function retention_cap(): int {
		return max( 1, (int) $this->setting( 'max_backups', 5 ) );
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public function list_backups(): array {
		return ( new BackupStore() )->all();
	}

	public function delete_backup( string $id ): bool {
		return ( new BackupStore() )->delete( $id );
	}

	/**
	 * @return array<string,mixed>
	 */
	public function restore_backup( string $id, bool $files = true, bool $db = true ): array {
		$res = ( new RestoreEngine() )->restore( $id, $files, $db );
		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::BACKUP_RESTORED, array( 'id' => $id, 'files' => $res['files'] ?? 0 ) );
		}
		return $res;
	}

	public function recovery(): RecoveryAuth {
		return new RecoveryAuth();
	}

	public function enforce_retention(): void {
		( new BackupStore() )->prune( $this->retention_cap() );

		/**
		 * Fires after backup retention has been enforced (extension point for add-ons that keep
		 * data of their own alongside backups).
		 *
		 * @since 1.0.0
		 */
		do_action( 'totalsecwp_backup_retention_enforced' );
	}
}
