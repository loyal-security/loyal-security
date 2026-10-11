<?php
/**
 * Audit logging module.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Audit;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\AbstractModule;
use LoyalSecurity\Core\Cron;

/**
 * Wires the audit subscribers to WordPress events. The actual write path ({@see Logger})
 * is a shared container service so every other module can log without depending on this
 * module being enabled.
 */
class AuditModule extends AbstractModule {

	public function id(): string {
		return 'audit';
	}

	public function title(): string {
		return __( 'Audit Logging', 'loyal-security' );
	}

	public function default_settings(): array {
		return array(
			'enabled'            => true,
			'retention_days'     => 90,
			// Days of audit events to keep (older rows are pruned daily).
			'log_retention_days' => 90,
			// Log nopriv AJAX calls to *registered* plugin endpoints?
			// Default false: registered public endpoints are normal plugin behaviour.
			// Only unregistered action probes are genuinely suspicious.
			'monitor_registered_nopriv_ajax' => false,
		);
	}

	/**
	 * Public reader for a scoped setting (used by LogRepository::prune_to_limit()).
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public function setting_public( string $key, $default = null ) {
		return $this->setting( $key, $default );
	}

	public function register_hooks(): void {
		// Retention window for the shared prune path (Cron::prune_logs reads this): exactly the
		// retention the site owner configured.
		add_filter(
			'loyalsec_log_retention_days',
			function () {
				return max( 1, (int) $this->setting( 'log_retention_days', (int) $this->setting( 'retention_days', 90 ) ) );
			}
		);

		// Prune on the shared daily prune cron.
		add_action(
			Cron::PRUNE_LOGS,
			function () {
				( new LogRepository() )->prune_to_limit();
			}
		);
	}

	public function boot(): void {
		( new Subscribers( $this->logger() ) )->register();
	}
}
