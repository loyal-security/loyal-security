<?php
/**
 * Plugin bootstrap and central Module Factory.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Contracts\ModuleInterface;
use TotalSecurityWP\Core\Assets;
use TotalSecurityWP\Core\Cron;
use TotalSecurityWP\Core\Installer;
use TotalSecurityWP\Core\ProStatus;
use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Admin\AdminMenu;
use TotalSecurityWP\Admin\Notices;
use TotalSecurityWP\Admin\UninstallPrompt;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Rest\RestRouter;

/**
 * Singleton entry point. Wires the DI container, registers shared services, and runs the
 * Module Factory that instantiates every decoupled security engine.
 */
final class Plugin {

	private static ?Plugin $instance = null;

	private Container $container;

	/**
	 * Instantiated modules keyed by id.
	 *
	 * @var array<string, ModuleInterface>
	 */
	private array $modules = array();

	/**
	 * Module classes registered with the factory. Missing classes are skipped so the
	 * plugin stays runnable while modules are added build-phase by build-phase.
	 *
	 * @var string[]
	 */
	private array $module_classes = array(
		\TotalSecurityWP\Modules\Firewall\FirewallModule::class,
		\TotalSecurityWP\Modules\Hardening\HardeningModule::class,
		\TotalSecurityWP\Modules\Scanner\ScannerModule::class,
		\TotalSecurityWP\Modules\Integrity\IntegrityModule::class,
		\TotalSecurityWP\Modules\Incident\IncidentModule::class,
		\TotalSecurityWP\Modules\Auth\AuthModule::class,
		\TotalSecurityWP\Modules\Audit\AuditModule::class,
		\TotalSecurityWP\Modules\Notifications\NotificationsModule::class,
		\TotalSecurityWP\Modules\Backup\BackupModule::class,
		\TotalSecurityWP\Modules\ThreatIntel\ThreatIntelModule::class,
		\TotalSecurityWP\Modules\Traffic\TrafficModule::class,
		\TotalSecurityWP\Modules\Csp\CspModule::class,
		\TotalSecurityWP\Modules\Telemetry\TelemetryModule::class,
	);

	private function __construct() {
		$this->container = new Container();
	}

	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function container(): Container {
		return $this->container;
	}

	/**
	 * All instantiated modules.
	 *
	 * @return array<string, ModuleInterface>
	 */
	public function modules(): array {
		return $this->modules;
	}

	/**
	 * Fetch a single module by id.
	 */
	public function module( string $id ): ?ModuleInterface {
		return $this->modules[ $id ] ?? null;
	}

	/**
	 * Boot the plugin (called on `plugins_loaded`).
	 */
	public function boot(): void {
		Installer::maybe_install();

		$this->register_services();
		$this->boot_core_services();
		$this->register_modules();

		// WP-CLI commands (loaded only under the CLI runtime).
		if ( defined( 'WP_CLI' ) && \WP_CLI ) {
			require_once TOTALSECWP_PATH . 'src/Cli/TotalSecurityWPCommand.php';
			\WP_CLI::add_command( 'loyal-security', \TotalSecurityWP\Cli\TotalSecurityWPCommand::class );
		}

		/**
		 * Fires after Loyal Security has fully booted.
		 *
		 * @param Plugin $plugin
		 */
		do_action( 'totalsecwp_booted', $this );
	}

	/**
	 * Bind shared services into the container.
	 */
	private function register_services(): void {
		$c = $this->container;

		$c->instance( 'plugin', $this );

		$c->singleton( 'settings', static fn() => new Settings() );
		$c->singleton( 'logger', static fn( Container $c ) => new Logger( $c->make( 'settings' ) ) );
		$c->singleton( 'pro_status', static fn() => new ProStatus() );
		$c->singleton( 'cron', static fn() => new Cron() );
		$c->singleton( 'assets', static fn() => new Assets() );
		$c->singleton( 'rest', static fn( Container $c ) => new RestRouter( $c ) );
		$c->singleton( 'admin_menu', static fn( Container $c ) => new AdminMenu( $c ) );
		$c->singleton( 'notices', static fn() => new Notices() );
		$c->singleton( 'uninstall_prompt', static fn() => new UninstallPrompt() );
	}

	/**
	 * Attach hooks for the always-on core services.
	 */
	private function boot_core_services(): void {
		$this->container->make( 'cron' )->register_hooks();
		$this->container->make( 'assets' )->register_hooks();
		$this->container->make( 'rest' )->register_hooks();

		// Admin-bar score badge. Registered unconditionally because the admin bar renders on
		// the front end too; the node is capability-gated inside the class.
		( new \TotalSecurityWP\Admin\AdminBarScore() )->register_hooks();

		if ( is_admin() ) {
			$this->container->make( 'admin_menu' )->register_hooks();
			$this->container->make( 'notices' )->register_hooks();
			$this->container->make( 'uninstall_prompt' )->register_hooks();
		}
	}

	/**
	 * The Module Factory: instantiate each module, register its defaults and hooks, and
	 * boot it when enabled. Modules are resolved with the container injected so they can
	 * reach shared services without knowing about one another.
	 */
	private function register_modules(): void {
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );

		foreach ( $this->module_classes as $class ) {
			if ( ! class_exists( $class ) ) {
				continue;
			}

			// A module must never be able to white-screen the whole site. If instantiating,
			// registering, or booting one throws — including a fatal Error such as a missing
			// or host-quarantined class file — log it and carry on with the other modules.
			try {
				/** @var ModuleInterface $module */
				$module                         = new $class( $this->container );
				$this->modules[ $module->id() ] = $module;

				$settings->register_defaults( $module->id(), $module->default_settings() );

				// Make the module resolvable by id for cross-cutting needs.
				$this->container->instance( 'module.' . $module->id(), $module );

				$module->register_hooks();

				if ( $module->is_enabled() ) {
					$module->boot();
				}
			} catch ( \Throwable $e ) {
				if ( function_exists( 'error_log' ) ) {
					\TotalSecurityWP\Support\Debug::log( 'module ' . $class . ' failed to boot — ' . $e->getMessage() );
				}
				continue;
			}
		}
	}
}
