<?php
/**
 * REST router — registers every plugin controller.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Container;
use TotalSecurityWP\Rest\Controllers\StatusController;
use TotalSecurityWP\Rest\Controllers\SettingsController;
use TotalSecurityWP\Rest\Controllers\FirewallController;
use TotalSecurityWP\Rest\Controllers\ScannerController;
use TotalSecurityWP\Rest\Controllers\LogsController;
use TotalSecurityWP\Rest\Controllers\HardeningController;
use TotalSecurityWP\Rest\Controllers\QuarantineController;
use TotalSecurityWP\Rest\Controllers\RepairController;
use TotalSecurityWP\Rest\Controllers\AuthController;
use TotalSecurityWP\Rest\Controllers\WizardController;
use TotalSecurityWP\Rest\Controllers\NotificationsController;
use TotalSecurityWP\Rest\Controllers\BackupController;
use TotalSecurityWP\Rest\Controllers\ThreatIntelController;
use TotalSecurityWP\Rest\Controllers\TrafficController;
use TotalSecurityWP\Rest\Controllers\CspController;
use TotalSecurityWP\Rest\Controllers\JobsController;
use TotalSecurityWP\Rest\Controllers\TelemetryController;
use TotalSecurityWP\Rest\Controllers\UpgradeController;

/**
 * Instantiates and registers all REST controllers on `rest_api_init`. Controllers are
 * resolved through the container so they can reach modules and services.
 */
class RestRouter {

	private Container $container;

	/**
	 * Controller class list. Only classes that exist are registered, so the router can
	 * ship ahead of controllers that are added in later build phases.
	 *
	 * @var string[]
	 */
	private array $controllers = array(
		StatusController::class,
		SettingsController::class,
		FirewallController::class,
		ScannerController::class,
		LogsController::class,
		HardeningController::class,
		QuarantineController::class,
		RepairController::class,
		AuthController::class,
		WizardController::class,
		NotificationsController::class,
		BackupController::class,
		ThreatIntelController::class,
		TrafficController::class,
		CspController::class,
		JobsController::class,
		TelemetryController::class,
		UpgradeController::class,
	);

	public function __construct( Container $container ) {
		$this->container = $container;
	}

	public function register_hooks(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		foreach ( $this->controllers as $class ) {
			if ( ! class_exists( $class ) ) {
				continue;
			}
			/** @var AbstractController $controller */
			$controller = new $class( $this->container );
			$controller->register_routes();
		}
	}
}
