<?php
/**
 * REST router — registers every plugin controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Container;
use LoyalSecurity\Rest\Controllers\StatusController;
use LoyalSecurity\Rest\Controllers\SettingsController;
use LoyalSecurity\Rest\Controllers\FirewallController;
use LoyalSecurity\Rest\Controllers\ScannerController;
use LoyalSecurity\Rest\Controllers\LogsController;
use LoyalSecurity\Rest\Controllers\HardeningController;
use LoyalSecurity\Rest\Controllers\QuarantineController;
use LoyalSecurity\Rest\Controllers\RepairController;
use LoyalSecurity\Rest\Controllers\AuthController;
use LoyalSecurity\Rest\Controllers\WizardController;
use LoyalSecurity\Rest\Controllers\NotificationsController;
use LoyalSecurity\Rest\Controllers\BackupController;
use LoyalSecurity\Rest\Controllers\ThreatIntelController;
use LoyalSecurity\Rest\Controllers\TrafficController;
use LoyalSecurity\Rest\Controllers\CspController;
use LoyalSecurity\Rest\Controllers\JobsController;
use LoyalSecurity\Rest\Controllers\TelemetryController;
use LoyalSecurity\Rest\Controllers\UpgradeController;

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
