<?php
/**
 * Base class for all security modules.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Core;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Container;
use LoyalSecurity\Contracts\ModuleInterface;
use LoyalSecurity\Modules\Audit\Logger;

/**
 * Provides shared plumbing (settings access, logging, enable gate) so concrete modules
 * only implement their domain logic. Services are resolved lazily from the container to
 * keep modules decoupled from one another.
 */
abstract class AbstractModule implements ModuleInterface {

	protected Container $container;

	public function __construct( Container $container ) {
		$this->container = $container;
	}

	/**
	 * Convenience accessor for the settings repository.
	 */
	protected function settings(): Settings {
		return $this->container->make( 'settings' );
	}

	/**
	 * Convenience accessor for the audit logger.
	 */
	protected function logger(): Logger {
		return $this->container->make( 'logger' );
	}

	/**
	 * Read a setting scoped to this module.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	protected function setting( string $key, $default = null ) {
		return $this->settings()->get( $this->id(), $key, $default );
	}

	/**
	 * Modules are enabled by default unless their settings say otherwise.
	 */
	public function is_enabled(): bool {
		return (bool) $this->settings()->get( $this->id(), 'enabled', true );
	}

	/**
	 * Default boot is a no-op; modules override as needed.
	 */
	public function boot(): void {}

	/**
	 * Default hooks are none; modules override as needed.
	 */
	public function register_hooks(): void {}
}
