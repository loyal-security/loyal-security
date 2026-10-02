<?php
/**
 * Module contract.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Contracts;

defined( 'ABSPATH' ) || exit;

/**
 * Every security engine (WAF, Hardening, Scanner, …) implements this interface and
 * is instantiated by the central Module Factory in {@see \TotalSecurityWP\Plugin}.
 */
interface ModuleInterface {

	/**
	 * Stable machine id used as the settings namespace and REST key.
	 */
	public function id(): string;

	/**
	 * Human-readable label for the dashboard.
	 */
	public function title(): string;

	/**
	 * Register WordPress hooks. Called for every module regardless of enabled state
	 * (so a module can still expose minimal hooks), but heavy work belongs in boot().
	 */
	public function register_hooks(): void;

	/**
	 * Perform runtime work. Only called when {@see is_enabled()} returns true.
	 */
	public function boot(): void;

	/**
	 * Default settings for this module, merged into the central settings repository.
	 *
	 * @return array<string, mixed>
	 */
	public function default_settings(): array;

	/**
	 * Whether the module is currently enabled in settings.
	 */
	public function is_enabled(): bool;
}
