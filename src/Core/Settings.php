<?php
/**
 * Central settings repository.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Stores all plugin configuration in a single autoloaded option, namespaced per module:
 *
 *     [ 'firewall' => [ 'enabled' => true, … ], 'scanner' => [ … ], … ]
 *
 * Defaults are supplied by each module's `default_settings()` and merged on read so new
 * keys appear automatically after upgrades.
 */
class Settings {

	/**
	 * In-memory cache of the persisted option.
	 *
	 * @var array<string, array<string, mixed>>|null
	 */
	private ?array $cache = null;

	/**
	 * Per-module default settings, registered at boot by the Module Factory.
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private array $defaults = array();

	public function __construct() {
		// Keep the cache in step with writes that bypass this class (WP-CLI `wp option update`,
		// another plugin, a migration script). Priority 0 runs before the other listeners on
		// these hooks, such as the firewall's config writer, so they never read a stale copy.
		if ( function_exists( 'add_action' ) ) {
			add_action( 'update_option_' . LOYALSEC_OPTION_SETTINGS, array( $this, 'refresh_cache' ), 0, 2 );
			add_action( 'add_option_' . LOYALSEC_OPTION_SETTINGS, array( $this, 'refresh_cache_on_add' ), 0, 2 );
		}
	}

	/**
	 * `update_option_{option}`: adopt the value just written.
	 *
	 * @param mixed $old_value Previous value.
	 * @param mixed $value     New value.
	 */
	public function refresh_cache( $old_value, $value ): void {
		unset( $old_value );
		$this->cache = is_array( $value ) ? $value : array();
	}

	/**
	 * `add_option_{option}`: adopt the value just written.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  New value.
	 */
	public function refresh_cache_on_add( $option, $value ): void {
		unset( $option );
		$this->cache = is_array( $value ) ? $value : array();
	}

	/**
	 * Register a module's default settings.
	 *
	 * @param string               $module   Module id.
	 * @param array<string, mixed> $defaults Default values.
	 */
	public function register_defaults( string $module, array $defaults ): void {
		$this->defaults[ $module ] = $defaults;
	}

	/**
	 * Get a single setting value for a module.
	 *
	 * @param string $module  Module id.
	 * @param string $key     Setting key.
	 * @param mixed  $default Fallback if unset in both store and defaults.
	 * @return mixed
	 */
	public function get( string $module, string $key, $default = null ) {
		$all = $this->for_module( $module );
		if ( array_key_exists( $key, $all ) ) {
			return $all[ $key ];
		}
		return $default;
	}

	/**
	 * Get all (defaults-merged) settings for a module.
	 *
	 * @param string $module Module id.
	 * @return array<string, mixed>
	 */
	public function for_module( string $module ): array {
		$store    = $this->all();
		$defaults = $this->defaults[ $module ] ?? array();
		$stored   = $store[ $module ] ?? array();
		return array_merge( $defaults, is_array( $stored ) ? $stored : array() );
	}

	/**
	 * Update one setting and persist.
	 *
	 * @param string $module Module id.
	 * @param string $key    Setting key.
	 * @param mixed  $value  New value.
	 */
	public function set( string $module, string $key, $value ): void {
		$store = $this->all();
		if ( ! isset( $store[ $module ] ) || ! is_array( $store[ $module ] ) ) {
			$store[ $module ] = array();
		}
		$store[ $module ][ $key ] = $value;
		$this->save( $store );
	}

	/**
	 * Merge an array of settings into a module namespace and persist.
	 *
	 * @param string               $module Module id.
	 * @param array<string, mixed> $values Values to merge.
	 */
	public function update_module( string $module, array $values ): void {
		$store            = $this->all();
		$current          = isset( $store[ $module ] ) && is_array( $store[ $module ] ) ? $store[ $module ] : array();
		$store[ $module ] = array_merge( $current, $values );
		$this->save( $store );
	}

	/**
	 * Entire (raw, non-merged) settings store.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function all(): array {
		if ( null === $this->cache ) {
			$opt         = get_option( LOYALSEC_OPTION_SETTINGS, array() );
			$this->cache = is_array( $opt ) ? $opt : array();
		}
		return $this->cache;
	}

	/**
	 * Defaults-merged view of every registered module (for the settings UI).
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function all_merged(): array {
		$out = array();
		foreach ( array_keys( $this->defaults ) as $module ) {
			$out[ $module ] = $this->for_module( $module );
		}
		return $out;
	}

	/**
	 * Persist the store and invalidate cache.
	 *
	 * @param array<string, array<string, mixed>> $store Full store.
	 */
	private function save( array $store ): void {
		$this->cache = $store;
		update_option( LOYALSEC_OPTION_SETTINGS, $store, true );
	}
}
