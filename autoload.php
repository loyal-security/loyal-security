<?php
/**
 * Built-in PSR-4 autoloader.
 *
 * Maps the `LoyalSecurity\` namespace prefix to the plugin's `src/` directory so
 * the plugin runs without `composer install`. A `composer.json` is still provided
 * for development tooling, but is never required at runtime.
 *
 * @package LoyalSecurity
 */

defined( 'ABSPATH' ) || exit;

spl_autoload_register(
	static function ( $class ) {
		$prefix   = 'LoyalSecurity\\';
		// This file's own directory, not a shared constant: another installed copy of the
		// plugin (same namespace) must never make this one load classes from its folder.
		$base_dir = __DIR__ . '/src/';

		$len = strlen( $prefix );
		if ( 0 !== strncmp( $prefix, $class, $len ) ) {
			return; // Not ours.
		}

		$relative = substr( $class, $len );
		$file     = $base_dir . str_replace( '\\', '/', $relative ) . '.php';

		if ( is_file( $file ) ) {
			require $file;
		}
	}
);
