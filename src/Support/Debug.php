<?php
/**
 * Opt-in diagnostic logging.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Writes a diagnostic line to the PHP error log only when the site owner has turned on
 * WordPress's own debug log (`WP_DEBUG_LOG`). Nothing is logged on a production site otherwise.
 */
final class Debug {

	public static function log( string $message ): void {
		if ( ! defined( 'WP_DEBUG_LOG' ) || ! WP_DEBUG_LOG ) {
			return;
		}
		error_log( '[Loyal Security] ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- only when the site owner enabled WP_DEBUG_LOG.
	}
}
