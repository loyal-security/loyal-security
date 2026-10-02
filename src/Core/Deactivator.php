<?php
/**
 * Plugin deactivation routine.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Setup\PrependInstaller;
use TotalSecurityWP\Setup\ServerProbe;
use TotalSecurityWP\Modules\Hardening\ServerRules;
use TotalSecurityWP\Modules\Hardening\ConfigHardener;

/**
 * Runs on deactivation. Conservative by design: clears scheduled events but leaves data,
 * tables, and capabilities intact (full teardown happens only on uninstall).
 *
 * Server-level changes (auto_prepend_file, .htaccess blocks, wp-config constants) ARE
 * reverted here because leaving them in place after the plugin is gone causes immediate
 * site breakage (500 errors) or orphaned configuration that can never be removed.
 */
class Deactivator {

	public static function deactivate(): void {
		Cron::unschedule_all();

		// Graceful degradation: never leave the site locked in Under Attack Mode if the
		// plugin is deactivated mid-attack. Clear the emergency state and its single event.
		$expire = wp_next_scheduled( 'totalsecwp_under_attack_expire' );
		if ( $expire ) {
			wp_unschedule_event( $expire, 'totalsecwp_under_attack_expire' );
		}
		delete_option( 'totalsecwp_under_attack' );
		delete_option( 'totalsecwp_under_attack_expiry' );

		// Revert all server-level changes so the site stays functional after deactivation.
		// Each step is wrapped individually — one failure must not prevent the others.
		try {
			( new PrependInstaller( new ServerProbe() ) )->rollback();
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
		}

		try {
			( new ServerRules() )->revert();
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
		}

		try {
			( new ConfigHardener() )->revert();
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
		}

		flush_rewrite_rules();
	}
}
