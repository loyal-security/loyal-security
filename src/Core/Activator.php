<?php
/**
 * Plugin activation routine.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Runs on plugin activation: installs tables, grants capabilities, seeds defaults, and
 * schedules cron events. Aborts cleanly on unsupported PHP.
 */
class Activator {

	/**
	 * @param bool $network_wide Whether activated network-wide.
	 */
	public static function activate( bool $network_wide = false ): void {
		if ( version_compare( PHP_VERSION, TOTALSECWP_MIN_PHP, '<' ) ) {
			deactivate_plugins( TOTALSECWP_BASENAME );
			wp_die(
				esc_html(
					sprintf(
						/* translators: 1: required PHP, 2: current PHP */
						__( 'Loyal Security requires PHP %1$s or higher. You are running %2$s.', 'loyal-security' ),
						TOTALSECWP_MIN_PHP,
						PHP_VERSION
					)
				)
			);
		}

		Installer::install();
		update_option( 'totalsecwp_db_version', TOTALSECWP_DB_VERSION, true );

		Capabilities::grant();

		// Mark that the setup wizard has not yet completed.
		if ( false === get_option( 'totalsecwp_setup_complete', false ) ) {
			add_option( 'totalsecwp_setup_complete', false, '', false );
		}

		// Anonymous bypass-telemetry consent starts OUT until the admin explicitly opts in
		// (GDPR). Nothing is ever transmitted while this is false.
		if ( false === get_option( 'totalsecwp_telemetry_consent', false ) ) {
			add_option(
				'totalsecwp_telemetry_consent',
				array( 'given' => false, 'timestamp' => 0, 'version' => 0, 'user_id' => 0 ),
				'',
				false
			);
		}

		// Opaque, random install identifier — the ONLY site identity sent with telemetry
		// (never home_url()). Generated once and reused.
		if ( false === get_option( 'totalsecwp_install_id', false ) ) {
			add_option( 'totalsecwp_install_id', self::generate_install_id(), '', true );
		}

		Cron::schedule_all();

		// Create the quarantine/private storage directory with hard protections.
		self::prepare_storage();

		flush_rewrite_rules();

		// Redirect to the Setup Wizard right after activation — the highest-intent moment an
		// admin will ever have with this plugin, and currently spent landing back on the
		// generic Plugins list instead. Skipped for network-wide and bulk activation (the
		// standard convention: a redirect mid-batch, or dropped onto one site from the network
		// screen, would be actively confusing) — Notices::maybe_redirect_after_activation()
		// consumes this on the very next admin_init and self-deletes either way.
		if ( ! $network_wide && ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! isset( $_GET['activate-multi'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- presence-only check for WP core's own bulk-activation query arg, nothing is read from it.
			set_transient( 'totalsecwp_activation_redirect', 1, 30 );
		}
	}

	/**
	 * Generate a random, opaque 32-char hex install id. Not derived from the site URL,
	 * domain, or any host identity — purely a random pseudonym for de-duplicating telemetry.
	 */
	private static function generate_install_id(): string {
		try {
			return bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $e ) {
			return md5( uniqid( 'totalsec', true ) . wp_rand() );
		}
	}

	/**
	 * Create a non-public, non-executable storage directory under wp-content/uploads.
	 */
	private static function prepare_storage(): void {
		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['error'] ) ) {
			return;
		}
		$base = trailingslashit( $uploads['basedir'] ) . 'loyal-security';
		if ( ! is_dir( $base ) ) {
			wp_mkdir_p( $base );
		}

		// Deny all web access and PHP execution within the storage dir.
		$htaccess = $base . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions
				$htaccess,
				"Require all denied\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\nphp_flag engine off\n"
			);
		}
		$index = $base . '/index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php // Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}
}
