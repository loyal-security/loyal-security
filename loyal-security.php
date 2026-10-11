<?php
/**
 * Plugin Name:       Loyal Security - Firewall & Malware Scanner
 * Plugin URI:        https://loyalsecuritywp.com
 * Description:       All-in-one WordPress security: dual-mode firewall (WAF), hardening, malware scanner and file integrity monitoring, incident response, two-factor login, backups and audit log.
 * Version:           1.5.1
 * Requires at least: 6.6
 * Requires PHP:      8.0
 * Author:            Loyal Security
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       loyal-security
 * Domain Path:       /languages
 *
 * @package LoyalSecurity
 */

defined( 'ABSPATH' ) || exit;

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */
define( 'LOYALSEC_VERSION', '1.5.1' );
define( 'LOYALSEC_DB_VERSION', '1.3.0' );
define( 'LOYALSEC_MIN_PHP', '8.0' );
define( 'LOYALSEC_FILE', __FILE__ );
define( 'LOYALSEC_BASENAME', plugin_basename( __FILE__ ) );
define( 'LOYALSEC_PATH', plugin_dir_path( __FILE__ ) );
define( 'LOYALSEC_URL', plugin_dir_url( __FILE__ ) );
define( 'LOYALSEC_SLUG', 'loyal-security' );
define( 'LOYALSEC_REST_NAMESPACE', 'loyal-security/v1' );
define( 'LOYALSEC_CAP', 'manage_loyal_security' );
define( 'LOYALSEC_OPTION_SETTINGS', 'loyalsec_settings' );

/*
 * EDD License Server — baked-in defaults, no wp-config.php changes needed for end users.
 *
 * As the plugin developer, set these two values once before distributing:
 *   LOYALSEC_LICENSE_API_URL   → your production EDD server URL (e.g. https://license.yourdomain.com)
 *   LOYALSEC_LICENSE_ITEM_SLUG → product slug in the EDD DB
 *
 * wp-config.php constants can override these for local development only:
 *   define( 'LOYALSEC_LICENSE_API_URL', 'http://localhost:3000' );
 */
if ( ! defined( 'LOYALSEC_LICENSE_API_URL' ) ) {
	define( 'LOYALSEC_LICENSE_API_URL', 'https://licensekit.loyalsecuritywp.com' );
}
if ( ! defined( 'LOYALSEC_LICENSE_ITEM_SLUG' ) ) {
	// Fixed EDD product slug in LicenseKit's DB — independent of the plugin's own display name/
	// slug, which has changed over time (total-security -> loyal-security -> ... -> the
	// current display name). Never rename this to match; it must match LicenseKit's seed data.
	define( 'LOYALSEC_LICENSE_ITEM_SLUG', 'loyal-security' );
}

/*
 * Anonymous firewall-bypass telemetry endpoint (opt-in, GDPR-gated).
 *
 * When an attack is confirmed to have bypassed the firewall, an anonymized report is sent
 * here so new WAF/malware signatures can be authored and pushed to every install. Defaults
 * to the LicenseKit backend; wp-config.php can override for development or self-hosting.
 */
if ( ! defined( 'LOYALSEC_TELEMETRY_API_URL' ) ) {
	define( 'LOYALSEC_TELEMETRY_API_URL', LOYALSEC_LICENSE_API_URL . '/api/v1/telemetry' );
}

/* -------------------------------------------------------------------------
 * PHP version guard — fail gracefully instead of fataling.
 * ---------------------------------------------------------------------- */
if ( version_compare( PHP_VERSION, LOYALSEC_MIN_PHP, '<' ) ) {
	add_action(
		'admin_notices',
		static function () {
			printf(
				'<div class="notice notice-error"><p>%s</p></div>',
				esc_html(
					sprintf(
						/* translators: 1: required PHP version, 2: current PHP version */
						__( 'Loyal Security requires PHP %1$s or higher. Your server is running PHP %2$s. The plugin has been halted.', 'loyal-security' ),
						LOYALSEC_MIN_PHP,
						PHP_VERSION
					)
				)
			);
		}
	);
	return; // Do not bootstrap on unsupported PHP.
}

/* -------------------------------------------------------------------------
 * Autoloader (built-in PSR-4 — no Composer required at runtime).
 * ---------------------------------------------------------------------- */
require_once LOYALSEC_PATH . 'autoload.php';

/* -------------------------------------------------------------------------
 * Fatal-error watchdog (early arm).
 *
 * A plugin reinstall or file fix records an in-flight flag while it swaps files. If the process
 * is killed mid-swap, a later request can fatal *while other plugins are still loading* — before
 * `plugins_loaded` (where the module normally arms the guard) ever fires. Arming here, right
 * after the autoloader, lets the self-heal guard catch that and auto-restore. The check is a
 * single DB-free `is_file()` so the common (nothing-in-flight) path costs nothing.
 * ---------------------------------------------------------------------- */
try {
	if ( \LoyalSecurity\Modules\Incident\RepairBackup::pending_flag_exists() ) {
		( new \LoyalSecurity\Modules\Incident\RepairGuard() )->arm();
	}
} catch ( \Throwable $e ) {
	// The watchdog must never be the thing that prevents the site from loading.
	unset( $e );
}

/* -------------------------------------------------------------------------
 * Lifecycle hooks.
 * ---------------------------------------------------------------------- */
register_activation_hook( __FILE__, array( \LoyalSecurity\Core\Activator::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( \LoyalSecurity\Core\Deactivator::class, 'deactivate' ) );

/* -------------------------------------------------------------------------
 * Boot the plugin once all plugins are loaded.
 * ---------------------------------------------------------------------- */
add_action(
	'plugins_loaded',
	static function () {
		\LoyalSecurity\Plugin::instance()->boot();
	},
	5
);
