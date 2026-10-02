<?php
/**
 * Admin asset enqueuing.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Enqueues the React dashboard. Uses WordPress core's bundled React (`wp-element`), so there is
 * no build step and no Node dependency. The dashboard source files are native ES modules loaded
 * through the Script Modules API; configuration (REST root, nonce, capabilities) is printed by a
 * small classic script before the modules run.
 */
class Assets {

	/** Module id of the dashboard entry point (assets/js/app.js). */
	private const ENTRY_MODULE = 'loyal-security-dashboard';

	/** Classic (non-module) scripts in assets/js that are enqueued on their own screens. */
	private const CLASSIC_SCRIPTS = array( 'app.js', '2fa-enroll-prompt.js', 'passkey-login.js', 'uninstall-prompt.js' );

	/** Admin page hook suffixes on which to load the dashboard. */
	private array $page_hooks = array();

	public function register_hooks(): void {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
	}

	/**
	 * Record the admin page hooks that should receive the assets.
	 *
	 * @param string ...$hooks Hook suffixes returned by add_menu_page/add_submenu_page.
	 */
	public function register_pages( string ...$hooks ): void {
		$this->page_hooks = array_merge( $this->page_hooks, $hooks );
	}

	/**
	 * @param string $hook Current admin page hook suffix.
	 */
	public function enqueue( string $hook ): void {
		if ( ! in_array( $hook, $this->page_hooks, true ) ) {
			return;
		}

		$ver = TOTALSECWP_VERSION;
		$url = TOTALSECWP_URL . 'assets/';

		wp_enqueue_style( 'totalsecwp-admin', $url . 'css/admin.css', array(), $ver . '.' . (int) filemtime( TOTALSECWP_PATH . 'assets/css/admin.css' ) );

		// Vendor: QR code generator (MIT, qrcode-generator by kazuhikoarase).
		wp_enqueue_script( 'totalsecwp-qrcode', $url . 'js/vendor/qrcode.js', array(), '1.4.4', true );

		// Classic handle that loads core React (wp-element) and prints the dashboard config
		// (window.TotalSecurityWP) before the modules below run.
		wp_register_script( 'totalsecwp-app', false, array( 'wp-element', 'wp-i18n', 'totalsecwp-qrcode' ), $ver, true );

		// Initial value for the dashboard's wording of its pointers to Pro (see ProGate.js); the
		// dashboard re-reads it from /status/license. Nothing is enabled or disabled by it.
		$tier = 'free';
		try {
			$tier = \TotalSecurityWP\Plugin::instance()->container()->make( 'pro_status' )->tier();
		} catch ( \Throwable $e ) {
			$tier = 'free';
		}

		$config = array(
			'root'    => esc_url_raw( rest_url( TOTALSECWP_REST_NAMESPACE ) ),
			'nonce'   => wp_create_nonce( 'wp_rest' ),
			'caps'    => array(
				'manage' => current_user_can( TOTALSECWP_CAP ) || current_user_can( 'manage_options' ),
			),
			'version'     => $ver,
			'assets'      => $url,
			'multisite'   => is_multisite(),
			'telemetry'   => $this->telemetry_state(),
			'tier'        => $tier,
			'brand_name'  => \TotalSecurityWP\Support\Brand::name(),
			'upgrade_url'  => admin_url( 'admin.php?page=loyal-security' ) . '#/upgrade',
			'checkout_url' => 'https://licensekit.loyalsecuritywp.com/register',
			'pricing_url'  => 'https://licensekit.loyalsecuritywp.com/pricing',
		);

		wp_add_inline_script(
			'totalsecwp-app',
			'window.TotalSecurityWP = ' . wp_json_encode( $config ) . ';',
			'before'
		);

		wp_enqueue_script( 'totalsecwp-app' );

		$this->enqueue_dashboard_modules( $ver );
	}

	/**
	 * Register every dashboard source file as a script module and enqueue the entry point.
	 *
	 * The modules import each other with relative paths (`./components/App.js`). Each file is
	 * registered under its own URL as the module id, so the import map WordPress prints maps
	 * that URL to the same URL with `?ver=` appended: the browser applies import-map entries to
	 * resolved relative imports too. The version includes each file's modification time, so a
	 * changed file always gets a new URL even when the plugin version does not change.
	 */
	private function enqueue_dashboard_modules( string $ver ): void {
		if ( ! function_exists( 'wp_enqueue_script_module' ) ) {
			return;
		}

		$dir  = TOTALSECWP_PATH . 'assets/js/';
		$base = TOTALSECWP_URL . 'assets/js/';
		$deps = array();
		foreach ( array_merge( (array) glob( $dir . '*.js' ), (array) glob( $dir . 'components/*.js' ) ) as $file ) {
			$rel = ltrim( str_replace( '\\', '/', substr( (string) $file, strlen( $dir ) ) ), '/' );
			if ( '' === $rel || in_array( $rel, self::CLASSIC_SCRIPTS, true ) ) {
				continue;
			}
			$id = $base . $rel;
			wp_register_script_module( $id, $id, array(), $ver . '.' . (int) filemtime( (string) $file ) );
			$deps[] = $id;
		}

		wp_enqueue_script_module( self::ENTRY_MODULE, $base . 'app.js', $deps, $ver . '.' . (int) filemtime( $dir . 'app.js' ) );

		// Print the import map and module tags on this admin screen even on a WordPress
		// version whose Script Modules API does not already do so in wp-admin.
		$modules = wp_script_modules();
		if ( false === has_action( 'admin_print_footer_scripts', array( $modules, 'print_import_map' ) ) ) {
			add_action( 'admin_print_footer_scripts', array( $modules, 'print_import_map' ), 9 );
			add_action( 'admin_print_footer_scripts', array( $modules, 'print_enqueued_script_modules' ) );
		}
	}

	/**
	 * Delete the assets/.htaccess that versions before 1.4.11 generated at runtime (the Script
	 * Modules import map now handles cache-busting). Called once on upgrade.
	 */
	public static function remove_legacy_htaccess(): void {
		$file = TOTALSECWP_PATH . 'assets/.htaccess';
		if ( is_file( $file ) ) {
			wp_delete_file( $file );
		}
	}

	/**
	 * Bypass-telemetry consent state for the dashboard. Lets the app raise the first-load
	 * consent modal without an extra round-trip. Mirrors TelemetryController's logic.
	 *
	 * @return array{consent_given:bool,needs_consent:bool}
	 */
	private function telemetry_state(): array {
		$raw     = get_option( 'totalsecwp_telemetry_consent', array() );
		$given   = is_array( $raw ) && ! empty( $raw['given'] );
		$ts      = is_array( $raw ) ? (int) ( $raw['timestamp'] ?? 0 ) : 0;
		$version = is_array( $raw ) ? (int) ( $raw['version'] ?? 0 ) : 0;

		$policy = class_exists( \TotalSecurityWP\Rest\Controllers\TelemetryController::class )
			? \TotalSecurityWP\Rest\Controllers\TelemetryController::POLICY_VERSION
			: 1;

		// Prompt when never answered or answered against an older policy version.
		$needs = ( $ts <= 0 ) || ( $version < $policy );

		return array(
			'consent_given' => $given,
			'needs_consent' => $needs,
		);
	}
}
