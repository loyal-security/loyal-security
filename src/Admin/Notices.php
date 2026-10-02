<?php
/**
 * Admin notices.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Surfaces a one-time prompt to run the setup wizard until it has been completed.
 */
class Notices {

	/** Option holding a "snooze until" timestamp for the feed-stale notice. */
	private const FEED_STALE_DISMISS_OPTION = 'totalsecwp_feed_stale_dismissed_until';

	/** How long a manual dismiss silences the notice for, if the underlying problem persists. */
	private const FEED_STALE_DISMISS_PERIOD = DAY_IN_SECONDS;

	/** User meta flag: this user dismissed the "finish setup" notice. */
	private const SETUP_DISMISS_META = 'totalsecwp_setup_notice_dismissed';

	public function register_hooks(): void {
		add_action( 'admin_notices', array( $this, 'setup_notice' ) );
		add_action( 'admin_notices', array( $this, 'autorollback_notice' ) );
		add_action( 'admin_notices', array( $this, 'waf_config_stale_notice' ) );
		add_action( 'admin_notices', array( $this, 'proxy_misconfig_notice' ) );
		add_action( 'admin_notices', array( $this, 'feed_stale_notice' ) );
		add_action( 'admin_init', array( $this, 'maybe_dismiss_autorollback' ) );
		add_action( 'admin_init', array( $this, 'maybe_dismiss_feed_stale' ) );
		add_action( 'admin_init', array( $this, 'maybe_dismiss_setup' ) );
		add_action( 'admin_init', array( $this, 'maybe_redirect_after_activation' ) );
	}

	/**
	 * One-time redirect to the guided onboarding flow, set by
	 * {@see \TotalSecurityWP\Core\Activator::activate()}. Consumes (deletes) the transient
	 * regardless of outcome so a skipped redirect never re-fires on a later request.
	 *
	 * Points at `#/onboarding` (site-type + protection-level walkthrough) rather than
	 * `#/wizard` (the technical nginx/PHP-FPM server-config deploy page) — a friendlier first
	 * screen for a new install. The technical wizard is still reachable from within onboarding
	 * and from its own notices ({@see waf_config_stale_notice}) for the ongoing server-config
	 * concern it actually addresses.
	 */
	public function maybe_redirect_after_activation(): void {
		if ( ! get_transient( 'totalsecwp_activation_redirect' ) ) {
			return;
		}
		delete_transient( 'totalsecwp_activation_redirect' );

		if ( wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// Already configured (e.g. deactivate/reactivate on a site that finished setup long
		// ago) — don't force onboarding on someone who doesn't need it.
		if ( get_option( 'totalsecwp_setup_complete', false ) ) {
			return;
		}

		wp_safe_redirect( admin_url( 'admin.php?page=loyal-security#/onboarding' ) );
		exit;
	}

	/**
	 * Warn when the threat-intelligence feed has stopped updating (see
	 * ThreatIntelModule::feed_is_stale()). A silently-dark feed means WAF/malware/CVE data is
	 * frozen at the bundled baseline — a real, invisible protection regression — so the operator
	 * is nudged to run the connection self-test.
	 *
	 * Dismissible, but only for FEED_STALE_DISMISS_PERIOD: the underlying condition is a real,
	 * ongoing problem (not a one-time event like the autorollback notice above), so a permanent
	 * dismiss would let a genuine multi-week outage go silently unnoticed. A fresh sync success
	 * clears the underlying condition anyway (feed_is_stale() starts returning false), which is
	 * the normal way this notice should stop appearing — the dismiss is just for "I know, I'm on
	 * it" in the meantime.
	 */
	public function feed_stale_notice(): void {
		if ( ! class_exists( '\TotalSecurityWP\Plugin' ) ) {
			return;
		}
		$module = \TotalSecurityWP\Plugin::instance()->module( 'threatintel' );
		if ( ! $module || ! method_exists( $module, 'feed_is_stale' ) || ! $module->feed_is_stale() ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( (int) get_option( self::FEED_STALE_DISMISS_OPTION, 0 ) > time() ) {
			return;
		}

		$dismiss = wp_nonce_url( add_query_arg( 'totalsecwp_dismiss_feed_stale', '1' ), 'totalsecwp_dismiss_feed_stale' );

		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s" class="button button-secondary">%4$s</a> <a href="%5$s" class="button-link">%6$s</a></p></div>',
			esc_html__( 'Loyal Security: threat intelligence feed is out of date.', 'loyal-security' ),
			esc_html__( 'The plugin has not been able to fetch fresh firewall/malware/vulnerability rules recently, so it is running on the bundled baseline. Check your connection to the update service.', 'loyal-security' ),
			esc_url( admin_url( 'admin.php?page=loyal-security#/threatintel' ) ),
			esc_html__( 'Open Threat Intelligence', 'loyal-security' ),
			esc_url( $dismiss ),
			esc_html__( 'Dismiss for 24 hours', 'loyal-security' )
		);
	}

	/**
	 * Snooze the feed-stale notice for FEED_STALE_DISMISS_PERIOD when the admin clicks Dismiss —
	 * same "Dismiss" link + admin_init handler pattern as maybe_dismiss_autorollback() above.
	 */
	public function maybe_dismiss_feed_stale(): void {
		if ( empty( $_GET['totalsecwp_dismiss_feed_stale'] ) ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'totalsecwp_dismiss_feed_stale' );
		update_option( self::FEED_STALE_DISMISS_OPTION, time() + self::FEED_STALE_DISMISS_PERIOD, false );
	}

	/**
	 * Warn when "Trust proxy" is enabled but no trusted proxy ranges are configured. In that
	 * state forwarded IP headers are deliberately IGNORED (client IP falls back to the direct
	 * connection) to prevent header-spoofed ban/rate-limit evasion — but that also means a
	 * CDN/proxy-fronted site resolves every visitor to the edge IP until ranges are added, so
	 * the operator must be told to fix it.
	 */
	public function proxy_misconfig_notice(): void {
		$settings = get_option( TOTALSECWP_OPTION_SETTINGS, array() );
		$fw       = is_array( $settings ) && isset( $settings['firewall'] ) && is_array( $settings['firewall'] ) ? $settings['firewall'] : array();
		$trust    = ! empty( $fw['trust_proxy'] );
		$ranges   = array_filter( array_map( 'trim', (array) ( $fw['trusted_proxies'] ?? array() ) ) );
		if ( ! $trust || ! empty( $ranges ) ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s" class="button button-secondary">%4$s</a></p></div>',
			esc_html__( 'Loyal Security: Trust Proxy is on but no trusted ranges are set.', 'loyal-security' ),
			esc_html__( 'For safety, forwarded IP headers (X-Forwarded-For, CF-Connecting-IP…) are being ignored — visitor IPs resolve to the direct connection. Add your proxy/CDN IP ranges (e.g. Cloudflare) in Firewall settings, or turn Trust Proxy off.', 'loyal-security' ),
			esc_url( admin_url( 'admin.php?page=loyal-security#/settings' ) ),
			esc_html__( 'Firewall Settings', 'loyal-security' )
		);
	}

	/**
	 * Warn when Optimized Mode is selected but the prepend config on disk could not be updated
	 * (the plugin directory is not writable by the web user). In that state a newly-approved
	 * virtual patch or changed firewall setting is applied in the dashboard but never reaches
	 * the pre-WordPress prepend — the firewall silently keeps enforcing the previous config.
	 * The flag auto-clears the moment a write succeeds (see FirewallModule::write_waf_config()).
	 */
	public function waf_config_stale_notice(): void {
		$info = get_option( \TotalSecurityWP\Modules\Firewall\FirewallModule::CONFIG_STALE_OPTION, false );
		if ( ! is_array( $info ) || empty( $info ) ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}

		printf(
			'<div class="notice notice-error"><p><strong>%1$s</strong> %2$s</p><p><code>%3$s</code></p><p><a href="%4$s" class="button button-secondary">%5$s</a></p></div>',
			esc_html__( 'Loyal Security: the optimized firewall config is out of date.', 'loyal-security' ),
			esc_html__( 'Changes you make (firewall settings, approved virtual patches) cannot be written to the pre-WordPress firewall because the file below is not writable. The firewall is still running, but on the previous configuration. Make the file (and its folder in wp-content/uploads) writable and save any firewall setting to refresh it, or re-run the Setup Wizard.', 'loyal-security' ),
			esc_html( (string) ( $info['path'] ?? '' ) ),
			esc_url( admin_url( 'admin.php?page=loyal-security#/wizard' ) ),
			esc_html__( 'Open Setup Wizard', 'loyal-security' )
		);
	}

	/**
	 * Tell the admin when the fatal-error watchdog automatically reverted a repair/reinstall that
	 * broke the site. Shown on every admin page until dismissed.
	 */
	public function autorollback_notice(): void {
		$info = get_option( \TotalSecurityWP\Modules\Incident\RepairGuard::NOTICE_OPTION, array() );
		if ( ! is_array( $info ) || empty( $info ) ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$restored = ! empty( $info['restored'] );
		$dismiss  = wp_nonce_url( add_query_arg( 'totalsecwp_dismiss_rollback', '1' ), 'totalsecwp_dismiss_rollback' );

		printf(
			'<div class="notice notice-%1$s"><p><strong>%2$s</strong> %3$s</p><p><code>%4$s</code></p><p><a href="%5$s" class="button button-secondary">%6$s</a> <a href="%7$s" class="button-link">%8$s</a></p></div>',
			$restored ? 'warning' : 'error',
			esc_html__( 'Loyal Security: a repair was automatically rolled back.', 'loyal-security' ),
			esc_html(
				$restored
					? __( 'A plugin reinstall or file fix caused a fatal error, so the previous working version was restored automatically. Your site is back online.', 'loyal-security' )
					: __( 'A plugin reinstall or file fix caused a fatal error and the automatic restore could not complete. Restore the backup manually from the Repair Center.', 'loyal-security' )
			),
			esc_html( (string) ( $info['error'] ?? '' ) ),
			esc_url( admin_url( 'admin.php?page=loyal-security#/repair' ) ),
			esc_html__( 'Open Repair Center', 'loyal-security' ),
			esc_url( $dismiss ),
			esc_html__( 'Dismiss', 'loyal-security' )
		);
	}

	/**
	 * Clear the auto-rollback notice when the admin dismisses it.
	 */
	public function maybe_dismiss_autorollback(): void {
		if ( empty( $_GET['totalsecwp_dismiss_rollback'] ) ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'totalsecwp_dismiss_rollback' );
		delete_option( \TotalSecurityWP\Modules\Incident\RepairGuard::NOTICE_OPTION );
	}

	/**
	 * Whether the current screen is the main Dashboard or the Plugins list — the only screens
	 * outside the plugin's own page where its informational notices appear.
	 */
	public static function on_overview_screen(): bool {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		return $screen && in_array( (string) $screen->id, array( 'dashboard', 'plugins', 'dashboard-network', 'plugins-network' ), true );
	}

	/**
	 * "Finish setup" reminder until the setup wizard is completed. Shown only on the Dashboard
	 * and Plugins screens, and never again for a user who dismissed it.
	 */
	public function setup_notice(): void {
		if ( get_option( 'totalsecwp_setup_complete', false ) ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! self::on_overview_screen() ) {
			return;
		}
		if ( get_user_meta( get_current_user_id(), self::SETUP_DISMISS_META, true ) ) {
			return;
		}

		$url     = admin_url( 'admin.php?page=loyal-security#/onboarding' );
		$dismiss = wp_nonce_url( add_query_arg( 'totalsecwp_dismiss_setup', '1' ), 'totalsecwp_dismiss_setup' );
		printf(
			'<div class="notice notice-info"><p><strong>%1$s</strong> %2$s <a href="%3$s" class="button button-primary">%4$s</a> <a href="%5$s" class="button-link">%6$s</a></p></div>',
			esc_html__( 'Loyal Security:', 'loyal-security' ),
			esc_html__( 'Finish setup to deploy the optimized firewall and harden your site.', 'loyal-security' ),
			esc_url( $url ),
			esc_html__( 'Finish Setup', 'loyal-security' ),
			esc_url( $dismiss ),
			esc_html__( 'Dismiss', 'loyal-security' )
		);
	}

	/**
	 * Remember that the current user dismissed the setup notice.
	 */
	public function maybe_dismiss_setup(): void {
		if ( empty( $_GET['totalsecwp_dismiss_setup'] ) ) {
			return;
		}
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'totalsecwp_dismiss_setup' );
		update_user_meta( get_current_user_id(), self::SETUP_DISMISS_META, 1 );
	}
}
