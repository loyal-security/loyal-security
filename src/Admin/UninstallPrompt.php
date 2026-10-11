<?php
/**
 * Uninstall confirmation prompt.
 *
 * Injects a modal on the Plugins list page that intercepts the "Delete" action for this
 * plugin, lets the administrator decide whether to wipe all security data, saves that
 * preference via an AJAX endpoint, then hands control back to WordPress's own delete flow.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Enqueues the uninstall-prompt script only on plugins.php and registers the companion
 * AJAX action that persists the data-deletion preference before the plugin is removed.
 */
class UninstallPrompt {

	public function register_hooks(): void {
		add_action( 'admin_enqueue_scripts', array( $this, 'maybe_enqueue' ) );
		add_action( 'wp_ajax_loyalsec_set_delete_flag', array( $this, 'ajax_set_delete_flag' ) );
	}

	/**
	 * Enqueue the prompt script exclusively on the Plugins list page.
	 */
	public function maybe_enqueue( string $hook ): void {
		if ( 'plugins.php' !== $hook ) {
			return;
		}

		wp_enqueue_script(
			'loyalsec-uninstall-prompt',
			LOYALSEC_URL . 'assets/js/uninstall-prompt.js',
			array(),
			LOYALSEC_VERSION,
			true
		);

		wp_localize_script(
			'loyalsec-uninstall-prompt',
			'LoyalSecUninstall',
			array(
				'ajaxUrl'           => admin_url( 'admin-ajax.php' ),
				'nonce'             => wp_create_nonce( 'loyalsec_uninstall' ),
				'plugin'            => LOYALSEC_BASENAME,
				'deleteOnUninstall' => (bool) get_option( 'loyalsec_delete_on_uninstall', false ),
			)
		);
	}

	/**
	 * AJAX handler: persist the administrator's data-deletion preference.
	 *
	 * Intentionally does not require the plugin to be inactive — the preference must be
	 * saveable even moments before the delete flow reaches uninstall.php.
	 */
	public function ajax_set_delete_flag(): void {
		// Explicit query_arg: the JS posts the nonce as `nonce`, and without naming it here
		// check_ajax_referer() only ever looks at `_ajax_nonce`/`_wpnonce` — same mismatch found
		// and fixed in TwoFactorEnrollPrompt::ajax_snooze(), same root cause here.
		check_ajax_referer( 'loyalsec_uninstall', 'nonce' );

		if ( ! current_user_can( 'delete_plugins' ) ) {
			wp_die( -1 );
		}

		$delete = isset( $_POST['delete_data'] ) && 'true' === sanitize_key( wp_unslash( $_POST['delete_data'] ) );
		update_option( 'loyalsec_delete_on_uninstall', $delete, false );

		wp_die( 1 );
	}
}
