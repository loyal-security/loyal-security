<?php
/**
 * Two-factor enrollment reminder popup.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;

/**
 * Enqueues a framework-free popup (same pattern as UninstallPrompt) on every wp-admin screen —
 * not just the plugin's own React dashboard, which doesn't load its JS on ordinary admin pages
 * (Posts, the core Dashboard, etc.) — in one of two modes. Owns the script's entire lifecycle
 * (enqueue + localize) for BOTH modes, even though profile.php's trigger button is rendered by
 * TwoFactorProfileSection, specifically so the two can never both try to wp_localize_script() the
 * same handle with different config on a page where both conditions happen to be true at once
 * (an enforced-role user who's mid-grace-period viewing their own profile.php, for instance).
 *
 *  - Reminder (auto-shown): for a logged-in user in an enforced 2FA role who hasn't enrolled.
 *    Within the grace period it's dismissible — "Remind me tomorrow" and the popup's own close
 *    button both snooze it for a day (LoginGuard::enforce_enrollment() does not hard-redirect
 *    yet, so this is the only nudge that exists during the grace period). Once the grace period
 *    expires it's non-dismissible. In practice that non-dismissible state only ever renders on
 *    the one page enforce_enrollment() deliberately exempts from its hard redirect
 *    (page=loyal-security, so a user already there to enroll isn't looped) — everywhere
 *    else, admin_init's exit() already fired before this script would even be enqueued.
 *  - Manage (click-to-open, profile.php only): available to ANY logged-in user regardless of
 *    force_2fa/role/grace state, because it's the only self-service way to enroll OR remove 2FA
 *    for someone who can't open the plugin's own admin page (which requires the
 *    manage_loyal_security capability an Editor, say, will never have).
 */
class TwoFactorEnrollPrompt {

	private Settings $settings;
	private TwoFactor $twofa;
	private TwoFactorGracePeriod $grace;

	public function __construct( Settings $settings, TwoFactor $twofa, TwoFactorGracePeriod $grace ) {
		$this->settings = $settings;
		$this->twofa    = $twofa;
		$this->grace    = $grace;
	}

	public function register_hooks(): void {
		add_action( 'admin_enqueue_scripts', array( $this, 'maybe_enqueue' ) );
		add_action( 'wp_ajax_loyalsec_2fa_snooze', array( $this, 'ajax_snooze' ) );
	}

	public function maybe_enqueue( string $hook ): void {
		$reminder = $this->should_show();
		$manage   = ! $reminder && 'profile.php' === $hook && is_user_logged_in();
		if ( ! $reminder && ! $manage ) {
			return;
		}

		$user_id = get_current_user_id();

		// QR rendering reuses the same vendor lib the React dashboard uses (window.qrcode) —
		// but that bundle is normally only enqueued on the plugin's own admin pages, which is
		// exactly the access this popup exists to work around (see class docblock), so it must
		// be pulled in here too.
		wp_enqueue_script(
			'loyalsec-qrcode',
			LOYALSEC_URL . 'assets/js/vendor/qrcode.js',
			array(),
			'1.4.4',
			true
		);

		wp_enqueue_script(
			'loyalsec-2fa-enroll-prompt',
			LOYALSEC_URL . 'assets/js/2fa-enroll-prompt.js',
			array( 'loyalsec-qrcode' ),
			LOYALSEC_VERSION,
			true
		);

		wp_localize_script(
			'loyalsec-2fa-enroll-prompt',
			'LoyalSec2faPrompt',
			array(
				'autoShow'      => $reminder,
				'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'loyalsec_2fa_snooze' ),
				// REST credentials for the enrollment flow itself: begin/confirm/disable are
				// gated by logged_in_check (any authenticated user), not the
				// manage_loyal_security capability the admin page requires — deliberately, so
				// a role like Editor (a default force_2fa_roles member) that can't open that page
				// at all can still enroll or remove 2FA entirely from this popup.
				'restRoot'      => esc_url_raw( rest_url( LOYALSEC_REST_NAMESPACE ) ),
				'restNonce'     => wp_create_nonce( 'wp_rest' ),
				'enrollUrl'     => admin_url( 'admin.php?page=loyal-security#/2fa' ),
				'canOpenPlugin' => \LoyalSecurity\Core\Capabilities::can_manage(),
				'logoutUrl'     => wp_logout_url(),
				'enforced'      => $reminder && $this->grace->is_enforced_now( $user_id ),
				'remainingDays' => $reminder ? $this->grace->remaining_days( $user_id ) : 0,
				'alreadyEnabled' => $this->twofa->is_enabled( $user_id ),
			)
		);
	}

	private function should_show(): bool {
		if ( ! is_user_logged_in() || ! (bool) $this->settings->get( 'auth', 'force_2fa', false ) ) {
			return false;
		}
		$user  = wp_get_current_user();
		$roles = (array) $this->settings->get( 'auth', 'force_2fa_roles', array( 'administrator', 'editor' ) );
		if ( ! array_intersect( $user->roles, $roles ) ) {
			return false;
		}
		if ( $this->twofa->is_enabled( (int) $user->ID ) ) {
			return false;
		}
		if ( $this->grace->is_enforced_now( (int) $user->ID ) ) {
			return true; // Non-dismissible state — always show, snooze no longer applies.
		}
		return ! $this->grace->is_snoozed( (int) $user->ID );
	}

	/**
	 * AJAX handler for "remind me tomorrow" / the popup's close button during the grace period.
	 */
	public function ajax_snooze(): void {
		// Explicit query_arg: the JS posts the nonce as `nonce`, and without naming it here
		// check_ajax_referer() only ever looks at `_ajax_nonce`/`_wpnonce` — it would silently
		// fail this check on every call and wp_die(-1) before snooze() ever runs. Confirmed:
		// this exact mismatch was live and meant "Remind me tomorrow" never actually persisted.
		check_ajax_referer( 'loyalsec_2fa_snooze', 'nonce' );
		if ( ! is_user_logged_in() ) {
			wp_die( -1 );
		}
		$this->grace->snooze( get_current_user_id() );
		wp_die( 1 );
	}
}
