<?php
/**
 * Login flow integration for two-factor authentication and enforcement.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;
use LoyalSecurity\Modules\Audit\Logger;
use LoyalSecurity\Modules\Audit\EventCatalog;

/**
 * Adds the TOTP challenge to the login form, verifies it during authentication, and gently
 * forces enrollment for users in enforced roles (redirecting them to the 2FA setup page
 * rather than locking them out).
 */
class LoginGuard {

	private Settings $settings;
	private TwoFactor $twofa;
	private Logger $logger;
	private TrustedDevice $trusted;
	private TwoFactorGracePeriod $grace;

	public function __construct( Settings $settings, TwoFactor $twofa, Logger $logger ) {
		$this->settings = $settings;
		$this->twofa    = $twofa;
		$this->logger   = $logger;
		$this->trusted  = new TrustedDevice();
		$this->grace    = new TwoFactorGracePeriod( $settings );
	}

	public function register(): void {
		add_action( 'login_form', array( $this, 'render_field' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_style' ) );
		add_filter( 'authenticate', array( $this, 'check_2fa' ), 30, 1 );
		add_filter( 'loyalsec_login_error_notes', array( $this, 'login_error_note' ), 10, 2 );

		if ( $this->settings->get( 'auth', 'force_2fa', false ) ) {
			// Hard redirect only fires once a user's individual grace period has run out — see
			// enforce_enrollment(). The reminder popup for the grace period itself (dismissible,
			// shown on every wp-admin screen including the one page this redirect exempts) is
			// TwoFactorEnrollPrompt, enqueued separately by AuthModule so it works without the
			// React dashboard's own JS ever loading.
			add_action( 'admin_init', array( $this, 'enforce_enrollment' ) );
		}
	}

	/**
	 * Grace-period helper — public so TwoFactorEnrollPrompt and the REST controller can share
	 * the exact same per-user deadline logic rather than re-deriving it.
	 */
	public function grace(): TwoFactorGracePeriod {
		return $this->grace;
	}

	/**
	 * Roles required to use 2FA.
	 *
	 * @return string[]
	 */
	public function enforced_roles(): array {
		if ( ! $this->settings->get( 'auth', 'force_2fa', false ) ) {
			return array();
		}
		$roles = (array) $this->settings->get( 'auth', 'force_2fa_roles', array( 'administrator', 'editor' ) );
		return array_map( 'strval', $roles );
	}

	/**
	 * Style the "Trust this device" checkbox label through core's login stylesheet.
	 */
	public function enqueue_style(): void {
		wp_add_inline_style( 'login', '#loginform label[for="loyalsec_trust_device"]{font-weight:400}' );
	}

	/**
	 * Render the authentication-code field on the login form.
	 *
	 * The field is only shown when it is actually needed:
	 *  - `force_2fa` is enabled  →  show unconditionally (every user must enrol).
	 *  - `force_2fa` is disabled →  show only when we already know the submitting
	 *    user's identity (from a previous failed attempt) AND that user has 2FA
	 *    enrolled. On the initial GET request the field is hidden completely so
	 *    users without 2FA never see it.
	 */
	public function render_field(): void {
		// Identify the user from the posted username (only present on a re-render after a
		// failed auth attempt — not on the initial GET).
		// phpcs:ignore WordPress.Security.NonceVerification
		$log = isset( $_POST['log'] ) ? sanitize_user( wp_unslash( (string) $_POST['log'] ) ) : '';
		if ( ! $this->shows_code_field( $log ) ) {
			return;
		}

		?>
		<p>
			<label for="loyalsec_totp"><?php esc_html_e( 'Authentication code', 'loyal-security' ); ?><br />
				<input type="text" name="loyalsec_totp" id="loyalsec_totp" class="input" value="" size="20"
					autocomplete="one-time-code" inputmode="numeric"
					placeholder="<?php esc_attr_e( '6-digit code from your authenticator app', 'loyal-security' ); ?>" />
			</label>
		</p>
		<p>
			<label for="loyalsec_trust_device">
				<input type="checkbox" name="loyalsec_trust_device" id="loyalsec_trust_device" value="1" />
				<?php esc_html_e( 'Trust this device for 30 days', 'loyal-security' ); ?>
			</label>
		</p>
		<?php
	}

	/**
	 * Whether the code field is shown for a submitted username: always when 2FA is required for
	 * everyone, otherwise only for an account with 2FA enrolled. Never depends on the password.
	 *
	 * @param string $log Submitted username or email ('' on the first page load).
	 */
	private function shows_code_field( string $log ): bool {
		if ( (bool) $this->settings->get( 'auth', 'force_2fa', false ) ) {
			return true;
		}
		if ( '' === $log ) {
			return false; // Initial page load — no username yet, hide the field.
		}
		$user = get_user_by( 'login', $log );
		if ( ! $user ) {
			$user = get_user_by( 'email', $log );
		}
		return $user && $this->twofa->is_enabled( (int) $user->ID );
	}

	/**
	 * With login errors normalised, "Two-factor required" becomes "Incorrect username or
	 * password", which told 2FA users with the right password that it was wrong. When the code
	 * field is shown, add how to finish signing in. The note follows the field (username only),
	 * so it does not reveal whether the password was right.
	 *
	 * @param string[] $notes Notes so far.
	 * @param string   $login Submitted username or email.
	 * @return string[]
	 */
	public function login_error_note( $notes, $login ): array {
		$notes = (array) $notes;
		if ( $this->shows_code_field( (string) $login ) ) {
			$notes[] = __( 'If your account uses two-factor authentication, enter your password together with the code from your authenticator app.', 'loyal-security' );
		}
		return $notes;
	}

	/**
	 * Verify the second factor for users who have 2FA enabled.
	 *
	 * @param mixed $user Result so far.
	 * @return mixed
	 */
	public function check_2fa( $user ) {
		if ( ! ( $user instanceof \WP_User ) ) {
			return $user; // Primary auth not yet successful.
		}
		if ( ! $this->twofa->is_enabled( (int) $user->ID ) ) {
			return $user; // No 2FA configured for this user.
		}

		// Signed in with a passkey this request: a passkey is itself a phishing-resistant
		// second factor (possession + biometric/PIN), so no TOTP code is asked for on top.
		if ( PasskeyLogin::verified_user_id() === (int) $user->ID ) {
			return $user;
		}

		// Skip the challenge entirely on a previously-trusted device.
		if ( $this->trusted->verify_token() === (int) $user->ID ) {
			return $user;
		}

		// phpcs:ignore WordPress.Security.NonceVerification
		$code = isset( $_POST['loyalsec_totp'] ) ? sanitize_text_field( wp_unslash( $_POST['loyalsec_totp'] ) ) : '';
		if ( '' === $code ) {
			return new \WP_Error( 'loyalsec_2fa_required', __( '<strong>Two-factor required.</strong> Enter the code from your authenticator app.', 'loyal-security' ) );
		}
		if ( ! $this->twofa->verify( (int) $user->ID, $code ) ) {
			$this->logger->log( EventCatalog::TWOFA_FAILED, array( 'user_id' => $user->ID ) );
			return new \WP_Error( 'loyalsec_2fa_bad', __( 'Invalid authentication code.', 'loyal-security' ) );
		}

		$this->logger->log( EventCatalog::TWOFA_SUCCESS, array( 'user_id' => $user->ID ) );

		// Honour "trust this device" only after a successful second factor.
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( isset( $_POST['loyalsec_trust_device'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['loyalsec_trust_device'] ) ) ) {
			$this->trusted->issue_token( (int) $user->ID );
			$this->logger->log( EventCatalog::DEVICE_TRUSTED, array( 'user_id' => $user->ID ) );
		}

		return $user;
	}

	/**
	 * Redirect enforced-role users who have not enrolled to the 2FA setup page — but only once
	 * their individual grace period has actually run out. Before that, TwoFactorEnrollPrompt's
	 * dismissible popup is the only nudge; this hard redirect would otherwise lock out every
	 * newly-enforced user on their very next click with zero warning.
	 */
	public function enforce_enrollment(): void {
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}
		$user = wp_get_current_user();
		$roles = $this->enforced_roles();
		if ( ! array_intersect( $user->roles, $roles ) ) {
			return;
		}
		if ( $this->twofa->is_enabled( (int) $user->ID ) ) {
			return;
		}
		if ( ! $this->grace->is_enforced_now( (int) $user->ID ) ) {
			return; // Still within their grace period — popup-only, no hard redirect yet.
		}
		// Allow access to our own page (so they can enrol) and to logout.
		$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( 'loyal-security' === $page ) {
			return;
		}
		global $pagenow;
		if ( in_array( $pagenow, array( 'profile.php', 'admin-ajax.php' ), true ) ) {
			return;
		}
		// The client router (App.js currentRoute()) only strips a `?query` suffix from the hash
		// route, not `&flag` — `#/2fa&enroll=required` doesn't match the `2fa` route at all and
		// falls through to the generic "under construction" placeholder instead of the real panel.
		wp_safe_redirect( admin_url( 'admin.php?page=loyal-security#/2fa?enroll=required' ) );
		exit;
	}
}
