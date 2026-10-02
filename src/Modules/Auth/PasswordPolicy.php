<?php
/**
 * Password strength policy enforcement.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\Settings;

/**
 * Enforces a configurable password policy on profile updates, registration, and resets.
 */
class PasswordPolicy {

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	public function register(): void {
		// Profile edits and admin "Add New User" (both via edit_user(), which hands the new
		// plaintext password to this hook on the user object).
		add_action( 'user_profile_update_errors', array( $this, 'on_profile_errors' ), 10, 3 );
		// wp-login.php "Reset password" form.
		add_action( 'validate_password_reset', array( $this, 'on_reset' ), 10, 2 );
		// Core's own registration form has no password field (the user sets one via the reset
		// link, which the hook above covers), so there is nothing to validate at registration.
	}

	/**
	 * Validate a password against the policy.
	 *
	 * @return string[] List of violation messages (empty = valid).
	 */
	public function validate( string $password ): array {
		$errors = array();
		$min    = (int) $this->settings->get( 'auth', 'pw_min_length', 12 );

		if ( strlen( $password ) < $min ) {
			$errors[] = sprintf( /* translators: min length */ __( 'Password must be at least %d characters.', 'loyal-security' ), $min );
		}
		if ( $this->settings->get( 'auth', 'pw_mixed_case', true ) && ( ! preg_match( '/[a-z]/', $password ) || ! preg_match( '/[A-Z]/', $password ) ) ) {
			$errors[] = __( 'Password must include both upper and lower case letters.', 'loyal-security' );
		}
		if ( $this->settings->get( 'auth', 'pw_number', true ) && ! preg_match( '/\d/', $password ) ) {
			$errors[] = __( 'Password must include at least one number.', 'loyal-security' );
		}
		if ( $this->settings->get( 'auth', 'pw_special', true ) && ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
			$errors[] = __( 'Password must include at least one special character.', 'loyal-security' );
		}
		return $errors;
	}

	/**
	 * Profile update / new user: WordPress has already read the new password (and rejected it
	 * if the two fields differ) and passes it on the user object — no request data is read here.
	 *
	 * @param \WP_Error $errors Errors object (by ref).
	 * @param bool      $update Whether updating.
	 * @param \stdClass $user   User data.
	 */
	public function on_profile_errors( $errors, $update, $user ): void {
		$pass = ( is_object( $user ) && isset( $user->user_pass ) && is_string( $user->user_pass ) ) ? $user->user_pass : '';
		if ( '' === $pass ) {
			return; // No password change in this request.
		}
		foreach ( $this->validate( $pass ) as $msg ) {
			$errors->add( 'totalsecwp_pw_policy', $msg );
		}
	}

	/**
	 * wp-login.php password reset. Core passes no password to `validate_password_reset`, so the
	 * submitted value is read the same way wp-login.php itself reads it right after this hook.
	 *
	 * @param \WP_Error          $errors Errors.
	 * @param \WP_User|\WP_Error $user   User.
	 */
	public function on_reset( $errors, $user ): void {
		$pass = self::submitted_reset_password();
		if ( null === $pass ) {
			$errors->add( 'totalsecwp_pw_policy', __( 'The new password contains characters that cannot be used in a password.', 'loyal-security' ) );
			return;
		}
		if ( '' === $pass ) {
			return;
		}
		foreach ( $this->validate( $pass ) as $msg ) {
			$errors->add( 'totalsecwp_pw_policy', $msg );
		}
	}

	/**
	 * The new password from the reset form, validated but deliberately not sanitized: any
	 * sanitizing function would change the characters of the password being set, so the policy
	 * would be checking a different string from the one WordPress stores. The value is only
	 * measured (length, character classes) — never stored, logged or output. The reset form is
	 * authorised by core's reset-key cookie before this hook runs.
	 */
	private static function submitted_reset_password(): ?string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- wp-login.php's reset form is protected by its reset key, not a nonce.
		if ( ! isset( $_POST['pass1'] ) || ! is_string( $_POST['pass1'] ) ) {
			return '';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- see docblock: a password must be validated, not altered.
		$pass = (string) wp_unslash( $_POST['pass1'] );
		// Validate: a password is a single line of at most 4096 bytes of valid UTF-8. Null tells
		// the caller to reject it outright.
		if ( strlen( $pass ) > 4096 || preg_match( '/[\r\n\0]/', $pass ) || ( '' !== $pass && '' === wp_check_invalid_utf8( $pass ) ) ) {
			return null;
		}
		return $pass;
	}
}
