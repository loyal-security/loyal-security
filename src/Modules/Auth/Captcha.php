<?php
/**
 * Login/register/lost-password CAPTCHA (Cloudflare Turnstile / reCAPTCHA v3).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;
use LoyalSecurity\Support\Http;

/**
 * Adds a bot-deterrent challenge to wp-login.php's three credential-adjacent forms — login,
 * registration, and lost password — and verifies the token server-side before each proceeds.
 * Supports Cloudflare Turnstile and Google reCAPTCHA v3.
 *
 * Each form is independently toggleable (`captcha_protect_login/register/lostpassword`, all
 * default true): once a provider and keys are configured, every form is already protected, and
 * the toggles are an opt-*out* per form rather than something that needs turning on. All three
 * flags are inert as long as no provider/keys are set — see configured().
 */
class Captcha {

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	private function provider(): string {
		return (string) $this->settings->get( 'auth', 'captcha_provider', 'none' );
	}

	/** Whether a provider and site key are both set — the gate every feature flag sits behind. */
	private function configured(): bool {
		return 'none' !== $this->provider() && '' !== (string) $this->settings->get( 'auth', 'captcha_site_key', '' );
	}

	public function register(): void {
		if ( ! $this->configured() ) {
			return;
		}

		// Shared across all three forms: they're all rendered by wp-login.php regardless of
		// which `action=` it's handling, so one enqueue covers whichever of the three below are
		// actually active. Harmless to load if a given page's own form isn't protected.
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue' ) );

		if ( (bool) $this->settings->get( 'auth', 'captcha_protect_login', true ) ) {
			add_action( 'login_form', array( $this, 'render_field' ) );
			add_filter( 'authenticate', array( $this, 'verify_on_login' ), 25, 1 );
		}
		if ( (bool) $this->settings->get( 'auth', 'captcha_protect_register', true ) ) {
			add_action( 'register_form', array( $this, 'render_field' ) );
			add_filter( 'registration_errors', array( $this, 'verify_on_register' ), 10, 3 );
		}
		if ( (bool) $this->settings->get( 'auth', 'captcha_protect_lostpassword', true ) ) {
			add_action( 'lostpassword_form', array( $this, 'render_field' ) );
			add_filter( 'allow_password_reset', array( $this, 'verify_on_lostpassword' ), 10, 2 );
		}
	}

	public function enqueue(): void {
		if ( 'turnstile' === $this->provider() ) {
			wp_enqueue_script( 'loyalsec-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), null, true ); // phpcs:ignore
		} elseif ( 'recaptcha_v3' === $this->provider() ) {
			// Whitelist before embedding in a URL — reCAPTCHA site keys are alphanumeric/-/_.
			$site = preg_replace( '/[^A-Za-z0-9_-]/', '', (string) $this->settings->get( 'auth', 'captcha_site_key', '' ) );
			wp_enqueue_script( 'loyalsec-recaptcha', 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site ), array(), null, true ); // phpcs:ignore

			// Attached to the handle above rather than echoed inline on the form: the token field
			// id is the same regardless of which of the three forms is active, so one inline
			// script (fired once, at enqueue time) covers login/register/lost-password alike.
			$site_js = wp_json_encode( $site );
			wp_add_inline_script(
				'loyalsec-recaptcha',
				'document.addEventListener("DOMContentLoaded",function(){if(window.grecaptcha){grecaptcha.ready(function(){grecaptcha.execute(' . $site_js . ',{action:"login"}).then(function(t){var e=document.getElementById("loyalsec_captcha_token");if(e)e.value=t;});});}});'
			);
		}
	}

	/**
	 * Shared by login_form/register_form/lostpassword_form — the markup is identical regardless
	 * of which of the three forms it's rendered into.
	 */
	public function render_field(): void {
		$site_raw = (string) $this->settings->get( 'auth', 'captcha_site_key', '' );
		if ( 'turnstile' === $this->provider() ) {
			// Turnstile key goes into an HTML attribute — esc_attr() is correct here.
			echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( $site_raw ) . '" data-response-field-name="loyalsec_captcha"></div>';
		} elseif ( 'recaptcha_v3' === $this->provider() ) {
			// The script that fills this field's value is enqueued once in enqueue(), not here.
			echo '<input type="hidden" name="loyalsec_captcha" id="loyalsec_captcha_token" />';
		}
	}

	/**
	 * @param mixed $user Current auth result.
	 * @return mixed
	 */
	public function verify_on_login( $user ) {
		// A passkey sign-in can't be scripted by a bot (it needs the user's authenticator), and
		// its form submission carries no username/password for the CAPTCHA to protect.
		if ( $user instanceof \WP_User && PasskeyLogin::verified_user_id() === (int) $user->ID ) {
			return $user;
		}
		// Only enforce on actual login POSTs.
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) || empty( $_POST['log'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return $user;
		}
		return $this->check_token() ?? $user;
	}

	/**
	 * @param \WP_Error $errors Accumulated registration errors.
	 * @param string    $sanitized_user_login Unused — same signature WP core calls this with.
	 * @param string    $user_email Unused.
	 * @return \WP_Error
	 */
	public function verify_on_register( $errors, $sanitized_user_login, $user_email ) {
		unset( $sanitized_user_login, $user_email );
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return $errors;
		}
		$error = $this->check_token();
		if ( null !== $error && $errors instanceof \WP_Error ) {
			$errors->add( $error->get_error_code(), $error->get_error_message() );
		}
		return $errors;
	}

	/**
	 * @param bool|\WP_Error $allow Whether the reset may proceed.
	 * @param int            $user_id Unused.
	 * @return bool|\WP_Error
	 */
	public function verify_on_lostpassword( $allow, $user_id ) {
		unset( $user_id );
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return $allow;
		}
		return $this->check_token() ?? $allow;
	}

	/**
	 * Read + verify the posted token. Returns null when it's valid (caller passes the original
	 * value through unchanged), or a WP_Error describing the failure otherwise.
	 */
	private function check_token(): ?\WP_Error {
		// phpcs:ignore WordPress.Security.NonceVerification
		$token = isset( $_POST['loyalsec_captcha'] ) ? sanitize_text_field( wp_unslash( $_POST['loyalsec_captcha'] ) ) : '';
		if ( '' === $token || ! $this->verify_token( $token ) ) {
			return new \WP_Error( 'loyalsec_captcha', __( 'CAPTCHA verification failed. Please try again.', 'loyal-security' ) );
		}
		return null;
	}

	/** Lazily-loaded, memoized copy of the JSON provider-endpoint data — see {@see verify_endpoint()}. */
	private static ?array $provider_endpoints = null;

	/**
	 * The token-verification endpoint for a given provider slug, loaded from a static JSON data
	 * file rather than a PHP string literal (new providers can be added there without a code
	 * change). Falls back to the reCAPTCHA endpoint for any unrecognised/legacy provider slug.
	 */
	private static function verify_endpoint( string $provider ): string {
		if ( null === self::$provider_endpoints ) {
			$json    = file_get_contents( LOYALSEC_PATH . 'assets/data/captcha-providers.json' );
			$decoded = is_string( $json ) ? json_decode( $json, true ) : null;
			self::$provider_endpoints = is_array( $decoded ) ? $decoded : array();
		}
		return self::$provider_endpoints[ $provider ] ?? self::$provider_endpoints['recaptcha'] ?? '';
	}

	private function verify_token( string $token ): bool {
		$secret = (string) $this->settings->get( 'auth', 'captcha_secret_key', '' );
		if ( '' === $secret ) {
			return true; // Misconfigured — fail open rather than lock out.
		}

		$endpoint = self::verify_endpoint( $this->provider() );

		$result = Http::post_json( $endpoint, array(
			'secret'   => $secret,
			'response' => $token,
			'remoteip' => \LoyalSecurity\Modules\Firewall\IpResolver::request_ip(),
		) );

		if ( ! is_array( $result ) || empty( $result['success'] ) ) {
			return false;
		}
		// reCAPTCHA v3 score threshold.
		if ( 'recaptcha_v3' === $this->provider() && isset( $result['score'] ) ) {
			$min = (float) $this->settings->get( 'auth', 'captcha_min_score', 0.5 );
			return (float) $result['score'] >= $min;
		}
		return true;
	}
}
