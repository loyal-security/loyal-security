<?php
/**
 * Passkey sign-in on the login form.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;

/**
 * Adds a "Sign in with a passkey" button to wp-login.php and verifies the passkey inside
 * WordPress's own sign-in.
 *
 * The browser half of a WebAuthn ceremony is asynchronous, so the button first asks the public
 * `/auth/passkey/login-options` endpoint for a single-use challenge, lets the authenticator sign
 * it, and then submits the signed assertion with the normal login form. WordPress's `wp_signon()`
 * handles that submission like any other login: {@see authenticate()} verifies the assertion on
 * the core `authenticate` filter and hands back the matching user, and core itself sets the
 * auth cookie, fires `wp_login` / `wp_login_failed`, and honours `redirect_to` — so ban lists,
 * lockouts and login logging from this and any other plugin apply to passkey sign-ins too.
 */
class PasskeyLogin {

	/** Posted field suffix => maximum length. All values are base64url. */
	private const FIELDS = array(
		'flow'        => 64,
		'id'          => 1024,
		'client_data' => 8192,
		'auth_data'   => 8192,
		'signature'   => 2048,
	);

	/** User verified by a passkey during this request (0 = none). */
	private static int $verified_user_id = 0;

	private ?\TotalSecurityWP\Core\Settings $settings;
	private ?\TotalSecurityWP\Modules\Audit\Logger $logger;

	public function __construct( ?\TotalSecurityWP\Core\Settings $settings = null, ?\TotalSecurityWP\Modules\Audit\Logger $logger = null ) {
		$this->settings = $settings;
		$this->logger   = $logger;
	}

	public function register(): void {
		add_action( 'login_form', array( $this, 'render_button' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue' ) );
		// After the brute-force/ban gate (priority 1) and before core's own password check (20).
		add_filter( 'authenticate', array( $this, 'authenticate' ), 10, 1 );
	}

	/**
	 * The user a passkey signed in during this request, so the 2FA and CAPTCHA checks further
	 * down the same `authenticate` chain can recognise it (a passkey is itself a phishing-
	 * resistant second factor).
	 */
	public static function verified_user_id(): int {
		return self::$verified_user_id;
	}

	/**
	 * Verify a passkey assertion submitted with the login form.
	 *
	 * @param null|\WP_User|\WP_Error $user Result so far.
	 * @return null|\WP_User|\WP_Error
	 */
	public function authenticate( $user ) {
		if ( $user instanceof \WP_User || is_wp_error( $user ) ) {
			return $user; // Already decided (e.g. a banned IP) — never override.
		}

		$assertion = self::posted_assertion();
		if ( null === $assertion ) {
			return $user; // Not a passkey sign-in.
		}

		$fail = new \WP_Error( 'totalsecwp_passkey_failed', __( 'Passkey sign-in failed. Please try again.', 'loyal-security' ) );
		if ( array() === $assertion ) {
			$this->log( EventCatalog::PASSKEY_LOGIN_FAILED, array() );
			return $fail;
		}

		$res = ( new WebAuthnCeremony() )->complete_login( $assertion['flow'], $assertion['id'], $assertion['client_data'], $assertion['auth_data'], $assertion['signature'] );
		if ( empty( $res['ok'] ) ) {
			$this->log( EventCatalog::PASSKEY_LOGIN_FAILED, array() );
			return $fail;
		}

		$wp_user = get_userdata( (int) $res['user_id'] );
		// user_status is a legacy core column; a nonzero value (or a multisite spam flag) is the
		// signal core itself uses to mean "this account may not log in".
		if ( ! $wp_user || 0 !== (int) $wp_user->user_status || ( is_multisite() && function_exists( 'is_user_spammy' ) && is_user_spammy( $wp_user ) ) ) {
			$this->log( EventCatalog::PASSKEY_LOGIN_FAILED, array() );
			return $fail;
		}

		self::$verified_user_id = (int) $wp_user->ID;
		$this->log( EventCatalog::PASSKEY_LOGIN_SUCCESS, array( 'user_id' => $wp_user->ID ) );
		return $wp_user;
	}

	/**
	 * The passkey assertion posted with the login form: null when this isn't a passkey sign-in,
	 * an empty array when the fields are present but malformed, otherwise the validated values.
	 * Every value is base64url (`A-Z a-z 0-9 - _`) with a length cap; anything else is rejected.
	 *
	 * @return array<string,string>|null
	 */
	private static function posted_assertion(): ?array {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- wp-login.php's form carries no nonce; the assertion is bound to a single-use server challenge and signed by the authenticator.
		if ( empty( $_POST['totalsecwp_passkey_flow'] ) ) {
			return null;
		}
		$out = array();
		foreach ( self::FIELDS as $key => $max ) {
			$name  = 'totalsecwp_passkey_' . $key;
			$value = isset( $_POST[ $name ] ) && is_string( $_POST[ $name ] ) ? sanitize_text_field( wp_unslash( $_POST[ $name ] ) ) : '';
			if ( '' === $value || strlen( $value ) > $max || ! preg_match( '/^[A-Za-z0-9_-]+$/', $value ) ) {
				return array();
			}
			$out[ $key ] = $value;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		return $out;
	}

	private function log( string $event, array $context ): void {
		if ( null === $this->logger ) {
			return;
		}
		$this->logger->log( $event, $context );
	}

	public function render_button(): void {
		?>
		<p class="totalsecwp-passkey">
			<button type="button" id="totalsecwp-passkey-btn" class="button button-secondary">
				<?php esc_html_e( '🔑 Sign in with a passkey', 'loyal-security' ); ?>
			</button>
		</p>
		<p id="totalsecwp-passkey-msg" class="totalsecwp-passkey-msg" role="status" hidden></p>
		<?php
		foreach ( array_keys( self::FIELDS ) as $key ) {
			printf( '<input type="hidden" name="%1$s" id="%1$s" value="" />', esc_attr( 'totalsecwp_passkey_' . $key ) );
		}
	}

	public function enqueue(): void {
		if ( ! defined( 'TOTALSECWP_URL' ) || ! defined( 'TOTALSECWP_REST_NAMESPACE' ) ) {
			return;
		}
		wp_enqueue_style(
			'totalsecwp-passkey-login',
			TOTALSECWP_URL . 'assets/css/passkey-login.css',
			array(),
			defined( 'TOTALSECWP_VERSION' ) ? TOTALSECWP_VERSION : false
		);
		wp_enqueue_script(
			'totalsecwp-passkey-login',
			TOTALSECWP_URL . 'assets/js/passkey-login.js',
			array(),
			defined( 'TOTALSECWP_VERSION' ) ? TOTALSECWP_VERSION : false,
			true
		);
		wp_localize_script(
			'totalsecwp-passkey-login',
			'TotalSecWPPasskey',
			array(
				'restBase' => esc_url_raw( rest_url( TOTALSECWP_REST_NAMESPACE ) ),
			)
		);
	}
}
