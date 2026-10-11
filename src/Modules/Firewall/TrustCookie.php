<?php
/**
 * Issues the signed cookie that tells the pre-WordPress firewall a trusted user is signed in.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;
use LoyalSecurity\Waf\TrustToken;

/**
 * See {@see TrustToken} for why this exists. The cookie is set when an administrator or editor
 * signs in, renewed while they keep using the site, and removed when they sign out or lose the
 * role. It lasts at most two days, and never longer than the WordPress session itself.
 */
class TrustCookie {

	/** Option holding the signing secret, baked into the firewall config. */
	public const KEY_OPTION = 'loyalsec_trust_key';

	/** Longest a token stays valid. */
	private const LIFETIME = 2 * DAY_IN_SECONDS;

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	public function register_hooks(): void {
		add_action( 'set_logged_in_cookie', array( $this, 'on_login' ), 10, 4 );
		add_action( 'clear_auth_cookie', array( $this, 'clear' ) );
		add_action( 'init', array( $this, 'refresh' ), 2 );
	}

	/**
	 * The signing secret (created on first use).
	 */
	public static function key(): string {
		$key = (string) get_option( self::KEY_OPTION, '' );
		if ( 32 > strlen( $key ) ) {
			$key = wp_generate_password( 48, false, false );
			update_option( self::KEY_OPTION, $key, true );
		}
		return $key;
	}

	/**
	 * `set_logged_in_cookie`: issue the token alongside WordPress's own cookie.
	 *
	 * @param string $logged_in_cookie Cookie value (unused).
	 * @param int    $expire           Cookie expiry (unused).
	 * @param int    $expiration       Session expiry.
	 * @param int    $user_id          User id.
	 */
	public function on_login( $logged_in_cookie, $expire, $expiration, $user_id ): void {
		unset( $logged_in_cookie, $expire );
		$user_id = (int) $user_id;
		if ( $user_id > 0 && $this->enabled() && $this->trusted( $user_id ) ) {
			$this->send( $user_id, min( (int) $expiration, time() + self::LIFETIME ) );
		}
	}

	/**
	 * `init`: renew the token for a trusted user before it runs out, and remove it from anyone
	 * who is no longer trusted.
	 */
	public function refresh(): void {
		if ( headers_sent() || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		$have    = isset( $_COOKIE[ TrustToken::COOKIE ] ) ? sanitize_text_field( wp_unslash( (string) $_COOKIE[ TrustToken::COOKIE ] ) ) : '';
		$user_id = get_current_user_id();
		if ( $user_id > 0 && $this->enabled() && $this->trusted( $user_id ) ) {
			$now = time();
			$uid = '' === $have ? 0 : TrustToken::verify( $have, self::key(), $now + DAY_IN_SECONDS );
			if ( $uid !== $user_id ) {
				$this->send( $user_id, $now + self::LIFETIME );
			}
			return;
		}
		if ( '' !== $have ) {
			$this->clear();
		}
	}

	/**
	 * `clear_auth_cookie`: remove the token.
	 */
	public function clear(): void {
		if ( headers_sent() ) {
			return;
		}
		setcookie( TrustToken::COOKIE, '', array( 'expires' => time() - YEAR_IN_SECONDS ) + $this->cookie_options() );
	}

	private function send( int $user_id, int $expires ): void {
		if ( headers_sent() ) {
			return;
		}
		setcookie( TrustToken::COOKIE, TrustToken::make( $user_id, $expires, self::key() ), array( 'expires' => $expires ) + $this->cookie_options() );
	}

	/**
	 * @return array<string, mixed>
	 */
	private function cookie_options(): array {
		return array(
			'path'     => COOKIEPATH ? COOKIEPATH : '/',
			'domain'   => COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		);
	}

	private function enabled(): bool {
		return (bool) $this->settings->get( 'firewall', 'whitelist_admins', true );
	}

	private function trusted( int $user_id ): bool {
		return user_can( $user_id, 'manage_options' ) || user_can( $user_id, 'unfiltered_html' );
	}
}
