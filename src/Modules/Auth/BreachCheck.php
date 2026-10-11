<?php
/**
 * Breached-password detection via HaveIBeenPwned (k-anonymity).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Plugin;
use LoyalSecurity\Modules\Audit\EventCatalog;

/**
 * Checks the password supplied at login against the HaveIBeenPwned "Pwned Passwords" range
 * API using k-anonymity: only the first five characters of the SHA-1 hash ever leave the
 * server. The cleartext password is available to the `check_password` filter, which is the
 * only point in the WordPress login flow where it can be inspected without storing it.
 *
 * Logins are never blocked — a breached password merely raises a dismissible admin notice for
 * that user and records a warning in the audit log. The check is throttled per user (it will
 * not re-query the API more than once per day) so repeated logins do not hammer the API.
 */
class BreachCheck {

	/** Transient prefix flagging that a user's password was found in a breach corpus. */
	private const FLAG_PREFIX = 'loyalsec_hibp_';

	/** Transient prefix throttling how often we query the API for a given user. */
	private const THROTTLE_PREFIX = 'loyalsec_hibp_chk_';

	/** Pwned Passwords range endpoint. */
	private const API_BASE = 'https://api.pwnedpasswords.com/range/';

	public function register_hooks(): void {
		// `check_password` exposes the plaintext password right after WordPress confirms it
		// matches the stored hash. Args: ( $check, $password, $hash, $user_id ).
		add_filter( 'check_password', array( $this, 'check_breach' ), 10, 4 );

		// Surface the result to the affected user inside wp-admin.
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
	}

	/**
	 * Inspect a just-verified password against the breach corpus.
	 *
	 * This is a pass-through filter: it always returns $check unchanged so it can never affect
	 * whether the login succeeds.
	 *
	 * @param bool   $check    Whether the password matched the stored hash.
	 * @param string $password The plaintext password submitted.
	 * @param string $hash     The stored password hash (unused).
	 * @param int    $user_id  The user being authenticated.
	 * @return bool The unmodified $check.
	 */
	public function check_breach( $check, $password, $hash, $user_id ) {
		// Only act on a successful match for a real user, and only if enabled.
		if ( ! $check || (int) $user_id <= 0 || ! is_string( $password ) || '' === $password ) {
			return $check;
		}

		/**
		 * Filters whether the breached-password check runs.
		 *
		 * @since 1.0.0
		 *
		 * @param bool $enabled True to run the HIBP lookup.
		 * @param int  $user_id The user being authenticated.
		 */
		if ( ! apply_filters( 'loyalsec_breach_check_enabled', true, (int) $user_id ) ) {
			return $check;
		}

		$user_id = (int) $user_id;

		// Throttle: at most one API call per user per day.
		if ( false !== get_transient( self::THROTTLE_PREFIX . $user_id ) ) {
			return $check;
		}
		set_transient( self::THROTTLE_PREFIX . $user_id, 1, DAY_IN_SECONDS );

		$count = $this->breach_count( $password );

		if ( $count > 0 ) {
			set_transient( self::FLAG_PREFIX . $user_id, $count, DAY_IN_SECONDS );
			$this->log_event( $user_id, $count );
		} else {
			// Clear any stale flag once the password is confirmed clean.
			delete_transient( self::FLAG_PREFIX . $user_id );
		}

		return $check;
	}

	/**
	 * Query the Pwned Passwords range API and return how many times the password appears in
	 * known breaches (0 if not found, or on any network/parse error — fail open).
	 */
	private function breach_count( string $password ): int {
		$sha1   = strtoupper( sha1( $password ) );
		$prefix = substr( $sha1, 0, 5 );
		$suffix = substr( $sha1, 5 );

		$response = wp_remote_get(
			self::API_BASE . $prefix,
			array(
				'timeout'    => 3,
				'user-agent' => \LoyalSecurity\Support\Http::user_agent(),
				'headers'    => array( 'Add-Padding' => 'true' ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return 0;
		}

		$body = (string) wp_remote_retrieve_body( $response );
		if ( '' === $body ) {
			return 0;
		}

		foreach ( preg_split( '/\r\n|\n/', $body ) as $line ) {
			$parts = explode( ':', trim( $line ), 2 );
			if ( count( $parts ) !== 2 ) {
				continue;
			}
			if ( 0 === strcasecmp( $parts[0], $suffix ) ) {
				return max( 0, (int) $parts[1] );
			}
		}

		return 0;
	}

	/**
	 * Show a one-time dismissible notice to the affected user.
	 */
	public function render_notice(): void {
		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		$count = get_transient( self::FLAG_PREFIX . $user_id );
		if ( false === $count ) {
			return;
		}

		// Show once: clear the flag as soon as it is displayed.
		delete_transient( self::FLAG_PREFIX . $user_id );

		$message = sprintf(
			/* translators: %s: formatted number of breach appearances. */
			__( 'Your account password has appeared in %s known data breaches. It still works, but it is no longer secret. Please change it as soon as possible.', 'loyal-security' ),
			number_format_i18n( (int) $count )
		);

		printf(
			'<div class="notice notice-error is-dismissible"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
			esc_html__( 'Loyal Security:', 'loyal-security' ),
			esc_html( $message ),
			esc_url( admin_url( 'profile.php' ) ),
			esc_html__( 'Change your password', 'loyal-security' )
		);
	}

	/**
	 * Record the detection in the audit log (best-effort).
	 */
	private function log_event( int $user_id, int $count ): void {
		try {
			Plugin::instance()->container()->make( 'logger' )->log(
				EventCatalog::BREACHED_PASSWORD_DETECTED,
				array(
					'user_id' => $user_id,
					'count'   => $count,
				)
			);
		} catch ( \Throwable $e ) {
			// Logging must never interfere with login.
		}
	}
}
