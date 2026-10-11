<?php
/**
 * Signed "trusted user" token for the pre-WordPress firewall.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * Optimized Mode inspects requests before WordPress loads, so it cannot ask WordPress who is
 * signed in. Standard Mode skips the heuristic and content checks for administrators and
 * editors (users who may post unfiltered HTML anyway); without this token the same people were
 * blocked in Optimized Mode for saving a post with an embed or a script.
 *
 * When such a user signs in, WordPress sets a cookie holding `v1.<user id>.<expiry>.<hmac>`,
 * signed with a site secret that lives only in the server-side firewall config. The prepend
 * checks the signature and expiry; it never trusts the user id on its own. Bans still apply.
 */
class TrustToken {

	/** Cookie name. */
	public const COOKIE = 'loyalsec_trust';

	/**
	 * Build a token.
	 *
	 * @param int    $user_id User id.
	 * @param int    $expires Unix time the token stops being valid.
	 * @param string $key     Site secret.
	 */
	public static function make( int $user_id, int $expires, string $key ): string {
		$payload = 'v1.' . $user_id . '.' . $expires;
		return $payload . '.' . hash_hmac( 'sha256', $payload, $key );
	}

	/**
	 * The user id a valid, unexpired token was issued to, or 0.
	 *
	 * @param string $token Cookie value.
	 * @param string $key   Site secret.
	 * @param int    $now   Current Unix time.
	 */
	public static function verify( string $token, string $key, int $now ): int {
		if ( strlen( $key ) < 32 || strlen( $token ) > 200 ) {
			return 0;
		}
		$parts = explode( '.', $token );
		if ( 4 !== count( $parts ) || 'v1' !== $parts[0] || ! ctype_digit( $parts[1] ) || ! ctype_digit( $parts[2] ) ) {
			return 0;
		}
		$expected = hash_hmac( 'sha256', 'v1.' . $parts[1] . '.' . $parts[2], $key );
		if ( ! hash_equals( $expected, $parts[3] ) || (int) $parts[2] < $now ) {
			return 0;
		}
		return (int) $parts[1];
	}
}
