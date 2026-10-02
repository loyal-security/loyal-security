<?php
/**
 * Trusted-device tokens — let users skip the 2FA challenge on a remembered device.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Crypto;

/**
 * Issues and verifies "remember this device for 30 days" tokens used to skip the second
 * factor on a previously-trusted browser.
 *
 * Storage model: the raw token never touches the database. On issue we store only
 * `sha256(token)` in the user's `_totalsecwp_trusted_devices` usermeta (a list of device
 * records). The browser keeps the raw token in an HttpOnly cookie of the form
 * `base64url("{user_id}|{token}")`. On verify we re-hash the cookie token and look for a
 * matching, non-expired record for that user — so a leaked database cannot be replayed to
 * forge a cookie, and a leaked cookie is scoped to a single device record with an expiry.
 */
class TrustedDevice {

	/** Cookie that carries the trusted-device token. */
	private const COOKIE_NAME = 'totalsecwp_td';

	/** Token lifetime (and cookie / record expiry). */
	private const COOKIE_TTL = 30 * DAY_IN_SECONDS;

	/** Usermeta key holding the per-user list of trusted-device records. */
	private const META_KEY = '_totalsecwp_trusted_devices';

	/**
	 * Issue a fresh trusted-device token for a user: persist its hash in usermeta and set the
	 * browser cookie.
	 */
	public function issue_token( int $user_id ): void {
		if ( $user_id <= 0 ) {
			return;
		}

		$ttl = (int) apply_filters( 'totalsecwp_trusted_device_ttl', self::COOKIE_TTL, $user_id );
		if ( $ttl <= 0 ) {
			$ttl = self::COOKIE_TTL;
		}

		$token = Crypto::token( 32 );
		$now   = time();

		$devices   = $this->get_records( $user_id );
		$devices[] = array(
			'token_hash' => hash( 'sha256', $token ),
			'issued_at'  => $now,
			'expires_at' => $now + $ttl,
			'user_agent' => $this->current_user_agent(),
		);

		// Keep the list tidy: drop expired entries before saving.
		$devices = $this->prune( $devices );
		update_user_meta( $user_id, self::META_KEY, $devices );

		$value = $this->encode_cookie( $user_id, $token );
		$this->set_cookie( $value, $now + $ttl );
	}

	/**
	 * Verify the trusted-device cookie.
	 *
	 * @return int|null The user id the cookie is valid for, or null if absent/invalid/expired.
	 */
	public function verify_token(): ?int {
		// phpcs:ignore WordPress.Security.NonceVerification
		$raw = isset( $_COOKIE[ self::COOKIE_NAME ] ) ? sanitize_text_field( wp_unslash( (string) $_COOKIE[ self::COOKIE_NAME ] ) ) : '';
		if ( '' === $raw ) {
			return null;
		}

		$decoded = $this->decode_cookie( $raw );
		if ( null === $decoded ) {
			return null;
		}
		[ $user_id, $token ] = $decoded;

		$hash    = hash( 'sha256', $token );
		$now     = time();
		$devices = $this->get_records( $user_id );

		foreach ( $devices as $device ) {
			$stored = (string) ( $device['token_hash'] ?? '' );
			if ( '' === $stored ) {
				continue;
			}
			if ( hash_equals( $stored, $hash ) && (int) ( $device['expires_at'] ?? 0 ) > $now ) {
				return $user_id;
			}
		}

		return null;
	}

	/**
	 * Revoke a single device by its token hash.
	 */
	public function revoke_token( int $user_id, string $token_hash ): bool {
		$devices = $this->get_records( $user_id );
		$kept    = array();
		$removed = false;

		foreach ( $devices as $device ) {
			if ( hash_equals( (string) ( $device['token_hash'] ?? '' ), $token_hash ) ) {
				$removed = true;
				continue;
			}
			$kept[] = $device;
		}

		if ( $removed ) {
			update_user_meta( $user_id, self::META_KEY, $kept );
		}
		return $removed;
	}

	/**
	 * Revoke every trusted device for a user.
	 */
	public function revoke_all_for_user( int $user_id ): void {
		delete_user_meta( $user_id, self::META_KEY );
	}

	/**
	 * Return a user's trusted devices (token hash, timestamps, user agent), pruning expired
	 * entries. The raw token is never stored, so it is never returned.
	 *
	 * @return array<int, array{token_hash:string,issued_at:int,expires_at:int,user_agent:string}>
	 */
	public function get_trusted_devices( int $user_id ): array {
		$devices = $this->get_records( $user_id );
		$pruned  = $this->prune( $devices );

		// Persist the pruned list so expired rows do not linger.
		if ( count( $pruned ) !== count( $devices ) ) {
			update_user_meta( $user_id, self::META_KEY, $pruned );
		}

		return array_values( $pruned );
	}

	/**
	 * Every trusted device across every user, flattened to one row per device with the owning
	 * user's identity attached — for the admin-wide "all trusted devices" view (search/filter by
	 * user, revoke any device if a machine is known compromised), as opposed to
	 * get_trusted_devices() which is scoped to a single user for self-service management.
	 *
	 * Only queries users who actually have a trusted-device record (meta_query EXISTS) rather
	 * than iterating every user on the site, so this stays cheap regardless of user count.
	 *
	 * @return array<int, array{user_id:int,login:string,display_name:string,roles:string[],token_hash:string,issued_at:int,expires_at:int,user_agent:string}>
	 */
	public function get_all_devices(): array {
		$users = get_users(
			array(
				'meta_key'     => self::META_KEY, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_compare' => 'EXISTS',
				'fields'       => array( 'ID', 'user_login', 'display_name' ),
			)
		);

		$rows = array();
		foreach ( $users as $u ) {
			$user_id = (int) $u->ID;
			$devices = $this->get_trusted_devices( $user_id ); // Already pruned of expired entries.
			if ( empty( $devices ) ) {
				continue; // Every record for this user had expired; get_trusted_devices() already saved the empty list.
			}
			$user_obj = get_userdata( $user_id );
			$roles    = $user_obj ? array_values( $user_obj->roles ) : array();
			foreach ( $devices as $device ) {
				$rows[] = array(
					'user_id'      => $user_id,
					'login'        => (string) $u->user_login,
					'display_name' => (string) $u->display_name,
					'roles'        => $roles,
					'token_hash'   => (string) $device['token_hash'],
					'issued_at'    => (int) $device['issued_at'],
					'expires_at'   => (int) $device['expires_at'],
					'user_agent'   => (string) $device['user_agent'],
				);
			}
		}

		return $rows;
	}

	/* ------------------------------ internals ------------------------------ */

	/**
	 * Read the raw record list from usermeta.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function get_records( int $user_id ): array {
		$devices = get_user_meta( $user_id, self::META_KEY, true );
		return is_array( $devices ) ? $devices : array();
	}

	/**
	 * Drop expired records.
	 *
	 * @param array<int, array<string, mixed>> $devices Records.
	 * @return array<int, array<string, mixed>>
	 */
	private function prune( array $devices ): array {
		$now = time();
		return array_values(
			array_filter(
				$devices,
				static fn( $d ) => is_array( $d ) && (int) ( $d['expires_at'] ?? 0 ) > $now
			)
		);
	}

	private function current_user_agent(): string {
		// phpcs:ignore WordPress.Security.NonceVerification
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		return substr( $ua, 0, 255 );
	}

	private function encode_cookie( int $user_id, string $token ): string {
		return rtrim( strtr( base64_encode( $user_id . '|' . $token ), '+/', '-_' ), '=' );
	}

	/**
	 * @return array{0:int,1:string}|null
	 */
	private function decode_cookie( string $raw ): ?array {
		$decoded = base64_decode( strtr( $raw, '-_', '+/' ), true );
		if ( false === $decoded || ! str_contains( $decoded, '|' ) ) {
			return null;
		}
		[ $id, $token ] = explode( '|', $decoded, 2 );
		$id = (int) $id;
		if ( $id <= 0 || '' === $token ) {
			return null;
		}
		return array( $id, $token );
	}

	private function set_cookie( string $value, int $expires ): void {
		if ( headers_sent() ) {
			return;
		}
		setcookie(
			self::COOKIE_NAME,
			$value,
			array(
				'expires'  => $expires,
				'path'     => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		$_COOKIE[ self::COOKIE_NAME ] = $value;
	}
}
