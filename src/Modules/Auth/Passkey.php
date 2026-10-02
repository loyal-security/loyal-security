<?php
/**
 * Passkey (WebAuthn) credential storage.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Stores each user's registered passkeys (public key, not the private key, which never
 * leaves the authenticator) in usermeta as a list of records — same storage shape as
 * {@see TrustedDevice}, since both are per-user lists of small, self-contained credential
 * records with no relational needs a dedicated table would justify.
 *
 * A passkey is a complete, standalone sign-in method (the private key is already sealed
 * behind the authenticator's own biometric/PIN unlock), not a second factor layered on top
 * of a password — this mirrors how every real-world passkey implementation treats it.
 */
class Passkey {

	/** Usermeta key holding the per-user list of passkey records. */
	private const META_KEY = '_totalsecwp_passkeys';

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function get_credentials( int $user_id ): array {
		$list = get_user_meta( $user_id, self::META_KEY, true );
		return is_array( $list ) ? $list : array();
	}

	public function has_any( int $user_id ): bool {
		return ! empty( $this->get_credentials( $user_id ) );
	}

	/**
	 * Store a newly-registered credential.
	 *
	 * @param string $credential_id Base64url-encoded credential ID.
	 * @param string $public_key    PEM-encoded public key.
	 */
	public function add_credential( int $user_id, string $credential_id, string $public_key, int $sign_count, string $label ): void {
		$list   = $this->get_credentials( $user_id );
		$list[] = array(
			'id'          => $credential_id,
			'public_key'  => $public_key,
			'sign_count'  => $sign_count,
			'label'       => '' !== $label ? mb_substr( $label, 0, 100 ) : $this->default_label(),
			'created_at'  => time(),
			'last_used_at' => 0,
		);
		update_user_meta( $user_id, self::META_KEY, $list );
	}

	/**
	 * Remove one of a user's own credentials by ID.
	 */
	public function remove_credential( int $user_id, string $credential_id ): bool {
		$list    = $this->get_credentials( $user_id );
		$kept    = array();
		$removed = false;
		foreach ( $list as $row ) {
			if ( hash_equals( (string) ( $row['id'] ?? '' ), $credential_id ) ) {
				$removed = true;
				continue;
			}
			$kept[] = $row;
		}
		if ( $removed ) {
			if ( empty( $kept ) ) {
				delete_user_meta( $user_id, self::META_KEY );
			} else {
				update_user_meta( $user_id, self::META_KEY, $kept );
			}
		}
		return $removed;
	}

	/**
	 * Reverse lookup: which user (if any) owns this credential ID — needed at login time,
	 * before we know who is signing in (the whole point of a discoverable/usernameless
	 * passkey flow). Only queries users who actually have at least one passkey (meta_query
	 * EXISTS), mirroring {@see TrustedDevice::get_all_devices()}'s approach, so this stays
	 * cheap regardless of total user count.
	 *
	 * @return array{user_id:int, record:array<string, mixed>}|null
	 */
	public function find_by_credential_id( string $credential_id ): ?array {
		$users = get_users(
			array(
				'meta_key'     => self::META_KEY, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_compare' => 'EXISTS',
				'fields'       => array( 'ID' ),
			)
		);

		foreach ( $users as $u ) {
			$user_id = (int) $u->ID;
			foreach ( $this->get_credentials( $user_id ) as $row ) {
				if ( hash_equals( (string) ( $row['id'] ?? '' ), $credential_id ) ) {
					return array( 'user_id' => $user_id, 'record' => $row );
				}
			}
		}
		return null;
	}

	/**
	 * Update the stored signature counter after a successful login — required so a cloned
	 * authenticator (one that replays an old counter value) is detectable on its next use.
	 */
	public function update_after_login( int $user_id, string $credential_id, int $sign_count ): void {
		$list = $this->get_credentials( $user_id );
		$now  = time();
		foreach ( $list as &$row ) {
			if ( hash_equals( (string) ( $row['id'] ?? '' ), $credential_id ) ) {
				$row['sign_count']   = $sign_count;
				$row['last_used_at'] = $now;
				break;
			}
		}
		unset( $row );
		update_user_meta( $user_id, self::META_KEY, $list );
	}

	/**
	 * All credential IDs across every user with at least one passkey — fed to the vendored
	 * WebAuthn library's exclude-list when a user registers a new one, so the same physical
	 * key can't be bound to two different WordPress accounts.
	 *
	 * @return string[]
	 */
	public function all_credential_ids(): array {
		$users = get_users(
			array(
				'meta_key'     => self::META_KEY, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_compare' => 'EXISTS',
				'fields'       => array( 'ID' ),
			)
		);
		$ids = array();
		foreach ( $users as $u ) {
			foreach ( $this->get_credentials( (int) $u->ID ) as $row ) {
				if ( ! empty( $row['id'] ) ) {
					$ids[] = (string) $row['id'];
				}
			}
		}
		return $ids;
	}

	private function default_label(): string {
		// phpcs:ignore WordPress.Security.NonceVerification
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( '' === $ua ) {
			return __( 'Passkey', 'loyal-security' );
		}
		if ( false !== stripos( $ua, 'iphone' ) || false !== stripos( $ua, 'ipad' ) ) {
			return __( 'iPhone/iPad passkey', 'loyal-security' );
		}
		if ( false !== stripos( $ua, 'android' ) ) {
			return __( 'Android passkey', 'loyal-security' );
		}
		if ( false !== stripos( $ua, 'mac os' ) ) {
			return __( 'Mac passkey', 'loyal-security' );
		}
		if ( false !== stripos( $ua, 'windows' ) ) {
			return __( 'Windows passkey', 'loyal-security' );
		}
		return __( 'Passkey', 'loyal-security' );
	}
}
