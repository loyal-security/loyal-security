<?php
/**
 * Two-factor authentication manager.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Crypto;

/**
 * Manages per-user TOTP enrollment, encrypted secret storage, hashed backup codes, and
 * verification. Enforcement-by-role is decided here too.
 */
class TwoFactor {

	private Totp $totp;
	private QrCode $qr;

	public function __construct() {
		$this->totp = new Totp();
		$this->qr   = new QrCode( $this->totp );
	}

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'totalsecwp_twofa';
	}

	/**
	 * @return array<string, mixed>|null
	 */
	private function row( int $user_id ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT * FROM %i WHERE user_id = %d", $this->table(), $user_id ),
			ARRAY_A
		);
		return $row ?: null;
	}

	public function is_enabled( int $user_id ): bool {
		$row = $this->row( $user_id );
		return $row && (int) $row['enabled'] === 1;
	}

	/**
	 * Begin enrollment: return the enrollment payload.
	 *
	 * If a pending (unconfirmed) enrollment already exists with a readable secret, the same
	 * secret is reused so a QR code the user already scanned stays valid. A new secret is
	 * generated only when there is no pending row, or the stored secret is unreadable.
	 *
	 * @return array<string, mixed>
	 */
	public function begin_enroll( int $user_id ): array {
		global $wpdb;
		$user   = get_userdata( $user_id );
		$label  = $user ? $user->user_email ?: $user->user_login : 'user';
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ?: 'WordPress';

		// Resume pending enrollment: reuse the existing secret so a QR the user already
		// scanned stays valid. Fall through only when the secret is unreadable.
		$existing = $this->row( $user_id );
		if ( $existing && (int) $existing['enabled'] === 0 ) {
			$secret = Crypto::decrypt( (string) $existing['secret'], '2fa' );
			if ( '' !== $secret ) {
				return $this->qr->payload( $secret, (string) $label, (string) $issuer );
			}
		}

		$secret = $this->totp->generate_secret();

		$wpdb->replace( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'user_id'      => $user_id,
				'secret'       => Crypto::encrypt( $secret, '2fa' ),
				'backup_codes' => null,
				'enabled'      => 0,
				'confirmed_at' => null,
				'last_used'    => 0,
			)
		);

		return $this->qr->payload( $secret, (string) $label, (string) $issuer );
	}

	/**
	 * Confirm enrollment with a code; on success enable 2FA and issue backup codes.
	 *
	 * @return array{ok:bool,backup_codes?:string[],message?:string}
	 */
	public function confirm_enroll( int $user_id, string $code ): array {
		$row = $this->row( $user_id );
		if ( ! $row ) {
			return array( 'ok' => false, 'message' => __( 'Begin enrollment first.', 'loyal-security' ) );
		}
		$secret = Crypto::decrypt( (string) $row['secret'], '2fa' );
		if ( ! $this->totp->verify( $secret, $code ) ) {
			return array( 'ok' => false, 'message' => __( 'Invalid code. Check your authenticator and try again.', 'loyal-security' ) );
		}

		$codes  = $this->generate_backup_codes();
		$hashed = array_map( static fn( $c ) => wp_hash_password( $c ), $codes );

		global $wpdb;
		$updated = $wpdb->update( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'enabled'      => 1,
				'confirmed_at' => gmdate( 'Y-m-d H:i:s' ),
				'backup_codes' => wp_json_encode( $hashed ),
			),
			array( 'user_id' => $user_id )
		);

		if ( false === $updated || 0 === $updated ) {
			return array( 'ok' => false, 'message' => __( 'Could not save enrollment. Please try again.', 'loyal-security' ) );
		}

		return array( 'ok' => true, 'backup_codes' => $codes );
	}

	/**
	 * Verify a login challenge: a TOTP code or a one-time backup code.
	 */
	public function verify( int $user_id, string $code ): bool {
		$row = $this->row( $user_id );
		if ( ! $row || (int) $row['enabled'] !== 1 ) {
			return false;
		}
		$secret = Crypto::decrypt( (string) $row['secret'], '2fa' );
		if ( $this->totp->verify( $secret, $code ) ) {
			global $wpdb;
			$wpdb->update( $this->table(), array( 'last_used' => time() ), array( 'user_id' => $user_id ) ); // phpcs:ignore WordPress.DB
			return true;
		}
		return $this->consume_backup_code( $user_id, $code, $row );
	}

	public function disable( int $user_id ): void {
		global $wpdb;
		$wpdb->delete( $this->table(), array( 'user_id' => $user_id ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Whether a given user must complete 2FA, based on enforced roles.
	 *
	 * @param \WP_User $user           User.
	 * @param string[] $enforced_roles Roles that require 2FA.
	 */
	public function is_required( \WP_User $user, array $enforced_roles ): bool {
		if ( $this->is_enabled( (int) $user->ID ) ) {
			return true; // Always challenge users who have set it up.
		}
		return (bool) array_intersect( $user->roles, $enforced_roles );
	}

	/**
	 * Status payload for the UI.
	 *
	 * @return array<string, mixed>
	 */
	public function status( int $user_id ): array {
		$row = $this->row( $user_id );
		return array(
			'enabled'      => $row && (int) $row['enabled'] === 1,
			'pending'      => $row && (int) $row['enabled'] === 0,
			'confirmed_at' => $row['confirmed_at'] ?? null,
			'backup_left'  => $row && $row['backup_codes'] ? count( array_filter( (array) json_decode( (string) $row['backup_codes'], true ) ) ) : 0,
		);
	}

	/* ------------------------------ internals ------------------------------ */

	/**
	 * @return string[]
	 */
	private function generate_backup_codes( int $count = 10 ): array {
		$codes = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$codes[] = sprintf( '%04d-%04d', random_int( 0, 9999 ), random_int( 0, 9999 ) );
		}
		return $codes;
	}

	/**
	 * @param array<string, mixed> $row 2FA row.
	 */
	private function consume_backup_code( int $user_id, string $code, array $row ): bool {
		$hashes = json_decode( (string) ( $row['backup_codes'] ?? '[]' ), true );
		if ( ! is_array( $hashes ) ) {
			return false;
		}
		require_once \TotalSecurityWP\Support\Paths::includes() . '/class-phpass.php';
		$hasher = new \PasswordHash( 8, true );

		foreach ( $hashes as $idx => $hash ) {
			if ( $hash && $hasher->CheckPassword( $code, $hash ) ) {
				unset( $hashes[ $idx ] ); // One-time use.
				global $wpdb;
				$wpdb->update( // phpcs:ignore WordPress.DB
					$this->table(),
					array( 'backup_codes' => wp_json_encode( array_values( $hashes ) ), 'last_used' => time() ),
					array( 'user_id' => $user_id )
				);
				return true;
			}
		}
		return false;
	}
}
