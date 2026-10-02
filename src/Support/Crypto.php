<?php
/**
 * Cryptographic helpers for secret storage and constant-time comparison.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Encrypts sensitive values (e.g. TOTP secrets) at rest using AES-256-GCM, keyed off the
 * site's auth salts. Falls back gracefully when OpenSSL is unavailable.
 */
final class Crypto {

	private const CIPHER = 'aes-256-gcm';

	/**
	 * Derive a 32-byte key from WordPress salts plus a context label.
	 */
	private static function key( string $context = 'default' ): string {
		$material = ( defined( 'AUTH_KEY' ) ? AUTH_KEY : 'totalsec' )
			. ( defined( 'SECURE_AUTH_SALT' ) ? SECURE_AUTH_SALT : 'salt' )
			. $context;
		return hash( 'sha256', $material, true );
	}

	/**
	 * Encrypt a plaintext string. Returns a base64 blob (iv|tag|ciphertext) or the
	 * plaintext prefixed when OpenSSL is missing (so the system still functions).
	 */
	public static function encrypt( string $plaintext, string $context = 'default' ): string {
		if ( ! function_exists( 'openssl_encrypt' ) ) {
			return 'plain:' . base64_encode( $plaintext );
		}
		$iv  = random_bytes( 12 );
		$tag = '';
		$ct  = openssl_encrypt( $plaintext, self::CIPHER, self::key( $context ), OPENSSL_RAW_DATA, $iv, $tag );
		if ( false === $ct ) {
			return 'plain:' . base64_encode( $plaintext );
		}
		return 'enc:' . base64_encode( $iv . $tag . $ct );
	}

	/**
	 * Decrypt a blob produced by {@see encrypt()}.
	 */
	public static function decrypt( string $blob, string $context = 'default' ): string {
		if ( 0 === strpos( $blob, 'plain:' ) ) {
			return (string) base64_decode( substr( $blob, 6 ) );
		}
		if ( 0 !== strpos( $blob, 'enc:' ) || ! function_exists( 'openssl_decrypt' ) ) {
			return '';
		}
		$raw = base64_decode( substr( $blob, 4 ) );
		if ( false === $raw || strlen( $raw ) < 28 ) {
			return '';
		}
		$iv  = substr( $raw, 0, 12 );
		$tag = substr( $raw, 12, 16 );
		$ct  = substr( $raw, 28 );
		$pt  = openssl_decrypt( $ct, self::CIPHER, self::key( $context ), OPENSSL_RAW_DATA, $iv, $tag );
		return false === $pt ? '' : $pt;
	}

	/**
	 * Timing-safe string comparison.
	 */
	public static function equals( string $known, string $given ): bool {
		return hash_equals( $known, $given );
	}

	/**
	 * Generate a URL-safe random token.
	 */
	public static function token( int $bytes = 32 ): string {
		return rtrim( strtr( base64_encode( random_bytes( $bytes ) ), '+/', '-_' ), '=' );
	}
}
