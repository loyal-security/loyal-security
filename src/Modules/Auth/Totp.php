<?php
/**
 * Pure-PHP TOTP (RFC 6238) implementation.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Time-based one-time passwords compatible with Google Authenticator, Authy, 1Password,
 * etc. No external dependencies — Base32 + HMAC-SHA1 are implemented inline.
 */
class Totp {

	private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	private int $digits;
	private int $period;

	public function __construct( int $digits = 6, int $period = 30 ) {
		$this->digits = $digits;
		$this->period = $period;
	}

	/**
	 * Generate a new random Base32 secret.
	 *
	 * @param int $bytes Entropy bytes (20 = 160-bit, the RFC default).
	 */
	public function generate_secret( int $bytes = 20 ): string {
		return $this->base32_encode( random_bytes( $bytes ) );
	}

	/**
	 * Current TOTP code for a secret.
	 *
	 * @param string   $secret Base32 secret.
	 * @param int|null $time   Unix time (defaults to now).
	 */
	public function code( string $secret, ?int $time = null ): string {
		$time    = $time ?? time();
		$counter = (int) floor( $time / $this->period );
		return $this->hotp( $secret, $counter );
	}

	/**
	 * Verify a submitted code within a +/- window of time-steps.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $code   Submitted code.
	 * @param int    $window Allowed steps of clock drift each direction.
	 * @return bool
	 */
	public function verify( string $secret, string $code, int $window = 1 ): bool {
		$code = preg_replace( '/\s+/', '', $code );
		if ( ! preg_match( '/^\d{' . $this->digits . '}$/', (string) $code ) ) {
			return false;
		}
		$counter = (int) floor( time() / $this->period );
		for ( $i = -$window; $i <= $window; $i++ ) {
			if ( hash_equals( $this->hotp( $secret, $counter + $i ), (string) $code ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Build an otpauth:// provisioning URI for QR/manual entry.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $label  Account label (e.g. user@site).
	 * @param string $issuer Issuer name.
	 */
	public function provisioning_uri( string $secret, string $label, string $issuer ): string {
		return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $label )
			. '?secret=' . $secret
			. '&issuer=' . rawurlencode( $issuer )
			. '&algorithm=SHA1&digits=' . $this->digits . '&period=' . $this->period;
	}

	/**
	 * Format a secret in space-separated groups for manual entry.
	 */
	public function format_secret( string $secret ): string {
		return trim( chunk_split( $secret, 4, ' ' ) );
	}

	/* ------------------------------ internals ------------------------------ */

	private function hotp( string $secret, int $counter ): string {
		$key = $this->base32_decode( $secret );
		if ( '' === $key ) {
			return str_repeat( '0', $this->digits );
		}
		$binary = pack( 'N*', 0 ) . pack( 'N*', $counter ); // 8-byte big-endian counter.
		$hash   = hash_hmac( 'sha1', $binary, $key, true );
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;
		$part   = substr( $hash, $offset, 4 );
		$value  = unpack( 'N', $part )[1] & 0x7fffffff;
		$otp    = $value % ( 10 ** $this->digits );
		return str_pad( (string) $otp, $this->digits, '0', STR_PAD_LEFT );
	}

	private function base32_encode( string $data ): string {
		$bits = '';
		foreach ( str_split( $data ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$out  .= self::ALPHABET[ bindec( $chunk ) ];
		}
		return $out;
	}

	private function base32_decode( string $secret ): string {
		$secret = strtoupper( preg_replace( '/[^A-Z2-7]/', '', $secret ) );
		if ( '' === $secret ) {
			return '';
		}
		$bits = '';
		$len  = strlen( $secret );
		for ( $i = 0; $i < $len; $i++ ) {
			$pos = strpos( self::ALPHABET, $secret[ $i ] );
			if ( false === $pos ) {
				continue;
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$bytes = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$bytes .= chr( bindec( $byte ) );
			}
		}
		return $bytes;
	}
}
