<?php
/**
 * Per-request CSP nonce.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Csp;

defined( 'ABSPATH' ) || exit;

/**
 * One random value per request, shared by the header builder and every place that tags an
 * inline <script>/<style> tag with it. A CSP nonce only works if the exact same value that
 * appears in the Content-Security-Policy header also appears on the tag — generating it lazily
 * on first use (rather than once in CspModule::boot()) means whichever runs first, the header
 * emission (send_headers) or a content filter (wp_inline_script_attributes, which fires during
 * template rendering), both get the same value, since it's cached after the first call.
 */
class CspNonce {

	private static ?string $value = null;

	/**
	 * The current request's nonce, base64 of 16 random bytes (matches what CSP's
	 * base64-value grammar expects, and is what WordPress core's own nonce-consumers —
	 * e.g. wp_inline_script_attributes callers — conventionally produce).
	 */
	public static function value(): string {
		if ( null === self::$value ) {
			self::$value = base64_encode( random_bytes( 16 ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- CSP nonce encoding, not obfuscation.
		}
		return self::$value;
	}

	/**
	 * Reset for tests only.
	 */
	public static function reset(): void {
		self::$value = null;
	}
}
