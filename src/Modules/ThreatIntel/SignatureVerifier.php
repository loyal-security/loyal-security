<?php
/**
 * Ed25519 payload verifier for the ThreatIntel feed.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\ThreatIntel;

defined( 'ABSPATH' ) || exit;

/**
 * Verifies the detached Ed25519 signature on every feed bundle before the payload is trusted.
 *
 * Verification is mandatory and fail-closed: a bad or missing signature leaves the existing
 * cache untouched. A MITM or compromised CDN therefore cannot inject malicious rules into the
 * plugin — the only way to get rules onto disk is to possess the feed backend's private key.
 *
 * The production feed public key is baked in below so verification works out of the box on
 * every site with no configuration. Override only for key rotation or a self-hosted feed via:
 *   - The LOYALSEC_FEED_PUBKEY constant (define in wp-config.php)
 *   - The loyalsec_feed_public_key filter (Freemius adapter, test override, etc.)
 */
class SignatureVerifier {

	/**
	 * Ed25519 public key of the Loyal Security / LicenseKit feed backend (base64, 32 bytes).
	 *
	 * This is the LIVE production key (confirmed with the LicenseKit backend), not a placeholder.
	 * A public key is not a secret — it is *designed* to ship with the plugin: it can only verify
	 * signatures, never create them. The matching private key (LOYALSEC_FEED_PRIVATE_KEY) lives
	 * only on the feed server. Rotating this key requires a plugin update; sites can override it
	 * in the meantime via the LOYALSEC_FEED_PUBKEY constant or the loyalsec_feed_public_key filter.
	 */
	private const PUBLIC_KEY_DEFAULT = 'MlJkKDWAN5UDaNl1tYeapotirgY8ltrO7T4oou40JbM=';

	/**
	 * Verify a signed bundle from the feed server.
	 *
	 * The bundle must contain:
	 *   payload   — base64-encoded JSON (the dataset: version + rules).
	 *   signature — base64-encoded 64-byte Ed25519 detached signature over the raw payload bytes.
	 *
	 * @param array<string, mixed> $bundle Raw bundle from FeedClient::fetch().
	 * @return array<string, mixed>|null Decoded payload on success; null on any failure.
	 */
	public static function verify( array $bundle ): ?array {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return null;
		}

		$payload_b64 = isset( $bundle['payload'] ) ? (string) $bundle['payload'] : '';
		$sig_b64     = isset( $bundle['signature'] ) ? (string) $bundle['signature'] : '';
		if ( '' === $payload_b64 || '' === $sig_b64 ) {
			return null;
		}

		// Resolve the public key: constant override → filter → built-in production key.
		$key_b64 = defined( 'LOYALSEC_FEED_PUBKEY' )
			? (string) LOYALSEC_FEED_PUBKEY
			: self::PUBLIC_KEY_DEFAULT;

		/** @param string $key_b64 Base64-encoded 32-byte Ed25519 public key. */
		$key_b64 = (string) apply_filters( 'loyalsec_feed_public_key', $key_b64 );

		$public_key = base64_decode( $key_b64, true );
		if ( false === $public_key || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $public_key ) ) {
			return null;
		}

		$payload_raw = base64_decode( $payload_b64, true );
		$sig_raw     = base64_decode( $sig_b64, true );
		if ( false === $payload_raw || false === $sig_raw ) {
			return null;
		}

		if ( ! sodium_crypto_sign_verify_detached( $sig_raw, $payload_raw, $public_key ) ) {
			return null;
		}

		$data = json_decode( $payload_raw, true );
		return is_array( $data ) ? $data : null;
	}
}
