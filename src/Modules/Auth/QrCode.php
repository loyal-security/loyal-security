<?php
/**
 * TOTP enrollment helper (provisioning URI + manual-entry formatting).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Produces the data an authenticator app needs to enrol. To stay fully standalone (no Node,
 * no external image services, no fragile vendored encoder) enrollment uses the universally
 * supported **manual setup key** plus the raw `otpauth://` URI. Every major authenticator
 * (Google Authenticator, Authy, 1Password, Microsoft Authenticator) accepts manual entry.
 *
 * A QR image can be layered on later by feeding {@see otpauth_uri()} to any QR renderer;
 * the data contract here is intentionally renderer-agnostic.
 */
class QrCode {

	private Totp $totp;

	public function __construct( ?Totp $totp = null ) {
		$this->totp = $totp ?? new Totp();
	}

	/**
	 * Build the enrollment payload for the UI.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $label  Account label.
	 * @param string $issuer Issuer.
	 * @return array{otpauth:string,manual_key:string,issuer:string,label:string}
	 */
	public function payload( string $secret, string $label, string $issuer ): array {
		return array(
			'otpauth'    => $this->totp->provisioning_uri( $secret, $label, $issuer ),
			'manual_key' => $this->totp->format_secret( $secret ),
			'issuer'     => $issuer,
			'label'      => $label,
		);
	}

	/**
	 * The raw otpauth:// URI (for QR rendering or copy/paste).
	 */
	public function otpauth_uri( string $secret, string $label, string $issuer ): string {
		return $this->totp->provisioning_uri( $secret, $label, $issuer );
	}
}
