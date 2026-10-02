<?php
/**
 * Passkey (WebAuthn) registration & authentication ceremonies.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Crypto;
use TotalSecurityWP\Vendor\WebAuthn\WebAuthn;
use TotalSecurityWP\Vendor\WebAuthn\WebAuthnException;
use TotalSecurityWP\Vendor\WebAuthn\Binary\ByteBuffer;

/**
 * Thin glue between the vendored {@see WebAuthn} library and this plugin's storage
 * ({@see Passkey}) and challenge lifecycle. All binary fields cross the REST boundary as
 * unpadded base64url strings — this class owns every encode/decode so neither the REST
 * controller nor the browser JS has to reason about the library's own binary types.
 *
 * Challenges are single-use, short-lived WordPress transients rather than PHP sessions
 * (which WordPress does not reliably enable) — registration challenges are scoped to the
 * logged-in user; login challenges are scoped to a random, unguessable flow id handed to the
 * browser, since the whole point of a discoverable/usernameless passkey flow is that the
 * server does not know who is signing in until the signed assertion comes back.
 */
class WebAuthnCeremony {

	private const REG_TTL   = 5 * MINUTE_IN_SECONDS;
	private const LOGIN_TTL = 2 * MINUTE_IN_SECONDS;

	private Passkey $passkeys;

	public function __construct( ?Passkey $passkeys = null ) {
		$this->passkeys = $passkeys ?? new Passkey();
	}

	/**
	 * @throws WebAuthnException If OpenSSL/SHA-256 support is missing on this host.
	 */
	private function webauthn(): WebAuthn {
		$rp_id   = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		$rp_name = $this->rp_name();
		// 'none'-only: sufficient for consumer passkey login (identity of the physical
		// authenticator model doesn't matter here) and avoids needing to vendor/maintain
		// root CA trust bundles for every hardware vendor's device-attestation format.
		return new WebAuthn( $rp_name, $rp_id, array( 'none' ), true );
	}

	private function rp_name(): string {
		try {
			return \TotalSecurityWP\Support\Brand::name();
		} catch ( \Throwable $e ) {
			return get_bloginfo( 'name' ) ?: 'WordPress';
		}
	}

	/* ------------------------------ registration ------------------------------ */

	/**
	 * Begin registering a new passkey for a logged-in user.
	 *
	 * @return array{options:array<string,mixed>}
	 */
	public function begin_registration( int $user_id ): array {
		$user = get_userdata( $user_id );
		$w    = $this->webauthn();

		$exclude = array_map(
			static fn( string $id ) => self::b64url_decode( $id ),
			$this->passkeys->all_credential_ids()
		);

		// requireResidentKey: true — this passkey is meant to be a complete, passwordless
		// sign-in method, which requires a discoverable credential so the browser can offer it
		// at login time before anyone has typed a username. requireUserVerification: true — a
		// credential with no password behind it needs the authenticator's own biometric/PIN
		// check, not just proof someone touched the device (that's merely presence, not identity).
		$args = $w->getCreateArgs(
			(string) $user_id,
			$user ? $user->user_login : 'user',
			$user ? $user->display_name : 'user',
			60,
			true,
			true,
			null,
			$exclude
		);

		// Transients round-trip through wp_options, a utf8mb4 text column — the raw challenge
		// bytes are arbitrary binary, not valid UTF-8, and MySQL silently rejects the write
		// (set_transient() returns false) rather than storing it. Base64 keeps it as plain text.
		set_transient( $this->reg_key( $user_id ), base64_encode( $w->getChallenge()->getBinaryString() ), self::REG_TTL );

		return array( 'options' => json_decode( (string) wp_json_encode( $args ), true ) );
	}

	/**
	 * Verify a registration response and store the new credential.
	 *
	 * @return array{ok:bool,message?:string}
	 */
	public function complete_registration( int $user_id, string $client_data_json_b64, string $attestation_object_b64, string $label ): array {
		$stored = get_transient( $this->reg_key( $user_id ) );
		delete_transient( $this->reg_key( $user_id ) ); // Single-use regardless of outcome.

		if ( ! is_string( $stored ) || '' === $stored ) {
			return array( 'ok' => false, 'message' => __( 'Registration expired — try again.', 'loyal-security' ) );
		}
		$challenge = base64_decode( $stored, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $challenge ) {
			return array( 'ok' => false, 'message' => __( 'Registration expired — try again.', 'loyal-security' ) );
		}

		try {
			$w    = $this->webauthn();
			$data = $w->processCreate(
				self::b64url_decode( $client_data_json_b64 ),
				self::b64url_decode( $attestation_object_b64 ),
				$challenge,
				true,  // requireUserVerification — see begin_registration()'s comment.
				true,  // requireUserPresent
				false  // failIfRootMismatch — attestation is 'none'-only, there is no root to match
			);
		} catch ( \Throwable $e ) {
			return array( 'ok' => false, 'message' => $this->friendly_message( $e ) );
		}

		$this->passkeys->add_credential(
			$user_id,
			self::b64url_encode( (string) $data->credentialId ),
			(string) $data->credentialPublicKey,
			(int) $data->signatureCounter,
			sanitize_text_field( $label )
		);

		return array( 'ok' => true );
	}

	/* ------------------------------ authentication ------------------------------ */

	/**
	 * Begin a passwordless login: a discoverable-credential request with no allowlist, so the
	 * browser/authenticator itself presents whichever passkeys it holds for this site.
	 *
	 * @return array{flow:string,options:array<string,mixed>}
	 */
	public function begin_login(): array {
		$w    = $this->webauthn();
		// requireUserVerification: true — see begin_registration()'s comment; a passkey login
		// has no password behind it, so the authenticator's biometric/PIN check IS the proof
		// of identity, not an optional extra.
		$args = $w->getGetArgs( array(), 60, true, true, true, true, true, true );

		$flow = Crypto::token( 24 );
		// See begin_registration()'s comment — the challenge is arbitrary binary and must be
		// text-safe before it can survive a round trip through the wp_options table.
		set_transient( $this->login_key( $flow ), base64_encode( $w->getChallenge()->getBinaryString() ), self::LOGIN_TTL );

		return array( 'flow' => $flow, 'options' => json_decode( (string) wp_json_encode( $args ), true ) );
	}

	/**
	 * Verify a login assertion. On success returns the user id to sign in as — the REST
	 * controller (not this class) is responsible for actually setting the auth cookie, so a
	 * ceremony/verification bug here can fail closed without also owning the sign-in side effect.
	 *
	 * @return array{ok:bool,user_id?:int,message?:string}
	 */
	public function complete_login( string $flow, string $credential_id_b64, string $client_data_json_b64, string $authenticator_data_b64, string $signature_b64 ): array {
		$stored = get_transient( $this->login_key( $flow ) );
		delete_transient( $this->login_key( $flow ) ); // Single-use regardless of outcome.

		if ( ! is_string( $stored ) || '' === $stored ) {
			return array( 'ok' => false, 'message' => __( 'Login request expired — try again.', 'loyal-security' ) );
		}
		$challenge = base64_decode( $stored, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $challenge ) {
			return array( 'ok' => false, 'message' => __( 'Login request expired — try again.', 'loyal-security' ) );
		}

		// Re-canonicalize so minor padding/charset differences from the browser can't cause a
		// false lookup miss.
		$credential_id = self::b64url_encode( self::b64url_decode( $credential_id_b64 ) );

		$found = $this->passkeys->find_by_credential_id( $credential_id );
		if ( null === $found ) {
			return array( 'ok' => false, 'message' => __( 'Passkey not recognized.', 'loyal-security' ) );
		}

		$w = $this->webauthn();
		try {
			$w->processGet(
				self::b64url_decode( $client_data_json_b64 ),
				self::b64url_decode( $authenticator_data_b64 ),
				self::b64url_decode( $signature_b64 ),
				(string) $found['record']['public_key'],
				$challenge,
				(int) ( $found['record']['sign_count'] ?? 0 ),
				true // requireUserVerification
			);
		} catch ( \Throwable $e ) {
			return array( 'ok' => false, 'message' => $this->friendly_message( $e ) );
		}

		$this->passkeys->update_after_login( $found['user_id'], $credential_id, (int) $w->getSignatureCounter() );

		return array( 'ok' => true, 'user_id' => $found['user_id'] );
	}

	/* ------------------------------ helpers ------------------------------ */

	private function reg_key( int $user_id ): string {
		return 'totalsecwp_wan_reg_' . $user_id;
	}

	private function login_key( string $flow ): string {
		return 'totalsecwp_wan_login_' . $flow;
	}

	/**
	 * WebAuthnException messages are already short and non-sensitive (e.g. "invalid
	 * signature", "invalid challenge") — safe to surface directly rather than collapsing
	 * everything to a generic string, which would make the browser console the only way to
	 * ever diagnose a misconfigured RP ID or a stale challenge.
	 */
	private function friendly_message( \Throwable $e ): string {
		if ( $e instanceof WebAuthnException ) {
			return $e->getMessage();
		}
		return __( 'Could not verify the passkey response.', 'loyal-security' );
	}

	public static function b64url_encode( string $raw ): string {
		return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
	}

	public static function b64url_decode( string $encoded ): string {
		$decoded = base64_decode( strtr( $encoded, '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		return false !== $decoded ? $decoded : '';
	}
}
