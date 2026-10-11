<?php
/**
 * Telemetry redactor — strips site identity and personal data before anything leaves the box.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Telemetry;

defined( 'ABSPATH' ) || exit;

/**
 * Single place where anonymization happens. Everything that is transmitted to the LicenseKit
 * backend passes through here first. The contract is: keep the *attacker's* payload (the
 * learning signal needed to author a WAF rule) but remove anything that identifies the site
 * or its data subjects.
 *
 * Mirrors Wordfence's "share basic attack data" model: attacker request data is shared,
 * site-owner content/credentials are not.
 */
class Redactor {

	/** Hard cap on a redacted request body (bytes). Keeps payloads bounded. */
	private const MAX_BODY = 8192;

	/** Header keys that must never be transmitted (carry session / auth / PII). */
	private const HEADER_DENYLIST = array(
		'cookie',
		'authorization',
		'proxy-authorization',
		'x-wp-nonce',
		'php-auth-pw',
		'php-auth-user',
		'set-cookie',
	);

	/** Parameter keys whose *values* are always masked regardless of content. */
	private const PARAM_DENYLIST = array(
		'pass', 'pwd', 'password', 'pass1', 'pass2', 'secret', 'token', 'nonce',
		'auth_key', 'api_key', 'apikey', 'access_token', 'session', 'cookie', 'email',
		'user_login', 'log', 'user_email',
	);

	private const MASK = '«redacted»';

	/**
	 * Extra literal strings to scrub out of every value (e.g. the current admin's login/email,
	 * the site's own host). Populated by the caller so the site can never leak its own identity.
	 *
	 * @var string[]
	 */
	private array $extra_needles;

	/**
	 * @param string[] $extra_needles Literal strings to mask out of payloads.
	 */
	public function __construct( array $extra_needles = array() ) {
		$this->extra_needles = array_values(
			array_filter(
				array_map( 'strval', $extra_needles ),
				static fn( string $s ): bool => strlen( $s ) >= 3
			)
		);
	}

	/**
	 * Build a Redactor seeded with the current site's own identifiers so they are scrubbed
	 * from any payload (defence in depth — they should not appear in attacker data anyway).
	 */
	public static function for_site(): self {
		$needles = array();

		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( is_string( $host ) && '' !== $host ) {
			$needles[] = $host;
		}

		$uid = function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0;
		if ( $uid > 0 ) {
			$user = get_userdata( $uid );
			if ( $user ) {
				$needles[] = (string) $user->user_login;
				$needles[] = (string) $user->user_email;
			}
		}

		return new self( $needles );
	}

	/**
	 * Redact a single scalar string: mask emails, long digit runs (card/phone-like), obvious
	 * key=secret pairs, and any caller-supplied identifiers.
	 */
	public function scrub_string( string $value ): string {
		if ( '' === $value ) {
			return $value;
		}

		// Emails.
		$value = preg_replace( '/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', self::MASK, $value );
		// 13–19 digit runs (payment-card-like), allowing spaces/dashes.
		$value = preg_replace( '/\b(?:\d[ \-]?){13,19}\b/', self::MASK, (string) $value );
		// secret-ish key=value or key:value pairs in raw bodies / query strings.
		$value = preg_replace(
			'/((?:pass(?:word)?|pwd|secret|token|api[_\-]?key|auth|session|nonce)[a-z0-9_\-]*\s*[=:]\s*)([^&\s"\']+)/i',
			'$1' . self::MASK,
			(string) $value
		);

		// Caller-supplied literals (site host, admin login/email).
		foreach ( $this->extra_needles as $needle ) {
			$value = str_ireplace( $needle, self::MASK, (string) $value );
		}

		return (string) $value;
	}

	/**
	 * Redact a key/value bag (GET/POST). Values under denylisted keys are fully masked;
	 * everything else is scrubbed for embedded PII but otherwise preserved (the attack signal).
	 *
	 * @param array<string,mixed> $params
	 * @return array<string,mixed>
	 */
	public function scrub_params( array $params ): array {
		$out = array();
		foreach ( $params as $key => $value ) {
			$lower = strtolower( (string) $key );

			$denied = false;
			foreach ( self::PARAM_DENYLIST as $needle ) {
				if ( false !== strpos( $lower, $needle ) ) {
					$denied = true;
					break;
				}
			}

			if ( $denied ) {
				$out[ $key ] = self::MASK;
				continue;
			}

			if ( is_array( $value ) ) {
				$out[ $key ] = $this->scrub_params( $value );
			} else {
				$out[ $key ] = $this->scrub_string( (string) $value );
			}
		}
		return $out;
	}

	/**
	 * Filter request headers down to a safe, useful subset (UA, referer, content-type, accept,
	 * host is dropped) with values scrubbed.
	 *
	 * @param array<string,mixed> $headers
	 * @return array<string,string>
	 */
	public function scrub_headers( array $headers ): array {
		$out = array();
		foreach ( $headers as $key => $value ) {
			$lower = strtolower( (string) $key );
			if ( in_array( $lower, self::HEADER_DENYLIST, true ) ) {
				continue;
			}
			if ( 'host' === $lower ) {
				continue; // site identity.
			}
			$out[ $lower ] = $this->scrub_string( is_array( $value ) ? wp_json_encode( $value ) : (string) $value );
		}
		return $out;
	}

	/**
	 * Cap and scrub a raw request body.
	 */
	public function scrub_body( string $body ): string {
		if ( '' === $body ) {
			return '';
		}
		if ( strlen( $body ) > self::MAX_BODY ) {
			$body = substr( $body, 0, self::MAX_BODY );
		}
		return $this->scrub_string( $body );
	}

	/**
	 * Strip the absolute filesystem prefix from a path so it is relative to the WP root.
	 */
	public function relativize_path( string $path ): string {
		$root = untrailingslashit( \LoyalSecurity\Support\Paths::root() );
		if ( '' !== $root && 0 === strpos( $path, $root ) ) {
			return ltrim( substr( $path, strlen( $root ) ), '/\\' );
		}
		return $path;
	}
}
