<?php
/**
 * Security response headers guard.
 *
 * Emits a set of defensive HTTP response headers (CSP, X-Frame-Options,
 * X-Content-Type-Options, Referrer-Policy, Permissions-Policy) on send_headers.
 * Each header is gated by its own setting so administrators can opt out of any
 * one that conflicts with their stack. CSP can be sent in report-only mode for
 * staged rollout.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

class SecurityHeaders {

	/** @var array<string, bool> Header toggles keyed by setting name. */
	private array $opts;

	/**
	 * @param array<string, bool> $opts Header toggles: add_xfo, add_xcto,
	 *                                   add_referrer_policy, add_permissions_policy.
	 *                                   CSP is owned by CspModule.
	 */
	public function __construct( array $opts ) {
		$this->opts = $opts;
	}

	public function register(): void {
		add_action( 'send_headers', array( $this, 'emit' ) );
	}

	public function emit(): void {
		if ( headers_sent() ) {
			return;
		}

		if ( $this->on( 'add_xfo' ) ) {
			header( 'X-Frame-Options: SAMEORIGIN' );
		}

		if ( $this->on( 'add_xcto' ) ) {
			header( 'X-Content-Type-Options: nosniff' );
		}

		if ( $this->on( 'add_referrer_policy' ) ) {
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		}

		if ( $this->on( 'add_permissions_policy' ) ) {
			header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
		}
	}

	/**
	 * Is a given toggle enabled?
	 *
	 * @param string $key Setting key.
	 */
	private function on( string $key ): bool {
		return ! empty( $this->opts[ $key ] );
	}
}
