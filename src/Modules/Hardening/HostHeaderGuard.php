<?php
/**
 * Host header injection guard.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Modules\Audit\Logger;

/**
 * Validates the HTTP Host header on init and redirects to the canonical
 * siteurl if the host does not match — prevents cache-poisoning and
 * password-reset link hijacking via a spoofed Host header.
 */
class HostHeaderGuard {

	private Logger $logger;

	public function __construct( Logger $logger ) {
		$this->logger = $logger;
	}

	public function register(): void {
		add_action( 'init', array( $this, 'validate' ), 0 );
	}

	public function validate(): void {
		// Only real HTTP requests carry a client-chosen Host header. Internal PHP runs (WP-CLI,
		// cron, WordPress Playground's setup steps) have no request URI and nothing to poison.
		$uri = sanitize_text_field( wp_unslash( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) ) );
		if ( '' === $uri || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$request_host = strtolower( trim( sanitize_text_field( wp_unslash( (string) ( $_SERVER['HTTP_HOST'] ?? '' ) ) ) ) );
		$home         = wp_parse_url( home_url() );
		$home_host    = strtolower( (string) ( $home['host'] ?? '' ) );
		$site_host    = strtolower( (string) wp_parse_url( (string) get_option( 'siteurl' ), PHP_URL_HOST ) );

		if ( '' === $request_host || '' === $home_host ) {
			return;
		}

		// Strip port from request host for comparison. Both the site and home hosts are
		// legitimate: they differ when WordPress's files are served from another host.
		$request_bare = preg_replace( '/:\d+$/', '', $request_host );

		// The site's own hosts plus every host WordPress may redirect to: multilingual plugins
		// serving one language per domain (WPML, Polylang) and domain mappers add theirs to
		// `allowed_redirect_hosts`, and redirecting those to the main domain broke them. The
		// site's own hosts are checked first and on their own: some callbacks replace that list
		// instead of adding to it, which turned every request into a redirect to itself.
		if ( in_array( $request_bare, array( $home_host, $site_host ), true ) ) {
			return;
		}
		if ( preg_match( '/^[a-z0-9.-]+$/', $request_bare ) && '' !== wp_validate_redirect( 'http://' . $request_bare . '/', '' ) ) {
			return;
		}

		$this->logger->log(
			EventCatalog::HOST_INJECTION,
			array(
				'request_host'   => $request_host,
				'canonical_host' => $home_host,
				'uri'            => $uri,
			),
			EventCatalog::SEV_WARNING
		);

		// Redirect to the canonical host (keeping its port) to prevent password-reset link poisoning.
		$scheme = is_ssl() ? 'https' : 'http';
		$port   = isset( $home['port'] ) ? ':' . (int) $home['port'] : '';
		wp_safe_redirect( $scheme . '://' . $home_host . $port . $uri, 301 );
		exit;
	}
}
