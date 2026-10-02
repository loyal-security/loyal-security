<?php
/**
 * Host header injection guard.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Audit\Logger;

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

		if ( in_array( $request_bare, array( $home_host, $site_host ), true ) ) {
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
