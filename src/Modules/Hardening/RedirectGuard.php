<?php
/**
 * Open redirect guard.
 *
 * Hooks the wp_redirect filter to detect (and optionally abort) off-site
 * redirects. WordPress itself doesn't prevent wp_redirect() from sending
 * users to external URLs — this guard adds that layer.
 *
 * A redirect is "open" when the Location header points to a host that differs
 * from the current site. Safe-list exceptions: the WordPress.org admin update
 * handshake URLs are allowed because core uses wp_redirect() for those.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Support\Ip;

class RedirectGuard {

	private Logger $logger;
	private bool   $block;

	/**
	 * @param Logger $logger Audit logger.
	 * @param bool   $block  When true, abort the redirect (return false to wp_redirect).
	 */
	public function __construct( Logger $logger, bool $block ) {
		$this->logger = $logger;
		$this->block  = $block;
	}

	public function register(): void {
		add_filter( 'wp_redirect', array( $this, 'check' ), 10, 1 );
	}

	/**
	 * @param string $location Redirect URL.
	 * @return string|false Original URL to allow, or false to abort.
	 */
	public function check( $location ) {
		if ( ! is_string( $location ) || '' === $location ) {
			return $location;
		}

		$dest_host = wp_parse_url( $location, PHP_URL_HOST );
		if ( ! is_string( $dest_host ) || '' === $dest_host ) {
			// Relative URL — always safe.
			return $location;
		}

		$site_host = wp_parse_url( site_url(), PHP_URL_HOST );
		if ( ! is_string( $site_host ) ) {
			return $location;
		}

		$strip = static fn( string $h ): string => preg_replace( '/^www\./i', '', strtolower( $h ) ) ?? $h;

		if ( $strip( $dest_host ) === $strip( $site_host ) ) {
			return $location; // Same origin — safe.
		}

		// wordpress.org/wp-admin handshake and API calls are legitimate core redirects.
		if ( str_ends_with( $dest_host, '.wordpress.org' ) || 'api.wordpress.org' === $dest_host ) {
			return $location;
		}

		$this->logger->log(
			EventCatalog::OPEN_REDIRECT,
			array(
				'location'  => substr( $location, 0, 500 ),
				'dest_host' => $dest_host,
				'site_host' => $site_host,
				'user_id'   => get_current_user_id(),
				'ip'        => Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() ),
				'referer'   => substr( sanitize_text_field( wp_unslash( (string) ( $_SERVER['HTTP_REFERER'] ?? '' ) ) ), 0, 300 ),
			),
			EventCatalog::SEV_WARNING
		);

		if ( $this->block ) {
			// Return site root so WordPress can still complete the request flow
			// without sending the user to an attacker-controlled URL.
			return home_url( '/' );
		}

		return $location;
	}
}
