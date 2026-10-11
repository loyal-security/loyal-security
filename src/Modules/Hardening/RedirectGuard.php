<?php
/**
 * Open redirect guard.
 *
 * Hooks the wp_redirect filter to detect (and optionally abort) off-site
 * redirects. WordPress itself doesn't prevent wp_redirect() from sending
 * users to external URLs — this guard adds that layer.
 *
 * A redirect is "open" when it sends the visitor to another site AND that destination came
 * from the request itself (a `?redirect_to=https://evil.example` an attacker put in a link).
 * Redirects a plugin builds on its own are left alone: payment pages, OAuth sign-in (Google,
 * Jetpack, PayPal and Stripe onboarding), and redirect rules the owner created. Blocking those
 * sent customers and admins to the home page instead. The WordPress.org admin update handshake
 * URLs are always allowed because core uses wp_redirect() for those.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Modules\Audit\Logger;

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

		if ( ! $this->destination_from_request( $dest_host ) ) {
			return $location;
		}

		$this->logger->log(
			EventCatalog::OPEN_REDIRECT,
			array(
				'location'  => substr( $location, 0, 500 ),
				'dest_host' => $dest_host,
				'site_host' => $site_host,
				'user_id'   => get_current_user_id(),
				'ip'        => \LoyalSecurity\Modules\Firewall\IpResolver::request_ip(),
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

	/**
	 * Whether the redirect's host appears in the requested URL's query string, i.e. whoever
	 * made the link chose where it goes. Open redirects are abused through links, so the query
	 * string is where the destination travels.
	 *
	 * @param string $dest_host Destination host.
	 */
	private function destination_from_request( string $dest_host ): bool {
		$query = (string) wp_parse_url( \LoyalSecurity\Support\RequestVars::uri(), PHP_URL_QUERY );
		if ( '' === $query ) {
			return false;
		}
		// Decode twice: a destination is often encoded once more inside another parameter.
		$query = strtolower( rawurldecode( rawurldecode( $query ) ) );
		return false !== strpos( $query, strtolower( $dest_host ) );
	}
}
