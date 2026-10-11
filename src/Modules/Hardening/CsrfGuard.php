<?php
/**
 * CSRF detection guard for authenticated admin-ajax.php requests.
 *
 * Checks the HTTP Referer against the site URL. When a logged-in user's
 * AJAX request originates from a foreign domain the request is very likely a
 * CSRF attempt — the browser sent the auth cookies but the page triggering
 * the request was hosted elsewhere.
 *
 * Detection only (logs + optional 403). We deliberately do NOT abort
 * legitimate traffic that has no Referer (privacy proxies, curl tools used
 * by admins, etc.) — only a confirmed foreign-origin Referer is flagged.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Modules\Audit\Logger;

class CsrfGuard {

	private Logger $logger;
	private bool   $block;

	/**
	 * @param Logger $logger  Audit logger.
	 * @param bool   $block   When true, send a 403 and die. When false, log only.
	 */
	public function __construct( Logger $logger, bool $block ) {
		$this->logger = $logger;
		$this->block  = $block;
	}

	public function register(): void {
		// admin_init fires for both regular admin pages and admin-ajax.php.
		add_action( 'admin_init', array( $this, 'check' ), 2 );
	}

	public function check(): void {
		if ( ! wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}

		$referer = sanitize_text_field( wp_unslash( (string) ( $_SERVER['HTTP_REFERER'] ?? '' ) ) );
		if ( '' === $referer ) {
			// No Referer header — could be a privacy proxy or CLI tool; don't flag.
			return;
		}

		$ref_host  = wp_parse_url( $referer, PHP_URL_HOST );
		$site_host = wp_parse_url( site_url(), PHP_URL_HOST );

		if ( ! is_string( $ref_host ) || ! is_string( $site_host ) ) {
			return;
		}

		// Strip "www." prefix for a lenient same-origin check.
		$strip = static fn( string $h ): string => preg_replace( '/^www\./i', '', strtolower( $h ) ) ?? $h;

		if ( $strip( $ref_host ) === $strip( $site_host ) ) {
			return; // Same origin — legitimate request.
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = sanitize_key( wp_unslash( $_REQUEST['action'] ?? '' ) );

		$this->logger->log(
			EventCatalog::CSRF_ATTEMPT,
			array(
				'action'    => $action,
				'referer'   => $referer,
				'ref_host'  => $ref_host,
				'site_host' => $site_host,
				'user_id'   => get_current_user_id(),
				'ip'        => \LoyalSecurity\Modules\Firewall\IpResolver::request_ip(),
			),
			EventCatalog::SEV_WARNING
		);

		if ( $this->block ) {
			wp_send_json_error( array( 'code' => 'csrf_blocked' ), 403 );
		}
	}
}
