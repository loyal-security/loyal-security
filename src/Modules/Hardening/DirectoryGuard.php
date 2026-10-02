<?php
/**
 * Runtime directory / enumeration protection.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Support\Ip;

/**
 * Blocks user/author enumeration via `?author=N` and the REST/oEmbed author probes.
 * Directory browsing itself is disabled at the server level by {@see ServerRules}.
 */
class DirectoryGuard {

	private ?Logger $logger;

	public function __construct( ?Logger $logger = null ) {
		$this->logger = $logger;
	}

	public function register(): void {
		add_action( 'template_redirect', array( $this, 'block_author_enum' ) );
		add_action( 'init', array( $this, 'block_author_query' ) );
	}

	/**
	 * Block `/?author=N` numeric enumeration for non-privileged requests.
	 * Returns 403 (not a redirect) so the username is never leaked via the Location header.
	 */
	public function block_author_query(): void {
		if ( is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification
		$author = isset( $_REQUEST['author'] ) ? sanitize_text_field( wp_unslash( (string) $_REQUEST['author'] ) ) : '';
		if ( '' !== $author && preg_match( '/^\d+$/', $author ) && ! current_user_can( 'list_users' ) ) {
			$this->log_probe( $author );
			status_header( 403 );
			nocache_headers();
			exit;
		}
	}

	/**
	 * Catch author archive requests resolved through pretty permalinks.
	 * Returns 403 (not a redirect) to avoid leaking the slug via the Location header.
	 */
	public function block_author_enum(): void {
		if ( is_author() && ! is_user_logged_in() ) {
			global $wp_query;
			$this->log_probe( (string) get_query_var( 'author_name' ) ?: (string) get_query_var( 'author' ) );
			$wp_query->set_404();
			status_header( 403 );
			nocache_headers();
			exit;
		}
	}

	/**
	 * Record the probe so it shows up in the Audit Log with an actionable IP — previously this
	 * guard blocked silently, leaving no trail to ban the source from.
	 */
	private function log_probe( string $probed ): void {
		if ( null === $this->logger ) {
			return;
		}
		$this->logger->log(
			EventCatalog::AUTHOR_ENUM_BLOCKED,
			array( 'probed' => $probed, 'ip' => Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() ) ) // phpcs:ignore WordPress.Security.NonceVerification
		);
	}
}
