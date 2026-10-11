<?php
/**
 * Runtime directory / enumeration protection.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Modules\Audit\Logger;

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
		// Not wp-admin, and not REST: there `author` is a post filter (the block editor's Query
		// Loop and Latest Posts blocks send it), and the users endpoint has its own guard.
		if ( is_admin() || $this->is_rest_request() || current_user_can( 'edit_posts' ) ) {
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
	 * Hide the archive of an account that has published nothing. Author pages of people who
	 * publish are public on purpose (bylines link to them, and they matter for SEO), so they
	 * stay; an empty archive only confirms that a login name exists, so it answers 404 like a
	 * name that does not.
	 */
	public function block_author_enum(): void {
		if ( ! is_author() || is_user_logged_in() ) {
			return;
		}
		$author = get_queried_object();
		if ( $author instanceof \WP_User && count_user_posts( $author->ID, get_post_types( array( 'public' => true ) ), true ) > 0 ) {
			return;
		}
		global $wp_query;
		$this->log_probe( (string) get_query_var( 'author_name' ) ?: (string) get_query_var( 'author' ) );
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
	}

	/**
	 * Whether this is a REST API request. Runs on `init`, before WordPress defines REST_REQUEST,
	 * so it reads the path and the `rest_route` parameter.
	 */
	private function is_rest_request(): bool {
		$uri = \LoyalSecurity\Support\RequestVars::uri();
		if ( false !== strpos( (string) wp_parse_url( $uri, PHP_URL_QUERY ), 'rest_route=' ) ) {
			return true;
		}
		$prefix = (string) wp_parse_url( get_rest_url(), PHP_URL_PATH );
		$path   = (string) wp_parse_url( $uri, PHP_URL_PATH );
		return '' !== $prefix && 0 === strpos( trailingslashit( $path ), trailingslashit( $prefix ) );
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
			array( 'probed' => $probed, 'ip' => \LoyalSecurity\Modules\Firewall\IpResolver::request_ip() ) // phpcs:ignore WordPress.Security.NonceVerification
		);
	}
}
