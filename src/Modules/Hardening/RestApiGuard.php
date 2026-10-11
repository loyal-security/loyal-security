<?php
/**
 * REST API exposure hardening.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Modules\Audit\Logger;

/**
 * Restricts information disclosure through the REST API: hides the user-enumeration
 * endpoints from unauthenticated callers, and (optionally) requires authentication for the
 * entire API.
 */
class RestApiGuard {

	/** Option storing the anonymous-namespace tally built while learning mode is active. */
	private const OPT_LEARNING = 'loyalsec_rest_learning_namespaces';
	private const LEARNING_CAP = 200;

	private bool  $restrict_users;
	private bool  $require_auth;
	/** @var string[] REST namespace prefixes that are always public (exempt from require_auth). */
	private array $public_namespaces;
	private bool  $learning_mode;
	private ?Logger $logger;

	/**
	 * @param string[] $public_namespaces Namespace prefixes (e.g. 'wc/store') exempt from auth.
	 */
	public function __construct( bool $restrict_users, bool $require_auth, array $public_namespaces = array(), bool $learning_mode = true, ?Logger $logger = null ) {
		$this->restrict_users    = $restrict_users;
		$this->require_auth      = $require_auth;
		$this->public_namespaces = $public_namespaces;
		$this->learning_mode     = $learning_mode;
		$this->logger            = $logger;
	}

	public function register(): void {
		if ( $this->restrict_users ) {
			add_filter( 'rest_endpoints', array( $this, 'hide_users' ) );
		}
		if ( $this->require_auth ) {
			add_filter( 'rest_authentication_errors', array( $this, 'require_authentication' ) );
		}
	}

	/**
	 * Remove the users endpoints unless the caller can list users.
	 *
	 * @param array<string, mixed> $endpoints REST endpoints.
	 * @return array<string, mixed>
	 */
	public function hide_users( array $endpoints ): array {
		// Anyone who writes posts needs this endpoint: the block editor's author picker reads
		// it. Hidden from visitors and from accounts that cannot write (subscribers, customers).
		if ( current_user_can( 'list_users' ) || current_user_can( 'edit_posts' ) ) {
			return $endpoints;
		}
		foreach ( array( '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ) as $route ) {
			if ( isset( $endpoints[ $route ] ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/**
	 * Require authentication for all REST requests.
	 *
	 * Exempts any namespace listed in $public_namespaces (e.g. WooCommerce store API,
	 * Contact Form 7) so plugins that need unauthenticated REST access still work.
	 *
	 * @param mixed $result Current auth result.
	 * @return mixed
	 */
	public function require_authentication( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}
		if ( is_user_logged_in() ) {
			return $result;
		}
		if ( $this->public_namespaces && $this->current_route_is_public() ) {
			return $result;
		}

		if ( $this->learning_mode ) {
			$this->record_learning_hit();
			return $result;
		}

		return new \WP_Error(
			'loyalsec_rest_forbidden',
			__( 'REST API access is restricted to authenticated users.', 'loyal-security' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * Learning mode: observe (never block) which anonymous namespace/route was hit, so the
	 * dashboard can suggest exemptions before an admin flips sitewide REST auth from log-only
	 * to enforcing.
	 */
	private function record_learning_hit(): void {
		$route     = isset( $_SERVER['REQUEST_URI'] ) ? (string) strtok( sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ), '?' ) : '';
		$namespace = $this->namespace_of_uri( $route );

		if ( null !== $this->logger ) {
			$this->logger->log(
				EventCatalog::REST_LEARNING,
				array( 'namespace' => $namespace, 'route' => $route, 'ip' => \LoyalSecurity\Modules\Firewall\IpResolver::request_ip() ) // phpcs:ignore WordPress.Security.NonceVerification
			);
		}

		if ( '' === $namespace ) {
			return;
		}

		$tally = get_option( self::OPT_LEARNING, array() );
		if ( ! is_array( $tally ) ) {
			$tally = array();
		}
		$now = time();
		if ( isset( $tally[ $namespace ] ) && is_array( $tally[ $namespace ] ) ) {
			$tally[ $namespace ]['count']     = (int) $tally[ $namespace ]['count'] + 1;
			$tally[ $namespace ]['last_seen'] = $now;
		} else {
			$tally[ $namespace ] = array( 'count' => 1, 'last_seen' => $now );
		}

		// LRU-trim: keep the most recently seen namespaces if the tally grows past the cap.
		if ( count( $tally ) > self::LEARNING_CAP ) {
			uasort( $tally, static fn( $a, $b ) => ( $b['last_seen'] ?? 0 ) <=> ( $a['last_seen'] ?? 0 ) );
			$tally = array_slice( $tally, 0, self::LEARNING_CAP, true );
		}

		update_option( self::OPT_LEARNING, $tally, false );
	}

	/**
	 * Read the current learning tally for the dashboard.
	 *
	 * @return array<int, array{namespace:string,count:int,last_seen:int}>
	 */
	public static function learning_tally(): array {
		$tally = get_option( self::OPT_LEARNING, array() );
		if ( ! is_array( $tally ) ) {
			return array();
		}
		$out = array();
		foreach ( $tally as $namespace => $row ) {
			$out[] = array(
				'namespace' => (string) $namespace,
				'count'     => (int) ( $row['count'] ?? 0 ),
				'last_seen' => (int) ( $row['last_seen'] ?? 0 ),
			);
		}
		usort( $out, static fn( $a, $b ) => $b['last_seen'] <=> $a['last_seen'] );
		return $out;
	}

	/**
	 * Namespace segment of a raw request URI (not just the REST-dispatched request), since
	 * learning needs to record the namespace even though the guard itself never blocked it.
	 */
	private function namespace_of_uri( string $uri ): string {
		$prefix = '/' . rest_get_url_prefix() . '/';
		$pos    = strpos( $uri, $prefix );
		if ( false === $pos ) {
			return '';
		}
		$route = ltrim( substr( $uri, $pos + strlen( $prefix ) ), '/' );
		$parts = explode( '/', $route );
		if ( count( $parts ) >= 2 ) {
			return $parts[0] . '/' . $parts[1];
		}
		return $parts[0] ?? '';
	}

	/**
	 * Whether the current REST request path starts with a public namespace.
	 */
	private function current_route_is_public(): bool {
		if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST ) {
			return false;
		}
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : '';
		$prefix = '/' . rest_get_url_prefix() . '/';
		$pos    = strpos( $uri, $prefix );
		if ( false === $pos ) {
			return false;
		}
		$route = ltrim( substr( $uri, $pos + strlen( $prefix ) ), '/' );
		$route = (string) strtok( $route, '?' );
		foreach ( $this->public_namespaces as $ns ) {
			$ns = ltrim( (string) $ns, '/' );
			if ( '' !== $ns && str_starts_with( $route, $ns ) ) {
				return true;
			}
		}
		return false;
	}
}
