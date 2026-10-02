<?php
/**
 * Base REST controller.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Container;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

/**
 * Shared base for all plugin REST controllers. Centralises the capability/nonce
 * permission check and response envelope helpers.
 */
abstract class AbstractController {

	protected Container $container;

	public function __construct( Container $container ) {
		$this->container = $container;
	}

	/**
	 * Register this controller's routes. Implemented per controller.
	 */
	abstract public function register_routes(): void;

	/**
	 * Permission callback enforcing the custom capability.
	 *
	 * The cookie nonce (`X-WP-Nonce`) is validated automatically by WordPress for
	 * logged-in REST requests; here we additionally require the management capability.
	 *
	 * @return bool|WP_Error
	 */
	public function permission_check() {
		if ( ! current_user_can( TOTALSECWP_CAP ) && ! current_user_can( 'manage_options' ) ) {
			return new WP_Error(
				'totalsecwp_forbidden',
				__( 'You do not have permission to manage Loyal Security.', 'loyal-security' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}
		return true;
	}

	/**
	 * Build a success response envelope.
	 *
	 * @param mixed $data   Payload.
	 * @param int   $status HTTP status.
	 */
	protected function ok( $data, int $status = 200 ): WP_REST_Response {
		return new WP_REST_Response(
			array(
				'success' => true,
				'data'    => $data,
			),
			$status
		);
	}

	/**
	 * Build a success response for one-time secret delivery (shared secrets, recovery and
	 * staging access tokens). WordPress only sends `no-cache` for logged-in REST requests;
	 * `no-store` additionally forbids shared caches/proxies from persisting the body.
	 *
	 * @param mixed $data   Payload containing a plaintext credential.
	 * @param int   $status HTTP status.
	 */
	protected function ok_no_store( $data, int $status = 200 ): WP_REST_Response {
		$response = $this->ok( $data, $status );
		$response->header( 'Cache-Control', 'no-store, private' );
		return $response;
	}

	/**
	 * Build an error response.
	 *
	 * @param string $code    Machine code.
	 * @param string $message Human message.
	 * @param int    $status  HTTP status.
	 */
	protected function fail( string $code, string $message, int $status = 400 ): WP_Error {
		return new WP_Error( $code, $message, array( 'status' => $status ) );
	}

	/**
	 * Full REST route base for this plugin.
	 */
	protected function namespace(): string {
		return TOTALSECWP_REST_NAMESPACE;
	}

	/**
	 * Strip the server-side filesystem prefix from a path so the API never leaks
	 * absolute paths (e.g. /home/john/web/site/...) into the admin UI.
	 *
	 * Returns a path relative to the WordPress root (ABSPATH), e.g.
	 *   /home/john/web/site/wp-content/uploads/foo.php  → wp-content/uploads/foo.php
	 *
	 * If the path does not start with ABSPATH it is returned unchanged (already relative
	 * or outside the WP tree — caller should not expose it).
	 *
	 * @param string $path Absolute filesystem path.
	 * @return string
	 */
	protected function mask_path( string $path ): string {
		if ( '' === $path ) {
			return $path;
		}
		// Logical "paths" (DB rows + mu-plugin/drop-in integrity locators) are not filesystem
		// paths, so they must pass through the root-stripping untouched.
		if ( preg_match( '#^(post|option|user|theme|comment|usermeta|mu|dropin):#', $path ) ) {
			return $path;
		}

		// Relative to the WordPress root, or — for a relocated content directory, which is where
		// the private storage dir lives too — relative to that directory's parent, so the
		// server's absolute path (…/home/<user>/…/public_html/…) is never exposed.
		$short = \TotalSecurityWP\Support\Paths::display( $path );
		return null !== $short ? $short : $path;
	}

	/**
	 * Strip the absolute server root from anywhere inside a free-form string (e.g. an audit-log
	 * context value or a message), turning
	 *   /home/john/web/site/public_html/wp-content/uploads/x.php → wp-content/uploads/x.php
	 * without disturbing the rest of the string. Handles both forward- and native-separator forms.
	 */
	protected function strip_server_root( string $value ): string {
		$root = untrailingslashit( \TotalSecurityWP\Support\Paths::root() );
		if ( '' === $root ) {
			return $value;
		}
		foreach ( array_unique( array( $root, wp_normalize_path( $root ) ) ) as $r ) {
			$value = str_replace( array( $r . '/', $r . '\\', $r ), '', $value );
		}
		return $value;
	}

	/**
	 * Recursively strip the server root from every string in an arbitrary structure (used for the
	 * audit-log event context, which can carry an absolute `path`/`file`/`target`).
	 *
	 * @param mixed $data Any value.
	 * @return mixed
	 */
	protected function mask_paths_deep( $data ) {
		if ( is_string( $data ) ) {
			return $this->strip_server_root( $data );
		}
		if ( is_array( $data ) ) {
			foreach ( $data as $k => $v ) {
				$data[ $k ] = $this->mask_paths_deep( $v );
			}
		}
		return $data;
	}

	/**
	 * Mask a flat list of path strings.
	 *
	 * @param array<int,mixed> $paths Path strings (non-strings are passed through).
	 * @return array<int,mixed>
	 */
	protected function mask_path_list( array $paths ): array {
		return array_map(
			function ( $p ) {
				return is_string( $p ) ? $this->mask_path( $p ) : $p;
			},
			$paths
		);
	}

	/**
	 * Recursively mask_path in an array of items.
	 * Only touches keys listed in $keys; other keys are passed through untouched.
	 *
	 * @param array<int,array<string,mixed>> $items Array of row arrays.
	 * @param string[]                       $keys  Keys whose values should be masked.
	 * @return array<int,array<string,mixed>>
	 */
	protected function mask_paths_in( array $items, array $keys ): array {
		return array_map( function ( array $item ) use ( $keys ): array {
			foreach ( $keys as $k ) {
				if ( isset( $item[ $k ] ) && is_string( $item[ $k ] ) ) {
					$item[ $k ] = $this->mask_path( $item[ $k ] );
				}
			}
			return $item;
		}, $items );
	}
}
