<?php
/**
 * XML-RPC hardening.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Support\Ip;

/**
 * Disables or restricts XML-RPC, which is a frequent target for brute-force amplification
 * (system.multicall) and pingback DDoS reflection.
 */
class XmlRpcGuard {

	private bool $disable;
	private bool $disable_pingback;
	private ?Logger $logger;

	public function __construct( bool $disable, bool $disable_pingback, ?Logger $logger = null ) {
		$this->disable          = $disable;
		$this->disable_pingback = $disable_pingback;
		$this->logger           = $logger;
	}

	public function register(): void {
		if ( $this->disable ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			// Hard block direct hits on xmlrpc.php.
			add_action( 'init', array( $this, 'block_endpoint' ), 0 );
		}

		if ( $this->disable || $this->disable_pingback ) {
			// Remove pingback advertise header + methods.
			add_filter( 'wp_headers', array( $this, 'strip_pingback_header' ) );
			add_filter( 'xmlrpc_methods', array( $this, 'remove_pingback_methods' ) );
			add_filter( 'bloginfo_url', array( $this, 'strip_pingback_url' ), 10, 2 );
		}

		// Always log XML-RPC method probes for audit.
		add_action( 'xmlrpc_call', array( $this, 'log_xmlrpc_call' ), 10, 1 );
	}

	/**
	 * Log XML-RPC method calls for audit. Fired by WP core on xmlrpc.php.
	 *
	 * @param string $method The XML-RPC method name being called.
	 */
	public function log_xmlrpc_call( $method ): void {
		if ( null === $this->logger ) {
			return;
		}
		$method = (string) $method;
		if ( 'system.listMethods' === $method || 'system.getCapabilities' === $method ) {
			$this->logger->log(
				EventCatalog::XMLRPC_PROBE,
				array( 'method' => $method, 'ip' => Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() ) )
			);
		}
		if ( 'system.multicall' === $method ) {
			$this->logger->log(
				EventCatalog::XMLRPC_MULTICALL,
				array( 'method' => $method, 'ip' => Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() ) ),
				EventCatalog::SEV_WARNING
			);
		}
	}

	public function block_endpoint(): void {
		if ( isset( $_SERVER['SCRIPT_FILENAME'] ) && 'xmlrpc.php' === basename( sanitize_text_field( wp_unslash( (string) $_SERVER['SCRIPT_FILENAME'] ) ) ) ) {
			if ( null !== $this->logger ) {
				// Log probe before exit — the xmlrpc_call hook never fires when we exit early.
				$method = $this->requested_method();
				if ( 'system.multicall' === $method ) {
					$this->logger->log(
						EventCatalog::XMLRPC_MULTICALL,
						array( 'method' => $method, 'ip' => Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() ), 'blocked' => true ),
						EventCatalog::SEV_WARNING
					);
				} else {
					$this->logger->log(
						EventCatalog::XMLRPC_PROBE,
						array( 'method' => $method ?: 'unknown', 'ip' => Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() ), 'blocked' => true )
					);
				}
			}
			status_header( 403 );
			exit( 'XML-RPC is disabled.' );
		}
	}

	/**
	 * Name of the XML-RPC method being called, for the audit log. Reads the request body that
	 * xmlrpc.php itself already buffered into `$HTTP_RAW_POST_DATA` before loading WordPress
	 * (so php://input is never read twice), and returns only a name that looks like a real
	 * XML-RPC method (`namespace.method`); anything else is reported as ''.
	 */
	private function requested_method(): string {
		$raw = isset( $GLOBALS['HTTP_RAW_POST_DATA'] ) && is_string( $GLOBALS['HTTP_RAW_POST_DATA'] ) ? $GLOBALS['HTTP_RAW_POST_DATA'] : '';
		if ( ! preg_match( '/<methodName>\s*([^<\r\n]{1,100}?)\s*<\/methodName>/i', substr( $raw, 0, 65536 ), $m ) ) {
			return '';
		}
		$method = sanitize_text_field( $m[1] );
		return preg_match( '/^[A-Za-z0-9_.]{1,100}$/', $method ) ? $method : '';
	}

	/**
	 * @param array<string, string> $headers Response headers.
	 * @return array<string, string>
	 */
	public function strip_pingback_header( array $headers ): array {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * @param array<string, mixed> $methods XML-RPC methods.
	 * @return array<string, mixed>
	 */
	public function remove_pingback_methods( array $methods ): array {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'], $methods['system.multicall'] );
		return $methods;
	}

	/**
	 * @param string $output Bloginfo output.
	 * @param string $show   Requested key.
	 * @return string
	 */
	public function strip_pingback_url( $output, $show ) {
		return ( 'pingback_url' === $show ) ? '' : $output;
	}
}
