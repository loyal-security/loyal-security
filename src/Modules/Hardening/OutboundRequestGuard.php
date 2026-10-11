<?php
/**
 * Outbound request guard — blocks SSRF attempts via pre_http_request.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Modules\Audit\Logger;

/**
 * Hooks WordPress's HTTP API before any outbound request is dispatched.
 * Blocks requests to RFC-1918 / loopback addresses (SSRF prevention).
 */
class OutboundRequestGuard {

	private Logger $logger;
	/** @var string[] */
	private array $allowlist;

	/**
	 * @param Logger   $logger    Audit logger.
	 * @param string[] $allowlist Trusted hostnames that bypass the block.
	 */
	public function __construct( Logger $logger, array $allowlist = array() ) {
		$this->logger    = $logger;
		$this->allowlist = $allowlist;
	}

	public function register(): void {
		add_filter( 'pre_http_request', array( $this, 'inspect' ), 1, 3 );
	}

	/**
	 * Inspect an outbound request before it is dispatched.
	 *
	 * @param false|array|\WP_Error $pre  Short-circuit value from earlier filters.
	 * @param array                 $args Request arguments.
	 * @param string                $url  Target URL.
	 * @return false|array|\WP_Error Unchanged $pre, or a WP_Error to block the request.
	 */
	public function inspect( $pre, array $args, string $url ) {
		if ( false !== $pre ) {
			return $pre; // Already short-circuited.
		}

		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		$host = strtolower( trim( $host, '[]' ) ); // strip IPv6 brackets.

		// Allowlisted hosts pass through, and so does the site itself: WordPress makes loopback
		// requests to its own host on purpose (spawning wp-cron, Site Health), and that host
		// may resolve to a private address behind NAT or in a container. Core's
		// wp_http_validate_url() makes the same exception.
		if ( in_array( $host, $this->allowlist, true ) || in_array( $host, $this->own_hosts(), true ) ) {
			return $pre;
		}

		if ( ! $this->is_private( $host ) ) {
			return $pre;
		}

		$this->logger->log(
			EventCatalog::SSRF_BLOCKED,
			array(
				'url'  => $url,
				'host' => $host,
				'src'  => $this->calling_source(),
			),
			EventCatalog::SEV_CRITICAL
		);

		return new \WP_Error( 'ssrf_blocked', 'Request to private/internal host blocked by Loyal Security.' );
	}

	/**
	 * Returns true if $host resolves to a private / loopback / link-local range.
	 * Works with hostnames, IPv4, and IPv6.
	 */
	private function is_private( string $host ): bool {
		// Quick literal checks (avoid DNS for obvious cases).
		$private_literals = array( 'localhost', '::1', '0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:0000:0000:0001' );
		if ( in_array( $host, $private_literals, true ) ) {
			return true;
		}

		$is_literal = (bool) filter_var( $host, FILTER_VALIDATE_IP );

		// PHP compiled to WebAssembly (WordPress Playground) has no real DNS: gethostbyname()
		// returns placeholder 172.29.x.x addresses for every name, so a lookup cannot tell a
		// private host from a public one. Judge only literal IPs there.
		if ( ! $is_literal && function_exists( 'php_uname' ) && 'Emscripten' === php_uname( 's' ) ) {
			return false;
		}

		// Convert hostname to IP.
		$ip = $is_literal ? $host : @gethostbyname( $host ); // phpcs:ignore

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false; // Can't resolve — allow (fail-open).
		}

		// FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE returns false for private ranges.
		return false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Hosts of the site's own home and WordPress URLs, lower-cased.
	 *
	 * @return string[]
	 */
	private function own_hosts(): array {
		return array_filter(
			array(
				strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ),
				strtolower( (string) wp_parse_url( site_url(), PHP_URL_HOST ) ),
			)
		);
	}

	/**
	 * Best-effort detection of the caller (pingback, oEmbed, etc.) from the call stack.
	 * Only used for log context — never relied on for security decisions.
	 */
	private function calling_source(): string {
		foreach ( debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 8 ) as $frame ) { // phpcs:ignore
			$fn = (string) ( $frame['function'] ?? '' );
			if ( false !== strpos( $fn, 'pingback' ) ) {
				return 'pingback';
			}
			if ( false !== strpos( $fn, 'oembed' ) ) {
				return 'oembed';
			}
		}
		return 'unknown';
	}
}
