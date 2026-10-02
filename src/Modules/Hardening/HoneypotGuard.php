<?php
/**
 * Honeypot trap-URL guard.
 *
 * Automated vulnerability scanners probe a well-known set of bait paths (`/.env`,
 * `/config.php`, exposed debug logs, vulnerable-plugin readmes, etc.) that no
 * legitimate visitor ever requests. A hit is a high-confidence signal of an active
 * scan, so it is logged at CRITICAL and — when enabled — the source IP is banned.
 *
 * Detection runs on template_redirect (after WordPress has resolved the request but
 * before a template is rendered) and compares the request path only, case-insensitively.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Support\Ip;

class HoneypotGuard {

	private Logger $logger;
	private bool   $ban;

	/**
	 * Normalized (lowercased) list of bait paths.
	 *
	 * @var string[]
	 */
	private array $paths;

	/**
	 * @param Logger   $logger Audit logger.
	 * @param string[] $paths  Scanner-bait paths to trap on.
	 * @param bool     $ban    When true, ban the source IP via the firewall BanStore.
	 */
	public function __construct( Logger $logger, array $paths, bool $ban ) {
		$this->logger = $logger;
		$this->ban    = $ban;
		$this->paths  = array_map(
			static fn( $p ): string => strtolower( trim( (string) $p ) ),
			$paths
		);
	}

	public function register(): void {
		add_action( 'template_redirect', array( $this, 'check' ) );
	}

	public function check(): void {
		if ( empty( $this->paths ) ) {
			return;
		}

		$uri = sanitize_text_field( wp_unslash( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) ) );
		if ( '' === $uri ) {
			return;
		}

		// Compare the path only (ignore query string), case-insensitively, no trailing slash.
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$path = strtolower( rtrim( $path, '/' ) );
		if ( '' === $path ) {
			return;
		}

		$hit = false;
		foreach ( $this->paths as $bait ) {
			if ( '' === $bait ) {
				continue;
			}
			if ( $path === rtrim( $bait, '/' ) ) {
				$hit = true;
				break;
			}
		}

		if ( ! $hit ) {
			return;
		}

		$ip = Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() );
		$ua = substr( sanitize_text_field( wp_unslash( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ) ), 0, 200 );

		$this->logger->log(
			EventCatalog::HONEYPOT_HIT,
			array(
				'uri' => substr( $uri, 0, 300 ),
				'ip'  => $ip,
				'ua'  => $ua,
			),
			EventCatalog::SEV_CRITICAL
		);

		if ( $this->ban && '' !== $ip ) {
			$this->ban_ip( $ip );
		}

		$this->block();
	}

	/**
	 * Ban the offending IP. Fail-safe: never let a ban failure break the response.
	 *
	 * @param string $ip Source IP.
	 */
	private function ban_ip( string $ip ): void {
		try {
			( new BanStore() )->add(
				$ip,
				__( 'Honeypot trap URL accessed', 'loyal-security' ),
				'temporary',
				DAY_IN_SECONDS,
				'honeypot'
			);
		} catch ( \Throwable $e ) {
			// Banning is best-effort; the event is already logged.
			return;
		}
	}

	/**
	 * Send a 403 and stop. Mirrors the deny style used elsewhere in the firewall.
	 */
	private function block(): void {
		if ( ! headers_sent() ) {
			status_header( 403 );
			nocache_headers();
		}
		wp_die(
			esc_html__( 'Forbidden', 'loyal-security' ),
			esc_html__( 'Forbidden', 'loyal-security' ),
			array( 'response' => 403 )
		);
	}
}
