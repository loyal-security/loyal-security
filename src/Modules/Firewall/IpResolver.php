<?php
/**
 * Settings-aware client IP resolver.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;
use LoyalSecurity\Support\Ip;

/**
 * Wraps {@see Ip::client_ip()} with the firewall's proxy configuration (trusted proxies and
 * Cloudflare) so every module resolves the same client IP. Code that bans, logs or allowlists
 * an address must use this, never a bare {@see Ip::client_ip()} call, which only sees the direct
 * connection and so returns the proxy's address behind a CDN.
 */
class IpResolver {

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * The current request's client IP.
	 */
	public function current(): string {
		[ $trust, $ranges ] = $this->trust();
		return Ip::client_ip( \LoyalSecurity\Support\RequestVars::ip_headers(), $trust, $ranges );
	}

	/**
	 * The proxy trust in effect: arguments for {@see Ip::client_ip()} or RequestContext::capture().
	 *
	 * @return array{0: bool, 1: string[]}
	 */
	public function trust(): array {
		return Ip::effective_trust(
			(bool) $this->settings->get( 'firewall', 'trust_proxy', false ),
			(array) $this->settings->get( 'firewall', 'trusted_proxies', array() ),
			(bool) $this->settings->get( 'firewall', 'trust_cloudflare', true )
		);
	}

	/**
	 * Whether an address is one of the proxies in front of the site (a configured trusted proxy
	 * or a Cloudflare edge). Such an address carries many visitors' traffic, so it must never be
	 * allowlisted or banned as if it were one visitor.
	 */
	public function is_proxy( string $ip ): bool {
		if ( '' === $ip || ! Ip::is_valid( $ip ) ) {
			return false;
		}
		if ( Ip::is_cloudflare( $ip ) ) {
			return true;
		}
		$configured = array_filter( array_map( 'trim', array_map( 'strval', (array) $this->settings->get( 'firewall', 'trusted_proxies', array() ) ) ) );
		return $configured && Ip::in_ranges( $ip, $configured );
	}

	/**
	 * The current request's client IP, for code without a Settings instance at hand.
	 */
	public static function request_ip(): string {
		return ( new self( \LoyalSecurity\Plugin::instance()->container()->make( 'settings' ) ) )->current();
	}
}
