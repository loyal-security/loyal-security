<?php
/**
 * Settings-aware client IP resolver.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Support\Ip;

/**
 * Wraps {@see Ip::client_ip()} with the firewall's trusted-proxy configuration so all
 * modules resolve the same client IP consistently.
 */
class IpResolver {

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	public function current(): string {
		$trust   = (bool) $this->settings->get( 'firewall', 'trust_proxy', false );
		$proxies = (array) $this->settings->get( 'firewall', 'trusted_proxies', array() );
		return Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers(), $trust, $proxies );
	}
}
