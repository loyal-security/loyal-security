<?php
/**
 * Setup wizard REST controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Plugin;
use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Setup\SetupWizard;
use LoyalSecurity\Modules\Firewall\IpResolver;
use LoyalSecurity\Modules\Firewall\BanStore;
use WP_REST_Request;

/**
 * Drives the onboarding/WAF-deployment flow from the dashboard.
 */
class WizardController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		$routes = array(
			'/wizard/status'       => array( 'GET',  'status' ),
			'/wizard/deploy'       => array( 'POST', 'deploy' ),
			'/wizard/verify'       => array( 'POST', 'verify' ),
			'/wizard/rollback'     => array( 'POST', 'rollback' ),
			'/wizard/complete'     => array( 'POST', 'complete' ),
			'/wizard/whitelist-ip' => array( 'POST', 'whitelist_ip' ),
		);

		foreach ( $routes as $path => [ $method, $callback ] ) {
			register_rest_route(
				$ns,
				$path,
				array(
					'methods'             => $method,
					'callback'            => array( $this, $callback ),
					'permission_callback' => array( $this, 'permission_check' ),
				)
			);
		}
	}

	public function status( WP_REST_Request $request ) {
		$data           = ( new SetupWizard() )->status();
		$my_ip          = $this->resolve_ip();
		// Behind a proxy whose visitor address isn't trusted yet, the address seen is the proxy's.
		// Offering it as "your IP" would allowlist every visitor routed through that proxy.
		$data['my_ip_is_proxy'] = BanStore::is_proxy_address( $my_ip )
			|| \LoyalSecurity\Support\Ip::behind_unknown_proxy( $my_ip, \LoyalSecurity\Support\RequestVars::ip_headers() );
		$data['my_ip']          = $data['my_ip_is_proxy'] ? '' : $my_ip;
		$firewall       = Plugin::instance()->module( 'firewall' );
		$data['ip_whitelist'] = $firewall ? (array) $this->container->make( 'settings' )->get( 'firewall', 'ip_whitelist', array() ) : array();
		return $this->ok( $data );
	}

	public function whitelist_ip( WP_REST_Request $request ) {
		$ip = sanitize_text_field( (string) $request->get_param( 'ip' ) );

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $this->fail( 'Invalid IP address.' );
		}
		if ( BanStore::is_proxy_address( $ip ) ) {
			return $this->fail( __( 'That address belongs to a proxy or CDN in front of your site (such as Cloudflare), so allowing it would let every visitor through. Turn on "Trust Cloudflare" or add the proxy under Trusted proxies so your own address is seen.', 'loyal-security' ) );
		}

		$firewall = Plugin::instance()->module( 'firewall' );
		if ( ! $firewall ) {
			return $this->fail( 'Firewall module unavailable.' );
		}

		$list = (array) $this->container->make( 'settings' )->get( 'firewall', 'ip_whitelist', array() );
		if ( ! in_array( $ip, $list, true ) ) {
			$list[] = $ip;
			$this->container->make( 'settings' )->set( 'firewall', 'ip_whitelist', $list );
		}

		return $this->ok( array( 'ip_whitelist' => $list ) );
	}

	private function resolve_ip(): string {
		return ( new IpResolver( $this->container->make( 'settings' ) ) )->current();
	}

	public function deploy( WP_REST_Request $request ) {
		return $this->ok( ( new SetupWizard() )->deploy_optimized() );
	}

	public function verify( WP_REST_Request $request ) {
		return $this->ok( ( new SetupWizard() )->verify() );
	}

	public function rollback( WP_REST_Request $request ) {
		return $this->ok( ( new SetupWizard() )->rollback() );
	}

	public function complete( WP_REST_Request $request ) {
		( new SetupWizard() )->complete();
		return $this->ok( array( 'setup_complete' => true ) );
	}
}
