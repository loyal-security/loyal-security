<?php
/**
 * Setup wizard REST controller.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Plugin;
use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Setup\SetupWizard;
use TotalSecurityWP\Modules\Firewall\IpResolver;
use TotalSecurityWP\Support\Ip;
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
		$data['my_ip']  = $this->resolve_ip();
		$firewall       = Plugin::instance()->module( 'firewall' );
		$data['ip_whitelist'] = $firewall ? (array) $this->container->make( 'settings' )->get( 'firewall', 'ip_whitelist', array() ) : array();
		return $this->ok( $data );
	}

	public function whitelist_ip( WP_REST_Request $request ) {
		$ip = sanitize_text_field( (string) $request->get_param( 'ip' ) );

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $this->fail( 'Invalid IP address.' );
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
		$firewall = Plugin::instance()->module( 'firewall' );
		if ( $firewall ) {
			$resolver = new IpResolver( $this->container->make( 'settings' ) );
			return $resolver->current();
		}
		return Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() );
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
