<?php
/**
 * Hardening REST controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Plugin;
use LoyalSecurity\Modules\Hardening\HardeningModule;
use LoyalSecurity\Modules\Hardening\RestApiGuard;
use LoyalSecurity\Modules\Hardening\ExposureScanner;
use WP_REST_Request;

/**
 * Drives the hardening checklist: status, server-rule and wp-config apply/revert.
 */
class HardeningController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route( $ns, '/hardening/status', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'status' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/hardening/server-rules', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'server_rules' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/hardening/config', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'config' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/hardening/rest-learning', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'rest_learning' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/hardening/exposure', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'exposure' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/hardening/exposure-scan', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'exposure_scan' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/hardening/exposure-fix', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'exposure_fix' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
	}

	public function rest_learning( WP_REST_Request $request ) {
		return $this->ok( array( 'items' => RestApiGuard::learning_tally() ) );
	}

	public function exposure( WP_REST_Request $request ) {
		return $this->ok( ( new ExposureScanner( $this->container->make( 'logger' ) ) )->cached() );
	}

	public function exposure_scan( WP_REST_Request $request ) {
		return $this->ok( ( new ExposureScanner( $this->container->make( 'logger' ) ) )->scan() );
	}

	public function exposure_fix( WP_REST_Request $request ) {
		$id = (string) $request->get_param( 'id' );
		if ( '' === $id ) {
			return $this->fail( 'missing_id', __( 'A finding id is required.', 'loyal-security' ), 400 );
		}
		$m = $this->module();
		$result = ( new ExposureScanner( $this->container->make( 'logger' ) ) )->fix( $id, $m );
		return $this->ok( $result );
	}

	private function module(): ?HardeningModule {
		$m = Plugin::instance()->module( 'hardening' );
		return $m instanceof HardeningModule ? $m : null;
	}

	public function status( WP_REST_Request $request ) {
		$m = $this->module();
		return $m ? $this->ok( $m->status() ) : $this->fail( 'loyalsec_hardening_off', __( 'Hardening module disabled.', 'loyal-security' ), 409 );
	}

	public function server_rules( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'loyalsec_hardening_off', __( 'Hardening module disabled.', 'loyal-security' ), 409 );
		}
		$action = (string) $request->get_param( 'action' );
		return $this->ok( 'revert' === $action ? $m->revert_server_rules() : $m->apply_server_rules() );
	}

	public function config( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'loyalsec_hardening_off', __( 'Hardening module disabled.', 'loyal-security' ), 409 );
		}
		if ( 'revert' === $request->get_param( 'action' ) ) {
			return $this->ok( $m->revert_config() );
		}
		$constants = array(
			'DISALLOW_FILE_EDIT' => (bool) $request->get_param( 'DISALLOW_FILE_EDIT' ),
			'DISALLOW_FILE_MODS' => (bool) $request->get_param( 'DISALLOW_FILE_MODS' ),
			'FORCE_SSL_ADMIN'    => (bool) $request->get_param( 'FORCE_SSL_ADMIN' ),
		);
		return $this->ok( $m->apply_config( $constants ) );
	}
}
