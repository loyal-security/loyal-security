<?php
/**
 * Incident / quarantine REST controller.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Plugin;
use TotalSecurityWP\Modules\Incident\IncidentModule;
use TotalSecurityWP\Modules\Scanner\ScannerModule;
use WP_REST_Request;

/**
 * Quarantine management plus core recovery and permission reset.
 */
class QuarantineController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route( $ns, '/quarantine', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'list_items' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		foreach ( array( 'add', 'restore', 'delete', 'clear' ) as $action ) {
			register_rest_route( $ns, '/quarantine/' . $action, array(
				'methods'             => 'POST',
				'callback'            => array( $this, $action ),
				'permission_callback' => array( $this, 'permission_check' ),
			) );
		}

		register_rest_route( $ns, '/incident/recover-core', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'recover_core' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/reset-permissions', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'reset_permissions' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
	}

	private function incident(): ?IncidentModule {
		$m = Plugin::instance()->module( 'incident' );
		return $m instanceof IncidentModule ? $m : null;
	}

	public function list_items( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->ok( array( 'items' => array() ) );
		}
		$status = (string) ( $request->get_param( 'status' ) ?: 'quarantined' );
		$items  = $incident->quarantine()->list( $status );
		return $this->ok( array( 'items' => $this->mask_paths_in( $items, array( 'original_path', 'stored_path', 'quarantine_path' ) ) ) );
	}

	public function add( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'totalsecwp_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}

		$path       = (string) $request->get_param( 'path' );
		$finding_id = (int) $request->get_param( 'finding_id' );
		$reason     = (string) ( $request->get_param( 'reason' ) ?: 'Manual quarantine' );

		// Resolve path from a scan finding when provided.
		if ( $finding_id && '' === $path ) {
			$scanner = Plugin::instance()->module( 'scanner' );
			if ( $scanner instanceof ScannerModule ) {
				$finding = $scanner->get_finding( $finding_id );
				if ( $finding ) {
					$path   = (string) $finding['path'];
					$reason = 'Finding #' . $finding_id . ': ' . $finding['rule'];
				}
			}
		}

		if ( '' === $path ) {
			return $this->fail( 'totalsecwp_no_path', __( 'No file path provided.', 'loyal-security' ), 422 );
		}

		$res = $incident->quarantine_file( $path, $reason, $finding_id ?: null );
		if ( empty( $res['ok'] ) ) {
			return $this->fail( 'totalsecwp_quarantine_failed', $res['message'] ?? __( 'Quarantine failed.', 'loyal-security' ), 500 );
		}

		// Mark the finding as quarantined.
		if ( $finding_id ) {
			$scanner = Plugin::instance()->module( 'scanner' );
			if ( $scanner instanceof ScannerModule ) {
				$scanner->set_finding_status( $finding_id, 'quarantined' );
			}
		}

		return $this->ok( $res );
	}

	public function restore( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'totalsecwp_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		$res = $incident->restore_file( (int) $request->get_param( 'id' ) );
		return empty( $res['ok'] )
			? $this->fail( 'totalsecwp_restore_failed', $res['message'] ?? 'Failed.', 500 )
			: $this->ok( $res );
	}

	public function delete( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'totalsecwp_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		$res = $incident->quarantine()->delete( (int) $request->get_param( 'id' ) );
		return $this->ok( $res );
	}

	/**
	 * Permanently delete every quarantined file in one action.
	 */
	public function clear( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'totalsecwp_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		return $this->ok( $incident->quarantine()->clear() );
	}

	public function recover_core( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'totalsecwp_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		return $this->ok( $incident->recover_core() );
	}

	public function reset_permissions( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'totalsecwp_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		$root = (string) $request->get_param( 'root' );
		return $this->ok( $incident->reset_permissions( $root ) );
	}
}
