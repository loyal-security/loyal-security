<?php
/**
 * Job-progress polling endpoint.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Support\JobStore;
use WP_REST_Request;

/**
 * GET /jobs/{id} — Returns the current snapshot of a background job so the dashboard can
 * poll for live progress without WebSockets or SSE.
 */
class JobsController extends AbstractController {

	public function register_routes(): void {
		register_rest_route(
			$this->namespace(),
			'/jobs/(?P<id>[a-zA-Z0-9]{1,32})',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_job' ],
				'permission_callback' => [ $this, 'permission_check' ],
				'args'                => [
					'id' => [
						'sanitize_callback' => static fn( $v ) => preg_replace( '/[^a-zA-Z0-9]/', '', (string) $v ),
					],
				],
			]
		);
	}

	public function get_job( WP_REST_Request $request ) {
		$id  = (string) $request->get_param( 'id' );
		$job = JobStore::get( $id );
		if ( ! $job ) {
			return $this->fail( 'totalsecwp_job_not_found', __( 'Job not found or expired.', 'loyal-security' ), 404 );
		}
		return $this->ok( $job );
	}
}
