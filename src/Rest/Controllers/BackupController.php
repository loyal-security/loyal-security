<?php
/**
 * Backup & Recovery REST controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Plugin;
use LoyalSecurity\Modules\Backup\BackupModule;
use WP_REST_Request;

/**
 * Dashboard control of backups (list/create/delete/restore) and the standalone-recovery
 * secret. All routes require the management capability; the plaintext recovery token is only
 * ever returned once, in the response to an explicit enable/rotate request.
 */
class BackupController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route( $ns, '/backups', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'list_items' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/backups/create', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'create' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/backups/delete', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'delete' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/backups/restore', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'restore' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/backups/recovery', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'recovery_status' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/backups/recovery', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'recovery_set' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/backups/recovery/download', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'recovery_download' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
	}

	private function backup(): ?BackupModule {
		$m = Plugin::instance()->module( 'backup' );
		return $m instanceof BackupModule ? $m : null;
	}

	public function list_items( WP_REST_Request $request ) {
		$b = $this->backup();
		if ( ! $b ) {
			return $this->ok( array( 'items' => array(), 'recovery' => array( 'enabled' => false ) ) );
		}
		return $this->ok( array(
			'items'    => $b->list_backups(),
			'recovery' => $b->recovery()->status(),
		) );
	}

	public function create( WP_REST_Request $request ) {
		$b = $this->backup();
		if ( ! $b ) {
			return $this->fail( 'loyalsec_backup_off', __( 'The backup module is disabled.', 'loyal-security' ), 409 );
		}
		$scope   = 'files' === (string) $request->get_param( 'scope' ) ? 'files' : 'full';
		$uploads = null === $request->get_param( 'include_uploads' ) ? null : (bool) $request->get_param( 'include_uploads' );

		// Dispatch the backup as a background WP-Cron job and return immediately so the HTTP
		// request finishes in <200 ms — no more 504 timeouts on large sites. The dashboard
		// polls GET /jobs/{job_id} for live progress.
		$job_id = \LoyalSecurity\Support\JobStore::create( 'backup', [ 'scope' => $scope ] );

		wp_schedule_single_event( time() - 1, 'loyalsec_run_backup', [ $job_id, $scope, $uploads ] );

		// Kick WP-Cron immediately (non-blocking loopback) so the job starts right away
		// instead of waiting for the next page load to trigger cron naturally.
		wp_remote_post(
			add_query_arg( 'doing_wp_cron', '1', site_url( '/' ) ),
			[ 'timeout' => 0.01, 'blocking' => false, 'sslverify' => \LoyalSecurity\Support\Http::local_sslverify(), 'body' => [] ]
		);

		return $this->ok( [ 'job_id' => $job_id, 'status' => 'queued' ] );
	}

	public function delete( WP_REST_Request $request ) {
		$b = $this->backup();
		if ( ! $b ) {
			return $this->fail( 'loyalsec_backup_off', __( 'The backup module is disabled.', 'loyal-security' ), 409 );
		}
		$id = (string) $request->get_param( 'id' );
		if ( '' === $id ) {
			return $this->fail( 'loyalsec_no_id', __( 'No backup specified.', 'loyal-security' ), 422 );
		}
		return $this->ok( array( 'deleted' => $b->delete_backup( $id ) ) );
	}

	public function restore( WP_REST_Request $request ) {
		$b = $this->backup();
		if ( ! $b ) {
			return $this->fail( 'loyalsec_backup_off', __( 'The backup module is disabled.', 'loyal-security' ), 409 );
		}
		$id = (string) $request->get_param( 'id' );
		if ( '' === $id ) {
			return $this->fail( 'loyalsec_no_id', __( 'No backup specified.', 'loyal-security' ), 422 );
		}
		$files = null === $request->get_param( 'files' ) ? true : (bool) $request->get_param( 'files' );
		$db    = null === $request->get_param( 'db' ) ? true : (bool) $request->get_param( 'db' );
		$res   = $b->restore_backup( $id, $files, $db );
		return empty( $res['ok'] )
			? $this->fail( 'loyalsec_restore_failed', $res['message'] ?? __( 'Restore failed.', 'loyal-security' ), 500 )
			: $this->ok( $res );
	}

	public function recovery_status( WP_REST_Request $request ) {
		$b = $this->backup();
		if ( ! $b ) {
			return $this->ok( array( 'enabled' => false ) );
		}
		return $this->ok( $b->recovery()->status() );
	}

	public function recovery_set( WP_REST_Request $request ) {
		$b = $this->backup();
		if ( ! $b ) {
			return $this->fail( 'loyalsec_backup_off', __( 'The backup module is disabled.', 'loyal-security' ), 409 );
		}
		$enable = (bool) $request->get_param( 'enable' );
		if ( $enable ) {
			$res = $b->recovery()->enable();
			return empty( $res['ok'] )
				? $this->fail( 'loyalsec_recovery_failed', $res['message'] ?? __( 'Could not enable recovery.', 'loyal-security' ), 500 )
				: $this->ok_no_store( $res ); // Includes the one-time plaintext token.
		}
		$b->recovery()->disable();
		return $this->ok( array( 'enabled' => false ) );
	}

	/**
	 * Stream the standalone recovery script as a file download. Regenerates it from the
	 * current template first, so re-downloading always ships a copy in sync with the live
	 * endpoint URL — there is no separate "stale" download vs. "live" file to reconcile.
	 * Available any time recovery is enabled, not just at first-enable, so an operator who
	 * misplaces their saved copy can always fetch a fresh one from the dashboard.
	 */
	public function recovery_download( WP_REST_Request $request ) {
		$b = $this->backup();
		if ( ! $b ) {
			return $this->fail( 'loyalsec_backup_off', __( 'The backup module is disabled.', 'loyal-security' ), 409 );
		}
		$recovery = $b->recovery();
		if ( ! $recovery->is_enabled() ) {
			return $this->fail( 'loyalsec_recovery_off', __( 'Standalone recovery is not enabled.', 'loyal-security' ), 409 );
		}

		// Returned as JSON and saved as a file by the dashboard: the plugin itself never writes
		// the tool to the server — the administrator uploads it wherever they choose.
		return $this->ok_no_store(
			array(
				'filename' => 'loyal-security-recovery.php',
				'mime'     => 'application/x-httpd-php',
				'content'  => $recovery->script_source(),
			)
		);
	}
}
