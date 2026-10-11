<?php
/**
 * Repair Center REST controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Plugin;
use LoyalSecurity\Modules\Incident\IncidentModule;
use LoyalSecurity\Modules\Scanner\ScannerModule;
use WP_REST_Request;

/**
 * Non-destructive recovery: clean reinstall of core and WordPress.org plugins, a best-effort
 * per-file fix for code that can't be re-fetched, and management of the backups those
 * operations create. Complements {@see QuarantineController}, which isolates files rather than
 * repairing them.
 */
class RepairController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route( $ns, '/incident/repair-core', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'repair_core' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/repairs', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'inventory' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/triage', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'triage' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/repair-plugin', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'repair_plugin' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/verify-plugin', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'verify_plugin' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/fix-file', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'fix_file' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/remove-file', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'remove_file' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/inspect', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'inspect' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/backups', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'backups' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/restore-backup', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'restore_backup' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/delete-backup', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'delete_backup' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/incident/clear-backups', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'clear_backups' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
	}

	private function incident(): ?IncidentModule {
		$m = Plugin::instance()->module( 'incident' );
		return $m instanceof IncidentModule ? $m : null;
	}

	public function repair_core( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		$res = $incident->repair_core();
		return empty( $res['ok'] )
			? $this->fail( 'loyalsec_core_repair_failed', $res['message'] ?? __( 'Core repair failed.', 'loyal-security' ), 500 )
			: $this->ok( $res );
	}

	public function inventory( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->ok( array( 'repairable' => array(), 'unrepairable' => array() ) );
		}
		$inv = $incident->plugin_inventory();
		foreach ( array( 'repairable', 'unrepairable' ) as $group ) {
			if ( empty( $inv[ $group ] ) || ! is_array( $inv[ $group ] ) ) {
				continue;
			}
			$inv[ $group ] = array_map(
				function ( $entry ) {
					if ( ! empty( $entry['issues'] ) && is_array( $entry['issues'] ) ) {
						$entry['issues'] = $this->mask_paths_in( $entry['issues'], array( 'path' ) );
					}
					return $entry;
				},
				$inv[ $group ]
			);
		}
		return $this->ok( $inv );
	}

	public function triage( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->ok( array( 'core' => array( 'count' => 0, 'ids' => array() ), 'plugins' => array(), 'covered_ids' => array() ) );
		}
		return $this->ok( $incident->triage_findings() );
	}

	/**
	 * Reinstall a single WordPress.org plugin. Async-first: returns a job id the dashboard polls
	 * for live progress (no more 504s on large plugins like WooCommerce). When the caller passes
	 * `sync: true` (the dashboard's fallback if the background job never starts) it runs inline.
	 */
	public function repair_plugin( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		$slug = sanitize_text_field( (string) $request->get_param( 'slug' ) );
		if ( '' === $slug ) {
			return $this->fail( 'loyalsec_no_slug', __( 'No plugin specified.', 'loyal-security' ), 422 );
		}

		if ( $this->wants_sync( $request ) ) {
			$res = $incident->repair_plugin( $slug );
			return empty( $res['ok'] )
				? $this->fail( 'loyalsec_plugin_repair_failed', $res['message'] ?? __( 'Plugin repair failed.', 'loyal-security' ), 500 )
				: $this->ok( $res );
		}

		$job_id = $incident->dispatch_job(
			IncidentModule::JOB_REPAIR_PLUGIN,
			'repair_plugin',
			array( $slug ),
			array( 'slug' => $slug, 'step' => __( 'Queued…', 'loyal-security' ) )
		);
		return $this->ok( array( 'job_id' => $job_id, 'status' => 'queued' ) );
	}

	/**
	 * Verify a WordPress.org plugin against official checksums and clear false-positive findings
	 * on files that match the official copy. Fast (no file rewrites) — the right action for a
	 * freshly installed plugin still showing flagged files.
	 */
	public function verify_plugin( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		$slug = sanitize_text_field( (string) $request->get_param( 'slug' ) );
		if ( '' === $slug ) {
			return $this->fail( 'loyalsec_no_slug', __( 'No plugin specified.', 'loyal-security' ), 422 );
		}
		$res = $incident->verify_plugin_findings( $slug );
		return empty( $res['ok'] )
			? $this->fail( 'loyalsec_verify_failed', $res['message'] ?? __( 'Verification failed.', 'loyal-security' ), 422 )
			: $this->ok( $res );
	}

	public function delete_backup( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		$id = sanitize_text_field( (string) $request->get_param( 'id' ) );
		if ( '' === $id ) {
			return $this->fail( 'loyalsec_no_backup', __( 'No backup specified.', 'loyal-security' ), 422 );
		}
		return $this->ok( array( 'deleted' => $incident->delete_backup( $id ) ) );
	}

	/**
	 * Delete every repair backup. Async-first (live progress) with a `sync` fallback.
	 */
	public function clear_backups( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}

		if ( $this->wants_sync( $request ) ) {
			return $this->ok( $incident->clear_backups() );
		}

		$job_id = $incident->dispatch_job(
			IncidentModule::JOB_CLEAR_BACKUPS,
			'clear_backups',
			array(),
			array( 'step' => __( 'Queued…', 'loyal-security' ) )
		);
		return $this->ok( array( 'job_id' => $job_id, 'status' => 'queued' ) );
	}

	/**
	 * Whether the request explicitly asked for synchronous (inline) execution.
	 */
	private function wants_sync( WP_REST_Request $request ): bool {
		return filter_var( $request->get_param( 'sync' ), FILTER_VALIDATE_BOOLEAN );
	}

	public function fix_file( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}

		$path       = (string) $request->get_param( 'path' );
		$finding_id = (int) $request->get_param( 'finding_id' );
		$path       = $this->resolve_path_from_finding( $path, $finding_id );

		if ( '' === $path ) {
			return $this->fail( 'loyalsec_no_path', __( 'No file path provided.', 'loyal-security' ), 422 );
		}

		$res = $incident->fix_file( $path, $finding_id ?: null );
		return empty( $res['ok'] )
			? $this->fail( 'loyalsec_fix_failed', $res['message'] ?? __( 'File fix failed.', 'loyal-security' ), 422 )
			: $this->ok( $res );
	}

	public function remove_file( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}

		$path       = (string) $request->get_param( 'path' );
		$finding_id = (int) $request->get_param( 'finding_id' );
		$path       = $this->resolve_path_from_finding( $path, $finding_id );

		if ( '' === $path ) {
			return $this->fail( 'loyalsec_no_path', __( 'No file path provided.', 'loyal-security' ), 422 );
		}

		$res = $incident->remove_file( $path, $finding_id ?: null );
		return empty( $res['ok'] )
			? $this->fail( 'loyalsec_remove_failed', $res['message'] ?? __( 'File deletion failed.', 'loyal-security' ), 422 )
			: $this->ok( $res );
	}

	public function inspect( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}

		$path       = (string) $request->get_param( 'path' );
		$finding_id = (int) $request->get_param( 'finding_id' );
		$path       = $this->resolve_path_from_finding( $path, $finding_id );

		if ( '' === $path ) {
			return $this->fail( 'loyalsec_no_path', __( 'No file path provided.', 'loyal-security' ), 422 );
		}

		$res = $incident->preview_fix( $path );
		return empty( $res['ok'] )
			? $this->fail( 'loyalsec_inspect_failed', $res['message'] ?? __( 'Could not inspect the file.', 'loyal-security' ), 422 )
			: $this->ok( $res );
	}

	/**
	 * Resolve a path from a scan finding when only the id is given.
	 */
	private function resolve_path_from_finding( string $path, int $finding_id ): string {
		if ( '' !== $path || ! $finding_id ) {
			return $path;
		}
		$scanner = Plugin::instance()->module( 'scanner' );
		if ( $scanner instanceof ScannerModule ) {
			$finding = $scanner->get_finding( $finding_id );
			if ( $finding ) {
				return (string) $finding['path'];
			}
		}
		return $path;
	}

	public function backups( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->ok( array( 'items' => array(), 'summary' => array( 'count' => 0, 'bytes' => 0, 'size_human' => '0 B' ) ) );
		}
		// Never let a malformed manifest 500 the dashboard — degrade to an empty list instead.
		try {
			$items = array_map(
				function ( $b ) {
					if ( isset( $b['target'] ) ) {
						$b['target'] = $this->mask_path( (string) $b['target'] );
					}
					unset( $b['backup'] ); // internal storage path — never expose it.
					return $b;
				},
				$incident->list_backups()
			);
			return $this->ok( array(
				'items'   => $items,
				'summary' => $incident->backups_summary(),
			) );
		} catch ( \Throwable $e ) {
			return $this->ok( array(
				'items'   => array(),
				'summary' => array( 'count' => 0, 'bytes' => 0, 'size_human' => '0 B', 'error' => $e->getMessage() ),
			) );
		}
	}

	public function restore_backup( WP_REST_Request $request ) {
		$incident = $this->incident();
		if ( ! $incident ) {
			return $this->fail( 'loyalsec_incident_off', __( 'The incident module is disabled.', 'loyal-security' ), 409 );
		}
		$id = sanitize_text_field( (string) $request->get_param( 'id' ) );
		if ( '' === $id ) {
			return $this->fail( 'loyalsec_no_backup', __( 'No backup specified.', 'loyal-security' ), 422 );
		}
		$res = $incident->restore_backup( $id );
		return empty( $res['ok'] )
			? $this->fail( 'loyalsec_restore_failed', $res['message'] ?? __( 'Restore failed.', 'loyal-security' ), 500 )
			: $this->ok( $res );
	}
}
