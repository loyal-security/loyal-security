<?php
/**
 * Transient-based job store for long-running background operations.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Tracks async jobs (backup, integrity check, …) via WP transients so the dashboard can
 * poll for live progress without a WebSocket or SSE connection.
 *
 * Lifecycle: queued → running → done | error.
 * Transients expire after TTL (2 h) — no cleanup needed.
 */
class JobStore {

	const PREFIX = 'totalsecwp_job_';
	const TTL    = 7200;

	/**
	 * Create a new job and return its id.
	 *
	 * @param  string $type Slug identifying the operation ('backup', 'integrity', …).
	 * @param  array  $meta Extra fields stored alongside standard ones.
	 * @return string 16-char hex job id.
	 */
	public static function create( string $type, array $meta = [] ): string {
		$id  = substr( md5( uniqid( '', true ) . (string) wp_rand() ), 0, 16 );
		$job = array_merge(
			[
				'id'      => $id,
				'type'    => $type,
				'status'  => 'queued',
				'pct'     => 0,
				'step'    => 'Queued…',
				'steps'   => [],
				'result'  => null,
				'error'   => null,
				'created' => time(),
			],
			$meta
		);
		set_transient( self::PREFIX . $id, $job, self::TTL );
		return $id;
	}

	/**
	 * Emit a progress update. Keeps the last 12 steps for the activity feed.
	 *
	 * @param string $id  Job id.
	 * @param int    $pct 0–99 (100 is reserved for complete()).
	 * @param string $step User-visible status line.
	 */
	public static function progress( string $id, int $pct, string $step ): void {
		$job = self::get( $id );
		if ( ! $job ) {
			return;
		}
		$job['pct']    = max( 0, min( 99, $pct ) );
		$job['step']   = $step;
		$job['status'] = 'running';
		$job['steps']  = array_slice(
			array_merge( $job['steps'], [ [ 't' => time(), 'msg' => $step ] ] ),
			-12
		);
		set_transient( self::PREFIX . $id, $job, self::TTL );
	}

	/**
	 * Mark the job done.
	 *
	 * @param string $id     Job id.
	 * @param string $step   Final user-visible line shown in the dashboard.
	 * @param array  $result Arbitrary result payload the dashboard can read.
	 */
	public static function complete( string $id, string $step, array $result = [] ): void {
		$job = self::get( $id );
		if ( ! $job ) {
			return;
		}
		$job['pct']    = 100;
		$job['step']   = $step;
		$job['status'] = 'done';
		$job['result'] = $result;
		$job['steps']  = array_slice(
			array_merge( $job['steps'], [ [ 't' => time(), 'msg' => $step ] ] ),
			-12
		);
		set_transient( self::PREFIX . $id, $job, self::TTL );
	}

	/**
	 * Mark the job as failed.
	 *
	 * @param string $id    Job id.
	 * @param string $error User-visible error message.
	 */
	public static function fail( string $id, string $error ): void {
		$job = self::get( $id );
		if ( ! $job ) {
			return;
		}
		$job['status'] = 'error';
		$job['error']  = $error;
		$job['step']   = $error;
		$job['steps']  = array_slice(
			array_merge( $job['steps'], [ [ 't' => time(), 'msg' => $error ] ] ),
			-12
		);
		set_transient( self::PREFIX . $id, $job, self::TTL );
	}

	/**
	 * Read a job by id. Returns null if not found or expired.
	 *
	 * @param  string $id Job id.
	 * @return array|null
	 */
	public static function get( string $id ): ?array {
		$id  = preg_replace( '/[^a-zA-Z0-9]/', '', $id );
		$job = get_transient( self::PREFIX . $id );
		return is_array( $job ) ? $job : null;
	}
}
