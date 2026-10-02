<?php
/**
 * Scanner + integrity REST controller.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Plugin;
use TotalSecurityWP\Modules\Scanner\ScannerModule;
use TotalSecurityWP\Modules\Scanner\ScanState;
use TotalSecurityWP\Modules\Scanner\Finding;
use TotalSecurityWP\Modules\Integrity\IntegrityModule;
use TotalSecurityWP\Modules\Firewall\CustomVirtualPatches;
use TotalSecurityWP\Modules\Firewall\FirewallModule;
use TotalSecurityWP\Modules\Firewall\PatchSubmissionClient;
use TotalSecurityWP\Modules\Telemetry\BypassReporter;
use WP_REST_Request;

/**
 * Exposes batched malware scanning and file-integrity verification to the dashboard.
 */
class ScannerController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		$post = function ( $path, $cb ) use ( $ns ) {
			register_rest_route( $ns, $path, array(
				'methods'             => 'POST',
				'callback'            => array( $this, $cb ),
				'permission_callback' => array( $this, 'permission_check' ),
			) );
		};
		$get = function ( $path, $cb ) use ( $ns ) {
			register_rest_route( $ns, $path, array(
				'methods'             => 'GET',
				'callback'            => array( $this, $cb ),
				'permission_callback' => array( $this, 'permission_check' ),
			) );
		};

		$post( '/scan/start', 'start' );
		$post( '/scan/batch', 'batch' );
		$get( '/scan/progress', 'progress' );
		$get( '/scan/findings', 'findings' );
		$post( '/scan/findings/status', 'finding_status' );
		$post( '/scan/findings/bulk', 'finding_bulk' );
		$post( '/scan/findings/refresh', 'finding_refresh' );
		$post( '/scan/findings/patch', 'finding_patch' );
		$get( '/scan/whitelist', 'whitelist_list' );
		$post( '/scan/whitelist', 'whitelist_add' );
		register_rest_route( $ns, '/scan/whitelist', array(
			'methods'             => 'DELETE',
			'callback'            => array( $this, 'whitelist_remove' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
		$get( '/scanner/history', 'history' );
		$post( '/integrity/run', 'integrity_run' );
		$post( '/integrity/snapshot', 'integrity_snapshot' );
	}

	private function scanner(): ?ScannerModule {
		$m = Plugin::instance()->module( 'scanner' );
		return $m instanceof ScannerModule ? $m : null;
	}

	private function settings(): \TotalSecurityWP\Core\Settings {
		return $this->container->make( 'settings' );
	}

	private function integrity(): ?IntegrityModule {
		$m = Plugin::instance()->module( 'integrity' );
		return $m instanceof IntegrityModule ? $m : null;
	}

	public function start( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->fail( 'totalsecwp_scanner_off', __( 'The scanner module is disabled.', 'loyal-security' ), 409 );
		}
		$type = (string) ( $request->get_param( 'type' ) ?: 'full' );
		return $this->ok( $scanner->start( $type ) );
	}

	public function batch( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->fail( 'totalsecwp_scanner_off', __( 'The scanner module is disabled.', 'loyal-security' ), 409 );
		}
		$scan_id = (string) $request->get_param( 'scan_id' );
		if ( '' === $scan_id ) {
			return $this->fail( 'totalsecwp_no_scan', __( 'Missing scan id.', 'loyal-security' ), 422 );
		}
		return $this->ok( $scanner->run_batch( $scan_id ) );
	}

	public function progress( WP_REST_Request $request ) {
		$state   = new ScanState();
		$scan_id = (string) $request->get_param( 'scan_id' );
		$row     = $scan_id ? $state->get( $scan_id ) : $state->latest();
		return $this->ok( $row ?: array( 'status' => 'none' ) );
	}

	public function findings( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->ok( array( 'items' => array() ) );
		}
		$status = (string) ( $request->get_param( 'status' ) ?: 'open' );
		return $this->ok( array( 'items' => $this->mask_paths_in( $scanner->findings( $status ), array( 'path' ) ) ) );
	}

	public function finding_status( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->fail( 'totalsecwp_scanner_off', __( 'The scanner module is disabled.', 'loyal-security' ), 409 );
		}
		$id     = (int) $request->get_param( 'id' );
		$status = (string) $request->get_param( 'status' );
		$allowed = array( 'open', 'ignored', 'resolved', 'quarantined' );
		if ( ! in_array( $status, $allowed, true ) ) {
			return $this->fail( 'totalsecwp_bad_status', __( 'Invalid status.', 'loyal-security' ), 422 );
		}
		$scanner->set_finding_status( $id, $status );
		return $this->ok( array( 'id' => $id, 'status' => $status ) );
	}

	/**
	 * Bulk-clear the Open findings list. action=ignore moves every open finding to "ignored"
	 * (reversible — still visible under the Ignored filter). action=whitelist additionally adds
	 * each open file finding's path to the false-positive whitelist so it never re-appears.
	 */
	public function finding_bulk( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->fail( 'totalsecwp_scanner_off', __( 'The scanner module is disabled.', 'loyal-security' ), 409 );
		}
		$action = (string) ( $request->get_param( 'action' ) ?: 'ignore' );
		if ( ! in_array( $action, array( 'ignore', 'whitelist' ), true ) ) {
			return $this->fail( 'totalsecwp_bad_action', __( 'Invalid bulk action.', 'loyal-security' ), 422 );
		}

		$whitelisted = 0;
		if ( 'whitelist' === $action ) {
			$whitelist = $scanner->whitelist();
			foreach ( $scanner->findings( 'open', 1000 ) as $f ) {
				$path = (string) ( $f['path'] ?? '' );
				// Only file paths can be whitelisted; database-row findings have no path to allow.
				if ( '' === $path || preg_match( '/^(post:|option:|user:|theme:|comment:|usermeta:|mu:|dropin:)/', $path ) ) {
					continue;
				}
				if ( $whitelist->add( $path, 'path' ) ) {
					$whitelisted++;
				}
			}
		}

		$updated = $scanner->set_status_bulk( 'open', 'ignored' );
		return $this->ok( array( 'action' => $action, 'updated' => $updated, 'whitelisted' => $whitelisted ) );
	}

	/**
	 * Re-check every open finding without a full rescan (see ScannerModule::refresh_findings()) —
	 * clears stale findings (file gone, now matches an official WordPress.org release, or the
	 * rule no longer matches the current content) without acting on anything still genuinely open.
	 */
	public function finding_refresh( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->fail( 'totalsecwp_scanner_off', __( 'The scanner module is disabled.', 'loyal-security' ), 409 );
		}
		return $this->ok( $scanner->refresh_findings() );
	}

	/**
	 * Review action on a finding's auto-drafted virtual-patch suggestion (see PatchSuggester).
	 * approve  → adds the rule to CustomVirtualPatches and it's live immediately (Standard Mode
	 *            and the prepend both re-merge it on the next request / next write_waf_config()).
	 * reject   → dismisses it; nothing changes.
	 * submit_cloud → with data-sharing consent, sends the rule (not a hash) to the feed service
	 *            for review and possible redistribution to other sites running the same plugin.
	 */
	public function finding_patch( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->fail( 'totalsecwp_scanner_off', __( 'The scanner module is disabled.', 'loyal-security' ), 409 );
		}

		$id     = (int) $request->get_param( 'id' );
		$action = (string) $request->get_param( 'action' );
		if ( ! in_array( $action, array( 'approve', 'reject', 'submit_cloud' ), true ) ) {
			return $this->fail( 'totalsecwp_bad_action', __( 'Invalid action.', 'loyal-security' ), 422 );
		}

		$row = $scanner->get_finding( $id );
		if ( ! $row ) {
			return $this->fail( 'totalsecwp_not_found', __( 'Finding not found.', 'loyal-security' ), 404 );
		}
		$suggestion = ! empty( $row['suggested_patch'] ) ? json_decode( (string) $row['suggested_patch'], true ) : null;
		if ( ! is_array( $suggestion ) || empty( $suggestion['rule'] ) || ! is_array( $suggestion['rule'] ) ) {
			return $this->fail( 'totalsecwp_no_suggestion', __( 'This finding has no suggested patch.', 'loyal-security' ), 422 );
		}
		// Findings are only ever backfilled with a suggestion once (see
		// ScannerModule::store_findings()'s dedup check) — a suggestion computed months ago,
		// before PatchSuggester gained a new field (this session's value_regex/param additions
		// being the concrete case), stays frozen in that old shape forever unless something
		// recomputes it. Approve/submit_cloud are the two moments a stale shape actually causes
		// a problem (an old-shape rule silently misses new safety fields, or a cloud submission
		// 422s on fields that didn't exist when it was first drafted) — so refresh from the
		// underlying finding right before acting, and persist the refreshed shape so future
		// actions (and the dashboard's own display) see it too, not just this one request.
		$refreshed = $this->refresh_suggestion( $id, $row, $suggestion );
		if ( null !== $refreshed ) {
			$suggestion = $refreshed;
		}

		if ( 'approve' === $action ) {
			( new CustomVirtualPatches() )->add( $suggestion['rule'] );
			$firewall = Plugin::instance()->module( 'firewall' );
			if ( $firewall instanceof FirewallModule ) {
				$firewall->write_waf_config();
			}

			// If anonymous data-sharing consent is already recorded, submit the approved rule
			// to LicenseKit in the same step — no separate manual click needed. Fails open: a
			// skipped or failed submission still leaves the rule applied locally, just without
			// the "submitted" status (the dashboard then offers "Submit to Cloud" only for the
			// no-consent case, since once consent exists this is meant to be automatic).
			$status         = 'approved';
			$cloud_error    = '';
			$cloud_error_body = '';
			if ( BypassReporter::consent_given() ) {
				$result = $this->submit_to_cloud( $suggestion['rule'], (string) ( $row['rule'] ?? '' ) );
				if ( ! empty( $result['ok'] ) ) {
					$status = 'submitted';
				} else {
					$cloud_error      = (string) ( $result['error'] ?? 'unknown' );
					// The actual LicenseKit response body (validation error detail, etc.),
					// humanized when it's a recognizable structured error — surfaced to the
					// dashboard so any rejection (this one or a future one) is diagnosable from
					// the browser without needing server log access at all.
					$cloud_error_body = $this->humanize_cloud_error( (string) ( $result['body'] ?? '' ) );
				}
			}
			$scanner->set_patch_status( $id, $status );
			return $this->ok( array(
				'id'                => $id,
				'patch_status'      => $status,
				'cloud_error'       => $cloud_error,
				'cloud_error_body'  => $cloud_error_body,
			) );
		}

		if ( 'reject' === $action ) {
			$scanner->set_patch_status( $id, 'rejected' );
			return $this->ok( array( 'id' => $id, 'patch_status' => 'rejected' ) );
		}

		// submit_cloud — the manual path, used when consent was just granted (the dashboard only
		// shows this action while consent is missing; once given, 'approve' submits automatically).
		// Requires the data-sharing consent.
		if ( ! BypassReporter::consent_given() ) {
			return $this->fail( 'totalsecwp_no_consent', __( 'Anonymous data-sharing consent is required to submit to the cloud.', 'loyal-security' ), 409 );
		}
		$result = $this->submit_to_cloud( $suggestion['rule'], (string) ( $row['rule'] ?? '' ) );
		if ( empty( $result['ok'] ) ) {
			$detail = $this->humanize_cloud_error( (string) ( $result['body'] ?? '' ) );
			return $this->fail(
				'totalsecwp_submit_failed',
				'Could not reach the cloud service: ' . (string) ( $result['error'] ?? 'unknown' ) . ( '' !== $detail ? ' — ' . $detail : '' ),
				502
			);
		}
		$scanner->set_patch_status( $id, 'submitted' );
		return $this->ok( array( 'id' => $id, 'patch_status' => 'submitted' ) );
	}

	/**
	 * Recompute a finding's suggestion fresh via PatchSuggester and persist it if it differs
	 * from what's stored — see the call site in finding_patch() for why this matters: a
	 * suggestion is only ever computed once (ScannerModule::store_findings()'s dedup check
	 * skips already-open findings), so one drafted before PatchSuggester gained a field or
	 * rule type stays frozen in that old shape indefinitely otherwise.
	 *
	 * `param` isn't its own column on scan_findings (Finding::$param is transient, consumed by
	 * PatchSuggester and never persisted per its own doc comment) — recovered here from the
	 * currently-stored suggestion's `rule.param` instead, so a tainted-* finding's recompute
	 * still has the parameter TaintAnalyzer originally traced, not just whatever's in the DB row.
	 *
	 * @param array<string, mixed> $row        The finding's DB row (from ScannerModule::get_finding()).
	 * @param array<string, mixed> $suggestion The currently-stored, possibly-stale suggestion.
	 * @return array<string, mixed>|null The refreshed suggestion if recomputable and different, else null.
	 */
	private function refresh_suggestion( int $id, array $row, array $suggestion ): ?array {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return null;
		}

		$stored_param = isset( $suggestion['rule']['param'] ) && is_string( $suggestion['rule']['param'] )
			? $suggestion['rule']['param']
			: '';

		$finding = new Finding(
			(string) ( $row['path'] ?? '' ),
			(string) ( $row['rule'] ?? '' ),
			(string) ( $row['category'] ?? '' ),
			(int) ( $row['score'] ?? 0 ),
			(int) ( $row['line'] ?? 0 ),
			(string) ( $row['snippet'] ?? '' ),
			isset( $row['severity'] ) ? (int) $row['severity'] : null,
			$stored_param
		);

		$fresh = $scanner->suggest_for( $finding );
		if ( null === $fresh ) {
			return null; // Rule type no longer (or never) supported — keep whatever's stored.
		}
		if ( wp_json_encode( $fresh ) === wp_json_encode( $suggestion ) ) {
			return null; // Already current — nothing to refresh.
		}

		$scanner->update_suggested_patch( $id, $fresh );
		return $fresh;
	}

	/**
	 * Turn a LicenseKit error response body into a short, human-readable string when it's a
	 * recognizable structured error shape, so any current or future rejection is diagnosable
	 * from the dashboard alone — no assumption baked in about *which* validation failed, just
	 * that Zod-style `{ error, issues: [{ path, message }] }` bodies get flattened into
	 * "message (at a.b.c)" instead of forcing the admin to read raw JSON. Falls back to the
	 * raw (truncated) body untouched for anything that doesn't match this shape, so nothing is
	 * ever hidden — only made more readable when it can be.
	 *
	 * @param string $raw_body Truncated response body from PatchSubmissionClient::submit().
	 */
	private function humanize_cloud_error( string $raw_body ): string {
		if ( '' === $raw_body ) {
			return '';
		}
		$data = json_decode( $raw_body, true );
		if ( ! is_array( $data ) || empty( $data['issues'] ) || ! is_array( $data['issues'] ) ) {
			return $raw_body;
		}
		$parts = $this->flatten_zod_issues( $data['issues'], array() );
		return $parts ? implode( '; ', $parts ) : $raw_body;
	}

	/**
	 * Recursively flatten Zod issues into "message (at a.b.c)" strings. Needed specifically for
	 * `invalid_union` issues: a union failure's own top-level `message` is generic boilerplate
	 * ("Invalid input") — the actually useful detail (which field, on which branch of the
	 * union, failed and why) is nested one level down in `errors: [[...issues for branch 1],
	 * [...issues for branch 2]]`. A flat single-level read (an earlier version of this method)
	 * silently discards exactly the information needed to diagnose a schema mismatch, which is
	 * the one thing this whole function exists to surface.
	 *
	 * @param array<int, array<string, mixed>> $issues     Zod issues at this level.
	 * @param array<int, int|string>           $path_prefix Path segments inherited from the
	 *                                                       enclosing union issue, if any.
	 * @return array<int, string>
	 */
	private function flatten_zod_issues( array $issues, array $path_prefix ): array {
		$parts = array();
		foreach ( $issues as $issue ) {
			if ( ! is_array( $issue ) ) {
				continue;
			}
			$path = isset( $issue['path'] ) && is_array( $issue['path'] )
				? array_merge( $path_prefix, $issue['path'] )
				: $path_prefix;

			if ( isset( $issue['code'] ) && 'invalid_union' === $issue['code']
				&& ! empty( $issue['errors'] ) && is_array( $issue['errors'] ) ) {
				foreach ( $issue['errors'] as $i => $branch_issues ) {
					if ( ! is_array( $branch_issues ) ) {
						continue;
					}
					foreach ( $this->flatten_zod_issues( $branch_issues, $path ) as $p ) {
						$parts[] = 'union option ' . ( (int) $i + 1 ) . ': ' . $p;
					}
				}
				continue;
			}

			if ( ! empty( $issue['message'] ) ) {
				$message = (string) $issue['message'];
				$parts[] = $path ? ( $message . ' (at ' . implode( '.', $path ) . ')' ) : $message;
			}
		}
		return $parts;
	}

	/**
	 * @param array<string, mixed> $rule     The virtual-patch rule.
	 * @param string               $category TaintAnalyzer rule id (e.g. 'tainted-rce').
	 * @return array{ok: bool, error?: string}
	 */
	private function submit_to_cloud( array $rule, string $category ): array {
		$license_key = (string) $this->settings()->get( 'threatintel', 'license_key', '' );
		return ( new PatchSubmissionClient() )->submit( $rule, $category, $license_key );
	}

	public function whitelist_list( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->ok( array( 'items' => array() ) );
		}
		return $this->ok( array( 'items' => $scanner->whitelist()->all() ) );
	}

	public function whitelist_add( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->fail( 'totalsecwp_scanner_off', __( 'The scanner module is disabled.', 'loyal-security' ), 409 );
		}
		$value = (string) $request->get_param( 'value' );
		$type  = 'rule' === (string) $request->get_param( 'type' ) ? 'rule' : 'path';
		if ( '' === trim( $value ) ) {
			return $this->fail( 'totalsecwp_no_value', __( 'Nothing to whitelist.', 'loyal-security' ), 422 );
		}
		$scanner->whitelist()->add( $value, $type );

		// Optionally clear the matching open finding(s) so the entry takes effect immediately.
		$finding_id = (int) $request->get_param( 'finding_id' );
		if ( $finding_id ) {
			$scanner->set_finding_status( $finding_id, 'ignored' );
		}
		return $this->ok( array( 'items' => $scanner->whitelist()->all() ) );
	}

	public function whitelist_remove( WP_REST_Request $request ) {
		$scanner = $this->scanner();
		if ( ! $scanner ) {
			return $this->fail( 'totalsecwp_scanner_off', __( 'The scanner module is disabled.', 'loyal-security' ), 409 );
		}
		$value = (string) $request->get_param( 'value' );
		$type  = 'rule' === (string) $request->get_param( 'type' ) ? 'rule' : 'path';
		$scanner->whitelist()->remove( $value, $type );
		return $this->ok( array( 'items' => $scanner->whitelist()->all() ) );
	}

	/**
	 * Recent completed-scan history (every entry the site keeps).
	 */
	public function history( WP_REST_Request $request ) {
		$history = get_option( 'totalsecwp_scan_history', array() );
		if ( ! is_array( $history ) ) {
			$history = array();
		}
		return $this->ok( array( 'items' => array_values( $history ) ) );
	}

	public function integrity_run( WP_REST_Request $request ) {
		$integrity = $this->integrity();
		if ( ! $integrity ) {
			return $this->fail( 'totalsecwp_integrity_off', __( 'The integrity module is disabled.', 'loyal-security' ), 409 );
		}
		return $this->ok( $integrity->run() );
	}

	public function integrity_snapshot( WP_REST_Request $request ) {
		$integrity = $this->integrity();
		if ( ! $integrity ) {
			return $this->fail( 'totalsecwp_integrity_off', __( 'The integrity module is disabled.', 'loyal-security' ), 409 );
		}
		return $this->ok( array( 'recorded' => $integrity->snapshot_baselines() ) );
	}
}
