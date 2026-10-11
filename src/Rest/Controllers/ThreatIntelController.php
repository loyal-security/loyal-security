<?php
/**
 * Threat Intelligence REST controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Plugin;
use LoyalSecurity\Modules\ThreatIntel\ThreatIntelModule;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Routes:
 *   GET  /threatintel/status         — channel, tier, last_sync, dataset versions.
 *   POST /threatintel/sync           — trigger a manual feed sync.
 *   GET  /threatintel/vulnerabilities — CVE findings.
 */
class ThreatIntelController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route( $ns, '/threatintel/status', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'get_status' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/threatintel/sync', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'manual_sync' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/threatintel/connection-test', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'connection_test' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/threatintel/vulnerabilities', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'get_vulnerabilities' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
	}

	public function get_status( WP_REST_Request $request ): WP_REST_Response {
		$module = $this->module();
		if ( ! $module ) {
			return $this->fail( 'module_unavailable', __( 'ThreatIntel module is not active.', 'loyal-security' ), 503 );
		}
		return $this->ok( $module->get_status() );
	}

	public function manual_sync( WP_REST_Request $request ): WP_REST_Response {
		$module = $this->module();
		if ( ! $module ) {
			return $this->fail( 'module_unavailable', __( 'ThreatIntel module is not active.', 'loyal-security' ), 503 );
		}
		$result = $module->run_sync();
		return $this->ok( array_merge( $module->get_status(), array( 'sync_result' => $result ) ) );
	}

	/**
	 * Run the LicenseKit connection self-test: liveness (`GET /health`) plus the one-call
	 * `POST /diagnostics` probe, using this site's stored license key + telemetry identity.
	 * Never throws — it reports exactly which link (base URL / install / signature / license /
	 * clock) is misconfigured so the operator can pinpoint the problem.
	 */
	public function connection_test( WP_REST_Request $request ): WP_REST_Response {
		/** @var \LoyalSecurity\Core\Settings $settings */
		$settings    = $this->container->make( 'settings' );
		$license_key = (string) $settings->get( 'threatintel', 'license_key', '' );

		return $this->ok( \LoyalSecurity\Core\LicenseKit::connection_test( $license_key ) );
	}

	public function get_vulnerabilities( WP_REST_Request $request ): WP_REST_Response {
		$module = $this->module();
		if ( ! $module ) {
			return $this->fail( 'module_unavailable', __( 'ThreatIntel module is not active.', 'loyal-security' ), 503 );
		}

		// Check whether the CVE database has been populated from the feed yet.
		$store     = new \LoyalSecurity\Modules\ThreatIntel\FeedStore();
		$cve_db    = $store->get_rules( 'cve' );
		$db_loaded = ! empty( $cve_db );

		global $wpdb;
		$table = $wpdb->prefix . 'loyalsec_scan_findings';
		$rows  = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT * FROM %i WHERE status = 'open' AND category = 'vulnerability' ORDER BY id DESC LIMIT %d", $table,
				500
			),
			ARRAY_A
		);

		// Live re-filter: only show advisories that STILL affect the currently-installed version.
		// This drops (a) legacy junk findings recorded before the version logic was corrected, and
		// (b) findings for plugins the operator has since updated — immediately, without waiting
		// for the next sync's resolve_stale pass. Uses the live CVE db when available (most
		// accurate); when the feed isn't loaded we don't re-filter, to avoid hiding everything.
		$cve_index = array();
		if ( is_array( $cve_db ) ) {
			foreach ( $cve_db as $c ) {
				if ( ! is_array( $c ) ) {
					continue;
				}
				$cid = (string) ( $c['cve_id'] ?? $c['id'] ?? '' );
				if ( '' !== $cid ) {
					$cve_index[ $cid ] = $c;
				}
			}
		}
		$installed_index = $this->installed_versions();

		$vulns = array();
		foreach ( (array) $rows as $row ) {
			// Context is encoded as JSON in the snippet column.
			$ctx = array();
			if ( ! empty( $row['snippet'] ) ) {
				$decoded = json_decode( (string) $row['snippet'], true );
				if ( is_array( $decoded ) ) {
					$ctx = $decoded;
				}
			}

			// Re-verify against the current installed version when we have the CVE db to compare to.
			if ( ! empty( $cve_index ) ) {
				$cid     = (string) ( $ctx['cve_id'] ?? $row['rule'] );
				$type    = (string) ( $ctx['type'] ?? '' );
				$slug    = (string) ( $ctx['slug'] ?? '' );
				$current = $this->installed_version_for( $type, $slug, $installed_index );
				if ( null === $current ) {
					continue; // No longer installed → not an active vulnerability.
				}
				// Prefer the live advisory's version fields; fall back to what the finding stored.
				$check = isset( $cve_index[ $cid ] ) && is_array( $cve_index[ $cid ] ) ? $cve_index[ $cid ] : $ctx;
				if ( ! \LoyalSecurity\Modules\ThreatIntel\VulnerabilityScanner::version_affected( $check, $current ) ) {
					continue; // Patched in the running version (or unverifiable) → hide.
				}
			}

			$vulns[] = array(
				'id'               => (int) $row['id'],
				'rule'             => (string) $row['rule'],
				'path'             => (string) $row['path'],
				'severity'         => (int) $row['severity'],
				'status'           => (string) $row['status'],
				'created_at'       => (string) $row['created_at'],
				'cve_id'           => (string) ( $ctx['cve_id'] ?? $row['rule'] ),
				'title'            => (string) ( $ctx['title'] ?? $row['rule'] ),
				'type'             => (string) ( $ctx['type'] ?? '' ),
				'slug'             => (string) ( $ctx['slug'] ?? '' ),
				'installed'        => (string) ( $ctx['installed'] ?? '' ),
				'max_version'      => (string) ( $ctx['max_version'] ?? '' ),
				'fixed_in'         => (string) ( $ctx['fixed_in'] ?? '' ),
				'virtual_patch_id' => (string) ( $ctx['virtual_patch_id'] ?? '' ),
				'source'           => (string) ( $ctx['source'] ?? '' ),
				'cvss_score'       => isset( $ctx['cvss_score'] ) ? $ctx['cvss_score'] : null,
				'severity_label'   => (string) ( $ctx['severity_label'] ?? '' ),
			);
		}

		return $this->ok( array(
			'vulnerabilities' => $vulns,
			'cve_db_loaded'   => $db_loaded,
		) );
	}

	/**
	 * Snapshot of installed plugin/theme versions + core, for the live vulnerability re-filter.
	 *
	 * @return array{plugin: array<string,string>, theme: array<string,string>, core: string}
	 */
	private function installed_versions(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug            = dirname( (string) $file );
			$slug            = ( '.' === $slug ) ? basename( (string) $file, '.php' ) : $slug;
			$plugins[ $slug ] = isset( $data['Version'] ) ? (string) $data['Version'] : '0';
		}
		$themes = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$themes[ (string) $slug ] = (string) $theme->get( 'Version' );
		}
		global $wp_version;
		return array(
			'plugin' => $plugins,
			'theme'  => $themes,
			'core'   => isset( $wp_version ) ? (string) $wp_version : '0',
		);
	}

	/**
	 * Current installed version for a finding's (type, slug), or null when not installed.
	 *
	 * @param array{plugin: array<string,string>, theme: array<string,string>, core: string} $index
	 */
	private function installed_version_for( string $type, string $slug, array $index ): ?string {
		switch ( $type ) {
			case 'plugin':
				return $index['plugin'][ $slug ] ?? null;
			case 'theme':
				return $index['theme'][ $slug ] ?? null;
			case 'core':
				return '' !== $index['core'] ? $index['core'] : null;
			default:
				return null;
		}
	}

	private function module(): ?ThreatIntelModule {
		$m = Plugin::instance()->module( 'threatintel' );
		return $m instanceof ThreatIntelModule ? $m : null;
	}
}
