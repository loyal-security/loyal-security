<?php
/**
 * CSP Manager REST controller.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Modules\Csp\CspModule;
use TotalSecurityWP\Modules\Csp\CspPolicy;
use TotalSecurityWP\Modules\Csp\CspNonce;
use TotalSecurityWP\Modules\Csp\CspPendingStore;
use TotalSecurityWP\Modules\Csp\CspViolationStore;
use TotalSecurityWP\Plugin;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

/**
 * Endpoints:
 *   GET    /csp/policy           — return current settings + compiled header preview + presets list.
 *   POST   /csp/policy           — save settings.
 *   GET    /csp/presets          — list all available presets (label, icon).
 *   POST   /csp/scan             — trigger a frontend resource scan; returns domains + suggested presets.
 *   GET    /csp/scan             — return last cached scan result.
 *   POST   /csp/report           — CSP violation report receiver (public, no auth).
 *   GET    /csp/violations       — list violation reports, grouped + filterable + paginated.
 *   DELETE /csp/violations       — clear the violation log.
 *   POST   /csp/violations/allow — add a violation's blocked source directly into the active policy.
 */
class CspController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route( $ns, '/csp/policy', array(
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_policy' ),
				'permission_callback' => array( $this, 'permission_check' ),
			),
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'save_policy' ),
				'permission_callback' => array( $this, 'permission_check' ),
			),
		) );

		register_rest_route( $ns, '/csp/presets', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'get_presets' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/csp/scan', array(
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_scan' ),
				'permission_callback' => array( $this, 'permission_check' ),
			),
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'run_scan' ),
				'permission_callback' => array( $this, 'permission_check' ),
			),
		) );

		// Public — browsers POST CSP violation reports here without auth.
		register_rest_route( $ns, '/csp/report', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'receive_report' ),
			'permission_callback' => '__return_true',
		) );

		register_rest_route( $ns, '/csp/violations', array(
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_violations' ),
				'permission_callback' => array( $this, 'permission_check' ),
			),
			array(
				'methods'             => 'DELETE',
				'callback'            => array( $this, 'clear_violations' ),
				'permission_callback' => array( $this, 'permission_check' ),
			),
		) );

		register_rest_route( $ns, '/csp/violations/allow', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'allow_violation' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		// Pending-domain learning system endpoints.
		register_rest_route( $ns, '/csp/pending', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'get_pending' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/csp/pending/approve', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'approve_pending' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/csp/pending/dismiss', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'dismiss_pending' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		register_rest_route( $ns, '/csp/pending/clear', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'clear_pending' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );

		// Codebase (PHP/JS file) scan — separate from the HTML page scan.
		register_rest_route( $ns, '/csp/codebase-scan', array(
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_codebase_scan' ),
				'permission_callback' => array( $this, 'permission_check' ),
			),
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'run_codebase_scan' ),
				'permission_callback' => array( $this, 'permission_check' ),
			),
		) );
	}

	/* ------------------------------------------------------------------ */
	/* Handlers                                                             */
	/* ------------------------------------------------------------------ */

	/** Standalone option (not folded into the Settings blob — same reasoning as
	 *  UnderAttackMode's options: cheap to read every request, and Settings has no
	 *  built-in change-history for us to derive this from otherwise). */
	private const MODE_CHANGED_AT_OPTION = 'totalsecwp_csp_mode_changed_at';

	/** Days in Report-Only, with zero admin action required, before we suggest Enforce —
	 *  matches Wordfence's default Learning Mode window. */
	private const READY_TO_ENFORCE_DAYS = 7;

	/** CSP3 fetch directives this policy never defines explicitly, mapped to the ancestor
	 *  directive it does — see the comment in allow_violation() for why this mapping exists. */
	private const DIRECTIVE_FALLBACK = array(
		'script-src-elem' => 'script-src',
		'script-src-attr' => 'script-src',
		'style-src-elem'  => 'style-src',
		'style-src-attr'  => 'style-src',
	);

	public function get_policy(): WP_REST_Response {
		$module   = $this->csp_module();
		$settings = $this->container->make( 'settings' );
		$mode     = (string) $settings->get( 'csp', 'mode', 'report-only' );

		$changed_at        = (int) get_option( self::MODE_CHANGED_AT_OPTION, 0 );
		$days_in_mode       = $changed_at ? (int) floor( ( time() - $changed_at ) / DAY_IN_SECONDS ) : null;
		$violations_since   = $changed_at ? ( new CspViolationStore() )->count_since( $changed_at ) : null;
		$ready_to_enforce    = 'report-only' === $mode && null !== $days_in_mode && $days_in_mode >= self::READY_TO_ENFORCE_DAYS;

		return $this->ok( array(
			'enabled'                    => (bool) $settings->get( 'csp', 'enabled', false ),
			'mode'                       => $mode,
			'presets'                    => (array) $settings->get( 'csp', 'presets', array() ),
			'custom_directives'          => (array) $settings->get( 'csp', 'custom_directives', array() ),
			'violations_log'             => (bool) $settings->get( 'csp', 'violations_log', true ),
			'nonce_protect_inline'       => (bool) $settings->get( 'csp', 'nonce_protect_inline', false ),
			'strict_eval'                => (bool) $settings->get( 'csp', 'strict_eval', false ),
			'preview'                    => $module ? $module->build_policy() : '',
			'presets_list'               => CspPolicy::presets_list(),
			'report_uri'                 => rest_url( TOTALSECWP_REST_NAMESPACE . '/csp/report' ),
			'mode_changed_at'            => $changed_at ?: null,
			'days_in_current_mode'       => $days_in_mode,
			'violations_since_mode_change' => $violations_since,
			'ready_to_enforce'           => $ready_to_enforce,
			'ready_to_enforce_days'      => self::READY_TO_ENFORCE_DAYS,
		) );
	}

	public function save_policy( WP_REST_Request $request ): WP_REST_Response {
		$settings = $this->container->make( 'settings' );

		$enabled  = (bool) $request->get_param( 'enabled' );
		$mode     = in_array( $request->get_param( 'mode' ), array( 'enforce', 'report-only' ), true )
			? $request->get_param( 'mode' ) : 'report-only';

		// Only stamp the change-timestamp when the effective mode actually moves (Off counts
		// as its own state here) — a re-save with the same mode (e.g. toggling a preset) must
		// not reset the "days in this mode" clock.
		$previous_mode      = (string) $settings->get( 'csp', 'mode', 'report-only' );
		$previous_enabled   = (bool) $settings->get( 'csp', 'enabled', false );
		$previous_effective = $previous_enabled ? $previous_mode : 'off';
		$next_effective     = $enabled ? $mode : 'off';
		if ( $next_effective !== $previous_effective ) {
			update_option( self::MODE_CHANGED_AT_OPTION, time(), false );
		}
		$presets      = array_map( 'sanitize_key', (array) ( $request->get_param( 'presets' ) ?? array() ) );
		$vlog         = (bool) ( $request->get_param( 'violations_log' ) ?? true );
		$nonce_inline = (bool) ( $request->get_param( 'nonce_protect_inline' ) ?? false );
		$strict_eval  = (bool) ( $request->get_param( 'strict_eval' ) ?? false );

		// Sanitise custom directives: directive-name → array of source values.
		$raw_custom    = (array) ( $request->get_param( 'custom_directives' ) ?? array() );
		$clean_custom  = array();
		foreach ( $raw_custom as $directive => $values ) {
			$directive = sanitize_key( (string) $directive );
			if ( $directive ) {
				$clean_custom[ $directive ] = array_map( 'sanitize_text_field', (array) $values );
			}
		}

		$settings->update_module( 'csp', array(
			'enabled'              => $enabled,
			'mode'                 => $mode,
			'presets'              => $presets,
			'custom_directives'    => $clean_custom,
			'violations_log'       => $vlog,
			'nonce_protect_inline' => $nonce_inline,
			'strict_eval'          => $strict_eval,
		) );

		$preview = CspPolicy::build(
			array(
				'presets'           => $presets,
				'custom_directives' => $clean_custom,
			),
			$nonce_inline ? CspNonce::value() : '',
			$strict_eval
		);

		return $this->ok( array( 'saved' => true, 'preview' => $preview ) );
	}

	public function get_presets(): WP_REST_Response {
		return $this->ok( array( 'presets' => CspPolicy::presets_list() ) );
	}

	/** Trigger a fresh site scan (may take a few seconds). */
	public function run_scan(): WP_REST_Response|WP_Error {
		$module = $this->csp_module();
		if ( ! $module ) {
			return $this->fail( 'module_missing', __( 'CSP module not loaded.', 'loyal-security' ), 503 );
		}
		$result = $module->scanner()->scan();
		return $this->ok( $result );
	}

	/** Return the most recently cached scan result (or null). */
	public function get_scan(): WP_REST_Response {
		$module = $this->csp_module();
		if ( ! $module ) {
			return $this->ok( null );
		}
		return $this->ok( $module->scanner()->get_cached() );
	}

	/**
	 * Public: receive a browser-posted CSP violation report (JSON).
	 * Supports both the older report-uri format and the newer Reporting API format.
	 * Also feeds external domains into the pending-review store.
	 */
	public function receive_report( WP_REST_Request $request ): WP_REST_Response {
		$body = (string) $request->get_body();
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return new WP_REST_Response( null, 204 );
		}

		// The classic CSP report-uri format wraps the report in 'csp-report'.
		$report = $data['csp-report'] ?? $data;

		$blocked   = sanitize_text_field( (string) ( $report['blocked-uri'] ?? $report['blockedURL'] ?? '' ) );
		$directive = sanitize_text_field( (string) ( $report['violated-directive'] ?? $report['effectiveDirective'] ?? '' ) );
		$doc_uri   = esc_url_raw( (string) ( $report['document-uri'] ?? $report['documentURL'] ?? '' ) );

		if ( ! $blocked && ! $directive ) {
			return new WP_REST_Response( null, 204 );
		}

		// `violated-directive` (the older report-uri format) can come back with the matched
		// source list appended, e.g. "script-src 'self' https://example.com" — strip that down
		// to the bare directive name so grouping/filtering/display all key on the same value.
		$dir_name = (string) strtok( $directive, ' ' );

		// Record into the grouped violations log (for the Violations tab). Repeat hits on the
		// same (directive, blocked-uri) bump a counter rather than adding a row per report.
		( new CspViolationStore() )->record(
			$dir_name,
			$blocked,
			$doc_uri,
			esc_url_raw( (string) ( $report['referrer'] ?? '' ) )
		);

		// URI-scheme keywords (blob, data, etc.) are not hostnames but they may indicate
		// that a core WordPress preset directive is missing.  Map them to the wordpress
		// preset rather than silently discarding them.
		$scheme_to_preset = array(
			'blob'   => 'wordpress', // worker-src / img-src blob: → wordpress preset
			'data'   => 'wordpress', // font-src / img-src data:  → wordpress preset
		);

		$truly_inline = array( 'eval', 'inline', 'wasm-eval', 'wasm-unsafe-eval', 'unsafe-inline', 'unsafe-eval', 'self', 'none' );

		if ( $blocked && $dir_name && ! in_array( $blocked, $truly_inline, true ) ) {
			$store = new CspPendingStore();

			if ( isset( $scheme_to_preset[ $blocked ] ) ) {
				// Scheme violation: use a synthetic key like "blob: (worker-src)" so the admin
				// can see it and the system can suggest the right preset.
				$synthetic = $blocked . ': (' . $dir_name . ')';
				$preset    = $scheme_to_preset[ $blocked ];
				$is_new    = $store->record( $synthetic, $dir_name );

				if ( $is_new ) {
					// Force the preset hint so the pending review always shows the right button.
					$store->set_preset_hint( $synthetic, $preset );
				}
			} elseif ( str_contains( $blocked, '.' ) ) {
				$domain   = (string) ( wp_parse_url( $blocked, PHP_URL_HOST ) ?: '' );
				$own_host = (string) ( wp_parse_url( home_url(), PHP_URL_HOST ) ?: '' );

				if ( $domain && $domain !== $own_host ) {
					$store->record( $domain, $dir_name );
				}
			}
		}

		return new WP_REST_Response( null, 204 );
	}

	/** Return CSP violations (grouped, filterable, paginated), most recently seen first. */
	public function get_violations( WP_REST_Request $request ): WP_REST_Response {
		$store  = new CspViolationStore();
		$result = $store->query( array(
			'directive' => sanitize_key( (string) ( $request->get_param( 'directive' ) ?? '' ) ),
			'search'    => sanitize_text_field( (string) ( $request->get_param( 'search' ) ?? '' ) ),
			'page'      => (int) ( $request->get_param( 'page' ) ?: 1 ),
			'per_page'  => (int) ( $request->get_param( 'per_page' ) ?: 50 ),
		) );

		// Map DB columns to the shape the panel already renders (ts = last_seen).
		$result['items'] = array_map(
			static function ( array $row ): array {
				return array(
					'id'         => (int) $row['id'],
					'ts'         => strtotime( $row['last_seen'] . ' UTC' ) ?: 0,
					'first_seen' => strtotime( $row['first_seen'] . ' UTC' ) ?: 0,
					'directive'  => $row['directive'],
					'blocked'    => $row['blocked_uri'],
					'doc_uri'    => $row['doc_uri'],
					'hits'       => (int) $row['hits'],
				);
			},
			$result['items']
		);
		$result['directives'] = $store->distinct_directives();

		return $this->ok( $result );
	}

	/** Clear the violation log entirely. */
	public function clear_violations(): WP_REST_Response {
		( new CspViolationStore() )->clear();
		return $this->ok( array( 'cleared' => true ) );
	}

	/**
	 * Add a violation's blocked source directly into the active CSP policy — either by
	 * enabling a matched preset, or by adding the literal value/domain to custom_directives.
	 *
	 * Body params:
	 *   id (int) — violation row id (from GET /csp/violations).
	 */
	public function allow_violation( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$id = (int) $request->get_param( 'id' );
		if ( ! $id ) {
			return $this->fail( 'invalid_id', __( 'id is required.', 'loyal-security' ), 400 );
		}

		$row = ( new CspViolationStore() )->get( $id );
		if ( ! $row ) {
			return $this->fail( 'not_found', __( 'Violation not found.', 'loyal-security' ), 404 );
		}

		$directive = (string) $row['directive']; // already a bare directive name — see receive_report()
		$blocked   = (string) $row['blocked_uri'];

		// Browsers report violations against the specific CSP3 fetch directive that actually
		// governs the resource (e.g. `script-src-elem` for a <script> tag), which this policy
		// never defines explicitly — only its broader ancestor (`script-src`) is. Per spec, a
		// directive that IS explicitly present is authoritative on its own and does NOT fall
		// back to the ancestor for anything else. Writing the violation's exact reported
		// directive straight into custom_directives would therefore create a brand-new
		// top-level directive containing only the one approved source — silently dropping
		// 'self'/'unsafe-inline'/'unsafe-eval' and blocking every other script or style on the
		// site. Normalise to the ancestor this policy actually defines so "Add to CSP" only
		// ever extends an existing baseline, never creates an orphan one.
		$directive = self::DIRECTIVE_FALLBACK[ $directive ] ?? $directive;

		// Keyword violations (report as the bare token, no quotes) map to their quoted CSP form.
		$keyword_map = array(
			'unsafe-inline'    => "'unsafe-inline'",
			'unsafe-eval'      => "'unsafe-eval'",
			'inline'           => "'unsafe-inline'",
			'eval'             => "'unsafe-eval'",
			'wasm-eval'        => "'wasm-unsafe-eval'",
			'wasm-unsafe-eval' => "'wasm-unsafe-eval'",
		);
		// Scheme violations (blob:, data:) map straight onto the literal scheme token.
		$scheme_map = array(
			'blob' => 'blob:',
			'data' => 'data:',
		);

		$settings = $this->container->make( 'settings' );

		if ( isset( $keyword_map[ $blocked ] ) ) {
			$value = $keyword_map[ $blocked ];
		} elseif ( isset( $scheme_map[ $blocked ] ) ) {
			$value = $scheme_map[ $blocked ];
		} elseif ( str_contains( $blocked, '.' ) ) {
			$domain = (string) ( wp_parse_url( $blocked, PHP_URL_HOST ) ?: $blocked );
			$preset = ( new CspPendingStore() )->find_preset( $domain );

			if ( $preset ) {
				$existing = (array) $settings->get( 'csp', 'presets', array() );
				if ( ! in_array( $preset, $existing, true ) ) {
					$settings->set( 'csp', 'presets', array_merge( $existing, array( $preset ) ) );
				}
				return $this->ok( array( 'applied' => 'preset', 'preset' => $preset ) );
			}
			$value = $domain;
		} else {
			return $this->fail(
				'not_allowlistable',
				__( 'This violation has no source that can be added automatically — use Custom Sources instead.', 'loyal-security' ),
				400
			);
		}

		$custom = (array) $settings->get( 'csp', 'custom_directives', array() );
		if ( ! isset( $custom[ $directive ] ) || ! is_array( $custom[ $directive ] ) ) {
			$custom[ $directive ] = array();
		}
		if ( ! in_array( $value, $custom[ $directive ], true ) ) {
			$custom[ $directive ][] = $value;
		}
		$settings->set( 'csp', 'custom_directives', $custom );

		return $this->ok( array( 'applied' => 'custom', 'directive' => $directive, 'value' => $value ) );
	}

	/* ------------------------------------------------------------------ */
	/* Pending-domain learning system                                       */
	/* ------------------------------------------------------------------ */

	/** List all pending (unreviewed) domains. */
	public function get_pending(): WP_REST_Response {
		$store = new CspPendingStore();
		$items = $store->get_pending();
		return $this->ok( array(
			'items' => $items,
			'total' => count( $items ),
		) );
	}

	/**
	 * Approve a pending domain and write it into the active CSP policy.
	 *
	 * Body params:
	 *   domain  (string)          – hostname to approve.
	 *   action  ('preset'|'custom') – 'preset' enables the matched preset; 'custom' adds
	 *                                 the domain directly to custom_directives.
	 *   preset  (string, optional) – preset slug; required when action = 'preset'.
	 */
	public function approve_pending( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$domain = sanitize_text_field( (string) ( $request->get_param( 'domain' ) ?? '' ) );
		$action = in_array( $request->get_param( 'action' ), array( 'preset', 'custom' ), true )
			? (string) $request->get_param( 'action' ) : 'custom';
		$preset = sanitize_key( (string) ( $request->get_param( 'preset' ) ?? '' ) );

		if ( ! $domain ) {
			return $this->fail( 'invalid_domain', __( 'domain is required.', 'loyal-security' ), 400 );
		}

		$store = new CspPendingStore();
		$entry = $store->get_entry( $domain );

		$settings = $this->container->make( 'settings' );

		if ( 'preset' === $action && $preset ) {
			// Enable the named preset in the CSP policy.
			$existing = (array) $settings->get( 'csp', 'presets', array() );
			if ( ! in_array( $preset, $existing, true ) ) {
				$settings->set( 'csp', 'presets', array_merge( $existing, array( $preset ) ) );
			}
		} else {
			// Add the domain directly to custom_directives for each affected directive.
			$directives = $entry ? (array) ( $entry['directives'] ?? array() ) : array( 'default-src' );
			$custom     = (array) $settings->get( 'csp', 'custom_directives', array() );
			foreach ( $directives as $dir ) {
				// Normalise in case older entries stored full directive values.
				$dir = (string) strtok( (string) $dir, ' ' );
				if ( ! isset( $custom[ $dir ] ) || ! is_array( $custom[ $dir ] ) ) {
					$custom[ $dir ] = array();
				}
				if ( ! in_array( $domain, $custom[ $dir ], true ) ) {
					$custom[ $dir ][] = $domain;
				}
			}
			$settings->set( 'csp', 'custom_directives', $custom );
		}

		$store->approve( $domain );
		return $this->ok( array( 'approved' => true, 'domain' => $domain ) );
	}

	/** Dismiss a pending domain (mark as intentionally blocked / not needed). */
	public function dismiss_pending( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$domain = sanitize_text_field( (string) ( $request->get_param( 'domain' ) ?? '' ) );
		if ( ! $domain ) {
			return $this->fail( 'invalid_domain', __( 'domain is required.', 'loyal-security' ), 400 );
		}
		( new CspPendingStore() )->dismiss( $domain );
		return $this->ok( array( 'dismissed' => true, 'domain' => $domain ) );
	}

	/** Clear the entire pending store. */
	public function clear_pending(): WP_REST_Response {
		( new CspPendingStore() )->clear();
		return $this->ok( array( 'cleared' => true ) );
	}

	/* ------------------------------------------------------------------ */
	/* Codebase scan                                                        */
	/* ------------------------------------------------------------------ */

	/** Return the last cached codebase scan result (or null). */
	public function get_codebase_scan(): WP_REST_Response {
		$module = $this->csp_module();
		if ( ! $module ) {
			return $this->ok( null );
		}
		return $this->ok( $module->scanner()->get_cached_codebase() );
	}

	/** Run a fresh codebase (PHP / JS file) scan. May take 10–30 seconds on large sites. */
	public function run_codebase_scan(): WP_REST_Response|WP_Error {
		$module = $this->csp_module();
		if ( ! $module ) {
			return $this->fail( 'module_missing', __( 'CSP module not loaded.', 'loyal-security' ), 503 );
		}
		$result = $module->scanner()->scan_codebase();
		return $this->ok( $result );
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                              */
	/* ------------------------------------------------------------------ */

	private function csp_module(): ?CspModule {
		$module = Plugin::instance()->module( 'csp' );
		return ( $module instanceof CspModule ) ? $module : null;
	}

	private function empty_policy(): array {
		return array(
			'enabled'           => false,
			'mode'              => 'report-only',
			'presets'           => array(),
			'custom_directives' => array(),
			'violations_log'    => true,
			'nonce_protect_inline' => false,
			'strict_eval'          => false,
			'preview'           => '',
			'presets_list'      => CspPolicy::presets_list(),
			'report_uri'        => rest_url( TOTALSECWP_REST_NAMESPACE . '/csp/report' ),
		);
	}
}
