<?php
/**
 * Settings read/write endpoint.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Rest\AbstractController;
use LoyalSecurity\Core\Settings;
use LoyalSecurity\Modules\Audit\Logger;
use LoyalSecurity\Modules\Audit\EventCatalog;
use WP_REST_Request;

/**
 * Exposes the defaults-merged settings tree and accepts per-module updates. Every change
 * is recorded in the audit log.
 */
class SettingsController extends AbstractController {

	public function register_routes(): void {
		register_rest_route(
			$this->namespace(),
			'/settings',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_settings' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/settings/global',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_global' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'update_global' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/preferences/view',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_view_preference' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'update_view_preference' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/preferences/theme',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_theme_preference' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'update_theme_preference' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/settings/batch',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'batch_update' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			$this->namespace(),
			'/settings/(?P<module>[a-z0-9_-]+)',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'update_settings' ),
					'permission_callback' => array( $this, 'permission_check' ),
					'args'                => array(
						'module' => array(
							'required' => true,
							'type'     => 'string',
						),
					),
				),
			)
		);
	}

	public function get_settings( WP_REST_Request $request ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		return $this->ok( $this->without_retired_keys( $settings->all_merged() ) );
	}

	/**
	 * Settings that earlier versions defined and this version no longer uses. Values saved by an
	 * earlier version stay in the stored option (nothing is deleted) but are not shown or
	 * editable in the Settings screen.
	 *
	 * @var array<string, string[]>
	 */
	private const RETIRED_KEYS = array(
		'firewall'      => array(
			'cloudflare_token',
			'cloudflare_zone_id',
			'cloudflare_sync',
			'geo_escalation_enabled',
			'geo_escalation_threshold',
			'geo_escalation_window_hours',
			'geo_escalation_block_hours',
		),
		'scanner'       => array( 'auto_quarantine', 'scan_schedule', 'scan_schedule_enabled' ),
		'notifications' => array(
			'webhook_enabled',
			'webhook_url',
			'webhook_min_severity',
			'pagerduty_enabled',
			'pagerduty_routing_key',
			'pagerduty_min_severity',
			'opsgenie_enabled',
			'opsgenie_api_key',
			'opsgenie_min_severity',
		),
	);

	/**
	 * @param array<string, array<string, mixed>> $merged
	 * @return array<string, array<string, mixed>>
	 */
	private function without_retired_keys( array $merged ): array {
		foreach ( self::RETIRED_KEYS as $module => $keys ) {
			if ( isset( $merged[ $module ] ) ) {
				$merged[ $module ] = array_diff_key( $merged[ $module ], array_flip( $keys ) );
			}
		}
		return $merged;
	}

	/**
	 * Read plugin-wide (non-module) settings stored as standalone WP options.
	 */
	public function get_global( WP_REST_Request $request ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		return $this->ok(
			array(
				'delete_on_uninstall' => (bool) get_option( 'loyalsec_delete_on_uninstall', false ),
			)
		);
	}

	/**
	 * Persist plugin-wide settings. Only recognised keys are accepted.
	 */
	public function update_global( WP_REST_Request $request ) {
		$params = $request->get_json_params();
		if ( ! is_array( $params ) ) {
			$params = array();
		}

		if ( array_key_exists( 'delete_on_uninstall', $params ) ) {
			update_option( 'loyalsec_delete_on_uninstall', (bool) $params['delete_on_uninstall'], false );
		}

		return $this->ok(
			array(
				'delete_on_uninstall' => (bool) get_option( 'loyalsec_delete_on_uninstall', false ),
			)
		);
	}

	/** Per-admin-account (not per-site) preference — deliberately user_meta rather than a
	 *  site-wide option, so an agency operator and the site owner can each see the dashboard
	 *  at the density that suits them without fighting over one shared setting. Mirrors the
	 *  existing user_meta pattern used by the Auth modules (passkeys, trusted devices, 2FA
	 *  grace period) rather than introducing a new storage abstraction. */
	private const VIEW_META_KEY = 'loyalsec_ui_view';

	/**
	 * Read the current admin's Basic/Advanced dashboard view preference.
	 */
	public function get_view_preference() {
		$view = get_user_meta( get_current_user_id(), self::VIEW_META_KEY, true );
		return $this->ok( array( 'view' => 'basic' === $view ? 'basic' : 'advanced' ) );
	}

	/**
	 * Save the current admin's Basic/Advanced dashboard view preference.
	 */
	public function update_view_preference( WP_REST_Request $request ) {
		$view = 'basic' === $request->get_param( 'view' ) ? 'basic' : 'advanced';
		update_user_meta( get_current_user_id(), self::VIEW_META_KEY, $view );
		return $this->ok( array( 'view' => $view ) );
	}

	/** Per-admin light/dark/system display preference for the plugin UI only — independent of
	 *  both the visitor's OS setting and WordPress core's own admin color scheme, so a user can
	 *  explicitly override either of those just for this app. Same user_meta pattern as the
	 *  Basic/Advanced view preference above. */
	private const THEME_META_KEY = 'loyalsec_theme';
	private const VALID_THEMES   = array( 'system', 'light', 'dark' );

	/**
	 * Read the current admin's light/dark/system theme preference.
	 */
	public function get_theme_preference() {
		$theme = get_user_meta( get_current_user_id(), self::THEME_META_KEY, true );
		return $this->ok( array( 'theme' => in_array( $theme, self::VALID_THEMES, true ) ? $theme : 'system' ) );
	}

	/**
	 * Save the current admin's light/dark/system theme preference.
	 */
	public function update_theme_preference( WP_REST_Request $request ) {
		$theme = $request->get_param( 'theme' );
		$theme = in_array( $theme, self::VALID_THEMES, true ) ? $theme : 'system';
		update_user_meta( get_current_user_id(), self::THEME_META_KEY, $theme );
		return $this->ok( array( 'theme' => $theme ) );
	}

	/**
	 * Apply settings for multiple modules in one request.
	 *
	 * Accepts { settings: { module: { key: value } } }. Each module is validated against its
	 * known defaults (same whitelist as single-module save); unknown modules are skipped
	 * silently so the onboarding wizard never hard-fails on a missing module.
	 */
	public function batch_update( WP_REST_Request $request ) {
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		$params   = $request->get_json_params();
		$modules  = ( isset( $params['settings'] ) && is_array( $params['settings'] ) ) ? $params['settings'] : array();

		if ( empty( $modules ) ) {
			return $this->fail( 'loyalsec_empty_batch', __( 'No settings provided.', 'loyal-security' ), 422 );
		}

		$applied = array();
		foreach ( $modules as $module => $values ) {
			if ( ! is_string( $module ) || ! is_array( $values ) ) {
				continue;
			}
			$known = $settings->for_module( $module );
			if ( empty( $known ) ) {
				continue; // unknown module id — skip silently
			}
			$cleaned = array();
			foreach ( $values as $key => $value ) {
				if ( array_key_exists( $key, $known ) ) {
					$cleaned[ $key ] = $this->coerce( $known[ $key ], $value );
				}
			}
			if ( ! empty( $cleaned ) ) {
				$settings->update_module( $module, $cleaned );
				$applied[ $module ] = array_keys( $cleaned );
			}
		}

		if ( empty( $applied ) ) {
			return $this->fail( 'loyalsec_no_valid_keys', __( 'No recognised settings were provided.', 'loyal-security' ), 422 );
		}

		/** @var Logger $logger */
		$logger = $this->container->make( 'logger' );
		$logger->log( EventCatalog::SETTING_CHANGED, array( 'batch' => true, 'modules' => $applied ) );

		return $this->ok( array( 'applied' => $applied ) );
	}

	public function update_settings( WP_REST_Request $request ) {
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		$module   = (string) $request['module'];

		$values = $request->get_json_params();
		if ( ! is_array( $values ) ) {
			$values = $request->get_params();
			unset( $values['module'] );
		}

		// Only allow keys that already exist in the module's defaults (whitelist).
		$known   = $settings->for_module( $module );
		$retired = self::RETIRED_KEYS[ $module ] ?? array();
		$cleaned = array();
		foreach ( $values as $key => $value ) {
			if ( array_key_exists( $key, $known ) && ! in_array( $key, $retired, true ) ) {
				$cleaned[ $key ] = $this->coerce( $known[ $key ], $value );
			}
		}

		if ( empty( $cleaned ) ) {
			return $this->fail( 'loyalsec_no_valid_keys', __( 'No recognised settings were provided.', 'loyal-security' ), 422 );
		}

		$settings->update_module( $module, $cleaned );

		/** @var Logger $logger */
		$logger = $this->container->make( 'logger' );
		$logger->log( EventCatalog::SETTING_CHANGED, array( 'module' => $module, 'keys' => array_keys( $cleaned ) ) );

		return $this->ok( $settings->for_module( $module ) );
	}

	/**
	 * Coerce an incoming value to the type of the existing default to avoid type drift.
	 *
	 * @param mixed $current Existing value (defines target type).
	 * @param mixed $value   Incoming value.
	 * @return mixed
	 */
	private function coerce( $current, $value ) {
		if ( is_bool( $current ) ) {
			return (bool) $value;
		}
		if ( is_int( $current ) ) {
			return (int) $value;
		}
		if ( is_float( $current ) ) {
			return (float) $value;
		}
		if ( is_array( $current ) ) {
			return is_array( $value ) ? array_values( $value ) : array();
		}
		return is_scalar( $value ) ? (string) $value : '';
	}
}
