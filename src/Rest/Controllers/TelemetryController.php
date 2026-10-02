<?php
/**
 * Bypass-telemetry REST controller — consent + transparency.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Telemetry\BypassReporter;
use WP_REST_Request;

/**
 * Surfaces the GDPR consent state, records opt-in/opt-out (the auditable consent record), and
 * exposes a fully-redacted sample report so admins can see exactly what would be transmitted.
 */
class TelemetryController extends AbstractController {

	/** Bump when the consent wording / data practices change, to force re-consent. */
	public const POLICY_VERSION = 1;

	private const CONSENT_OPTION = 'totalsecwp_telemetry_consent';

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route(
			$ns,
			'/telemetry/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'status' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/telemetry/consent',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'consent' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/telemetry/sample',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'sample' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);
	}

	/**
	 * Current consent + preference state.
	 */
	public function status( WP_REST_Request $request ) {
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		$consent  = $this->consent_record();

		return $this->ok(
			array(
				'consent_given'      => (bool) $consent['given'],
				'consent_timestamp'  => (int) $consent['timestamp'],
				'consent_version'    => (int) $consent['version'],
				'policy_version'     => self::POLICY_VERSION,
				'needs_consent'      => $this->needs_consent( $consent ),
				'install_id'         => BypassReporter::install_id(),
				'has_secret'         => '' !== (string) get_option( 'totalsecwp_telemetry_secret', '' ),
				'share_attacker_ip'  => (bool) $settings->get( 'telemetry', 'share_attacker_ip', true ),
				'near_miss_capture'  => (bool) $settings->get( 'telemetry', 'near_miss_capture', true ),
				'max_reports_per_day' => (int) $settings->get( 'telemetry', 'max_reports_per_day', 20 ),
			)
		);
	}

	/**
	 * Record consent (accept or withdraw) and any preference toggles.
	 */
	public function consent( WP_REST_Request $request ) {
		$accepted = (bool) $request->get_param( 'accepted' );

		update_option(
			self::CONSENT_OPTION,
			array(
				'given'     => $accepted,
				'timestamp' => time(),
				'version'   => self::POLICY_VERSION,
				'user_id'   => get_current_user_id(),
			),
			false
		);

		// Optional preference toggles passed alongside consent.
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		$prefs    = array();
		if ( null !== $request->get_param( 'share_attacker_ip' ) ) {
			$prefs['share_attacker_ip'] = (bool) $request->get_param( 'share_attacker_ip' );
		}
		if ( null !== $request->get_param( 'near_miss_capture' ) ) {
			$prefs['near_miss_capture'] = (bool) $request->get_param( 'near_miss_capture' );
		}
		if ( $prefs ) {
			$settings->update_module( 'telemetry', $prefs );
		}

		// Auditable consent record.
		$this->container->make( 'logger' )->log(
			EventCatalog::TELEMETRY_CONSENT_CHANGED,
			array(
				'given'   => $accepted,
				'version' => self::POLICY_VERSION,
			)
		);

		// Register with LicenseKit immediately on opt-in, rather than waiting for a real bypass
		// event to trigger the next cron flush — a quiet site would otherwise never be recognized.
		// `force` (used by the dashboard's explicit "Grant consent & register" recovery action)
		// discards any existing local secret first, since otherwise a stale/orphaned secret
		// (e.g. the server-side record was lost) makes every retry a silent no-op forever.
		$registered = false;
		if ( $accepted ) {
			$force      = (bool) $request->get_param( 'force' );
			$registered = ( new BypassReporter( $settings ) )->register_now( $force );
		}

		return $this->ok(
			array(
				'consent_given' => $accepted,
				'needs_consent' => false,
				'registered'    => $registered,
			)
		);
	}

	/**
	 * A real, fully-redacted example of what a report looks like (nothing is sent).
	 */
	public function sample( WP_REST_Request $request ) {
		/** @var Settings $settings */
		$settings = $this->container->make( 'settings' );
		return $this->ok( ( new BypassReporter( $settings ) )->sample() );
	}

	/* ------------------------------------------------------------------ */

	/**
	 * @return array{given:bool,timestamp:int,version:int,user_id:int}
	 */
	private function consent_record(): array {
		$raw = get_option( self::CONSENT_OPTION, array() );
		return array(
			'given'     => (bool) ( $raw['given'] ?? false ),
			'timestamp' => (int) ( $raw['timestamp'] ?? 0 ),
			'version'   => (int) ( $raw['version'] ?? 0 ),
			'user_id'   => (int) ( $raw['user_id'] ?? 0 ),
		);
	}

	/**
	 * True when we should (re-)prompt: never answered, or answered against an older policy.
	 *
	 * @param array{given:bool,timestamp:int,version:int,user_id:int} $consent
	 */
	private function needs_consent( array $consent ): bool {
		if ( $consent['timestamp'] <= 0 ) {
			return true; // never answered.
		}
		return $consent['version'] < self::POLICY_VERSION; // policy changed since last answer.
	}
}
