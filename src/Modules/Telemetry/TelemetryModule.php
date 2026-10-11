<?php
/**
 * Bypass-telemetry module — anonymous, opt-in reporting of firewall bypasses.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Telemetry;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\AbstractModule;
use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Waf\Decision;
use LoyalSecurity\Waf\RequestContext;

/**
 * When an attack is *confirmed* to have slipped past the firewall (malware found, core file
 * tampered, or an unexpected admin user created — all while the firewall was enabled), this
 * module reconstructs and anonymizes the originating request and ships it to the LicenseKit
 * backend so a new signature can be authored and pushed to every install.
 *
 * Strictly opt-in: nothing is captured or transmitted until the admin records GDPR consent.
 * Decoupled from other modules — it subscribes to the audit event stream and a single firewall
 * action rather than calling any module directly.
 */
class TelemetryModule extends AbstractModule {

	private const FLUSH_HOOK = 'loyalsec_telemetry_flush';

	/** Compromise events that may indicate a firewall bypass. */
	private const TRIGGERS = array(
		EventCatalog::SCAN_FINDING,
		EventCatalog::INTEGRITY_CHANGED,
		EventCatalog::USER_ADMIN_CREATED,
	);

	/** Triggers that also fire on legitimate admin activity — only report when corroborated. */
	private const NEEDS_CORROBORATION = array(
		EventCatalog::USER_ADMIN_CREATED,
	);

	public function id(): string {
		return 'telemetry';
	}

	public function title(): string {
		return __( 'Bypass Telemetry', 'loyal-security' );
	}

	/**
	 * @return array<string,mixed>
	 */
	public function default_settings(): array {
		return array(
			'enabled'             => true,  // module on; sending still requires consent.
			'share_attacker_ip'   => true,  // include attacker IPs (hashed when off).
			'near_miss_capture'   => true,  // record allowed-but-suspicious requests.
			'max_reports_per_day' => 20,    // outbound rate limit.
			'lookback_seconds'    => 3600,  // correlation window before the artifact.
		);
	}

	public function register_hooks(): void {
		// Cheap to attach; the handlers gate on consent + firewall state before doing work.
		add_action( 'loyalsec_event_logged', array( $this, 'on_event_logged' ), 20, 3 );
		add_action( self::FLUSH_HOOK, array( $this, 'flush' ) );
	}

	public function boot(): void {
		// Near-miss capture only runs once the admin has consented — no consent, no data at rest.
		if ( self::consent() && (bool) $this->setting( 'near_miss_capture', true ) ) {
			add_action( 'loyalsec_waf_near_miss', array( $this, 'on_near_miss' ), 10, 2 );
		}

		if ( ! wp_next_scheduled( self::FLUSH_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::FLUSH_HOOK );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Handlers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Record an allowed-but-suspicious request snapshot (already anonymized inside the buffer).
	 *
	 * @param RequestContext $req
	 * @param Decision       $decision
	 */
	public function on_near_miss( $req, $decision ): void {
		if ( ! ( $req instanceof RequestContext ) || ! ( $decision instanceof Decision ) ) {
			return;
		}
		( new NearMissBuffer() )->capture( $req, $decision );
	}

	/**
	 * Inspect every logged event; on a confirmed-compromise trigger, correlate + queue a report.
	 *
	 * @param string              $type EventCatalog type.
	 * @param array<string,mixed> $data Logged event row.
	 * @param int                 $id   Inserted row id.
	 */
	public function on_event_logged( string $type, $data, $id = 0 ): void {
		if ( ! in_array( $type, self::TRIGGERS, true ) ) {
			return;
		}
		if ( ! self::consent() ) {
			return;
		}
		// A bypass is only meaningful if the firewall was actually on.
		if ( ! (bool) $this->settings()->get( 'firewall', 'enabled', true ) ) {
			return;
		}
		$data = is_array( $data ) ? $data : array();

		// Only act on a *confirmed* malware finding (critical), not low-score heuristics.
		if ( EventCatalog::SCAN_FINDING === $type && ! $this->is_critical_finding( $data ) ) {
			return;
		}

		try {
			$lookback  = max( 300, (int) $this->setting( 'lookback_seconds', 3600 ) );
			$fragment  = ( new BypassCorrelator( $lookback ) )->correlate( $type, $data );

			// Events that also occur during normal admin work (e.g. an admin legitimately
			// creating another admin) are only a bypass signal when corroborated by attack
			// evidence — a correlated malicious request or a scored incident cluster. Without
			// that, stay silent so routine administration never generates a report.
			if ( in_array( $type, self::NEEDS_CORROBORATION, true ) ) {
				$corroborated = ! empty( $fragment['web_vector_evidence'] ) || ! empty( $fragment['related_incident'] );
				if ( ! $corroborated ) {
					return;
				}
			}

			$reporter = new BypassReporter( $this->settings() );

			if ( $reporter->queue( $fragment ) ) {
				$this->logger()->log(
					EventCatalog::TELEMETRY_REPORT_QUEUED,
					array(
						'trigger'    => $type,
						'confidence' => (string) ( $fragment['confidence'] ?? '' ),
						'web_vector' => (bool) ( $fragment['web_vector_evidence'] ?? false ),
					)
				);
			}
		} catch ( \Throwable $e ) {
			// Telemetry must never disrupt the host. Swallow and move on.
			unset( $e );
		}
	}

	/**
	 * Cron: drain the report queue and emit a single sent event when anything went out.
	 */
	public function flush(): void {
		if ( ! self::consent() ) {
			return;
		}
		try {
			$sent = ( new BypassReporter( $this->settings() ) )->flush();
			if ( $sent > 0 ) {
				$this->logger()->log( EventCatalog::TELEMETRY_REPORT_SENT, array( 'count' => $sent ) );
			}
		} catch ( \Throwable $e ) {
			unset( $e );
		}
	}

	/* ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed> $data
	 */
	private function is_critical_finding( array $data ): bool {
		if ( (int) ( $data['severity'] ?? 0 ) >= EventCatalog::SEV_CRITICAL ) {
			return true;
		}
		$ctx = $data['context'] ?? array();
		if ( is_string( $ctx ) ) {
			$ctx = json_decode( $ctx, true );
		}
		return is_array( $ctx ) && (int) ( $ctx['score'] ?? 0 ) >= 30;
	}

	public static function consent(): bool {
		return BypassReporter::consent_given();
	}
}
