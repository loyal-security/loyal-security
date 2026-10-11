<?php
/**
 * Incident correlator — clusters audit events by attacker IP into scored incident groups.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Audit;

defined( 'ABSPATH' ) || exit;

/**
 * Threat-hunting helper. Reads the audit event stream, groups events per source IP into
 * temporal clusters, and scores each cluster so high-signal incidents float to the top.
 *
 * Pure read layer — no writes. All SQL goes through {@see \wpdb::prepare()}.
 */
class IncidentCorrelator {

	/** Hard cap on returned incident groups (keeps payloads bounded). */
	private const MAX_GROUPS = 50;

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_events';
	}

	/**
	 * Correlate recent events into scored incident groups.
	 *
	 * @param int $since_ts        Unix timestamp lower bound; 0 → last 24 hours.
	 * @param int $window_minutes  Max gap (minutes) between consecutive events in a cluster.
	 * @return array<int, array<string, mixed>> Incident groups sorted by score DESC.
	 */
	public function correlate( int $since_ts = 0, int $window_minutes = 10 ): array {
		global $wpdb;

		if ( $since_ts <= 0 ) {
			$since_ts = time() - DAY_IN_SECONDS;
		}
		$window_minutes = max( 1, $window_minutes );
		$window_seconds = $window_minutes * MINUTE_IN_SECONDS;

		$rows = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				'SELECT id, event_type, severity, ip, request_uri, context, created_at'
				. " FROM %i"
				. " WHERE created_at > %s AND ip <> ''"
				. ' ORDER BY ip ASC, created_at ASC', $this->table(),
				gmdate( 'Y-m-d H:i:s', $since_ts )
			),
			ARRAY_A
		);

		if ( empty( $rows ) ) {
			return array();
		}

		// Group rows by IP (already ordered by ip, created_at).
		$by_ip = array();
		foreach ( (array) $rows as $row ) {
			$by_ip[ (string) $row['ip'] ][] = $row;
		}

		$groups = array();
		foreach ( $by_ip as $ip => $events ) {
			$clusters = $this->cluster_events_by_ip( $events, $window_seconds );
			foreach ( $clusters as $cluster ) {
				$groups[] = $this->build_group( (string) $ip, $cluster );
			}
		}

		// Sort by score DESC, then by recency.
		usort(
			$groups,
			static function ( $a, $b ) {
				if ( $a['score'] === $b['score'] ) {
					return $b['last_event'] <=> $a['last_event'];
				}
				return $b['score'] <=> $a['score'];
			}
		);

		return array_slice( $groups, 0, self::MAX_GROUPS );
	}

	/**
	 * Split a single IP's chronologically-ordered events into temporal clusters: a new
	 * cluster starts whenever the gap to the previous event exceeds the window.
	 *
	 * @param array<int, array<string, mixed>> $events         Chronologically-ordered rows.
	 * @param int                               $window_seconds Max inter-event gap.
	 * @return array<int, array<int, array<string, mixed>>>
	 */
	private function cluster_events_by_ip( array $events, int $window_seconds ): array {
		$clusters = array();
		$current  = array();
		$prev_ts  = null;

		foreach ( $events as $event ) {
			$ts = strtotime( (string) ( $event['created_at'] ?? '' ) . ' UTC' );
			$ts = false === $ts ? 0 : $ts;

			if ( null !== $prev_ts && ( $ts - $prev_ts ) > $window_seconds ) {
				if ( $current ) {
					$clusters[] = $current;
				}
				$current = array();
			}

			$current[] = $event;
			$prev_ts   = $ts;
		}

		if ( $current ) {
			$clusters[] = $current;
		}

		return $clusters;
	}

	/**
	 * Score a cluster by event type and severity.
	 *
	 * @param array<int, array<string, mixed>> $events Cluster rows.
	 */
	private function score_group( array $events ): int {
		$score = 0;

		foreach ( $events as $event ) {
			$type     = (string) ( $event['event_type'] ?? '' );
			$severity = (int) ( $event['severity'] ?? 0 );

			// Type-based weighting.
			if ( EventCatalog::WAF_BRUTEFORCE === $type ) {
				$score += 20;
			} elseif ( EventCatalog::SCAN_FINDING === $type ) {
				$score += 30;
			} elseif ( EventCatalog::LOGIN_FAILED === $type ) {
				$score += 15;
			} elseif ( str_starts_with( $type, 'waf.' ) ) {
				$score += 10; // Any other WAF block-class event.
			}

			// Severity-based weighting.
			if ( EventCatalog::SEV_CRITICAL === $severity ) {
				$score += 25;
			} elseif ( EventCatalog::SEV_WARNING === $severity ) {
				$score += 10;
			}
		}

		/**
		 * Filter the computed incident score for a cluster.
		 *
		 * @since 1.0.0
		 *
		 * @param int                               $score  Computed score.
		 * @param array<int, array<string, mixed>>  $events Cluster rows.
		 */
		return (int) apply_filters( 'loyalsec_incident_score', $score, $events );
	}

	/**
	 * Assemble the public incident-group shape from a cluster of rows.
	 *
	 * @param string                            $ip      Source IP.
	 * @param array<int, array<string, mixed>>  $cluster Cluster rows (chronological).
	 * @return array<string, mixed>
	 */
	private function build_group( string $ip, array $cluster ): array {
		$first      = $cluster[0];
		$last       = $cluster[ count( $cluster ) - 1 ];
		$first_ts   = (string) ( $first['created_at'] ?? '' );
		$last_ts    = (string) ( $last['created_at'] ?? '' );
		$score      = $this->score_group( $cluster );

		$country     = null;
		$event_types = array();
		$events      = array();

		foreach ( $cluster as $row ) {
			$type          = (string) ( $row['event_type'] ?? '' );
			$event_types[] = $type;

			if ( null === $country ) {
				$ctx = json_decode( (string) ( $row['context'] ?? '' ), true );
				if ( is_array( $ctx ) && ! empty( $ctx['country'] ) ) {
					$country = (string) $ctx['country'];
				}
			}

			$events[] = array(
				'id'         => (int) ( $row['id'] ?? 0 ),
				'event_type' => $type,
				'severity'   => (int) ( $row['severity'] ?? 0 ),
				'request_uri' => (string) ( $row['request_uri'] ?? '' ),
				'created_at' => (string) ( $row['created_at'] ?? '' ),
			);
		}

		$event_types = array_values( array_unique( $event_types ) );

		return array(
			'id'          => sha1( $ip . '.' . $first_ts ),
			'ip'          => $ip,
			'country'     => $country,
			'score'       => $score,
			'severity'    => $this->severity_band( $score ),
			'first_event' => $first_ts,
			'last_event'  => $last_ts,
			'events'      => $events,
			'event_count' => count( $cluster ),
			'event_types' => $event_types,
		);
	}

	/**
	 * Map a numeric score to a coarse severity band.
	 */
	private function severity_band( int $score ): string {
		if ( $score >= 60 ) {
			return 'critical';
		}
		if ( $score >= 25 ) {
			return 'warning';
		}
		return 'notice';
	}
}
