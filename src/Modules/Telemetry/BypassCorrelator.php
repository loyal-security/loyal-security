<?php
/**
 * Bypass correlator — links a confirmed compromise back to the request that likely caused it.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Telemetry;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Modules\Audit\IncidentCorrelator;
use LoyalSecurity\Modules\Traffic\TrafficBuffer;

/**
 * The piece the rest of the plugin does not do: scan/integrity findings and the HTTP requests
 * that planted them live in separate stores with no foreign key between them. Given a confirmed
 * compromise event, this class reconstructs the most likely originating request(s) and grades
 * how confident the link is.
 *
 * Strategy, best signal first:
 *   1. {@see NearMissBuffer} — requests the WAF allowed but scored on (the actual bypass payload).
 *   2. {@see TrafficBuffer}  — recent request metadata (Live Traffic capture), URI-level only.
 *   3. {@see IncidentCorrelator} — clustered attacker activity from the audit event stream.
 *
 * All site-owner PII is already removed by the Redactor at capture time (near-miss) or here
 * (traffic/events). Attacker IPs are preserved for the backend; the Reporter applies the
 * share-attacker-ip policy as the final step.
 */
class BypassCorrelator {

	/** Default look-back window before the artifact's creation (seconds). */
	private const LOOKBACK = 3600;

	private int $lookback;

	public function __construct( int $lookback = self::LOOKBACK ) {
		$this->lookback = max( 300, $lookback );
	}

	/**
	 * Correlate one confirmed-compromise event into a bypass report fragment.
	 *
	 * @param string               $event_type One of the trigger EventCatalog constants.
	 * @param array<string,mixed>  $event_data The logged event row (ip, request_uri, method, context…).
	 * @return array<string,mixed>             Structured fragment (see keys below).
	 */
	public function correlate( string $event_type, array $event_data ): array {
		$redactor = Redactor::for_site();
		$context  = $this->decode_context( $event_data );

		$paths      = $this->affected_paths( $event_type, $context );
		$anchor_ts  = $this->anchor_timestamp( $paths, $event_data );
		$from       = $anchor_ts - $this->lookback;
		$to         = $anchor_ts + 120; // small forward slack for clock skew.

		$basenames = array();
		foreach ( $paths as $p ) {
			$basenames[] = strtolower( basename( $p ) );
		}

		$near_miss = $this->near_miss_candidates( $from, $to, $basenames );
		$traffic   = $this->traffic_candidates( $from, $to, $basenames, $redactor );
		$incident  = $this->incident_cluster( $from, $redactor );

		// The admin-creation / privilege-escalation triggers carry the attacker's own request
		// directly on the event row (it fired during the malicious request).
		$direct = $this->direct_request( $event_type, $event_data, $redactor );

		$candidates = array_merge( $direct, $near_miss, $traffic );

		return array(
			'trigger'             => $event_type,
			'finding'             => $this->finding_summary( $event_type, $context, $paths, $redactor ),
			'anchor_ts'           => $anchor_ts,
			'window'              => array( 'from' => $from, 'to' => $to ),
			'candidate_requests'  => array_slice( $candidates, 0, 15 ),
			'related_incident'    => $incident,
			'web_vector_evidence' => ! empty( $candidates ),
			'confidence'          => $this->confidence( $event_type, $candidates, $basenames, $incident ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Sources                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string[] $basenames
	 * @return array<int,array<string,mixed>>
	 */
	private function near_miss_candidates( int $from, int $to, array $basenames ): array {
		if ( ! class_exists( NearMissBuffer::class ) ) {
			return array();
		}
		$out = array();
		foreach ( ( new NearMissBuffer() )->between( $from, $to ) as $e ) {
			$e['source']        = 'near_miss';
			$e['references_artifact'] = $this->references_basename( (string) ( $e['uri'] ?? '' ), $basenames )
				|| $this->references_basename( wp_json_encode( $e['body'] ?? array() ) . ' ' . ( $e['raw_body'] ?? '' ), $basenames );
			$out[] = $e;
		}
		return $out;
	}

	/**
	 * @param string[] $basenames
	 * @return array<int,array<string,mixed>>
	 */
	private function traffic_candidates( int $from, int $to, array $basenames, Redactor $redactor ): array {
		if ( ! class_exists( TrafficBuffer::class ) ) {
			return array();
		}
		$result = ( new TrafficBuffer() )->query( array( 'since' => $from - 1, 'limit' => 500 ) );
		$items  = is_array( $result['items'] ?? null ) ? $result['items'] : array();

		$out = array();
		foreach ( $items as $e ) {
			$ts = (int) ( $e['ts'] ?? 0 );
			if ( $ts > $to ) {
				continue;
			}
			$uri    = (string) ( $e['uri'] ?? '' );
			$method = strtoupper( (string) ( $e['method'] ?? '' ) );
			$refs   = $this->references_basename( $uri, $basenames );

			// Keep write-ish methods or anything that references the planted file — the rest is noise.
			if ( ! $refs && ! in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) ) {
				continue;
			}
			$out[] = array(
				'source'              => 'traffic',
				'ts'                  => $ts,
				'ip'                  => (string) ( $e['ip'] ?? '' ),
				'method'              => $method,
				'uri'                 => $redactor->scrub_string( mb_substr( $uri, 0, 2048 ) ),
				'status'              => (int) ( $e['status'] ?? 0 ),
				'ua'                  => $redactor->scrub_string( (string) ( $e['ua_family'] ?? '' ) ),
				'country'             => (string) ( $e['country'] ?? '' ),
				'references_artifact' => $refs,
			);
		}
		return $out;
	}

	/**
	 * Summarize clustered attacker activity around the window via the existing correlator.
	 *
	 * @return array<string,mixed>
	 */
	private function incident_cluster( int $from, Redactor $redactor ): array {
		if ( ! class_exists( IncidentCorrelator::class ) ) {
			return array();
		}
		$groups = ( new IncidentCorrelator() )->correlate( $from, 15 );
		if ( empty( $groups ) ) {
			return array();
		}
		// Highest-scoring cluster is first.
		$top = $groups[0];
		return array(
			'ip'          => (string) ( $top['ip'] ?? '' ),
			'country'     => (string) ( $top['country'] ?? '' ),
			'score'       => (int) ( $top['score'] ?? 0 ),
			'event_types' => array_values( (array) ( $top['event_types'] ?? array() ) ),
			'event_count' => (int) ( $top['event_count'] ?? 0 ),
		);
	}

	/**
	 * For admin-creation / privilege-escalation events, the malicious request is the event itself.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function direct_request( string $event_type, array $event_data, Redactor $redactor ): array {
		$direct_types = array(
			EventCatalog::USER_ADMIN_CREATED,
			EventCatalog::USER_ROLE_CHANGED,
		);
		if ( ! in_array( $event_type, $direct_types, true ) ) {
			return array();
		}
		$uri = (string) ( $event_data['request_uri'] ?? '' );
		if ( '' === $uri ) {
			return array();
		}
		return array(
			array(
				'source'              => 'event',
				'ts'                  => strtotime( (string) ( $event_data['created_at'] ?? '' ) . ' UTC' ) ?: time(),
				'ip'                  => (string) ( $event_data['ip'] ?? '' ),
				'method'              => (string) ( $event_data['method'] ?? '' ),
				'uri'                 => $redactor->scrub_string( mb_substr( $uri, 0, 2048 ) ),
				'ua'                  => $redactor->scrub_string( mb_substr( (string) ( $event_data['user_agent'] ?? '' ), 0, 512 ) ),
				'references_artifact' => false,
			),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Resolve the file path(s) the compromise touched.
	 *
	 * @param array<string,mixed> $context
	 * @return string[] Absolute paths.
	 */
	private function affected_paths( string $event_type, array $context ): array {
		if ( EventCatalog::SCAN_FINDING === $event_type && ! empty( $context['path'] ) ) {
			return array( (string) $context['path'] );
		}
		if ( EventCatalog::INTEGRITY_CHANGED === $event_type && ! empty( $context['scan_id'] ) ) {
			return $this->paths_for_scan( (string) $context['scan_id'] );
		}
		return array();
	}

	/**
	 * @return string[]
	 */
	private function paths_for_scan( string $scan_id ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'loyalsec_scan_findings';
		$rows  = $wpdb->get_col( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT path FROM %i WHERE scan_id = %s LIMIT 25", $table,
				$scan_id
			)
		);
		return array_values( array_filter( array_map( 'strval', (array) $rows ) ) );
	}

	/**
	 * Time anchor = the planted file's mtime when known, else the event time.
	 *
	 * @param string[] $paths
	 */
	private function anchor_timestamp( array $paths, array $event_data ): int {
		foreach ( $paths as $p ) {
			if ( $p && file_exists( $p ) ) {
				$mtime = @filemtime( $p ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( $mtime ) {
					return (int) $mtime;
				}
			}
		}
		$ts = strtotime( (string) ( $event_data['created_at'] ?? '' ) . ' UTC' );
		return $ts ?: time();
	}

	/**
	 * @param array<string,mixed> $context
	 * @param string[]            $paths
	 * @return array<string,mixed>
	 */
	private function finding_summary( string $event_type, array $context, array $paths, Redactor $redactor ): array {
		return array(
			'event'    => $event_type,
			'path'     => isset( $paths[0] ) ? $redactor->relativize_path( (string) $paths[0] ) : '',
			'rule'     => (string) ( $context['rule'] ?? '' ),
			'score'    => (int) ( $context['score'] ?? 0 ),
			'affected_files' => count( $paths ),
		);
	}

	/**
	 * Grade the strength of the request→compromise link.
	 *
	 * @param array<int,array<string,mixed>> $candidates
	 * @param string[]                       $basenames
	 * @param array<string,mixed>            $incident
	 */
	private function confidence( string $event_type, array $candidates, array $basenames, array $incident ): string {
		$direct_types = array( EventCatalog::USER_ADMIN_CREATED, EventCatalog::USER_ROLE_CHANGED );
		if ( in_array( $event_type, $direct_types, true ) ) {
			return 'high';
		}
		foreach ( $candidates as $c ) {
			if ( ! empty( $c['references_artifact'] ) ) {
				return 'high'; // a request that names the planted file.
			}
		}
		// A near-miss request in the window is solid medium evidence; with a strong incident
		// cluster too, treat as high.
		$has_near_miss = false;
		foreach ( $candidates as $c ) {
			if ( ( $c['source'] ?? '' ) === 'near_miss' ) {
				$has_near_miss = true;
				break;
			}
		}
		if ( $has_near_miss ) {
			return ( (int) ( $incident['score'] ?? 0 ) >= 60 ) ? 'high' : 'medium';
		}
		if ( ! empty( $candidates ) ) {
			return 'medium';
		}
		return 'low'; // likely a non-web vector (FTP/SSH/supply-chain) — backend can discard.
	}

	/**
	 * @param string[] $basenames
	 */
	private function references_basename( string $haystack, array $basenames ): bool {
		if ( '' === $haystack ) {
			return false;
		}
		$haystack = strtolower( $haystack );
		foreach ( $basenames as $b ) {
			if ( '' !== $b && false !== strpos( $haystack, $b ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return array<string,mixed>
	 */
	private function decode_context( array $event_data ): array {
		$ctx = $event_data['context'] ?? array();
		if ( is_string( $ctx ) ) {
			$decoded = json_decode( $ctx, true );
			return is_array( $decoded ) ? $decoded : array();
		}
		return is_array( $ctx ) ? $ctx : array();
	}
}
