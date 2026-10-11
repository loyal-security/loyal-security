<?php
/**
 * Bypass reporter — assembles, queues, and ships anonymized bypass reports to LicenseKit.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Telemetry;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;

/**
 * Owns the outbound side: wrap a {@see BypassCorrelator} fragment in an anonymous envelope,
 * apply the attacker-IP sharing policy, de-duplicate, rate-limit, persist to a flat-file queue,
 * and drain that queue on cron with fire-and-forget POSTs (a slow backend never blocks a page).
 *
 * Nothing is queued or sent unless consent has been recorded — checked here as a backstop in
 * addition to the module's trigger gate.
 */
class BypassReporter {

	private const QUEUE_NAME    = 'queue.jsonl';
	private const STATE_OPTION  = 'loyalsec_telemetry_state';
	private const SECRET_OPTION = 'loyalsec_telemetry_secret';
	private const SCHEMA        = 1;

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/* ------------------------------------------------------------------ */
	/* Intake                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * Queue a correlator fragment for sending. Returns true when accepted (new + within limits).
	 *
	 * @param array<string,mixed> $fragment Output of {@see BypassCorrelator::correlate()}.
	 */
	public function queue( array $fragment ): bool {
		if ( ! self::consent_given() ) {
			return false;
		}

		$envelope = $this->envelope( $fragment );
		$hash     = $this->dedupe_hash( $fragment );

		$state = $this->state();
		if ( in_array( $hash, $state['seen'], true ) ) {
			return false; // already reported this compromise.
		}
		$max = max( 1, (int) $this->settings->get( 'telemetry', 'max_reports_per_day', 20 ) );
		if ( $state['sent_today'] >= $max ) {
			return false; // rate-limited.
		}

		$envelope['dedupe'] = $hash;
		$this->append_queue( $envelope );

		$state['seen'][] = $hash;
		$state['seen']   = array_slice( $state['seen'], -200 );
		$this->save_state( $state );

		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Outbound (cron)                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Drain the queue: POST each envelope fire-and-forget, then clear. Returns the count sent.
	 */
	public function flush(): int {
		if ( ! self::consent_given() ) {
			$this->clear_queue();
			return 0;
		}

		// Best-effort: retry registration on every flush (hourly), regardless of whether the
		// queue has anything to send. A quiet site (consent given, no bypass event has ever
		// been queued) would otherwise never retry past the single attempt made at
		// consent-toggle time — if that one attempt hit a transient error, it would stay
		// unregistered indefinitely, since the queue-gated call below would never run.
		$secret = $this->ensure_secret();

		$lines = $this->read_queue();
		if ( empty( $lines ) ) {
			return 0;
		}

		$endpoint = $this->endpoint();
		$sent     = 0;
		$state    = $this->state();

		foreach ( $lines as $envelope ) {
			$body    = (string) wp_json_encode( $envelope );
			$headers = array(
				'Content-Type'       => 'application/json',
				'X-LoyalSec-Install' => (string) $envelope['install_id'],
			);
			// Sign the exact bytes we send so the backend can verify authenticity. If we don't
			// have a secret yet (registration not available), send unsigned — the backend can
			// accept unsigned during rollout and we retry registration next flush.
			if ( '' !== $secret ) {
				$headers['X-LoyalSec-Sig'] = hash_hmac( 'sha256', $body, $secret );
			}

			$response = wp_remote_post(
				$endpoint,
				array(
					'timeout'    => 10,
					'blocking'   => false,
					'user-agent' => \LoyalSecurity\Support\Http::user_agent(),
					'headers'    => $headers,
					'body'       => $body,
				)
			);
			unset( $response ); // fire-and-forget.
			++$sent;
			++$state['sent_today'];
		}

		$this->clear_queue();
		$this->save_state( $state );

		return $sent;
	}

	/* ------------------------------------------------------------------ */
	/* Transparency                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * A realistic, fully-redacted example envelope for the consent UI ("see exactly what we send").
	 *
	 * The example attack body is described abstractly (never a live payload) so on-disk malware
	 * scanners don't flag this source file.
	 *
	 * @return array<string,mixed>
	 */
	public function sample(): array {
		$uploads  = wp_upload_dir( null, false );
		$uploads  = ltrim( (string) wp_parse_url( (string) ( $uploads['baseurl'] ?? '' ), PHP_URL_PATH ), '/' );
		$fragment = array(
			'trigger'  => 'scan.finding',
			'finding'  => array(
				'event'          => 'scan.finding',
				'path'           => $uploads . '/2026/06/avatar.php',
				'rule'           => 'php.webshell.eval_base64',
				'score'          => 38,
				'affected_files' => 1,
			),
			'anchor_ts'           => time() - 1800,
			'window'              => array( 'from' => time() - 5400, 'to' => time() - 1680 ),
			'candidate_requests'  => array(
				array(
					'source'   => 'near_miss',
					'ts'       => time() - 1805,
					'ip'       => '203.0.113.77',
					'method'   => 'POST',
					'uri'      => wp_parse_url( admin_url( 'admin-ajax.php' ), PHP_URL_PATH ) . '?action=upload_file',
					'body'     => array(
						'name' => 'avatar.php',
						'data' => '[PHP webshell payload omitted — PHP open tag + eval/base64 of $_POST]',
					),
					'score'    => 9,
					'category' => 'rce',
					'top_rule' => 'php.tags.in_upload',
					'references_artifact' => true,
				),
			),
			'related_incident'    => array(
				'ip'          => '203.0.113.77',
				'country'     => 'NL',
				'score'       => 55,
				'event_types' => array( 'waf.ratelimit', 'scan.finding' ),
				'event_count' => 6,
			),
			'web_vector_evidence' => true,
			'confidence'          => 'high',
		);

		return $this->envelope( $fragment );
	}

	/* ------------------------------------------------------------------ */
	/* Envelope                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed> $fragment
	 * @return array<string,mixed>
	 */
	private function envelope( array $fragment ): array {
		$share_ip = (bool) $this->settings->get( 'telemetry', 'share_attacker_ip', true );
		if ( ! $share_ip ) {
			$fragment = $this->strip_ips( $fragment );
		}

		return array(
			'schema'         => self::SCHEMA,
			'install_id'     => self::install_id(),
			'plugin_version' => defined( 'LOYALSEC_VERSION' ) ? LOYALSEC_VERSION : '',
			'rulesets'       => array(
				'waf'     => $this->ruleset_version( 'waf-signatures.php' ),
				'malware' => $this->ruleset_version( 'malware-signatures.php' ),
			),
			'waf_mode'       => (string) get_option( 'loyalsec_waf_mode', 'standard' ),
			'env'            => array(
				'php' => $this->coarse_version( PHP_VERSION ),
				'wp'  => $this->coarse_version( (string) get_bloginfo( 'version' ) ),
			),
			'reported_at'    => gmdate( 'c' ),
			'report'         => $fragment,
		);
	}

	/**
	 * Drop or coarsen attacker IPs when the site opted out of sharing them.
	 *
	 * @param array<string,mixed> $fragment
	 * @return array<string,mixed>
	 */
	private function strip_ips( array $fragment ): array {
		$mask = static function ( string $ip ): string {
			return '' === $ip ? '' : substr( hash( 'sha256', 'ts-ip|' . $ip ), 0, 16 );
		};
		if ( isset( $fragment['candidate_requests'] ) && is_array( $fragment['candidate_requests'] ) ) {
			foreach ( $fragment['candidate_requests'] as &$c ) {
				if ( isset( $c['ip'] ) ) {
					$c['ip'] = $mask( (string) $c['ip'] );
				}
			}
			unset( $c );
		}
		if ( isset( $fragment['related_incident']['ip'] ) ) {
			$fragment['related_incident']['ip'] = $mask( (string) $fragment['related_incident']['ip'] );
		}
		return $fragment;
	}

	/* ------------------------------------------------------------------ */
	/* State / queue helpers                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed> $fragment
	 */
	private function dedupe_hash( array $fragment ): string {
		$path = (string) ( $fragment['finding']['path'] ?? '' );
		$day  = gmdate( 'Y-m-d', (int) ( $fragment['anchor_ts'] ?? time() ) );
		return sha1( ( $fragment['trigger'] ?? '' ) . '|' . $path . '|' . $day );
	}

	/**
	 * @return array{sent_today:int,day:string,seen:array<int,string>}
	 */
	private function state(): array {
		$raw   = get_option( self::STATE_OPTION, array() );
		$today = gmdate( 'Y-m-d' );
		$state = array(
			'sent_today' => (int) ( $raw['sent_today'] ?? 0 ),
			'day'        => (string) ( $raw['day'] ?? $today ),
			'seen'       => is_array( $raw['seen'] ?? null ) ? $raw['seen'] : array(),
		);
		if ( $state['day'] !== $today ) {
			$state['day']        = $today;
			$state['sent_today'] = 0; // reset the daily counter.
		}
		return $state;
	}

	private function save_state( array $state ): void {
		update_option( self::STATE_OPTION, $state, false );
	}

	private function append_queue( array $envelope ): void {
		if ( '' === $this->queue_path() ) {
			return; // Uploads directory unavailable.
		}
		NearMissBuffer::ensure_dir();
		// Base64 at rest: queued envelopes embed raw attacker payloads. Encoding keeps the
		// queue file from being quarantined by on-box malware scanners / AV before it drains.
		file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$this->queue_path(),
			base64_encode( (string) wp_json_encode( $envelope ) ) . "\n",
			FILE_APPEND | LOCK_EX
		);
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	private function read_queue(): array {
		$file = $this->queue_path();
		if ( '' === $file || ! file_exists( $file ) ) {
			return array();
		}
		$content = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $content ) {
			return array();
		}
		$out = array();
		foreach ( explode( "\n", trim( $content ) ) as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$decoded = base64_decode( $line, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			$item    = ( false !== $decoded ) ? json_decode( $decoded, true ) : null;
			if ( ! is_array( $item ) ) {
				$item = json_decode( $line, true ); // legacy plain-JSON fallback.
			}
			if ( is_array( $item ) ) {
				$out[] = $item;
			}
		}
		return $out;
	}

	private function clear_queue(): void {
		$file = $this->queue_path();
		if ( '' !== $file && file_exists( $file ) ) {
			unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	private function queue_path(): string {
		$buffer = NearMissBuffer::path();
		return '' === $buffer ? '' : dirname( $buffer ) . '/' . self::QUEUE_NAME;
	}

	private function base(): string {
		$base = defined( 'LOYALSEC_TELEMETRY_API_URL' ) ? (string) LOYALSEC_TELEMETRY_API_URL : '';
		return rtrim( $base, '/' );
	}

	private function endpoint(): string {
		return $this->base() . '/bypass';
	}

	/**
	 * Register this install with LicenseKit right away, best-effort. Called the moment consent
	 * is granted so `/register` doesn't wait on a real bypass event to occur (a quiet site could
	 * otherwise go indefinitely without the server recognizing its install id). Safe to call
	 * repeatedly — `ensure_secret()` is a no-op once a secret is already stored.
	 *
	 * @param bool $force When true, discards any locally-stored secret first so a fresh
	 *                    registration attempt actually reaches the server — otherwise
	 *                    `ensure_secret()`'s short-circuit means calling this again is a silent
	 *                    no-op if a (possibly stale/orphaned, e.g. from a wiped server-side
	 *                    record) secret already exists locally. Used by the dashboard's explicit
	 *                    "Grant consent & register" action, which exists specifically to recover
	 *                    from a broken registration state.
	 */
	public function register_now( bool $force = false ): bool {
		if ( ! self::consent_given() ) {
			return false;
		}
		if ( $force ) {
			delete_option( self::SECRET_OPTION );
		}
		return '' !== $this->ensure_secret();
	}

	/**
	 * Return this install's per-install HMAC secret, registering once if we don't have one yet.
	 *
	 * Registration is a single blocking call (the cron context can afford it). Best-effort: if
	 * the register endpoint is unavailable, returns '' and the caller sends unsigned, retrying
	 * registration on the next flush. The secret is returned only once, at registration time.
	 */
	private function ensure_secret(): string {
		$secret = (string) get_option( self::SECRET_OPTION, '' );
		if ( '' !== $secret ) {
			return $secret;
		}

		$response = wp_remote_post(
			$this->base() . '/register',
			array(
				'timeout'    => 10,
				'user-agent' => \LoyalSecurity\Support\Http::user_agent(),
				'headers'    => array( 'Content-Type' => 'application/json' ),
				'body'       => wp_json_encode( array( 'install_id' => self::install_id() ) ),
			)
		);
		if ( is_wp_error( $response ) ) {
			// Was previously a silent black box on failure — log so a persistently-unregistered
			// install is diagnosable (transient vs. an actual outbound-connectivity problem)
			// instead of just retrying forever with no trace of why.
			\LoyalSecurity\Support\Debug::log( 'telemetry register failed: ' . $response->get_error_message() );
			return '';
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			\LoyalSecurity\Support\Debug::log( 'telemetry register failed: HTTP ' . $code . ' — ' . substr( (string) wp_remote_retrieve_body( $response ), 0, 300 ) );
			return '';
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		// Accept either { secret } or the standard { success, data: { secret } } envelope.
		$secret = '';
		if ( is_array( $data ) ) {
			$secret = (string) ( $data['secret'] ?? ( $data['data']['secret'] ?? '' ) );
		}
		if ( '' === $secret ) {
			\LoyalSecurity\Support\Debug::log( 'telemetry register: 2xx response but no secret field found — ' . substr( (string) wp_remote_retrieve_body( $response ), 0, 300 ) );
		} else {
			update_option( self::SECRET_OPTION, $secret, true );
		}
		return $secret;
	}

	private function ruleset_version( string $file ): string {
		$path = LOYALSEC_PATH . 'data/' . $file;
		if ( ! is_file( $path ) ) {
			return '';
		}
		$data = include $path;
		return is_array( $data ) && isset( $data['version'] ) ? (string) $data['version'] : '';
	}

	/** Reduce a full version to MAJOR.MINOR so it can't fingerprint a site. */
	private function coarse_version( string $version ): string {
		if ( preg_match( '/^(\d+\.\d+)/', $version, $m ) ) {
			return $m[1];
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* Static shared helpers                                                */
	/* ------------------------------------------------------------------ */

	public static function install_id(): string {
		$id = (string) get_option( 'loyalsec_install_id', '' );
		if ( '' === $id ) {
			try {
				$id = bin2hex( random_bytes( 16 ) );
			} catch ( \Throwable $e ) {
				$id = md5( uniqid( 'loyalsec', true ) );
			}
			update_option( 'loyalsec_install_id', $id, true );
		}
		return $id;
	}

	public static function consent_given(): bool {
		$consent = get_option( 'loyalsec_telemetry_consent', array() );
		return is_array( $consent ) && ! empty( $consent['given'] );
	}
}
