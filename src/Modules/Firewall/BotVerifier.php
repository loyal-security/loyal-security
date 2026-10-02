<?php
/**
 * Background reverse-DNS bot verification.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Waf\FileStore;

/**
 * Runs the actual reverse-DNS verification for bots that BotBlocker (or the Optimized-Mode
 * prepend) queued, entirely off the request path via WP-Cron.
 *
 * Registered UNCONDITIONALLY in FirewallModule::boot() — not gated by WAF mode — because a site
 * running Optimized Mode never executes Standard Mode's inspect_request() pipeline at all
 * (FirewallModule::boot() only hooks it to `init` `if ( ! $this->is_optimized_active() )`), so
 * verification has to live somewhere that runs regardless of which mode is doing the actual
 * request inspection. WP-Cron itself is unaffected by that branch — it's WordPress's normal
 * scheduler, not part of either mode's request-time code path.
 *
 * Reverse DNS (`gethostbyaddr()`/`gethostbynamel()`) is slow and has no PHP-level timeout, which
 * is exactly why this never runs synchronously on a real visitor's request in either mode —
 * both modes only ever READ a cached verdict (see FileStore::bot_verdict()). This class is the
 * only place the lookup itself happens, bounded to a small batch per run so a burst of spoofed
 * "good bot" traffic can't turn it into a slow cron job.
 */
class BotVerifier {

	private const HOOK     = 'totalsecwp_verify_bots';
	private const SCHEDULE = 'totalsecwp_bot_verify';

	public function __construct( private Settings $settings ) {}

	public function register_hooks(): void {
		add_filter( 'cron_schedules', array( $this, 'add_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval
		add_action( self::HOOK, array( $this, 'run' ) );

		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + 120, self::SCHEDULE, self::HOOK );
		}
	}

	/**
	 * @param array<string, array> $schedules Existing schedules.
	 * @return array<string, array>
	 */
	public function add_schedule( array $schedules ): array {
		if ( ! isset( $schedules[ self::SCHEDULE ] ) ) {
			// Read before `init` when register_hooks() schedules the event; translations may
			// only load from `init` on (see Cron::add_schedules()).
			$schedules[ self::SCHEDULE ] = array(
				'interval' => 10 * MINUTE_IN_SECONDS,
				'display'  => did_action( 'init' ) ? __( 'Every 10 Minutes (Loyal Security bot verification)', 'loyal-security' ) : 'Every 10 Minutes (Loyal Security bot verification)',
			);
		}
		return $schedules;
	}

	/**
	 * Verify up to 20 queued IPs. Fail-open per entry: a lookup error just leaves that IP
	 * unverified (never cached as a false negative that would need to age out) — it stays in
	 * "never checked" state and gets re-queued the next time it makes a request.
	 */
	public function run(): void {
		if ( ! (bool) $this->settings->get( 'firewall', 'bot_verify_enabled', true ) ) {
			return;
		}

		$store = new FileStore( BanStore::storage_dir() );
		foreach ( $store->pop_pending_bot_verifications( 20 ) as $ip => $meta ) {
			$suffixes = array_values( array_filter( array_map( 'strval', (array) ( $meta['suffixes'] ?? array() ) ) ) );
			if ( ! $suffixes || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				continue;
			}
			try {
				$store->store_bot_verdict( $ip, self::forward_confirm( $ip, $suffixes ) );
			} catch ( \Throwable $e ) {
				// A single bad lookup must never abort the rest of the batch.
				continue;
			}
		}
	}

	/**
	 * Forward-confirmed reverse DNS: resolve the IP's PTR record, require the hostname to end in
	 * one of the given trusted suffixes, then forward-resolve that hostname and require the
	 * result to include the original IP. Both halves matter — a bare PTR lookup alone is
	 * attacker-controllable (anyone can configure reverse DNS for IP space they control); the
	 * forward round-trip is what actually proves the claimed owner controls that hostname.
	 * Suffixes are resolved by the caller (builtin {@see \TotalSecurityWP\Waf\BotSignatures::TRUSTED_SUFFIXES}
	 * or an admin-provided custom suffix) — this method itself has no opinion on signature names.
	 *
	 * @param array<string> $suffixes Trusted hostname suffixes, e.g. `['googlebot.com']`.
	 */
	public static function forward_confirm( string $ip, array $suffixes ): bool {
		if ( ! $suffixes ) {
			return false;
		}

		$host = @gethostbyaddr( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_string( $host ) || '' === $host || $host === $ip ) {
			return false;
		}
		$host = strtolower( rtrim( $host, '.' ) );

		$matches_suffix = false;
		foreach ( $suffixes as $suffix ) {
			$suffix = strtolower( $suffix );
			if ( $host === $suffix || str_ends_with( $host, '.' . $suffix ) ) {
				$matches_suffix = true;
				break;
			}
		}
		if ( ! $matches_suffix ) {
			return false;
		}

		$forward = @gethostbynamel( $host ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return is_array( $forward ) && in_array( $ip, $forward, true );
	}
}
