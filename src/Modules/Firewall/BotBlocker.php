<?php
/**
 * Malicious-bot blocking.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;
use LoyalSecurity\Waf\BotSignatures;
use LoyalSecurity\Waf\FileStore;

/**
 * Blocks requests from known bad user agents and (optionally) empty user agents, while
 * never blocking claimed-good bots outright. Signatures live in {@see BotSignatures}, shared
 * with the Optimized-Mode prepend so both modes agree on what a "good" or "bad" UA looks like.
 */
class BotBlocker {

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * Decide whether the current request's user agent should be blocked.
	 *
	 * @return string|null Reason if blocked, null if allowed.
	 */
	public function evaluate( string $user_agent ): ?string {
		$ua = strtolower( trim( $user_agent ) );

		if ( '' === $ua ) {
			return $this->settings->get( 'firewall', 'block_empty_ua', false ) ? 'empty_user_agent' : null;
		}

		// Admin-added blocks always win, even over a builtin-trusted signature — this is the
		// only way to fully block a bot that would otherwise get an automatic pass below (e.g.
		// an admin who's decided they don't want a particular crawler on their site at all).
		foreach ( $this->custom_blocked_signatures() as $blocked ) {
			if ( '' !== $blocked && false !== strpos( $ua, $blocked ) ) {
				return 'bad_user_agent:custom:' . $blocked;
			}
		}

		foreach ( $this->trusted_signatures() as $good ) {
			if ( '' !== $good && false !== strpos( $ua, $good ) ) {
				return null;
			}
		}

		$extra = array_map( 'strtolower', (array) $this->settings->get( 'firewall', 'custom_bad_agents', array() ) );
		$builtin = BotSignatures::blocked_agents(
			(bool) $this->settings->get( 'firewall', 'block_http_clients', false ),
			(bool) $this->settings->get( 'firewall', 'block_seo_crawlers', false )
		);
		foreach ( array_merge( $builtin, $extra ) as $bad ) {
			if ( '' !== $bad && false !== strpos( $ua, $bad ) ) {
				return 'bad_user_agent:' . $bad;
			}
		}

		return null;
	}

	/**
	 * If the UA matches a known-good crawler signature, report whether it's *verified* (a
	 * cached, forward-confirmed reverse-DNS match) and eligible for the more generous rate-limit
	 * tier. Never performs the DNS lookup itself — that only ever happens in BotVerifier's
	 * background cron. An unverified or never-checked claim is queued for that cron and treated
	 * as an ordinary visitor this request (no special tier, but not blocked either).
	 *
	 * Only signatures with a real trusted DNS suffix — builtin ones from
	 * {@see BotSignatures::TRUSTED_SUFFIXES}, or a custom rule with an admin-provided
	 * `trusted_suffix` — ever reach the verify-and-queue flow. A custom "verified" rule added
	 * without a suffix is still trusted by evaluate() above (never blocked), it just never earns
	 * the bonus tier, since nothing actually confirms the claim.
	 */
	public function verified_bot_signature( string $user_agent, string $ip ): ?string {
		if ( ! (bool) $this->settings->get( 'firewall', 'bot_verify_enabled', true ) ) {
			return null;
		}
		$ua = strtolower( trim( $user_agent ) );

		$disabled  = array_map( 'strtolower', (array) $this->settings->get( 'firewall', 'disabled_builtin_bots', array() ) );
		$signature = BotSignatures::matches_good( $ua );
		if ( '' !== $signature && ! in_array( $signature, $disabled, true ) ) {
			$suffixes = BotSignatures::TRUSTED_SUFFIXES[ $signature ] ?? array();
			if ( $suffixes ) {
				return $this->check_verdict( $signature, $ip, $suffixes );
			}
		}

		foreach ( ( new CustomBotRules() )->active() as $rule ) {
			if ( 'verified' !== ( $rule['type'] ?? '' ) || empty( $rule['trusted_suffix'] ) ) {
				continue; // No suffix = not DNS-verifiable = never eligible for the bonus tier.
			}
			$sig = strtolower( (string) ( $rule['signature'] ?? '' ) );
			if ( '' !== $sig && false !== strpos( $ua, $sig ) ) {
				return $this->check_verdict( $sig, $ip, array( (string) $rule['trusted_suffix'] ) );
			}
		}

		return null;
	}

	/**
	 * Cache-gated verdict lookup shared by both the builtin and custom verified-bot paths — see
	 * verified_bot_signature()'s docblock for why the DNS lookup itself never happens here.
	 *
	 * @param array<string> $suffixes Trusted hostname suffixes to verify against.
	 */
	private function check_verdict( string $signature, string $ip, array $suffixes ): ?string {
		$store   = new FileStore( BanStore::storage_dir() );
		$ttl     = DAY_IN_SECONDS * max( 1, (int) $this->settings->get( 'firewall', 'bot_verify_ttl_days', 30 ) );
		$verdict = $store->bot_verdict( $ip, $ttl );

		if ( null === $verdict ) {
			$store->queue_bot_verification( $ip, $signature, $suffixes );
			return null;
		}
		return $verdict ? $signature : null;
	}

	/**
	 * Builtin GOOD_AGENTS (minus anything the admin has disabled via `disabled_builtin_bots`)
	 * plus every active custom 'verified' rule, regardless of whether it has a trusted_suffix —
	 * a suffix only affects bonus-tier eligibility (see verified_bot_signature()), not whether
	 * evaluate() treats a signature as good.
	 *
	 * @return array<int, string>
	 */
	private function trusted_signatures(): array {
		$disabled = array_map( 'strtolower', (array) $this->settings->get( 'firewall', 'disabled_builtin_bots', array() ) );
		$builtin  = array_values( array_diff( BotSignatures::GOOD_AGENTS, $disabled ) );
		$custom   = array_values( array_filter( array_map(
			static fn( $r ) => 'verified' === ( $r['type'] ?? '' ) ? strtolower( (string) ( $r['signature'] ?? '' ) ) : '',
			( new CustomBotRules() )->active()
		) ) );
		return array_values( array_unique( array_merge( $builtin, $custom ) ) );
	}

	/**
	 * Every active custom 'blocked' rule's signature — checked before the trusted list in
	 * evaluate(), so an admin can block a signature even if it's also builtin-trusted.
	 *
	 * @return array<int, string>
	 */
	private function custom_blocked_signatures(): array {
		return array_values( array_filter( array_map(
			static fn( $r ) => 'blocked' === ( $r['type'] ?? '' ) ? strtolower( (string) ( $r['signature'] ?? '' ) ) : '',
			( new CustomBotRules() )->active()
		) ) );
	}
}
