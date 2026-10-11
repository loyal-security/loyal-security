<?php
/**
 * Shared bot user-agent signatures.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * Single source of truth for bot detection, used by BOTH Standard Mode (BotBlocker,
 * BotVerifier) and the Optimized-Mode prepend (which reads GOOD_AGENTS directly) — kept here,
 * in the WAF-kernel directory that {@see \LoyalSecurity\Setup\WafKernelBundler} mirrors
 * verbatim into the deployed prepend bundle, so the two never drift out of sync.
 */
class BotSignatures {

	/** Substrings that identify vulnerability scanners and attack tools. Always blocked. */
	public const BAD_AGENTS = array(
		'masscan', 'zgrab', 'nikto', 'sqlmap', 'nessus', 'acunetix', 'nmap', 'dirbuster',
		'gobuster', 'wpscan', 'fimap', 'havij', 'jorgee', 'morfeus', 'zmeu', 'libwww-perl',
	);

	/**
	 * Generic HTTP libraries. Blocked only when the site owner opts in (`block_http_clients`):
	 * payment webhooks, shipping and accounting integrations, uptime checks and server cron jobs
	 * use these clients every day, and blocking them breaks orders silently.
	 */
	public const HTTP_CLIENTS = array( 'python-requests', 'go-http-client', 'curl/', 'winhttp' );

	/**
	 * SEO and backlink crawlers. Blocked only when the site owner opts in (`block_seo_crawlers`):
	 * many owners run these tools on their own site, and Petal is a search engine.
	 */
	public const SEO_CRAWLERS = array( 'semrushbot', 'ahrefsbot', 'dotbot', 'mj12bot', 'petalbot', 'megaindex' );

	/**
	 * The blocked user-agent substrings for a site's settings.
	 *
	 * @param bool $http_clients Whether generic HTTP libraries are blocked.
	 * @param bool $seo_crawlers Whether SEO crawlers are blocked.
	 * @return string[]
	 */
	public static function blocked_agents( bool $http_clients, bool $seo_crawlers ): array {
		return array_merge(
			self::BAD_AGENTS,
			$http_clients ? self::HTTP_CLIENTS : array(),
			$seo_crawlers ? self::SEO_CRAWLERS : array()
		);
	}

	/** Known-good crawlers, matched by UA substring, eligible for reverse-DNS verification. */
	public const GOOD_AGENTS = array(
		'googlebot', 'bingbot', 'applebot', 'duckduckbot', 'uptimerobot', 'slackbot', 'facebookexternalhit',
	);

	/**
	 * Forward-confirmed DNS hostname suffixes a verified bot's PTR record must end in, keyed by
	 * the UA substring that identified it. This is the anti-spoofing check: anyone can set any
	 * User-Agent string, but they can't fake owning reverse-DNS delegation for Google's or
	 * Facebook's IP space. A bot signature with no entry here (uptimerobot, slackbot) can never
	 * be *verified* — it just never gets the generous rate tier, which is a safe default, not
	 * a regression (today nothing gets a generous tier at all).
	 */
	public const TRUSTED_SUFFIXES = array(
		'googlebot'           => array( 'googlebot.com', 'google.com' ),
		'bingbot'             => array( 'search.msn.com' ),
		'applebot'            => array( 'applebot.apple.com' ),
		'duckduckbot'         => array( 'duckduckgo.com' ),
		'facebookexternalhit' => array( 'fbsv.net' ),
	);

	/**
	 * First GOOD_AGENTS substring found in the (already-lowercased, trimmed) UA, or '' if none.
	 */
	public static function matches_good( string $ua ): string {
		foreach ( self::GOOD_AGENTS as $good ) {
			if ( false !== strpos( $ua, $good ) ) {
				return $good;
			}
		}
		return '';
	}
}
