<?php
/**
 * Lightweight user-agent classifier — no external library, PHP 8.0+.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Traffic;

defined( 'ABSPATH' ) || exit;

/**
 * Classifies a raw User-Agent string into a type, browser family, and OS.
 * Used to annotate traffic-buffer entries and surface bot/human breakdowns
 * in the Live Traffic panel without any database overhead.
 */
final class UserAgentParser {

	/* ------------------------------------------------------------------ */
	/* Bot dictionaries                                                     */
	/* ------------------------------------------------------------------ */

	/** Known-good crawlers (search engines, social previews, validators). */
	private const GOOD_BOTS = array(
		'googlebot', 'google-inspectiontool', 'bingbot', 'slurp', 'duckduckbot',
		'baiduspider', 'yandexbot', 'sogou', 'exabot', 'facebot',
		'ia_archiver', 'archive.org_bot', 'rogerbot', 'linkedinbot',
		'outbrain', 'pinterest', 'slackbot', 'twitterbot', 'applebot',
		'googlebot-image', 'googlebot-video', 'googlebot-news',
		'facebookexternalhit', 'w3c_validator', 'vkshare', 'embedly',
		'showyoubot', 'quora link preview', 'whatsapp', 'telegrambot',
		'discordbot', 'iframely',
	);

	/** Active security scanners and exploitation frameworks. */
	private const SCANNER_BOTS = array(
		'nmap', 'nikto', 'sqlmap', 'masscan', 'zgrab', 'nuclei',
		'dirbuster', 'wfuzz', 'gobuster', 'hydra', 'metasploit',
		'acunetix', 'nessus', 'openvas', 'w3af', 'burpsuite',
		'havij', 'zap/', 'screaming frog', 'arachni', 'grabber',
		'skipfish', 'vega/', 'paros', 'webscarab', 'ratproxy',
		'beef/', 'dirhunt', 'feroxbuster',
	);

	/** Generic bot / automation signals (lower priority than the specific lists above). */
	private const BOT_SIGNALS = array(
		'bot', 'crawler', 'spider', 'scraper', 'scan', 'wget/',
		'curl/', 'python-requests', 'python-urllib', 'libwww-perl',
		'java/', 'go-http-client', 'ruby/', 'php/', 'axios/',
		'node-fetch', 'node-http', 'got/', 'httpie/', 'httpx/',
		'lwp-request', 'mechanize', 'scrapy', 'aiohttp/',
		'okhttp/', 'apache-httpclient', 'feedfetcher',
	);

	/* ------------------------------------------------------------------ */
	/* Public API                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Parse a raw UA string.
	 *
	 * @param  string $ua Raw User-Agent header value.
	 * @return array{type:string,is_bot:bool,family:string,os:string}
	 */
	public static function parse( string $ua ): array {
		$lower = strtolower( $ua );
		$type  = self::classify( $lower );

		return array(
			'type'   => $type,
			'is_bot' => 'human' !== $type && 'unknown' !== $type,
			'family' => self::family( $ua, $lower ),
			'os'     => self::os( $ua ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Internal helpers                                                     */
	/* ------------------------------------------------------------------ */

	private static function classify( string $lower ): string {
		if ( '' === $lower ) {
			return 'unknown';
		}

		foreach ( self::SCANNER_BOTS as $sig ) {
			if ( str_contains( $lower, $sig ) ) {
				return 'scanner';
			}
		}

		foreach ( self::GOOD_BOTS as $sig ) {
			if ( str_contains( $lower, $sig ) ) {
				return 'crawler';
			}
		}

		foreach ( self::BOT_SIGNALS as $sig ) {
			if ( str_contains( $lower, $sig ) ) {
				return 'bot';
			}
		}

		// Real browsers carry a Gecko/WebKit/Trident token alongside Mozilla/5.0.
		if (
			str_contains( $lower, 'mozilla/5.0' ) &&
			(
				str_contains( $lower, 'applewebkit' ) ||
				str_contains( $lower, 'gecko/' ) ||
				str_contains( $lower, 'trident/' )
			)
		) {
			return 'human';
		}

		return 'unknown';
	}

	/** Identify the browser / client family. */
	private static function family( string $ua, string $lower ): string {
		// Edge before Chrome (Edge UA contains "Chrome" too).
		if ( preg_match( '/Edg(?:e|A|iOS)?\//i', $ua ) ) {
			return 'Edge';
		}
		if ( preg_match( '/OPR\/|Opera\//i', $ua ) ) {
			return 'Opera';
		}
		if ( preg_match( '/SamsungBrowser\//i', $ua ) ) {
			return 'Samsung';
		}
		if ( preg_match( '/Chrome\/[\d]+/i', $ua ) && ! str_contains( $lower, 'chromium' ) ) {
			return 'Chrome';
		}
		if ( preg_match( '/Firefox\/[\d]+/i', $ua ) ) {
			return 'Firefox';
		}
		if ( preg_match( '/Safari\/[\d]+/i', $ua ) && ! str_contains( $lower, 'chrome' ) ) {
			return 'Safari';
		}
		if ( str_contains( $lower, 'trident/' ) || str_contains( $lower, 'msie ' ) ) {
			return 'IE';
		}

		// Good bots.
		if ( str_contains( $lower, 'googlebot' ) ) {
			return 'Googlebot';
		}
		if ( str_contains( $lower, 'bingbot' ) ) {
			return 'Bingbot';
		}
		if ( str_contains( $lower, 'yandexbot' ) ) {
			return 'YandexBot';
		}
		if ( str_contains( $lower, 'baiduspider' ) ) {
			return 'Baiduspider';
		}
		if ( str_contains( $lower, 'slurp' ) ) {
			return 'Yahoo';
		}
		if ( str_contains( $lower, 'facebookexternalhit' ) ) {
			return 'Facebook';
		}
		if ( str_contains( $lower, 'twitterbot' ) ) {
			return 'Twitter';
		}

		// CLI tools.
		if ( str_contains( $lower, 'curl/' ) ) {
			return 'curl';
		}
		if ( str_contains( $lower, 'wget/' ) ) {
			return 'Wget';
		}
		if ( str_contains( $lower, 'python' ) ) {
			return 'Python';
		}
		if ( str_contains( $lower, 'go-http-client' ) ) {
			return 'Go HTTP';
		}
		if ( str_contains( $lower, 'java/' ) ) {
			return 'Java';
		}

		return 'Other';
	}

	/** Identify the operating system. */
	private static function os( string $ua ): string {
		if ( str_contains( $ua, 'Windows NT' ) ) {
			return 'Windows';
		}
		if ( str_contains( $ua, 'iPhone' ) || str_contains( $ua, 'iPad' ) ) {
			return 'iOS';
		}
		if ( str_contains( $ua, 'Android' ) ) {
			return 'Android';
		}
		if ( str_contains( $ua, 'Macintosh' ) || str_contains( $ua, 'Mac OS X' ) ) {
			return 'macOS';
		}
		if ( str_contains( $ua, 'CrOS' ) ) {
			return 'ChromeOS';
		}
		if ( str_contains( $ua, 'Linux' ) ) {
			return 'Linux';
		}
		return '';
	}
}
