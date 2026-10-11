<?php
/**
 * Frontend resource scanner for CSP policy discovery.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Csp;

defined( 'ABSPATH' ) || exit;

/**
 * Discovers external resources the site actually loads by:
 *   1. Fetching the homepage HTML (and optionally extra pages).
 *   2. Parsing src/href/data-src, preconnect hints, inline scripts, inline CSS, and
 *      linked stylesheet files — covering GTM, GA, FB Pixel, and similar tag-manager
 *      services whose domains never appear as top-level src= attributes in the HTML.
 *   3. Reading the WP_Scripts / WP_Styles global registry (catches admin-only assets).
 *
 * Results are cached in a transient for 1 hour so repeat panel loads are instant.
 */
class CspScanner {

	private const TRANSIENT_KEY     = 'loyalsec_csp_scan';
	private const TRANSIENT_TTL     = 3600;
	private const MAX_CSS_FILES     = 8;   // linked CSS files to follow per page
	private const MAX_EXTRA_PAGES   = 3;   // additional pages to scan beyond homepage

	/** Separate transient for the codebase (PHP/JS file) scan. */
	private const CODEBASE_TRANSIENT_KEY = 'loyalsec_csp_codebase_scan';
	private const CODEBASE_TRANSIENT_TTL = 3600;

	/** Max files to scan in a single codebase scan run (safety cap). */
	private const MAX_SCAN_FILES = 600;

	/** Skip files larger than 512 KB to avoid memory spikes. */
	private const MAX_FILE_SIZE = 524288;

	/** Per-scan file counter (reset at start of each scan_codebase() call). */
	private int $scan_file_count = 0;

	/** Lazily-loaded, memoized copy of the JSON domain-map data — see {@see domain_map()}. */
	private static ?array $domain_map_cache = null;

	/**
	 * Domain-suffix → preset-slug map, loaded from a static JSON data file rather than a PHP
	 * array literal. A discovered host that ends with any pattern will suggest the matching
	 * preset. Public so CspPendingStore can use it for preset lookup without duplicating it.
	 *
	 * @return array<string, string>
	 */
	public static function domain_map(): array {
		if ( null === self::$domain_map_cache ) {
			$json    = file_get_contents( LOYALSEC_PATH . 'assets/data/csp-domain-map.json' );
			$decoded = is_string( $json ) ? json_decode( $json, true ) : null;
			self::$domain_map_cache = is_array( $decoded ) ? $decoded : array();
		}
		return self::$domain_map_cache;
	}

	/* ------------------------------------------------------------------ */
	/* Public API                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Run a fresh scan. Fetches the homepage (plus a few secondary pages) and builds
	 * the domain list. Saves the result in a transient.
	 *
	 * @return array{ domains: string[], presets: string[], pages_scanned: int, error: string|null, scanned_at: int }
	 */
	public function scan(): array {
		$domains       = array();
		$pages_scanned = 0;
		$error         = null;

		// Pages to scan in order. Stop scanning if a page 404s.
		$urls_to_scan = $this->pages_to_scan();

		foreach ( $urls_to_scan as $url ) {
			$result = $this->fetch_page( $url );
			if ( is_null( $result ) ) {
				continue; // skip fetch failures for secondary pages
			}
			if ( is_string( $result ) ) {
				$error = $result; // first page error is shown to the user
				break;
			}
			[ $html, $status ] = $result;
			if ( $status >= 400 && $url !== home_url( '/' ) ) {
				continue; // skip 404/error pages for secondary URLs
			}
			$pages_scanned++;
			$page_domains = $this->extract_all( $html, $url );
			$domains      = array_values( array_unique( array_merge( $domains, $page_domains ) ) );
		}

		// Also inspect the WP scripts/styles global registry (catches lazily-loaded assets).
		$registry_domains = $this->scan_wp_registry();
		$domains          = array_values( array_unique( array_merge( $domains, $registry_domains ) ) );

		// Filter out own-domain entries — only external hosts matter for CSP.
		$own_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$domains  = array_values( array_filter( $domains, static fn( string $d ) => $d !== $own_host ) );

		$result = array(
			'domains'       => $domains,
			'presets'       => $this->suggest_presets( $domains ),
			'pages_scanned' => $pages_scanned,
			'error'         => $error,
			'scanned_at'    => time(),
		);

		set_transient( self::TRANSIENT_KEY, $result, self::TRANSIENT_TTL );
		return $result;
	}

	/**
	 * Return a previously cached scan result, or null if none exists.
	 *
	 * @return array|null
	 */
	public function get_cached(): ?array {
		$cached = get_transient( self::TRANSIENT_KEY );
		return is_array( $cached ) ? $cached : null;
	}

	/* ------------------------------------------------------------------ */
	/* Codebase scan (PHP / JS / CSS file walk)                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Walk active plugins and the active theme, extract every external https:// URL
	 * referenced in PHP, JS, HTML, and CSS files, and return domains + preset suggestions.
	 *
	 * This catches third-party CDN references that only appear in server-side code or in
	 * JS that isn't exposed in a static page fetch (dynamic imports, tag managers, etc.).
	 *
	 * Results are cached for one hour (same TTL as the page scan).
	 *
	 * @return array{ domains: string[], presets: string[], files: int, scanned_at: int, source: string }
	 */
	public function scan_codebase(): array {
		$this->scan_file_count = 0;
		$domains               = array();
		$skip_dirs             = array( 'vendor', 'node_modules', '.git', '.svn', 'tests', 'test', 'Test', 'Tests', 'spec' );

		// Active plugins.
		foreach ( (array) get_option( 'active_plugins', array() ) as $plugin_file ) {
			if ( $this->scan_file_count >= self::MAX_SCAN_FILES ) {
				break;
			}
			$plugin_dir = \LoyalSecurity\Support\Paths::plugins() . '/' . dirname( (string) $plugin_file );
			if ( is_dir( $plugin_dir ) ) {
				$domains = array_merge( $domains, $this->walk_dir( $plugin_dir, $skip_dirs ) );
			}
		}

		// Active (child) theme — then parent if different.
		$theme_dirs = array_unique( array( get_stylesheet_directory(), get_template_directory() ) );
		foreach ( $theme_dirs as $dir ) {
			if ( $this->scan_file_count >= self::MAX_SCAN_FILES ) {
				break;
			}
			if ( is_dir( $dir ) ) {
				$domains = array_merge( $domains, $this->walk_dir( $dir, $skip_dirs ) );
			}
		}

		// Filter own domain.
		$own_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$domains  = array_values( array_filter(
			array_unique( $domains ),
			static fn( string $d ) => $d !== $own_host
		) );

		$result = array(
			'domains'    => $domains,
			'presets'    => $this->suggest_presets( $domains ),
			'files'      => $this->scan_file_count,
			'scanned_at' => time(),
			'source'     => 'codebase',
		);

		set_transient( self::CODEBASE_TRANSIENT_KEY, $result, self::CODEBASE_TRANSIENT_TTL );
		return $result;
	}

	/**
	 * Return the last cached codebase scan, or null if none.
	 *
	 * @return array|null
	 */
	public function get_cached_codebase(): ?array {
		$cached = get_transient( self::CODEBASE_TRANSIENT_KEY );
		return is_array( $cached ) ? $cached : null;
	}

	/**
	 * Recursively walk a directory and extract external hostnames from source files.
	 *
	 * @param string   $dir      Directory to scan.
	 * @param string[] $skip     Directory names to skip.
	 * @param int      $depth    Current recursion depth (hard-capped at 5).
	 * @return string[]
	 */
	private function walk_dir( string $dir, array $skip, int $depth = 0 ): array {
		if ( $depth > 5 || $this->scan_file_count >= self::MAX_SCAN_FILES ) {
			return array();
		}

		$domains = array();

		try {
			$it = new \DirectoryIterator( $dir );
		} catch ( \Exception $e ) {
			return array();
		}

		foreach ( $it as $entry ) {
			if ( $this->scan_file_count >= self::MAX_SCAN_FILES ) {
				break;
			}
			if ( $entry->isDot() ) {
				continue;
			}
			if ( $entry->isDir() ) {
				if ( in_array( $entry->getFilename(), $skip, true ) ) {
					continue;
				}
				$domains = array_merge( $domains, $this->walk_dir( $entry->getPathname(), $skip, $depth + 1 ) );
				continue;
			}
			if ( ! $entry->isFile() ) {
				continue;
			}

			$ext = strtolower( (string) $entry->getExtension() );
			if ( ! in_array( $ext, array( 'php', 'js', 'html', 'htm', 'css' ), true ) ) {
				continue;
			}
			if ( $entry->getSize() > self::MAX_FILE_SIZE ) {
				continue;
			}

			$content = @file_get_contents( $entry->getPathname() );
			if ( false === $content || '' === $content ) {
				continue;
			}

			$this->scan_file_count++;
			$domains = array_merge( $domains, $this->extract_urls_from_content( $content ) );
		}

		return array_unique( $domains );
	}

	/**
	 * Extract external hostnames from arbitrary source text (PHP, JS, CSS, HTML).
	 * Looks for https:// string literals quoted with ', ", or ` (template literals).
	 *
	 * @return string[]
	 */
	private function extract_urls_from_content( string $content ): array {
		$domains = array();
		preg_match_all(
			'/[\'"`](https?:\/\/([^\s\'"`<>\\\\]{3,}))[\'"`]/i',
			$content,
			$m
		);
		foreach ( $m[2] ?? array() as $raw ) {
			$host = (string) ( wp_parse_url( 'https://' . $raw, PHP_URL_HOST ) ?: '' );
			if ( $h = $this->clean_host( $host ) ) {
				$domains[] = $h;
			}
		}
		return array_unique( $domains );
	}

	/* ------------------------------------------------------------------ */
	/* Page selection                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Build the list of URLs to scan. Always includes the homepage; adds common
	 * secondary pages (blog, shop, contact) if they seem to exist.
	 *
	 * @return string[]
	 */
	private function pages_to_scan(): array {
		$urls = array( home_url( '/' ) );

		// Common secondary pages — different themes/plugins load different third-party scripts
		// on these pages, e.g. WooCommerce loads Stripe on /shop, not on the homepage.
		$candidates = array( '/blog/', '/shop/', '/store/', '/contact/', '/about/' );
		$count      = 0;

		foreach ( $candidates as $path ) {
			if ( $count >= self::MAX_EXTRA_PAGES ) {
				break;
			}
			$url = home_url( $path );
			if ( $url !== home_url( '/' ) ) {
				$urls[] = $url;
				$count++;
			}
		}

		return $urls;
	}

	/* ------------------------------------------------------------------ */
	/* HTML extraction                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Extract all external domains from an HTML document using multiple strategies.
	 *
	 * @param  string $html     Page HTML.
	 * @param  string $base_url Base URL of the page (for resolving relative CSS imports).
	 * @return string[]
	 */
	private function extract_all( string $html, string $base_url ): array {
		$domains = array();

		// 1. src="https://..." and href="https://..." attributes.
		$domains = array_merge( $domains, $this->extract_attr_domains( $html ) );

		// 2. <link rel="preconnect|dns-prefetch"> — explicit browser resource hints.
		$domains = array_merge( $domains, $this->extract_preconnects( $html ) );

		// 3. Inline <style> blocks — url() references, @import rules.
		$domains = array_merge( $domains, $this->extract_inline_style_domains( $html ) );

		// 4. Inline <script> blocks — string literals like "https://cdn.example.com/script.js".
		//    Catches GTM, GA (Universal + GA4), FB Pixel, Hotjar, etc.
		$domains = array_merge( $domains, $this->extract_inline_script_domains( $html ) );

		// 5. data-src / data-href — lazy-loaded images.
		$domains = array_merge( $domains, $this->extract_data_attr_domains( $html ) );

		// 6. Follow linked CSS stylesheets (up to MAX_CSS_FILES) and parse them.
		$css_urls = $this->find_stylesheet_urls( $html );
		$fetched  = 0;
		foreach ( $css_urls as $css_url ) {
			if ( $fetched >= self::MAX_CSS_FILES ) {
				break;
			}
			if ( ! str_starts_with( $css_url, 'http' ) ) {
				continue; // skip relative/own-domain CSS
			}
			$css = $this->fetch_css( $css_url );
			if ( $css ) {
				$domains = array_merge( $domains, $this->extract_css_domains( $css ) );
				$fetched++;
			}
		}

		return array_values( array_unique( $domains ) );
	}

	/**
	 * Standard src="https://..." and href="https://..." attributes.
	 *
	 * @return string[]
	 */
	private function extract_attr_domains( string $html ): array {
		$domains = array();
		preg_match_all( '/(?:src|href|action)\s*=\s*["\']?(https?:\/\/([^\/\s"\'>\?#]+))/i', $html, $m );
		foreach ( $m[2] ?? array() as $host ) {
			$host = $this->clean_host( $host );
			if ( $host ) {
				$domains[] = $host;
			}
		}
		return array_unique( $domains );
	}

	/**
	 * <link rel="preconnect|dns-prefetch"> — the most explicit CSP hint.
	 * Attributes can appear in either order.
	 *
	 * @return string[]
	 */
	private function extract_preconnects( string $html ): array {
		$domains = array();
		// href first, then rel
		preg_match_all(
			'/<link[^>]+href=["\']?(https?:\/\/([^\/\s"\'>\?#]+))["\']?[^>]+rel=["\'](?:preconnect|dns-prefetch)["\'][^>]*>/i',
			$html,
			$m
		);
		foreach ( $m[2] ?? array() as $host ) {
			if ( $h = $this->clean_host( $host ) ) {
				$domains[] = $h;
			}
		}
		// rel first, then href
		preg_match_all(
			'/<link[^>]+rel=["\'](?:preconnect|dns-prefetch)["\'][^>]+href=["\']?(https?:\/\/([^\/\s"\'>\?#]+))/i',
			$html,
			$m2
		);
		foreach ( $m2[2] ?? array() as $host ) {
			if ( $h = $this->clean_host( $host ) ) {
				$domains[] = $h;
			}
		}
		return array_unique( $domains );
	}

	/**
	 * Extract domains from data-src / data-href lazy-load attributes.
	 *
	 * @return string[]
	 */
	private function extract_data_attr_domains( string $html ): array {
		$domains = array();
		preg_match_all( '/data-(?:src|href|lazy-src)\s*=\s*["\']?(https?:\/\/([^\/\s"\'>\?#]+))/i', $html, $m );
		foreach ( $m[2] ?? array() as $host ) {
			if ( $h = $this->clean_host( $host ) ) {
				$domains[] = $h;
			}
		}
		return array_unique( $domains );
	}

	/**
	 * Extract domains from inline <style> blocks (url() and @import patterns).
	 *
	 * @return string[]
	 */
	private function extract_inline_style_domains( string $html ): array {
		$domains = array();
		preg_match_all( '/<style[^>]*>(.*?)<\/style>/is', $html, $blocks );
		foreach ( $blocks[1] ?? array() as $css ) {
			$domains = array_merge( $domains, $this->extract_css_domains( $css ) );
		}
		return array_unique( $domains );
	}

	/**
	 * Extract domains from inline <script> blocks by scanning for any https:// string
	 * literal — this is how GA, GTM, FB Pixel, Hotjar, and similar tag-manager services
	 * expose their CDN URLs without a plain src= attribute.
	 *
	 * @return string[]
	 */
	private function extract_inline_script_domains( string $html ): array {
		$domains = array();
		preg_match_all( '/<script(?:\s[^>]*)?>([^<]{20,})<\/script>/is', $html, $blocks );
		foreach ( $blocks[1] ?? array() as $js ) {
			// Find all URL-like string literals.
			preg_match_all( '/["\']?(https?:\/\/([^\/\s"\'<>\?#\\\\]{3,}[^\/\s"\'<>\?#\\\\]))/i', $js, $m );
			foreach ( $m[2] ?? array() as $host ) {
				// Strip common trailing junk (/path/etc appended to domain extraction).
				$host = (string) wp_parse_url( 'https://' . $host, PHP_URL_HOST );
				if ( $h = $this->clean_host( $host ) ) {
					$domains[] = $h;
				}
			}
		}
		return array_unique( $domains );
	}

	/**
	 * Extract stylesheet <link href> URLs so we can follow and parse them.
	 *
	 * @return string[]
	 */
	private function find_stylesheet_urls( string $html ): array {
		$urls = array();
		// href first
		preg_match_all( '/<link[^>]+href=["\']?(https?:\/\/[^"\'\s>]+)["\']?[^>]*rel=["\']stylesheet["\'][^>]*>/i', $html, $m );
		foreach ( $m[1] ?? array() as $url ) {
			$urls[] = (string) $url;
		}
		// rel first
		preg_match_all( '/<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']?(https?:\/\/[^"\'\s>]+)/i', $html, $m2 );
		foreach ( $m2[1] ?? array() as $url ) {
			$urls[] = (string) $url;
		}
		return array_unique( $urls );
	}

	/**
	 * Extract domains from CSS text: url(...) and @import rules.
	 *
	 * @return string[]
	 */
	private function extract_css_domains( string $css ): array {
		$domains = array();
		// url('https://...') and url("https://...") and url(https://...)
		preg_match_all( '/url\s*\(\s*["\']?(https?:\/\/([^\/\s"\'>\?#\)]+))/i', $css, $m );
		foreach ( $m[2] ?? array() as $host ) {
			if ( $h = $this->clean_host( $host ) ) {
				$domains[] = $h;
			}
		}
		// @import 'https://...' and @import url('https://...')
		preg_match_all( '/@import\s+["\']?(https?:\/\/([^\/\s"\'>\?#]+))/i', $css, $m2 );
		foreach ( $m2[2] ?? array() as $host ) {
			if ( $h = $this->clean_host( $host ) ) {
				$domains[] = $h;
			}
		}
		return array_unique( $domains );
	}

	/* ------------------------------------------------------------------ */
	/* WP registry scan                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Inspect the global WP_Scripts / WP_Styles registries for external src/href values.
	 *
	 * @return string[]
	 */
	private function scan_wp_registry(): array {
		global $wp_scripts, $wp_styles;
		$domains = array();

		$registries = array();
		if ( $wp_scripts instanceof \WP_Scripts ) {
			$registries[] = $wp_scripts->registered;
		}
		if ( $wp_styles instanceof \WP_Styles ) {
			$registries[] = $wp_styles->registered;
		}

		foreach ( $registries as $registered ) {
			if ( ! is_array( $registered ) ) {
				continue;
			}
			foreach ( $registered as $dep ) {
				$src = isset( $dep->src ) ? (string) $dep->src : '';
				if ( $src && str_starts_with( $src, 'http' ) ) {
					$host = (string) ( wp_parse_url( $src, PHP_URL_HOST ) ?: '' );
					if ( $h = $this->clean_host( $host ) ) {
						$domains[] = $h;
					}
				}
			}
		}

		return array_unique( $domains );
	}

	/* ------------------------------------------------------------------ */
	/* Preset suggestion                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Map a list of discovered domains to known CspPolicy preset slugs.
	 *
	 * @param  string[] $domains
	 * @return string[]
	 */
	private function suggest_presets( array $domains ): array {
		$presets = array();
		foreach ( $domains as $domain ) {
			foreach ( self::domain_map() as $pattern => $slug ) {
				if ( $domain === $pattern || str_ends_with( $domain, '.' . $pattern ) ) {
					if ( ! in_array( $slug, $presets, true ) ) {
						$presets[] = $slug;
					}
					break; // one pattern match per domain is enough
				}
			}
		}
		return array_values( $presets );
	}

	/* ------------------------------------------------------------------ */
	/* HTTP helpers                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Fetch a page via wp_remote_get. Returns [html, http_status], an error string,
	 * or null on WP_Error (silent skip).
	 *
	 * @return array{0:string,1:int}|string|null
	 */
	private function fetch_page( string $url ) {
		// Sign the internal request with AUTH_KEY so the WAF (and any custom middleware)
		// can distinguish genuine plugin-initiated loopback requests from external probes.
		$token = defined( 'AUTH_KEY' ) ? hash_hmac( 'sha256', 'csp-scanner', AUTH_KEY ) : '';

		$response = wp_remote_get( $url, array(
			'timeout'    => 15,
			'sslverify'  => \LoyalSecurity\Support\Http::local_sslverify(),
			'user-agent' => 'LoyalSecurity-CSP-Scanner/' . LOYALSEC_VERSION,
			'headers'    => array(
				'X-LoyalSecurity-Scanner' => $token,
			),
		) );

		if ( is_wp_error( $response ) ) {
			return $url === home_url( '/' ) ? $response->get_error_message() : null;
		}

		$status = (int) wp_remote_retrieve_response_code( $response );
		$body   = (string) wp_remote_retrieve_body( $response );

		return array( $body, $status );
	}

	/**
	 * Fetch a CSS file. Returns the CSS string or empty string on failure.
	 */
	private function fetch_css( string $url ): string {
		// Stylesheets can live on a third-party CDN: only a request back to this site uses the
		// loopback SSL setting; every other host is verified normally.
		$is_local = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) ) === strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$response = wp_remote_get( $url, array(
			'timeout'    => 8,
			'sslverify'  => $is_local ? \LoyalSecurity\Support\Http::local_sslverify() : true,
			'user-agent' => 'LoyalSecurity-CSP-Scanner/' . LOYALSEC_VERSION,
		) );

		if ( is_wp_error( $response ) ) {
			return '';
		}

		$ct = (string) wp_remote_retrieve_header( $response, 'content-type' );
		// Only accept CSS responses (some hosts return HTML for missing files).
		if ( $ct && ! str_contains( $ct, 'css' ) && ! str_contains( $ct, 'text/plain' ) ) {
			return '';
		}

		return (string) wp_remote_retrieve_body( $response );
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Strip port, lowercase, and return an empty string for invalid hosts.
	 */
	private function clean_host( string $raw ): string {
		$host = strtolower( preg_replace( '/:\d+$/', '', trim( $raw ) ) );
		// Reject empty, IP-only, or localhost entries — these are never CSP sources.
		if ( ! $host || filter_var( $host, FILTER_VALIDATE_IP ) || $host === 'localhost' ) {
			return '';
		}
		// Must contain at least one dot.
		if ( ! str_contains( $host, '.' ) ) {
			return '';
		}
		return $host;
	}
}
