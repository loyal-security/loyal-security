<?php
/**
 * Auto-drafts a virtual-patch rule from a confirmed tainted-sink scanner finding.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Integrity\PluginChecksums;
use LoyalSecurity\Modules\Scanner\Finding;

/**
 * The site that found a `TaintAnalyzer` sink already has everything needed to draft a
 * virtual-patch rule for it — the plugin, the exact request parameter, and (best-effort) the
 * REST route — without waiting on a cloud round-trip. Route resolution is inherently
 * heuristic (arbitrary plugin code varies too much to guarantee it), so a suggestion is
 * always tagged 'high' (path resolved) or 'low' (plugin+param only, no path) confidence.
 *
 * Never applies anything itself — {@see suggest()} only returns a candidate for a human to
 * review; {@see CustomVirtualPatches} is where an *approved* suggestion actually lands.
 */
class PatchSuggester {

	/** Which TaintAnalyzer rule ids this can draft a patch for, and their human label. */
	private const SUPPORTED_RULES = array(
		'tainted-rce'         => 'Command execution',
		'tainted-ssrf'        => 'Server-side request forgery (SSRF)',
		'tainted-lfi'         => 'Local file inclusion (LFI)',
		'tainted-sqli'        => 'SQL injection',
		'tainted-deserialize' => 'PHP object injection (unserialize)',
	);

	/**
	 * Whole-file malware-signature ids this can draft a require_auth (not content-matched)
	 * suggestion for — see {@see suggest_auth_gate()}.
	 */
	private const AUTH_GATE_RULES = array(
		'mal-insecure-rest-surface' => 'an unauthenticated REST route',
		'mal-insecure-ajax-nopriv'  => 'an unauthenticated AJAX action (wp_ajax_nopriv_*)',
	);

	/**
	 * Per-request cache of official WordPress.org hash sets, keyed by plugin slug (see
	 * {@see is_verified_official()}). Static because callers construct a fresh PatchSuggester
	 * per finding, and one scan batch can hit the same plugin dozens of times.
	 *
	 * @var array<string, array<string, bool>>
	 */
	private static array $official_hashes = array();

	/**
	 * @return array{rule: array<string, mixed>, confidence: string, reason: string}|null
	 */
	public function suggest( Finding $finding ): ?array {
		if ( ! isset( self::SUPPORTED_RULES[ $finding->rule ] ) ) {
			return null;
		}
		// Without a known parameter there's nothing safe to scope the rule to — blocking the
		// whole plugin on presence alone is exactly the "blocks legit plugins" risk this is
		// meant to avoid, so no suggestion is better than an overbroad one.
		if ( '' === $finding->param ) {
			return null;
		}
		if ( ! is_file( $finding->path ) || ! is_readable( $finding->path ) ) {
			return null;
		}

		$slug = $this->slug_from_path( $finding->path );
		if ( '' === $slug ) {
			return null; // Only plugin paths are supported for now (not themes/mu-plugins).
		}

		$content = (string) file_get_contents( $finding->path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$route   = $this->resolve_route( $content, $finding->line );

		// A tainted-sink heuristic hit inside a file that is byte-identical to its official
		// WordPress.org release is overwhelmingly a static-analysis false positive, not an
		// injected backdoor — and when the route can't even be resolved, the drafted rule
		// would lock down the WHOLE plugin's request surface (e.g. all of WooCommerce), the
		// worst possible trade for pristine vendor code. Real vulnerabilities in popular
		// official plugins reach sites through the curated `patches` feed instead, so
		// declining to draft here loses nothing. Route-resolved suggestions stay (they're
		// narrow: one param on one endpoint) but carry a pristine-file note for the reviewer.
		if ( $this->is_verified_official( $slug, $finding->path ) ) {
			if ( '' === $route['path_regex'] ) {
				return null;
			}
			$route['reason'] .= ' — note: this file is byte-identical to its official WordPress.org release, so treat as a probable false positive unless it matches a published CVE';
		}

		$rule_id = 'vp-auto-' . substr( hash( 'sha256', $slug . '|' . $finding->param . '|' . $finding->rule ), 0, 12 );
		$label   = self::SUPPORTED_RULES[ $finding->rule ];

		$rule = array(
			'id'          => $rule_id,
			'slug'        => $slug,
			'max_version' => $this->plugin_version( $slug ),
			'methods'     => array(),
			'path_regex'  => $route['path_regex'],
			'param'       => $finding->param,
			// A confirmed direct-sink vulnerability has no "safe" value for this parameter —
			// the correct virtual patch is to deny the parameter outright until the plugin is
			// fixed, not to try to filter dangerous-looking values (which the attacker can
			// always reshape).
			'value_regex' => '/[\s\S]/',
			'desc'        => sprintf(
				'Auto-drafted: %s via "%s" param on %s%s',
				$label,
				$finding->param,
				$slug,
				'' !== $route['path_regex'] ? '' : ' (route not resolved — applies to the whole plugin)'
			),
			'source'      => 'auto_suggested',
		);

		return array(
			'rule'       => $rule,
			'confidence' => '' !== $route['path_regex'] ? 'high' : 'low',
			'reason'     => $route['reason'],
		);
	}

	/**
	 * Auth-gate suggestion from a whole-file "insecure REST/AJAX surface" finding (an
	 * unauthenticated route sitting next to a privileged operation in the same file — see
	 * `mal-insecure-rest-surface` / `mal-insecure-ajax-nopriv` in malware-signatures.php).
	 *
	 * Unlike suggest(), there's no single sink line to scope a content match to — the bug is
	 * "this route has no capability check at all", not "this param needs sanitizing" — so the
	 * drafted rule gates the affected route(s) behind `require_auth` rather than matching
	 * request content (see VirtualPatch::match_auth_gate()). The signature match is
	 * whole-file, so there's no one sink line to correlate to a single
	 * register_rest_route()/add_action() call the way suggest() does — instead
	 * resolve_auth_gate_scope() collects every REST namespace or wp_ajax_nopriv_* action
	 * registered anywhere in the file, so the rule scopes to that plugin's own unauthenticated
	 * surface. When even that can't be resolved, it falls back to all REST or all
	 * admin-ajax.php requests (never the whole site) — see resolve_auth_gate_scope().
	 *
	 * @return array{rule: array<string, mixed>, confidence: string, reason: string}|null
	 */
	public function suggest_auth_gate( Finding $finding ): ?array {
		if ( ! isset( self::AUTH_GATE_RULES[ $finding->rule ] ) ) {
			return null;
		}
		if ( ! is_file( $finding->path ) || ! is_readable( $finding->path ) ) {
			return null;
		}

		$slug = $this->slug_from_path( $finding->path );
		if ( '' === $slug ) {
			return null;
		}

		// This suggestion type is always low confidence, so the bar is higher than
		// suggest()'s: if the flagged file matches its official WordPress.org checksum, the
		// "unauthenticated route + privileged operation" the signature saw is the plugin's
		// shipped design, not an injected backdoor — and gating it behind manage_options
		// (e.g. PixelYourSite's public tracking endpoints) would break it for every visitor.
		// No suggestion is drafted at all.
		if ( $this->is_verified_official( $slug, $finding->path ) ) {
			return null;
		}

		$label   = self::AUTH_GATE_RULES[ $finding->rule ];
		$rule_id = 'vp-auto-authgate-' . substr( hash( 'sha256', $slug . '|' . $finding->rule ), 0, 12 );

		$content = (string) file_get_contents( $finding->path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$scope   = $this->resolve_auth_gate_scope( $finding->rule, $content );

		$rule = array(
			'id'           => $rule_id,
			'slug'         => $slug,
			'max_version'  => $this->plugin_version( $slug ),
			'methods'      => array(),
			'path_regex'   => $scope['path_regex'],
			// Never-matching sentinel, deliberately present (not merely defaulted) even though
			// this site's own VirtualPatch::evaluate() already skips require_auth rules
			// explicitly and never reads this field. This is defense for OTHER installs: an
			// older client that has never heard of require_auth falls through to its own
			// path/value_regex logic. Because value_regex stays non-empty here, that fallback
			// (`matches()`) never takes the "path alone" shortcut regardless of what
			// path_regex is — scope_matches() still gates on path_regex, but the value_regex
			// check after it always fails, so an old client stays inert no matter how
			// path_regex is populated. This is what makes it safe for resolve_auth_gate_scope()
			// to fill path_regex with a real (narrower-than-empty) pattern below instead of
			// leaving the whole plugin (or whole site) in scope.
			'value_regex'  => '(?!)',
			// No `param` key at all — confirmed 2026-07-06 against LicenseKit's actual
			// authGateRule schema (a strict object with no `param` field defined), not merely
			// nullable as first assumed: sending `param: null` was itself rejected as an
			// "Unrecognized key". "Nullable DB column" (their earlier description) referred to
			// the storage schema, not this request-validation shape — the two aren't the same
			// contract. Do not re-add this key without re-confirming against their schema.
			'require_auth' => true,
			'require_cap'  => 'manage_options',
			'desc'         => sprintf(
				'Auto-drafted: requires an authenticated administrator on %s%s (found %s alongside a privileged operation in the same file, with no capability check)',
				$slug,
				$scope['desc_suffix'],
				$label
			),
			'source'       => 'auto_suggested',
		);

		return array(
			'rule'       => $rule,
			'confidence' => 'low',
			'reason'     => $scope['reason'],
		);
	}

	/**
	 * Narrow an auth-gate rule's scope to the flagged plugin's own unauthenticated surface
	 * instead of leaving it site-wide. The whole-file signature match gives no single sink
	 * line to correlate to one route (see suggest_auth_gate()), but the file can still be
	 * scanned for every REST namespace or wp_ajax_nopriv_* action it registers — scoping the
	 * rule to those is far narrower than "every request while this plugin is installed",
	 * which previously matched the site's homepage and login page for every anonymous
	 * visitor.
	 *
	 * @return array{path_regex: string, reason: string, desc_suffix: string}
	 */
	private function resolve_auth_gate_scope( string $rule_id, string $content ): array {
		if ( 'mal-insecure-rest-surface' === $rule_id ) {
			$namespaces = array();
			if ( preg_match_all( '/register_rest_route\s*\(\s*[\'"]([a-z0-9_\-\/]+\/v?\d[\w.\-]*)[\'"]/i', $content, $ms ) ) {
				$namespaces = array_values( array_unique( $ms[1] ) );
			}
			if ( $namespaces ) {
				$alts = array_map(
					static fn( $ns ) => preg_quote( trim( $ns, '/' ), '#' ),
					$namespaces
				);
				return array(
					'path_regex'  => '#/(?:' . implode( '|', $alts ) . ')/#i',
					'reason'      => 'whole-file signature match — no single sink line to correlate to one route, so this scopes to every REST namespace the plugin registers (' . implode( ', ', $namespaces ) . ') rather than the whole plugin or site',
					'desc_suffix' => ' — REST namespace(s): ' . implode( ', ', $namespaces ),
				);
			}
			return array(
				'path_regex'  => '#' . $this->rest_path_pattern() . '#i',
				'reason'      => 'whole-file signature match — could not resolve this plugin\'s specific REST namespace, so this scopes to all REST API requests rather than the whole site',
				'desc_suffix' => '',
			);
		}

		if ( 'mal-insecure-ajax-nopriv' === $rule_id ) {
			$actions = array();
			if ( preg_match_all( '/add_action\s*\(\s*[\'"]wp_ajax_nopriv_([a-z0-9_\-]+)[\'"]/i', $content, $ms ) ) {
				$actions = array_values( array_unique( $ms[1] ) );
			}
			if ( $actions ) {
				$alts = array_map( static fn( $a ) => preg_quote( $a, '#' ), $actions );
				return array(
					'path_regex'  => '#' . $this->ajax_path_pattern() . '.*[?&]action=(?:' . implode( '|', $alts ) . ')(?:&|$)#i',
					'reason'      => 'whole-file signature match — no single sink line to correlate to one action, so this scopes to every wp_ajax_nopriv_* action the plugin registers (' . implode( ', ', $actions ) . ') rather than the whole plugin or site',
					'desc_suffix' => ' — AJAX action(s): ' . implode( ', ', $actions ),
				);
			}
			return array(
				'path_regex'  => '#' . $this->ajax_path_pattern() . '#i',
				'reason'      => 'whole-file signature match — could not resolve this plugin\'s specific AJAX action, so this scopes to all admin-ajax.php requests rather than the whole site',
				'desc_suffix' => '',
			);
		}

		// Unreached in practice — suggest_auth_gate() already checks AUTH_GATE_RULES before
		// calling this — but fail closed to "all REST + ajax" rather than an empty (site-wide)
		// path_regex if a new AUTH_GATE_RULES entry is ever added without a matching branch here.
		return array(
			'path_regex'  => '#' . $this->rest_path_pattern() . '|' . $this->ajax_path_pattern() . '#i',
			'reason'      => 'unrecognized auth-gate finding type — scoped defensively to REST + admin-ajax rather than the whole site',
			'desc_suffix' => '',
		);
	}

	/**
	 * Whether a plugin file's content is byte-identical to the official WordPress.org release
	 * of the installed version (per-slug checksum list, transient-cached by PluginChecksums).
	 * False when unverifiable — not on WordPress.org, no version, or a checksum-API failure —
	 * i.e. fail-open in the same direction as the scanner's allow_hashes: an unverifiable
	 * file still gets its suggestion drafted for human review.
	 */
	private function is_verified_official( string $slug, string $path ): bool {
		if ( ! array_key_exists( $slug, self::$official_hashes ) ) {
			$set = array();
			try {
				$version = $this->plugin_version( $slug );
				if ( '' !== $version ) {
					foreach ( ( new PluginChecksums() )->hash_list_for( $slug, $version ) as $hash ) {
						$set[ $hash ] = true;
					}
				}
			} catch ( \Throwable $e ) {
				// Fail open — treat as unverifiable.
			}
			self::$official_hashes[ $slug ] = $set;
		}

		if ( ! self::$official_hashes[ $slug ] ) {
			return false;
		}
		$hash = @hash_file( 'sha256', $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return is_string( $hash ) && isset( self::$official_hashes[ $slug ][ strtolower( $hash ) ] );
	}

	/** Regex fragment (for `#` delimiters) matching this site's admin-ajax.php path. */
	private function ajax_path_pattern(): string {
		return preg_quote( (string) wp_parse_url( admin_url( 'admin-ajax.php' ), PHP_URL_PATH ), '#' );
	}

	/** Regex fragment (for `#` delimiters) matching this site's REST API path prefix. */
	private function rest_path_pattern(): string {
		return preg_quote( '/' . trim( rest_get_url_prefix(), '/' ) . '/', '#' );
	}

	/**
	 * Plugin slug from an absolute file path, or '' if it isn't inside the plugins directory.
	 */
	private function slug_from_path( string $path ): string {
		$p       = wp_normalize_path( $path );
		$plugins = wp_normalize_path( \LoyalSecurity\Support\Paths::plugins() ) . '/';
		if ( ! str_starts_with( $p, $plugins ) ) {
			return '';
		}
		$rel  = substr( $p, strlen( $plugins ) );
		$slug = strtok( $rel, '/' );
		return is_string( $slug ) ? (string) preg_replace( '/[^a-z0-9_\-]/i', '', $slug ) : '';
	}

	/**
	 * Installed version of a plugin slug (used as the virtual patch's max_version so it stops
	 * applying once the plugin updates past the version the vulnerability was found in).
	 */
	private function plugin_version( string $slug ): string {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		foreach ( get_plugins() as $file => $data ) {
			$s = dirname( $file );
			$s = ( '.' === $s ) ? basename( $file, '.php' ) : $s;
			if ( $s === $slug ) {
				return isset( $data['Version'] ) ? (string) $data['Version'] : '';
			}
		}
		return '';
	}

	/**
	 * Best-effort: which named function contains a given line. Functions are declared
	 * sequentially in real plugin code, so "the last named function seen at or before this
	 * line" is a reliable-enough approximation without needing full brace-matching.
	 */
	private function function_at_line( string $content, int $line ): string {
		$tokens = @token_get_all( $content ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $tokens ) ) {
			return '';
		}
		$count   = count( $tokens );
		$current = '';
		for ( $i = 0; $i < $count; $i++ ) {
			$t = $tokens[ $i ];
			if ( ! is_array( $t ) || T_FUNCTION !== $t[0] ) {
				continue;
			}
			if ( (int) ( $t[2] ?? 0 ) > $line ) {
				break;
			}
			for ( $j = $i + 1; $j < $count; $j++ ) {
				$tj = $tokens[ $j ];
				if ( is_array( $tj ) && in_array( $tj[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
					continue;
				}
				if ( '&' === $tj ) {
					continue; // by-reference return.
				}
				if ( is_array( $tj ) && T_STRING === $tj[0] ) {
					$current = $tj[1]; // Named function/method — anonymous closures are skipped.
				}
				break;
			}
		}
		return $current;
	}

	/**
	 * Best-effort correlation of the sink's containing function to a REST path, by grepping
	 * the same file for `register_rest_route()` calls. Handles the two common shapes: a
	 * direct literal `'callback' => 'fn_name'`, and a routes table of
	 * `array( 'route', <methods>, 'fn_name' )` tuples registered via a foreach loop.
	 *
	 * @return array{path_regex: string, reason: string}
	 */
	private function resolve_route( string $content, int $sink_line ): array {
		$fn = $this->function_at_line( $content, $sink_line );
		if ( '' === $fn ) {
			return array( 'path_regex' => '', 'reason' => 'could not determine which function contains the vulnerable sink' );
		}

		$namespace = '';
		if ( preg_match( '/\$\w+\s*=\s*[\'"]([a-z0-9_\-]+\/v?\d[\w.\-]*)[\'"]/i', $content, $m ) ) {
			$namespace = $m[1];
		}

		// Shape A: register_rest_route( $ns, '/route', array( ..., 'callback' => 'fn_name', ... ) ).
		if ( preg_match_all( '/register_rest_route\s*\([^,]+,\s*[\'"]([^\'"]+)[\'"]\s*,\s*array\(([\s\S]{0,500}?)\)\s*\)\s*;/i', $content, $ms, PREG_SET_ORDER ) ) {
			foreach ( $ms as $m ) {
				if ( preg_match( '/[\'"]callback[\'"]\s*=>\s*[\'"]' . preg_quote( $fn, '/' ) . '[\'"]/', $m[2] ) ) {
					return array(
						'path_regex' => $this->build_path_regex( $namespace, $m[1] ),
						'reason'     => 'resolved from a direct register_rest_route() callback literal',
					);
				}
			}
		}

		// Shape B: a routes table — array( 'route', METHOD_CONST_or_var, 'fn_name' ) — foreach-registered.
		if ( preg_match_all( '/array\(\s*[\'"]([a-z0-9_\-]+)[\'"]\s*,\s*[^,]+,\s*[\'"]([a-zA-Z_]\w*)[\'"]\s*\)/', $content, $ms, PREG_SET_ORDER ) ) {
			foreach ( $ms as $m ) {
				if ( $m[2] === $fn ) {
					return array(
						'path_regex' => $this->build_path_regex( $namespace, $m[1] ),
						'reason'     => 'resolved from a routes-table tuple registered via register_rest_route()',
					);
				}
			}
		}

		return array(
			'path_regex' => '',
			'reason'     => "found the containing function ({$fn}) but could not correlate it to a specific REST route",
		);
	}

	private function build_path_regex( string $namespace, string $route ): string {
		$ns = trim( $namespace, '/' );
		$rt = trim( $route, '/' );
		return '' !== $ns
			? '#/' . preg_quote( $ns, '#' ) . '/' . preg_quote( $rt, '#' ) . '#i'
			: '#/' . preg_quote( $rt, '#' ) . '#i';
	}
}
