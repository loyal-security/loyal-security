<?php
/**
 * Source template for the standalone WAF prepend bootstrapper.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Setup;

defined( 'ABSPATH' ) || exit;

/**
 * Holds the source of `totalsecwp-waf.php` — the standalone, zero-WordPress-dependency script
 * deployed as PHP's `auto_prepend_file` for Optimized Mode — as a plain string, so it never
 * exists as a checked-in file inside the distributed plugin. Like the rest of the WAF kernel it
 * depends on (see {@see WafKernelBundler}), this file genuinely can and must execute with
 * `ABSPATH` undefined; WordPress.org's Plugin Check has no guard syntax that accepts that, so
 * the fix is the same one used for the standalone recovery endpoint
 * ({@see \TotalSecurityWP\Modules\Backup\RecoveryScriptTemplate}): don't ship it as source at all,
 * generate it at deploy time instead.
 *
 * {@see WafKernelBundler::sync()} writes the rendered output of {@see render()}, alongside
 * relocated copies of the `src/Waf/*`, `src/Support/Ip.php`, and `data/*.php` files it depends
 * on, to `uploads/loyal-security/waf-kernel/` — outside the plugin directory entirely, so
 * Plugin Check's scan (which only covers the plugin's own folder) never sees any of it.
 * {@see \TotalSecurityWP\Setup\PrependInstaller} then points `auto_prepend_file` at the deployed
 * copy, never at anything inside the plugin.
 *
 * The rendered script is functionally identical to the original checked-in
 * `prepend/totalsecwp-waf.php`, with one addition: the PSR-4 autoloader it registers for the
 * `TotalSecurityWP\` namespace is explicitly unregistered in a `finally` block once request
 * inspection completes. Without this, the registration would outlive this file's execution for
 * the rest of the request — and since WordPress boots afterward in the same request (the normal
 * case), PHP tries registered autoloaders in registration order: this one, still pointing at the
 * deployed `uploads/` copy, would be asked before `autoload.php`'s own `TotalSecurityWP\`
 * autoloader for any class the prepend didn't already need this request. That's reachable in
 * practice — `FirewallModule::enforce_auth_gate()` runs unconditionally in both modes and
 * instantiates `VirtualPatch` on `init` regardless of whether the prepend itself found an
 * eligible virtual-patch rule — so without the fix, Standard Mode could silently execute the
 * relocated copy instead of the plugin's own, invisible until the two diverge (e.g. a plugin
 * update landing a fix that hasn't been resynced to `waf-kernel/` yet).
 */
class PrependBootstrapTemplate {

	/**
	 * Render the standalone WAF prepend bootstrapper source.
	 */
	public static function render(): string {
		return <<<'TOTALSECWP_PREPEND_BOOTSTRAP'
<?php
/**
 * Loyal Security — Standalone WAF Bootstrapper (Optimized Mode).
 *
 * Deployed as PHP's `auto_prepend_file` so it executes BEFORE WordPress (and before any
 * other PHP application) loads. This gives the firewall a chance to block malicious
 * requests with minimal overhead and without WordPress being parsed.
 *
 * DESIGN PRINCIPLES
 *   1. FAIL-OPEN. Any error, missing config, or unexpected state must let the request
 *      through untouched. The firewall must never take a site down.
 *   2. ZERO global side effects beyond inspection. No output, no headers, no session.
 *   3. Self-locating. Reads its companion `waf-config.php` (written by the Setup Wizard)
 *      for all absolute paths and tunables — it does not assume WordPress constants.
 *
 * This file is generated at runtime by TotalSecurityWP\Setup\PrependBootstrapTemplate — it is
 * never a checked-in part of the distributed plugin. Do not hand-edit the copy on disk; edit
 * the template and redeploy Optimized Mode (Setup Wizard) instead.
 *
 * @package TotalSecurityWP
 */

// Marker so the shared WAF classes (which normally require ABSPATH) may load here.
if ( ! defined( 'TOTALSECWP_WAF_PREPEND' ) ) {
	define( 'TOTALSECWP_WAF_PREPEND', true );
}

/**
 * Emit a block response, log it, and terminate. Defined in the global namespace so the
 * closure below can call it without class loading. Guarded so an accidental double
 * include of this file (e.g. overlapping auto_prepend_file deployments) cannot fatal
 * the site with a redeclaration error — fail-open principle #1.
 *
 * MUST be declared BEFORE the self-invoking closure runs: a conditionally-declared
 * function only exists once its `if` statement executes, so with this block placed after
 * the closure invocation every call to it threw "Call to undefined function", the
 * fail-open catch swallowed the Error, and every block path (ban, rate-limit, virtual
 * patch, signature) silently allowed the request — Optimized Mode was detection-only.
 *
 * @param object $req     RequestContext.
 * @param string $storage Storage dir.
 * @param string $type    Event type.
 * @param array  $context Context.
 * @param int    $status  HTTP status code.
 */
if ( ! function_exists( 'totalsecwp_waf_block' ) ) {
	function totalsecwp_waf_block( $req, $storage, $type, $context, $status ) {
		try {
			( new \TotalSecurityWP\Waf\Logger( $storage ) )->record( $type, $req, $context );
		} catch ( \Throwable $e ) {
			// Logging must never prevent the block.
		}

		if ( ! headers_sent() ) {
			$code = ( 429 === (int) $status ) ? 429 : 403;
			header( 'HTTP/1.1 ' . $code . ( 429 === $code ? ' Too Many Requests' : ' Forbidden' ) );
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'X-TotalSecWP-WAF: blocked' );
			if ( 429 === $code ) {
				header( 'Retry-After: 60' );
			}
		}

		$ref = isset( $context['rule'] ) ? (string) $context['rule'] : 'policy';
		// Plain, unstyled page: WordPress (and so wp_enqueue_style) is not loaded here.
		echo '<!doctype html><html><head><meta charset="utf-8"><title>Request blocked</title></head>'
			. '<body><h1>Request blocked</h1>'
			. '<p>This request was blocked by the Loyal Security firewall.</p>'
			. '<p><code>ref: ' . htmlspecialchars( $ref, ENT_QUOTES ) . '</code></p></body></html>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_html() is unavailable: this runs pre-WordPress via auto_prepend_file. htmlspecialchars(ENT_QUOTES) is the correct equivalent here.
		exit;
	}
}

// Run the whole bootstrapper inside a closure with a catch-all so nothing can fatal the
// host application. PHP <7 style guard kept minimal; this file is plain and version-safe.
( static function () {

	// Never interfere with CLI / WP-CLI / cron worker processes.
	if ( 'cli' === PHP_SAPI ) {
		return;
	}

	// Buffer the raw request body at the EARLIEST possible point — before the config include or
	// anything else can touch php://input. For application/x-www-form-urlencoded and multipart
	// POSTs PHP later drains this stream to build $_POST and silently truncates it at
	// max_input_vars; capturing it here means the WAF inspects the COMPLETE body regardless of
	// content type, so a payload positioned past the 1000th form field is still scored. Read
	// into a plain local (the WAF classes are not autoloaded yet) and hand it to RequestContext
	// once available. Fail-safe: a failed read yields false and RequestContext falls back.
	$totalsecwp_raw_body = @file_get_contents( 'php://input' ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors

	$config_file = __DIR__ . '/waf-config.php';
	if ( ! is_file( $config_file ) ) {
		return; // Not deployed/configured yet — fail open.
	}

	try {
		$config = include $config_file;
	} catch ( \Throwable $e ) {
		return;
	}

	if ( ! is_array( $config ) || empty( $config['enabled'] ) ) {
		return;
	}

	// Required paths.
	$src_dir    = isset( $config['src_dir'] ) ? (string) $config['src_dir'] : '';
	$signatures = isset( $config['signatures_file'] ) ? (string) $config['signatures_file'] : '';
	$storage    = isset( $config['storage_dir'] ) ? (string) $config['storage_dir'] : '';
	if ( ! is_dir( $src_dir ) || ! is_file( $signatures ) || ! is_dir( $storage ) ) {
		return;
	}

	// Minimal PSR-4 autoloader for the TotalSecurityWP\ namespace (Waf + Support classes).
	// Stored in a variable (not registered anonymously) so it can be explicitly unregistered
	// below — without this, the registration would outlive this file's execution for the rest
	// of the request, and if WordPress boots afterward in the same request (the normal case),
	// PHP tries registered autoloaders in registration order: this one — pointing at the
	// deployed uploads/ copy — would be asked before autoload.php's own TotalSecurityWP\
	// autoloader for any class the prepend didn't already need this request (e.g. VirtualPatch,
	// which FirewallModule::enforce_auth_gate() instantiates on `init` in BOTH modes regardless
	// of whether the prepend itself found an eligible virtual-patch rule this request).
	$totalsecwp_loader = static function ( $class ) use ( $src_dir ) {
		$prefix = 'TotalSecurityWP\\';
		if ( 0 !== strncmp( $class, $prefix, strlen( $prefix ) ) ) {
			return;
		}
		$rel  = substr( $class, strlen( $prefix ) );
		$path = rtrim( $src_dir, '/\\' ) . '/' . str_replace( '\\', '/', $rel ) . '.php';
		if ( is_file( $path ) ) {
			require $path;
		}
	};
	spl_autoload_register( $totalsecwp_loader );

	try {
		$trust_proxy     = ! empty( $config['trust_proxy'] );
		$trusted_proxies = isset( $config['trusted_proxies'] ) ? (array) $config['trusted_proxies'] : array();

		// Hand the early-buffered raw body to RequestContext so capture() sees the full payload
		// even for urlencoded/multipart POSTs (where php://input is now empty post-parse).
		\TotalSecurityWP\Waf\RequestContext::prime_raw_body( is_string( $totalsecwp_raw_body ) ? $totalsecwp_raw_body : null );

		$req = \TotalSecurityWP\Waf\RequestContext::capture( $trust_proxy, $trusted_proxies );

		// Self-test sentinel: lets the Setup Wizard verify the prepend executed.
		if ( isset( $req->headers['x-totalsecwp-selftest'] ) ) {
			header( 'X-TotalSecWP-WAF: active' );
			// Allow the request to continue; do not block the self-test probe.
		}

		$store = new \TotalSecurityWP\Waf\FileStore( $storage );

		// An unresolved client IP falls back to the shared 0.0.0.0 sentinel; IP-keyed checks
		// (ban, rate-limit) skip it so every unresolved request isn't pooled into one bucket.
		// Content inspection (virtual patches, signatures) below is not IP-keyed and still runs.
		$ip_unresolved = ( '' === $req->ip || '0.0.0.0' === $req->ip );

		// Effective IP allowlist (manual list + still-valid auto-added admin IPs), baked into
		// waf-config.php at write time. Standard Mode bypasses ALL checks for these IPs,
		// including active bans — that is the anti-lockout contract of auto_whitelist_admins —
		// so mirror it exactly here; otherwise an admin caught by a rate-limit ban stays locked
		// out precisely in the mode where the ban is enforced before WordPress can lift it.
		if ( ! $ip_unresolved && in_array( $req->ip, array_map( 'strval', (array) ( $config['ip_whitelist'] ?? array() ) ), true ) ) {
			return;
		}

		// 1) Ban check — fastest rejection path.
		if ( ! $ip_unresolved && $store->is_banned( $req->ip ) ) {
			totalsecwp_waf_block( $req, $storage, 'waf.ban.added', array( 'reason' => 'active_ban' ), (int) ( $config['block_status'] ?? 403 ) );
			return;
		}

		// 1b) Custom-blocked bot signatures — an admin-added block always wins, even over a
		// builtin-trusted signature. Mirrors BotBlocker::evaluate()'s priority order exactly.
		// Builtin BAD_AGENTS/custom_bad_agents blocking is Standard-Mode-only (a pre-existing
		// gap, not introduced here) — only the admin-managed custom-block list is enforced here.
		if ( ! $ip_unresolved && ! empty( $config['bot_rules']['blocked'] ) ) {
			$ua = strtolower( trim( (string) $req->user_agent ) );
			foreach ( (array) $config['bot_rules']['blocked'] as $totalsecwp_blocked_sig ) {
				$totalsecwp_blocked_sig = (string) $totalsecwp_blocked_sig;
				if ( '' !== $totalsecwp_blocked_sig && false !== strpos( $ua, $totalsecwp_blocked_sig ) ) {
					totalsecwp_waf_block( $req, $storage, 'waf.bot.block', array( 'reason' => 'bad_user_agent:custom:' . $totalsecwp_blocked_sig ), (int) ( $config['block_status'] ?? 403 ) );
					return;
				}
			}
		}

		// 1c) Verified-bot rate tier — READ-ONLY. The reverse-DNS lookup itself never runs here;
		// it only ever happens in Standard Mode's periodic WP-Cron job (BotVerifier), which is
		// registered unconditionally regardless of WAF mode. A cache miss below just means
		// "not verified yet" — it gets queued (a cheap, synchronous file write) and this
		// request falls through to the everyday rate-limit tier, exactly like any other visitor.
		// $totalsecwp_bot_rate holds the matched signature's own requests/window — already
		// resolved server-side from any per-signature bot_rate_overrides entry, see
		// FirewallModule::export_bot_rules() — once verified; null means "use the everyday tier".
		$totalsecwp_bot_rate = null;
		if ( ! $ip_unresolved && ! empty( $config['bot_verify']['enabled'] ) && ! empty( $config['bot_rules']['trusted'] ) ) {
			$ua = strtolower( trim( (string) $req->user_agent ) );
			foreach ( (array) $config['bot_rules']['trusted'] as $totalsecwp_trusted ) {
				$sig = (string) ( $totalsecwp_trusted['signature'] ?? '' );
				if ( '' === $sig || false === strpos( $ua, $sig ) ) {
					continue;
				}
				$suffixes = (array) ( $totalsecwp_trusted['suffixes'] ?? array() );
				if ( $suffixes ) {
					// 86400 = one day in seconds (not WordPress's DAY_IN_SECONDS -- undefined pre-WP).
					$ttl     = 86400 * (int) ( $config['bot_verify']['ttl_days'] ?? 30 );
					$verdict = $store->bot_verdict( $req->ip, $ttl );
					if ( null === $verdict ) {
						$store->queue_bot_verification( $req->ip, $sig, $suffixes );
					} elseif ( $verdict ) {
						$totalsecwp_bot_rate = array(
							'requests' => (int) ( $totalsecwp_trusted['requests'] ?? ( $config['bot_verify']['requests'] ?? 600 ) ),
							'window'   => (int) ( $totalsecwp_trusted['window'] ?? ( $config['bot_verify']['window'] ?? 60 ) ),
						);
					}
				}
				break;
			}
		}

		// 2) Rate limiting.
		if ( ! $ip_unresolved && ! empty( $config['rate_limit']['enabled'] ) ) {
			if ( null !== $totalsecwp_bot_rate ) {
				$limit  = (int) $totalsecwp_bot_rate['requests'];
				$window = (int) $totalsecwp_bot_rate['window'];
			} else {
				$limit  = (int) ( $config['rate_limit']['limit'] ?? 240 );
				$window = (int) ( $config['rate_limit']['window'] ?? 60 );
			}
			$rate   = $store->hit_rate( $req->ip, $limit, $window );
			if ( ! empty( $rate['exceeded'] ) ) {
				if ( ! empty( $config['detection_only'] ) ) {
					( new \TotalSecurityWP\Waf\Logger( $storage ) )->record( 'waf.ratelimit', $req, array( 'count' => $rate['count'], 'limit' => $limit, 'audit_only' => true ) );
				} else {
					totalsecwp_waf_block( $req, $storage, 'waf.ratelimit', array( 'count' => $rate['count'], 'limit' => $limit ), 429 );
					return;
				}
			}
		}

		// 2b) Query-cardinality limiter — distinct filter/search combinations from one IP, not
		// request volume (see FileStore::hit_distinct()'s docblock: a bot walking every filter
		// combination on a faceted-search page can look like ordinary low-volume traffic to the
		// plain rate limiter above, since any single combination might be requested only once).
		if ( ! $ip_unresolved && ! empty( $config['query_cardinality']['enabled'] ) ) {
			$qc_signature = $req->query_signature();
			if ( '' !== $qc_signature ) {
				$qc = $store->hit_distinct(
					$req->ip,
					$qc_signature,
					(int) ( $config['query_cardinality']['max'] ?? 60 ),
					(int) ( $config['query_cardinality']['window'] ?? 600 )
				);
				if ( ! empty( $qc['exceeded'] ) ) {
					if ( ! empty( $config['detection_only'] ) ) {
						( new \TotalSecurityWP\Waf\Logger( $storage ) )->record( 'waf.query_cardinality', $req, array( 'count' => $qc['count'], 'audit_only' => true ) );
					} else {
						totalsecwp_waf_block( $req, $storage, 'waf.query_cardinality', array( 'count' => $qc['count'] ), 429 );
						return;
					}
				}
			}
		}

		// 3) Virtual patching — base rules merged with cached remote feed patches (fail-open).
		// Uses the installed-plugins slug=>version snapshot baked into waf-config.php at the
		// last write (get_plugins() is WordPress-only and unavailable here, pre-WordPress).
		if ( ! empty( $config['virtual_patching'] ) ) {
			$vp_file = isset( $config['virtual_patches_file'] ) ? (string) $config['virtual_patches_file'] : '';
			if ( '' !== $vp_file && is_file( $vp_file ) ) {
				try {
					$vp_data  = include $vp_file;
					$vp_rules = isset( $vp_data['rules'] ) && is_array( $vp_data['rules'] ) ? $vp_data['rules'] : array();

					$vp_remote_file = rtrim( $storage, '/\\' ) . '/feed/patches-remote.php';
					if ( is_file( $vp_remote_file ) ) {
						$vp_remote_data = include $vp_remote_file;
						if ( is_array( $vp_remote_data ) && ! empty( $vp_remote_data['rules'] ) && is_array( $vp_remote_data['rules'] ) ) {
							$vp_rules = array_merge( $vp_rules, $vp_remote_data['rules'] );
						}
					}

					// Drop any bundled/feed rule whose id the local (site-reviewed) list already
					// has an opinion on — enabled or disabled, the local verdict wins, mirroring
					// FirewallModule::merged_virtual_patch_rules()'s dedupe for Standard Mode.
					// Without this, disabling a rule locally that also exists in the synced
					// `patches` feed (e.g. an auto-suggested rule later redistributed back down
					// through it) would be a no-op here: the feed's identical-id copy would keep
					// enforcing regardless of the local toggle. Also drop any id explicitly
					// disabled via 'disabled_virtual_patch_ids' — the lever for a bundled/feed
					// rule that has no local record at all (see
					// FirewallModule::set_virtual_patch_disabled()).
					$exclude_ids = array();
					if ( isset( $config['custom_patch_ids'] ) && is_array( $config['custom_patch_ids'] ) ) {
						$exclude_ids = $config['custom_patch_ids'];
					}
					if ( isset( $config['disabled_virtual_patch_ids'] ) && is_array( $config['disabled_virtual_patch_ids'] ) ) {
						$exclude_ids = array_merge( $exclude_ids, $config['disabled_virtual_patch_ids'] );
					}
					if ( $exclude_ids ) {
						$known_ids = array_flip( $exclude_ids );
						$vp_rules  = array_values( array_filter( $vp_rules, static function ( $rule ) use ( $known_ids ) {
							return ! isset( $known_ids[ (string) ( $rule['id'] ?? '' ) ] );
						} ) );
					}

					// Third source: site-local, admin-approved suggestions (CustomVirtualPatches),
					// inlined into waf-config.php since the set is small by nature. Enabled only —
					// disabled ones were already excluded from this array at bake time.
					if ( isset( $config['custom_patches'] ) && is_array( $config['custom_patches'] ) ) {
						$vp_rules = array_merge( $vp_rules, $config['custom_patches'] );
					}

					$installed_plugins = isset( $config['installed_plugins'] ) && is_array( $config['installed_plugins'] ) ? $config['installed_plugins'] : array();
					$vp_rule = ( new \TotalSecurityWP\Waf\VirtualPatch( $vp_rules, $installed_plugins ) )->evaluate( $req );
					if ( null !== $vp_rule ) {
						if ( empty( $config['detection_only'] ) ) {
							totalsecwp_waf_block( $req, $storage, 'waf.vpatch', array( 'rule' => $vp_rule ), (int) ( $config['block_status'] ?? 403 ) );
							return;
						}
						( new \TotalSecurityWP\Waf\Logger( $storage ) )->record( 'waf.vpatch', $req, array( 'rule' => $vp_rule, 'audit_only' => true ) );
					}
				} catch ( \Throwable $e ) {
					// Fail open — virtual patching is best-effort in the prepend.
				}
			}
		}

		// 4) Signature inspection — base ruleset merged with cached remote feed rules (fail-open).
		$waf_cfg = array(
			'threshold'      => (int) ( $config['threshold'] ?? 12 ),
			'disabled_rules' => isset( $config['disabled_rules'] ) ? (array) $config['disabled_rules'] : array(),
			'allow_params'   => isset( $config['allow_params'] ) ? (array) $config['allow_params'] : array(),
			'site_host'      => isset( $config['site_host'] ) ? (string) $config['site_host'] : '',
		);

		$base_data    = is_file( $signatures ) ? include $signatures : array();
		$base_rules   = isset( $base_data['rules'] ) && is_array( $base_data['rules'] ) ? $base_data['rules'] : array();
		$base_version = isset( $base_data['version'] ) ? (string) $base_data['version'] : '';

		// Attempt to merge remote feed rules (fail-open: any error falls back to base rules).
		try {
			$remote_file = rtrim( $storage, '/\\' ) . '/feed/waf-remote.php';
			if ( is_file( $remote_file ) ) {
				$remote_data = include $remote_file;
				if ( is_array( $remote_data ) && ! empty( $remote_data['rules'] ) && is_array( $remote_data['rules'] ) ) {
					$base_rules = array_merge( $base_rules, $remote_data['rules'] );
				}
			}
		} catch ( \Throwable $e ) {
			// Remote merge failed — base rules only.
		}

		$kernel   = new \TotalSecurityWP\Waf\Kernel(
			new \TotalSecurityWP\Waf\SignatureSet( $base_rules, $base_version ),
			$waf_cfg
		);
		$decision = $kernel->inspect( $req );

		if ( $decision->blocked && empty( $config['detection_only'] ) ) {
			totalsecwp_waf_block( $req, $storage, 'waf.block', $decision->to_context(), (int) ( $config['block_status'] ?? 403 ) );
			return;
		}

		if ( $decision->blocked ) {
			// Detection-only mode: log but allow.
			( new \TotalSecurityWP\Waf\Logger( $storage ) )->record( 'waf.block', $req, array_merge( $decision->to_context(), array( 'detection_only' => true ) ) );
		}
	} catch ( \Throwable $e ) {
		// Fail open on any unexpected error.
		return;
	} finally {
		// Restore autoloader precedence for the rest of this request — see this template
		// class's docblock for why this matters whenever WordPress boots afterward in the same
		// request (the normal case). Not reached if totalsecwp_waf_block() already exit()'d, but
		// that's fine: a blocked request never reaches a "later" WordPress boot phase to protect.
		spl_autoload_unregister( $totalsecwp_loader );
	}
} )();

TOTALSECWP_PREPEND_BOOTSTRAP;
	}
}
