<?php
/**
 * Firewall module — Standard-Mode orchestrator + WAF config management.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\AbstractModule;
use LoyalSecurity\Modules\Audit\EventCatalog;
use LoyalSecurity\Waf\BotSignatures;
use LoyalSecurity\Waf\Kernel;
use LoyalSecurity\Waf\Logger as WafLogger;
use LoyalSecurity\Waf\RequestContext;
use LoyalSecurity\Waf\SignatureSet;
use LoyalSecurity\Waf\VirtualPatch;

/**
 * Coordinates all network-defence engines. In Standard Mode it runs the shared WAF kernel
 * (plus rate-limit, brute-force, DDoS, bot, geo and virtual-patch checks) on `init`. In
 * Optimized Mode the prepend handles request inspection; this module then only manages
 * config, bans, login protection, and reconciles the prepend's event log into the database.
 */
class FirewallModule extends AbstractModule {

	/**
	 * Since 1.5.0, events reconciled from the pre-WordPress firewall's log fire
	 * `loyalsec_event_logged` like every other event. Add-ons that used to read those rows from
	 * the table themselves can check this constant and stop, so nothing is handled twice.
	 */
	public const PREPEND_EVENTS_FIRE_HOOK = true;

	private ?BanStore $bans = null;
	private ?IpResolver $ip = null;

	/** Request-scoped cache for is_optimized_active() (null = not yet computed). */
	private ?bool $optimized_active = null;

	/**
	 * Whether this request is a REST call carrying HTTP Basic credentials (an application
	 * password or a WooCommerce API key). WordPress checks those only once the REST API loads,
	 * after `init`, so a block decided on `init` waits for them (see defer_block()).
	 */
	private bool $defer_eligible = false;

	/** A block postponed until the request's credentials are known: [type, context, status]. */
	private ?array $deferred = null;

	public function id(): string {
		return 'firewall';
	}

	public function title(): string {
		return __( 'Firewall & Network Defense', 'loyal-security' );
	}

	public function default_settings(): array {
		return array(
			'enabled'               => true,
			'detection_only'        => false,
			'threshold'             => 12,
			'block_status'          => 403,
			'whitelist_admins'      => true,
			// Automatically add admin IPs to ip_whitelist on login so they can
			// never lock themselves out via DDoS/rate-limit bans.
			'auto_whitelist_admins' => true,
			'trust_proxy'           => false,
			'trusted_proxies'       => array(),
			// Believe Cloudflare's CF-Connecting-IP, but only from Cloudflare's published edge
			// ranges (Ip::CLOUDFLARE_RANGES). Safe on sites not behind Cloudflare: their visitors
			// never connect from those ranges, so nothing changes for them.
			'trust_cloudflare'      => true,
			// Show "IP Geolocation by DB-IP" on the page a visitor sees when a country rule blocks
			// them. Off by default: WordPress.org does not allow credit links on the public site
			// unless the site owner turns them on. DB-IP's licence asks for the link on pages that
			// use its data, so the setting's help explains that (see data/geo/NOTICE.txt).
			'geo_credit_on_block_page' => false,
			'disabled_rules'        => array(),
			'allow_params'          => array(),

			// Per-id override for a bundled/feed virtual-patch rule that has no local
			// (CustomVirtualPatches) record — see FirewallModule::set_virtual_patch_disabled().
			'disabled_virtual_patches' => array(),

			// Rate limiting.
			'rate_limit_enabled'  => true,
			'rate_limit_requests' => 240,
			'rate_limit_window'   => 60,

			// Query-cardinality limiter — catches a bot walking many distinct filter/search
			// combinations on a faceted-search or archive page (WooCommerce, directories), a
			// pattern the plain request-rate limiter above misses since each individual
			// combination might only be requested once. The default threshold is deliberately
			// generous: legitimate faceted-search browsing (a real shopper clicking through a
			// few filters) stays well under it, while enumeration abuse typically produces many
			// times this in the same window. Only page views count: AJAX, REST, form posts,
			// signed-in users and tracking-only query strings (utm_*, gclid, fbclid) do not.
			'query_cardinality_enabled' => true,
			'query_cardinality_max'     => 120,
			'query_cardinality_window'  => 600,

			// Brute force.
			'bruteforce_max'                   => 5,
			'bruteforce_window'                => 600,
			'bruteforce_lockout'               => 1800,
			'bruteforce_escalation_enabled'    => true,
			'bruteforce_escalation_multiplier' => 2,
			'bruteforce_escalation_cap'        => DAY_IN_SECONDS,
			'bruteforce_escalation_window'     => WEEK_IN_SECONDS,

			// DDoS shield.
			'ddos_enabled'        => true,
			'ddos_burst'          => 60,
			'ddos_window'         => 10,
			'ddos_ban'            => 900,

			// Bots.
			'block_empty_ua'      => false,
			'custom_bad_agents'   => array(),
			// Opt-in: generic HTTP libraries (curl, python-requests, Go) carry payment webhooks
			// and integrations, and SEO crawlers are tools many owners use on their own site.
			'block_http_clients'  => false,
			'block_seo_crawlers'  => false,

			// Verified bots (Googlebot, Bingbot, Facebook's crawler, etc.) — a claimed match is
			// forward-DNS-verified off the request path (see BotVerifier), then earns this more
			// generous rate-limit tier at step 5 instead of the everyday visitor limit above.
			'bot_verify_enabled'  => true,
			'bot_verify_requests' => 600,
			'bot_verify_window'   => 60,
			'bot_verify_ttl_days' => 30,
			// Builtin GOOD_AGENTS signatures the admin has removed trust from (see
			// CustomBotRules for the admin-added layer on top of this bundled baseline) — not
			// deleted, since it's not this site's data to delete, just excluded from the
			// trusted/verified-bot treatment.
			'disabled_builtin_bots' => array(),
			// Per-signature rate-limit overrides — `{ [signature]: {requests, window} }` — for a
			// verified bot that should get a tighter or looser tier than the shared
			// bot_verify_requests/window default. Applies to builtin and custom signatures alike;
			// absence of a key means "use the default". Set from the Bot Rules UI.
			'bot_rate_overrides'    => array(),

			// Public "Protected by" trust badge — opt-in (defaults off) since it's the one thing
			// this module renders on the site's own public-facing pages rather than just
			// wp-admin. Once enabled it defaults to a floating corner widget (no shortcode
			// needed, the same "just appears" pattern as a cookie-consent banner) — floating can
			// be switched off independently to fall back to shortcode-only manual placement. See
			// TrustBadge::render() / maybe_render_floating().
			'trust_badge_enabled'   => false,
			'trust_badge_floating'  => true,
			'trust_badge_position'  => 'bottom-right', // bottom-right | bottom-left.
			'trust_badge_style'     => 'dark', // dark | light — floating widget only; the shortcode has its own per-placement `style` attribute.

			// Geo.
			'geo_mode'            => 'off', // off | allow | block.
			'geo_countries'      => array(),

			// Virtual patching.
			'virtual_patching'    => true,

			// Explicit IP whitelist — these IPs bypass all checks including active bans.
			// Manually managed via the Settings UI; never auto-pruned.
			'ip_whitelist'        => array(),

			// Auto-added admin IPs (auto_whitelist_admins), stored as ip => last-seen epoch so
			// they can be aged out (TTL) and capped. Kept SEPARATE from ip_whitelist so the
			// admin's manual list is never touched by the auto-whitelist bookkeeping, and so this
			// self-maintaining set can't grow without bound. See maybe_whitelist_admin_ip().
			'auto_whitelist_ips'  => array(),

			// AJAX actions the admin has confirmed as legitimate (false-positive suppression).
			'ajax_action_whitelist' => array(),

		);
	}

	public function register_hooks(): void {
		// Public "Protected by" trust badge shortcode — always registered (not license/settings
		// gated), same reasoning as BotVerifier's cron: a lightweight, always-available utility.
		( new TrustBadge() )->register_hooks();

		// Keep the WAF config file in sync whenever settings change.
		add_action( 'update_option_' . LOYALSEC_OPTION_SETTINGS, array( $this, 'write_waf_config' ) );
		add_action( 'add_option_' . LOYALSEC_OPTION_SETTINGS, array( $this, 'write_waf_config' ) );

		// The exported config also carries an installed-plugins snapshot for the prepend's
		// virtual-patch engine (get_plugins() isn't available pre-WordPress) — refresh it
		// whenever that snapshot could go stale, not just on settings save.
		add_action( 'activated_plugin', array( $this, 'write_waf_config' ) );
		add_action( 'deactivated_plugin', array( $this, 'write_waf_config' ) );
		add_action( 'upgrader_process_complete', array( $this, 'write_waf_config' ) );

		// Keep the deployed Optimized-Mode bundle (uploads/loyal-security/waf-kernel/) in sync
		// with this plugin's own WAF kernel source whenever it could have changed. `init` is the
		// primary trigger, not these three — see maybe_resync_deployed_kernel()'s docblock for why.
		add_action( 'activated_plugin', array( $this, 'maybe_resync_deployed_kernel' ) );
		add_action( 'deactivated_plugin', array( $this, 'maybe_resync_deployed_kernel' ) );
		add_action( 'upgrader_process_complete', array( $this, 'maybe_resync_deployed_kernel' ) );

		// A synced 'waf' or 'patches' feed dataset doesn't need a config rewrite for its rules
		// (the prepend reads the feed cache file directly at request time), but the config is
		// still regenerated here to keep the installed-plugins snapshot and settings in lockstep
		// with each sync.
		add_action( 'loyalsec_feed_dataset_updated', array( $this, 'maybe_resync_waf_config' ), 10, 2 );

		// Drain pre-WordPress WAF events into the audit table (throttled).
		add_action( 'init', array( $this, 'reconcile_prepend_log' ), 99 );

		// Mark this site's requests to itself (WP-Cron, Site Health, loopback checks) so the
		// firewall can tell them from visitors even when they leave and come back through a
		// CDN or NAT with an address the server cannot see as its own.
		add_filter( 'http_request_args', array( $this, 'mark_loopback_request' ), 10, 2 );

		// Primary trigger for keeping the deployed Optimized-Mode bundle in sync — see
		// maybe_resync_deployed_kernel()'s docblock for why this, not the lifecycle hooks above,
		// is what this project's actual update workflow depends on.
		add_action( 'init', array( $this, 'maybe_resync_deployed_kernel' ) );

		// Rate-file GC piggybacks on the ban GC cron.
		add_action( \LoyalSecurity\Core\Cron::GC_BANS, array( $this, 'gc' ) );

		// Auto-whitelist admins on login so they can never lock themselves out.
		add_action( 'wp_login', array( $this, 'maybe_whitelist_admin_ip' ), 10, 2 );
	}

	public function boot(): void {
		$this->bans = new BanStore();
		$this->ip   = new IpResolver( $this->settings() );

		// Login brute-force protection (also gates banned IPs at the auth layer).
		( new BruteForce( $this->settings(), $this->bans, $this->ip, $this->logger() ) )->register_hooks();

		// Background bot-verification cron — unconditional, regardless of WAF mode (see the
		// class docblock: a site running Optimized Mode never executes inspect_request() below,
		// so this is the only place verification can live for every install).
		( new BotVerifier( $this->settings() ) )->register_hooks();

		// Standard-Mode request inspection runs on init (after the current user is known,
		// so trusted admins can be whitelisted). Optimized Mode does this in the prepend.
		if ( ! $this->is_optimized_active() ) {
			add_action( 'init', array( $this, 'inspect_request' ), 1 );
		}

		// A block on a REST call with Basic credentials waits until WordPress has checked them
		// (both modes: the prepend hands such blocks over the same way).
		add_filter( 'rest_authentication_errors', array( $this, 'resolve_deferred_block' ), 200 );
		add_action( 'wp', array( $this, 'resolve_deferred_block' ), 0 );
		$this->adopt_prepend_deferral();

		// The signed cookie that lets the pre-WordPress firewall recognise trusted users.
		( new TrustCookie( $this->settings() ) )->register_hooks();

		// require_auth virtual-patch rules ("block this route unless authenticated") can only
		// ever be enforced once WordPress knows who's logged in — unlike every other check,
		// that's not something Optimized Mode's pre-WordPress prepend can ever decide for
		// itself, no matter how the prepend evolves (VirtualPatch::evaluate() deliberately
		// skips require_auth rules everywhere — see match_auth_gate()). So this hook is
		// registered unconditionally, in BOTH modes: in Standard Mode inspect_request() never
		// touches these rules either, so this is their only enforcement path there too — not
		// just Optimized Mode's. Cheap when no such rules exist (one early-out array_filter).
		add_action( 'init', array( $this, 'enforce_auth_gate' ), 1 );
	}

	/**
	 * Whether the Optimized-Mode prepend is deployed AND can actually inspect this request.
	 *
	 * Fail-SAFE: it is not enough for the mode to be 'optimized' and the prepend marker to be
	 * defined — the prepend itself is fail-open, so if its config points at paths that don't
	 * exist on this filesystem (e.g. stale Windows paths copied from a dev box) it silently
	 * passes every request. In that case the prepend defines LOYALSEC_WAF_PREPEND but inspects
	 * nothing; if we also skipped registering the Standard `init` inspector the site would have
	 * ZERO inspection. So we only treat Optimized as active when the prepend's config resolves
	 * to a readable signatures file (and an existing src dir) here. Otherwise we report false,
	 * and boot() registers the Standard inspector as a fallback — the site is never silent.
	 *
	 * Result is cached for the request (one is_readable check).
	 */
	private function is_optimized_active(): bool {
		if ( null !== $this->optimized_active ) {
			return $this->optimized_active;
		}

		$active = false;
		if ( 'optimized' === get_option( 'loyalsec_waf_mode', 'standard' ) && defined( 'LOYALSEC_WAF_PREPEND' ) ) {
			$active = $this->prepend_can_inspect();
		}

		$this->optimized_active = $active;
		return $active;
	}

	/**
	 * Verify the prepend's config resolves to inspectable paths on THIS filesystem.
	 *
	 * Reads `prepend/waf-config.php` and confirms its `signatures_file` is readable and its
	 * `src_dir` is a directory — mirroring the prepend's own guard. Any miss (no config,
	 * unreadable, stale paths) means the prepend cannot inspect, so Optimized is not active.
	 */
	private function prepend_can_inspect(): bool {
		$config_file = $this->waf_config_path();
		if ( ! is_readable( $config_file ) ) {
			return false;
		}

		try {
			$config = include $config_file;
		} catch ( \Throwable $e ) {
			return false;
		}

		if ( ! is_array( $config ) ) {
			return false;
		}

		$signatures = isset( $config['signatures_file'] ) ? (string) $config['signatures_file'] : '';
		$src_dir    = isset( $config['src_dir'] ) ? (string) $config['src_dir'] : '';

		return '' !== $signatures && is_readable( $signatures )
			&& '' !== $src_dir && is_dir( $src_dir );
	}

	/* -------------------------- Admin auto-whitelist ---------------------------- */

	/**
	 * When an administrator logs in, remember their current IP (so a DDoS/rate-limit burst can
	 * never lock them out) and lift any active ban on it. The auto-added set is aged out and
	 * capped so it can never grow without bound — unlike the previous implementation, which
	 * appended one permanent entry per admin per (dynamic) IP into ip_whitelist forever, each
	 * bypassing ALL checks including bans, and rewrote the prepend config on every single login.
	 *
	 * @param string   $user_login Username (unused).
	 * @param \WP_User $user       The logged-in user object.
	 */
	public function maybe_whitelist_admin_ip( string $user_login, \WP_User $user ): void {
		if ( ! $this->setting( 'auto_whitelist_admins', true ) ) {
			return;
		}
		if ( ! user_can( $user, 'manage_options' ) ) {
			return;
		}

		$resolver = new IpResolver( $this->settings() );
		$ip       = $resolver->current();
		if ( ! $ip ) {
			return;
		}

		// Always lift any active ban for this IP first (e.g. triggered by a DDoS burst from load
		// tests). Cheap and unconditional — independent of the whitelist bookkeeping below.
		$bans = new BanStore();
		if ( $bans->is_banned( $ip ) ) {
			$bans->remove( $ip );
		}

		// Auto-whitelist bookkeeping, gated so the common case (a returning admin from the same
		// IP) does NOT rewrite settings/the prepend config. Persisted only when the set or the
		// (throttled) timestamps actually change.
		// Never allowlist a proxy's address (a Cloudflare edge or a configured trusted proxy):
		// when the real client IP can't be resolved the admin appears as the proxy, and
		// allowlisting it would let every visitor routed through that proxy skip the firewall.
		if ( $resolver->is_proxy( $ip ) || \LoyalSecurity\Support\Ip::behind_unknown_proxy( $ip, \LoyalSecurity\Support\RequestVars::ip_headers() ) ) {
			return;
		}

		$auto    = (array) $this->setting( 'auto_whitelist_ips', array() );
		$ttl     = (int) apply_filters( 'loyalsec_auto_whitelist_ttl', 30 * DAY_IN_SECONDS );
		$cap     = max( 1, (int) apply_filters( 'loyalsec_auto_whitelist_max', 25 ) );
		$now     = time();
		$changed = false;

		if ( ! isset( $auto[ $ip ] ) ) {
			$auto[ $ip ] = $now;
			$changed     = true;
		} elseif ( ( $now - (int) $auto[ $ip ] ) > DAY_IN_SECONDS ) {
			// Refresh the last-seen stamp at most once a day so an active admin's IP never
			// expires, without a settings write on every page-load-triggered login.
			$auto[ $ip ] = $now;
			$changed     = true;
		}

		// Prune entries past the TTL.
		$cutoff = $now - $ttl;
		foreach ( $auto as $k => $ts ) {
			if ( (int) $ts < $cutoff ) {
				unset( $auto[ $k ] );
				$changed = true;
			}
		}

		// Cap to the most-recent N.
		if ( count( $auto ) > $cap ) {
			arsort( $auto );
			$auto    = array_slice( $auto, 0, $cap, true );
			$changed = true;
		}

		if ( $changed ) {
			// Single write; triggers write_waf_config() once via update_option_loyalsec_settings.
			$this->settings()->update_module( 'firewall', array( 'auto_whitelist_ips' => $auto ) );
		}
	}

	/**
	 * The effective IP allowlist honoured by request inspection and baked into the prepend
	 * config: the admin's manual `ip_whitelist` plus every still-valid (non-expired) auto-added
	 * admin IP. Auto entries are filtered by TTL at read time too, so a lapsed one stops being
	 * trusted even before the next login prunes it from storage.
	 *
	 * @return string[]
	 */
	private function effective_ip_whitelist(): array {
		$manual = array_map( 'strval', (array) $this->setting( 'ip_whitelist', array() ) );

		$auto   = (array) $this->setting( 'auto_whitelist_ips', array() );
		$ttl    = (int) apply_filters( 'loyalsec_auto_whitelist_ttl', 30 * DAY_IN_SECONDS );
		$cutoff = time() - $ttl;
		$active = array();
		foreach ( $auto as $ip => $ts ) {
			if ( (int) $ts >= $cutoff ) {
				$active[] = (string) $ip;
			}
		}

		// Drop proxy addresses (Cloudflare edges, configured trusted proxies), including any
		// added before this check existed: each one carries many visitors' traffic, so an
		// allowlisted proxy lets all of them skip the firewall whenever the client IP is unresolved.
		$resolver = new IpResolver( $this->settings() );
		$list     = array_filter(
			array_unique( array_merge( $manual, $active ) ),
			static fn( $ip ) => ! $resolver->is_proxy( (string) $ip )
		);
		return array_values( $list );
	}

	/** Header carrying the loopback key on this site's requests to itself. */
	public const LOOPBACK_HEADER = 'X-LoyalSec-Loopback';

	/** Option holding the secret loopback key. */
	private const LOOPBACK_OPTION = 'loyalsec_loopback_key';

	/**
	 * `http_request_args`: add the secret loopback key to requests this site makes to its own
	 * address, and to no other host.
	 *
	 * @param array  $args Request arguments.
	 * @param string $url  Request URL.
	 * @return array
	 */
	public function mark_loopback_request( $args, $url ) {
		if ( ! is_array( $args ) || ! is_string( $url ) ) {
			return $args;
		}
		$host = wp_parse_url( $url, PHP_URL_HOST );
		if ( ! is_string( $host ) || '' === $host ) {
			return $args;
		}
		$own = array_filter(
			array(
				wp_parse_url( home_url(), PHP_URL_HOST ),
				wp_parse_url( site_url(), PHP_URL_HOST ),
			)
		);
		if ( ! in_array( strtolower( $host ), array_map( 'strtolower', $own ), true ) ) {
			return $args;
		}
		if ( ! isset( $args['headers'] ) || ! is_array( $args['headers'] ) ) {
			$args['headers'] = array();
		}
		$args['headers'][ self::LOOPBACK_HEADER ] = $this->loopback_key();
		return $args;
	}

	/**
	 * The secret that marks this site's requests to itself (created on first use).
	 */
	private function loopback_key(): string {
		$key = (string) get_option( self::LOOPBACK_OPTION, '' );
		if ( 32 > strlen( $key ) ) {
			$key = wp_generate_password( 40, false, false );
			update_option( self::LOOPBACK_OPTION, $key, true );
		}
		return $key;
	}

	/**
	 * Whether the current request carries this site's loopback key.
	 */
	private function is_marked_loopback( RequestContext $req ): bool {
		$sent = (string) ( $req->headers[ strtolower( self::LOOPBACK_HEADER ) ] ?? '' );
		return '' !== $sent && hash_equals( $this->loopback_key(), $sent );
	}

	/**
	 * Addresses of this server beyond the ones each request reports itself (SERVER_ADDR), for
	 * setups where loopback requests arrive from another address, such as a public IP behind NAT.
	 *
	 * @return string[]
	 */
	private function server_ips(): array {
		$ips = array();
		foreach ( array( 'SERVER_ADDR', 'LOCAL_ADDR' ) as $key ) {
			$value = \LoyalSecurity\Support\RequestVars::text( $key );
			if ( '' !== $value && \LoyalSecurity\Support\Ip::is_valid( $value ) ) {
				$ips[] = $value;
			}
		}
		/**
		 * Filters the addresses treated as this server, which skip the firewall's rate and
		 * query-cardinality limits (bans and content checks still apply).
		 *
		 * @since 1.5.0
		 *
		 * @param string[] $ips IP addresses.
		 */
		$ips = (array) apply_filters( 'loyalsec_server_ips', $ips );
		return array_values( array_unique( array_filter( array_map( 'strval', $ips ), array( \LoyalSecurity\Support\Ip::class, 'is_valid' ) ) ) );
	}

	/* -------------------------- Standard-Mode pipeline -------------------------- */

	/**
	 * Whether this is a command-line run (WP-CLI, a server cron script), not a web request.
	 * PHP_SAPI alone is not enough: WordPress Playground serves web requests through PHP's CLI
	 * SAPI, so checking only that left the firewall switched off there. A real command line
	 * has no HTTP request method.
	 */
	private static function is_command_line(): bool {
		return ( defined( 'WP_CLI' ) && WP_CLI )
			|| ( 'cli' === PHP_SAPI && '' === \LoyalSecurity\Support\RequestVars::text( 'REQUEST_METHOD' ) );
	}

	public function inspect_request(): void {
		if ( self::is_command_line() || wp_doing_cron() ) {
			return;
		}

		// Fail-safe: the WAF kernel classes live in src/Waf/. If those files weren't deployed
		// (e.g. a partial SFTP sync), skip inspection silently rather than fataling the site.
		if ( ! class_exists( RequestContext::class ) ) {
			return;
		}

		// The rest of this method is wrapped fail-open: a security plugin must never be the
		// thing that takes the whole site down. A missing/broken dependency anywhere below
		// (e.g. a partially-deployed src/Waf/ class) now logs and lets the request through
		// instead of fataling every single page load — this exact class of bug (an uncaught
		// Error from a missing class deep in this call chain) previously had no safety net past
		// the RequestContext check above. wp_die() in block()/maybe_block() still terminates the
		// script immediately via exit() either way — that's not a throwable, so it's unaffected.
		try {
			$this->inspect_request_unsafe();
		} catch ( \Throwable $e ) {
			\LoyalSecurity\Support\Debug::log( 'WAF inspection failed, failing open: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine() );
		}
	}

	/**
	 * The actual inspection pipeline — split out so {@see inspect_request()} can wrap it in a
	 * single fail-open try/catch.
	 */
	private function inspect_request_unsafe(): void {
		$ip    = $this->ip->current();
		$audit = (bool) $this->setting( 'detection_only', false );

		// Explicit IP whitelist bypasses all checks, including active bans.
		$whitelist = $this->effective_ip_whitelist();
		if ( in_array( $ip, $whitelist, true ) ) {
			return;
		}

		// Loopback requests (wp_remote_get/post server-to-self — the CSP scanner, backup
		// engine, setup probe, or a third-party plugin's own self-test tool) skip only the
		// *behavioural* checks below (bot/geo/ddos/rate-limit), which are prone to
		// false-positiving on legitimate automated internal callers. They do NOT skip the ban
		// check, virtual patching, or signature inspection: a request carrying an actual
		// malicious payload is just as dangerous bounced through localhost (e.g. an SSRF
		// vulnerability making the server request itself) as one arriving directly from the
		// internet — only the "looks abusive in volume/behaviour" signals are safe to relax for
		// a trusted internal caller. Was previously an unconditional early return, which meant
		// any loopback-originating request — attacker-driven SSRF included — bypassed the WAF
		// entirely.
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) ) : '';
		$is_loopback = in_array( $remote_addr, array( '127.0.0.1', '::1' ), true );

		// When the client IP can't be resolved it falls back to the shared sentinel 0.0.0.0.
		// Enforcing IP-keyed checks (bans, rate-limit, DDoS) against that sentinel would pool
		// every unresolved request into ONE bucket — one such request tripping a limit would
		// ban/throttle all of them. Skip the IP-keyed checks for an unresolved IP; the
		// content-based signature + virtual-patch inspection below still runs (it isn't IP-keyed).
		$ip_unresolved = ( '' === $ip || '0.0.0.0' === $ip );
		// Behind a proxy that is not in Trusted proxies every visitor shares the proxy's internal
		// address: that is no more a visitor's address than the sentinel is. (The plugin screens
		// show a notice asking the owner to add the proxy.)
		$ip_unresolved = $ip_unresolved || \LoyalSecurity\Support\Ip::behind_unknown_proxy( $ip, \LoyalSecurity\Support\RequestVars::ip_headers() );

		// Strip WordPress magic-quotes: this runs on `init`, after wp_magic_quotes() has
		// slashed GET/POST/COOKIE and $_SERVER['REQUEST_URI'], so the engine must inspect the
		// un-escaped client bytes or every quote-based payload (e.g. 1' OR '1'='1) bypasses it.
		// The Optimized-Mode prepend runs pre-WordPress on raw input and keeps the default false.
		[ $trust, $ranges ] = ( new IpResolver( $this->settings() ) )->trust();
		$req                = RequestContext::capture( $trust, $ranges, true );

		// Also this server's own address: loopback requests often arrive on it rather than on
		// 127.0.0.1 (and behind a CDN they come back through it with the server's address).
		// Only when the visitor is the direct peer, though: behind a trusted proxy on this server
		// (nginx in front of Apache, Varnish) every visitor arrives from 127.0.0.1, and treating
		// them all as the server itself switched the volume and bot checks off for everyone.
		$server_ips  = $this->server_ips();
		$is_loopback = ( $ip === $remote_addr && ( $is_loopback || $req->from_own_server( $server_ips ) ) )
			|| in_array( $ip, $server_ips, true )
			|| $this->is_marked_loopback( $req );

		// 1) Active bans are always enforced — even in audit mode. Bans represent explicit
		//    admin intent (manual ban or DDoS-shield response), not heuristic detections.
		//    Skipped only for an unresolved IP (would match a ban on the shared 0.0.0.0 sentinel).
		if ( ! $ip_unresolved && $this->bans->is_banned( $ip ) ) {
			$this->block( 'waf.ban.added', array( 'reason' => 'active_ban', 'ip' => $ip ), 403 );
		}

		// Trusted-user bypass for the remaining heuristic checks: administrators, and editors
		// who may post unfiltered HTML anyway (blocking an editor's embed protects nothing).
		if ( $this->setting( 'whitelist_admins', true ) && self::is_trusted_user() ) {
			return;
		}

		// REST calls with Basic credentials (application passwords, WooCommerce API keys) are
		// authenticated after `init`; a block for those waits until the user is known.
		$this->defer_eligible = $this->setting( 'whitelist_admins', true ) && $this->is_basic_auth_rest( $req );

		// Steps 2–7 all route through maybe_block(). In protect mode it calls block() and
		// terminates. In audit (detection_only) mode it logs the hit and returns, so every
		// subsequent check also runs and is logged — giving a complete picture of what would
		// have been blocked on a real request.

		// Steps 2–5 are behavioural/volume heuristics — skipped for loopback-originating
		// requests (see the note above `$is_loopback`) and for an unresolved IP (they all key on
		// the client IP). Steps 6–7 (content-based) always run.
		if ( ! $is_loopback && ! $ip_unresolved ) {
			// 2) Bad bots.
			$bot    = new BotBlocker( $this->settings() );
			$reason = $bot->evaluate( $req->user_agent );
			if ( $reason ) {
				$this->maybe_block( $audit, EventCatalog::WAF_BOT_BLOCK, array( 'reason' => $reason, 'ip' => $ip, 'user_agent' => $req->user_agent ), 403 );
			}
			// A cached, forward-confirmed verdict for a known-good crawler — never a live DNS
			// lookup (see BotBlocker::verified_bot_signature()) — earns the more generous rate
			// tier at step 5 below instead of the everyday visitor limit.
			$verified_bot = $bot->verified_bot_signature( $req->user_agent, $ip );

			// 3) Geo.
			$geo = new GeoBlocker( $this->settings() );

			$reason = $geo->evaluate( $ip, \LoyalSecurity\Support\RequestVars::geo_headers() );
			if ( $reason ) {
				$this->maybe_block( $audit, EventCatalog::WAF_GEO_BLOCK, array( 'reason' => $reason, 'ip' => $ip ), 403 );
			}

			// 4) DDoS burst.
			$ddos   = new DdosShield( $this->settings(), new RateLimiter(), $this->bans );
			$reason = $ddos->evaluate( $ip );
			if ( $reason ) {
				$this->maybe_block( $audit, EventCatalog::WAF_DDOS, array( 'reason' => $reason, 'ip' => $ip ), 429 );
			}

			// 5) Steady-state rate limit — verified bots get their own, more generous tier
			//    instead of the everyday visitor limit (previously they got no concession at
			//    all once past step 2, so a legitimate high-crawl-rate Googlebot pass could be
			//    throttled identically to any other visitor).
			if ( $this->setting( 'rate_limit_enabled', true ) ) {
				if ( $verified_bot ) {
					// A per-signature override (set from the Bot Rules UI) takes priority over
					// the flat bot_verify_requests/window default shared by every verified bot —
					// e.g. a custom bot the admin trusts less than Googlebot can get a tighter
					// tier without affecting anyone else's.
					$overrides = (array) $this->setting( 'bot_rate_overrides', array() );
					$override  = $overrides[ $verified_bot ] ?? null;
					if ( is_array( $override ) && isset( $override['requests'], $override['window'] ) ) {
						$rl_limit  = (int) $override['requests'];
						$rl_window = (int) $override['window'];
					} else {
						$rl_limit  = (int) $this->setting( 'bot_verify_requests', 600 );
						$rl_window = (int) $this->setting( 'bot_verify_window', 60 );
					}
				} else {
					$rl_limit  = (int) $this->setting( 'rate_limit_requests', 240 );
					$rl_window = (int) $this->setting( 'rate_limit_window', 60 );
				}
				$rl = ( new RateLimiter() )->hit( $ip, $rl_limit, $rl_window );
				if ( ! empty( $rl['exceeded'] ) ) {
					$this->maybe_block( $audit, EventCatalog::WAF_RATE_LIMIT, array( 'count' => $rl['count'], 'ip' => $ip, 'verified_bot' => $verified_bot ), 429 );
				}
			}

			// 5b) Query-cardinality limiter — distinct filter/search combinations, not request
			// volume (see FileStore::hit_distinct()'s docblock for why this is a separate check
			// from step 5's plain rate limit above).
			if ( $this->setting( 'query_cardinality_enabled', true ) && ! is_user_logged_in() ) {
				$signature = \LoyalSecurity\Waf\QueryCardinality::signature( $req, $this->rest_path_prefix() );
				if ( '' !== $signature ) {
					$qc = ( new \LoyalSecurity\Waf\FileStore( BanStore::storage_dir() ) )->hit_distinct(
						$ip,
						$signature,
						(int) $this->setting( 'query_cardinality_max', 120 ),
						(int) $this->setting( 'query_cardinality_window', 600 )
					);
					if ( ! empty( $qc['exceeded'] ) ) {
						$this->maybe_block( $audit, EventCatalog::WAF_QUERY_CARDINALITY, array( 'count' => $qc['count'], 'ip' => $ip ), 429 );
					}
				}
			}
		}

		// 6) Virtual patching — base rules merged with remote feed patches.
		if ( $this->setting( 'virtual_patching', true ) ) {
			$vp   = new VirtualPatch( $this->merged_virtual_patch_rules(), $this->installed_plugins_map() );
			$rule = $vp->evaluate( $req );
			if ( $rule ) {
				$this->maybe_block( $audit, EventCatalog::WAF_VIRTUAL_PATCH, array( 'rule' => $rule, 'ip' => $ip ), 403 );
			}
		}

		// 7) Signature inspection — base ruleset merged with remote feed WAF rules.
		$kernel   = new Kernel(
			$this->merged_signature_set(),
			array(
				'threshold'      => (int) $this->setting( 'threshold', 12 ),
				'disabled_rules' => (array) $this->setting( 'disabled_rules', array() ),
				'allow_params'   => (array) $this->setting( 'allow_params', array() ),
				'site_host'      => $this->site_host(),
			)
		);
		$decision = $kernel->inspect( $req );
		if ( $decision->blocked ) {
			$ctx = array_merge( $decision->to_context(), array( 'ip' => $ip ) );
			$this->maybe_block( $audit, EventCatalog::WAF_BLOCK, $ctx, (int) $this->setting( 'block_status', 403 ) );
		} elseif ( $decision->score > 0 ) {
			/**
			 * An allowed-but-suspicious ("near miss") request: it scored on the WAF but stayed
			 * below the block threshold, so it is being let through. The bypass-telemetry module
			 * subscribes (only when the admin has opted in) to record an anonymized snapshot, so
			 * that if this request later proves to have planted malware we can report exactly what
			 * slipped past the firewall. No-op when nothing is listening.
			 *
			 * @since 1.2.0
			 *
			 * @param RequestContext $req      The captured request.
			 * @param Decision       $decision The WAF decision (score below threshold).
			 */
			do_action( 'loyalsec_waf_near_miss', $req, $decision );
		}
	}

	/**
	 * Enforces require_auth virtual-patch rules — "block this plugin's route unless the
	 * visitor is authenticated" — on every request, in both Standard and Optimized Mode alike.
	 *
	 * This exists as its own always-on hook, separate from inspect_request(), specifically
	 * because it needs `is_user_logged_in()`/`current_user_can()`, which require WordPress to
	 * be booted. The pre-WordPress prepend can never answer that question no matter how it
	 * evolves, so unlike every other virtual-patch rule (content-matched, evaluated pre-boot
	 * by the prepend in Optimized Mode) this class of rule is enforced here, post-boot, for
	 * every request regardless of which mode is otherwise handling everything else — the one
	 * deliberate exception to "Optimized Mode does the WAF work pre-boot."
	 */
	public function enforce_auth_gate(): void {
		if ( self::is_command_line() || wp_doing_cron() ) {
			return;
		}
		if ( ! class_exists( RequestContext::class ) || ! class_exists( VirtualPatch::class ) ) {
			return;
		}
		try {
			$this->enforce_auth_gate_unsafe();
		} catch ( \Throwable $e ) {
			\LoyalSecurity\Support\Debug::log( 'Auth-gate enforcement failed, failing open: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine() );
		}
	}

	private function enforce_auth_gate_unsafe(): void {
		if ( ! $this->setting( 'virtual_patching', true ) ) {
			return;
		}

		// Explicit IP whitelist bypasses all checks here too, same as inspect_request_unsafe().
		$ip = $this->ip->current();
		if ( in_array( $ip, $this->effective_ip_whitelist(), true ) ) {
			return;
		}

		$rules = array_values( array_filter(
			$this->merged_virtual_patch_rules(),
			static fn( $r ) => is_array( $r ) && ! empty( $r['require_auth'] )
		) );
		if ( ! $rules ) {
			return; // No auth-gated rules configured — skip building a request context at all.
		}

		[ $trust, $ranges ] = ( new IpResolver( $this->settings() ) )->trust();
		$req                = RequestContext::capture( $trust, $ranges, true );
		$rule = ( new VirtualPatch( $rules, $this->installed_plugins_map() ) )->match_auth_gate( $req );
		if ( null === $rule ) {
			return;
		}

		$audit = (bool) $this->setting( 'detection_only', false );
		$this->maybe_block(
			$audit,
			EventCatalog::WAF_VIRTUAL_PATCH,
			array( 'rule' => $rule, 'ip' => $ip, 'reason' => 'unauthenticated_privileged_route' ),
			403
		);
	}

	/**
	 * In protect mode: log and terminate with a block response.
	 * In audit (detection_only) mode: log only, allow the request to continue.
	 *
	 * Active bans always call block() directly — they're explicit admin intent and are
	 * enforced regardless of mode.
	 *
	 * @param bool                 $audit   True when detection_only is enabled.
	 * @param string               $type    EventCatalog event type.
	 * @param array<string, mixed> $context Structured log context.
	 * @param int                  $status  HTTP status code for the block response.
	 */
	private function maybe_block( bool $audit, string $type, array $context, int $status ): void {
		// Extension point for signature/virtual-patch blocks. Fired here — before the dispatch
		// branch — because block() ends the request via wp_die().
		if ( EventCatalog::WAF_BLOCK === $type || EventCatalog::WAF_VIRTUAL_PATCH === $type ) {
			/**
			 * Fires on a WAF signature or virtual-patch block.
			 *
			 * @since 1.2.0
			 *
			 * @param string              $type    EventCatalog event type.
			 * @param array<string,mixed> $context Block context (rule, category, matches…).
			 */
			do_action( 'loyalsec_cloud_reputation_waf', $type, $context );
		}

		if ( $audit ) {
			$this->logger()->log( $type, array_merge( $context, array( 'audit_only' => true ) ) );
			return;
		}
		if ( $this->defer_eligible && in_array( $type, self::DEFERRABLE, true ) ) {
			// The first content or bot decision is held until the Basic credentials are checked;
			// volume limits (rate, DDoS, query) never wait.
			if ( null === $this->deferred ) {
				$this->deferred = array( $type, $context, $status );
			}
			return;
		}
		$this->block( $type, $context, $status );
	}

	/** Block types that can wait for a REST call's Basic credentials to be checked. */
	private const DEFERRABLE = array( EventCatalog::WAF_BLOCK, EventCatalog::WAF_VIRTUAL_PATCH, EventCatalog::WAF_BOT_BLOCK );

	/**
	 * Whether the current user is trusted by the firewall: an administrator, or a user who may
	 * post unfiltered HTML (editors on a single site).
	 */
	public static function is_trusted_user(): bool {
		return current_user_can( 'manage_options' ) || current_user_can( 'unfiltered_html' );
	}

	/**
	 * Whether a request is a REST API call carrying HTTP Basic credentials.
	 *
	 * @param RequestContext $req The request.
	 */
	private function is_basic_auth_rest( RequestContext $req ): bool {
		$auth = (string) ( $req->headers['authorization'] ?? '' );
		if ( 0 !== stripos( $auth, 'basic ' ) && '' === \LoyalSecurity\Support\RequestVars::text( 'PHP_AUTH_USER' ) ) {
			return false;
		}
		return isset( $req->get['rest_route'] ) || false !== strpos( strtolower( $req->path ), strtolower( $this->rest_path_prefix() ) );
	}

	/**
	 * The REST API's path prefix on this site, e.g. "/wp-json/".
	 */
	private function rest_path_prefix(): string {
		$path = (string) wp_parse_url( get_rest_url(), PHP_URL_PATH );
		return '' === $path ? '/wp-json/' : trailingslashit( $path );
	}

	/**
	 * Settle a block that waited for a REST call's credentials. Runs on `rest_authentication_errors`
	 * (after WordPress has checked application passwords; WooCommerce checks its keys earlier) and,
	 * for a request that never reached the REST API, on `wp`.
	 *
	 * @param mixed $result Authentication result, passed through.
	 * @return mixed
	 */
	public function resolve_deferred_block( $result = null ) {
		if ( null === $this->deferred ) {
			return $result;
		}
		[ $type, $context, $status ] = $this->deferred;
		$this->deferred              = null;
		if ( is_user_logged_in() && self::is_trusted_user() && ! is_wp_error( $result ) ) {
			return $result;
		}
		$this->block( $type, $context, $status );
		return $result;
	}

	/**
	 * Take over a block the Optimized-Mode prepend handed to WordPress because the request was
	 * a REST call with Basic credentials. The prepend records it in a global only it sets.
	 */
	private function adopt_prepend_deferral(): void {
		$handed = $GLOBALS['loyalsec_waf_deferred'] ?? null;
		if ( ! is_array( $handed ) || ! isset( $handed['type'] ) ) {
			return;
		}
		unset( $GLOBALS['loyalsec_waf_deferred'] );
		$type = (string) $handed['type'];
		if ( ! in_array( $type, self::DEFERRABLE, true ) ) {
			return;
		}
		$context        = is_array( $handed['context'] ?? null ) ? $handed['context'] : array();
		$this->deferred = array( $type, array_merge( $context, array( 'via' => 'prepend' ) ), (int) ( $handed['status'] ?? 403 ) );
	}

	/* ----------------------- Signature merge helpers ----------------------- */

	/**
	 * Build a SignatureSet from the base data file merged with any cached remote rules.
	 * Fail-open: if the remote file is missing or corrupt, base rules are used alone.
	 */
	private function merged_signature_set(): SignatureSet {
		$base_file = LOYALSEC_PATH . 'data/waf-signatures.php';
		$base_data = is_file( $base_file ) ? include $base_file : array();
		$base_rules  = isset( $base_data['rules'] ) && is_array( $base_data['rules'] ) ? $base_data['rules'] : array();
		$base_version = isset( $base_data['version'] ) ? (string) $base_data['version'] : '';

		try {
			if ( class_exists( \LoyalSecurity\Modules\ThreatIntel\FeedStore::class ) ) {
				$remote = ( new \LoyalSecurity\Modules\ThreatIntel\FeedStore() )->get_rules( 'waf' );
				if ( is_array( $remote ) && ! empty( $remote ) ) {
					$base_rules = array_merge( $base_rules, $remote );
				}
			}
		} catch ( \Throwable $e ) {
			// Fail open — remote merge is best-effort.
		}

		return new SignatureSet( $base_rules, $base_version );
	}

	/**
	 * Rules shipped with the plugin itself (data/virtual-patches.php) — one of the two sources
	 * bundled_and_feed_virtual_patch_rules() combines and list_virtual_patches() tags 'bundled'.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function bundled_virtual_patch_rules(): array {
		$base_file = LOYALSEC_PATH . 'data/virtual-patches.php';
		$base_data = is_file( $base_file ) ? include $base_file : array();
		return isset( $base_data['rules'] ) && is_array( $base_data['rules'] ) ? $base_data['rules'] : array();
	}

	/**
	 * Rules synced down through the ThreatIntel `patches` cloud feed — the other of the two
	 * sources bundled_and_feed_virtual_patch_rules() combines and list_virtual_patches() tags
	 * 'feed'. Fail-open: an absent/corrupt cache yields an empty list, not an error.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function feed_virtual_patch_rules(): array {
		try {
			if ( class_exists( \LoyalSecurity\Modules\ThreatIntel\FeedStore::class ) ) {
				$remote = ( new \LoyalSecurity\Modules\ThreatIntel\FeedStore() )->get_rules( 'patches' );
				if ( is_array( $remote ) ) {
					return $remote;
				}
			}
		} catch ( \Throwable $e ) {
			// Fail open.
		}
		return array();
	}

	/**
	 * Raw bundled + cached-remote-feed virtual-patch rules, untouched by local overrides —
	 * used by merged_virtual_patch_rules() (enforcement), which doesn't need to distinguish
	 * the two sources. list_virtual_patches() (management UI) calls the two fetchers above
	 * separately instead, since it needs to tag each rule with which one it came from.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function bundled_and_feed_virtual_patch_rules(): array {
		return array_merge( $this->bundled_virtual_patch_rules(), $this->feed_virtual_patch_rules() );
	}

	/**
	 * Index of every local (admin-reviewed) virtual-patch rule by id — the dashboard's source
	 * of truth for enabled/disabled state. Last one wins on an accidental duplicate id within
	 * the local list itself.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function local_virtual_patch_rules(): array {
		$local = array();
		foreach ( ( new CustomVirtualPatches() )->all() as $rule ) {
			$id = (string) ( $rule['id'] ?? '' );
			if ( '' !== $id ) {
				$local[ $id ] = $rule;
			}
		}
		return $local;
	}

	/**
	 * Return virtual-patch rules from the base data file merged with any cached remote patches
	 * and this site's local (admin-reviewed) rules — de-duplicated by rule id so the same rule
	 * is never enforced twice, and so a local verdict on an id always wins over a bundled/feed
	 * copy of it. Also honours 'disabled_virtual_patches' — an explicit per-id override for a
	 * bundled/feed rule that was never locally suggested, so has no CustomVirtualPatches record
	 * to toggle instead (see set_virtual_patch_disabled()).
	 *
	 * The local list is the one an admin can actually see and toggle from the dashboard
	 * (Firewall → Virtual Patches), so it must be authoritative for any id it has an opinion
	 * on. Without this, an auto-suggested rule that gets approved locally AND later
	 * redistributed back down through the ThreatIntel `patches` feed (see
	 * PatchSuggester::suggest_auth_gate() / docs/licensekit-patch-suggestions.md — the feed
	 * copy is how other sites running the same vulnerable plugin get the fix too) leaves the
	 * admin with no way to actually turn it off: disabling the local copy only removes that
	 * one entry, while the feed's identical-id copy — invisible in this dashboard, sourced
	 * from a file this class merges in unconditionally — keeps enforcing it. Confirmed live
	 * 2026-07-13: disabling `vp-auto-authgate-*` locally left the site still 403ing every
	 * anonymous visitor because the feed cache carried the same id.
	 *
	 * A purely bundled/feed rule (never locally suggested) has the opposite blind spot: with
	 * no local record at all, there was previously no lever to disable it short of the
	 * site-wide `virtual_patching` master switch. `disabled_virtual_patches` closes that gap.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function merged_virtual_patch_rules(): array {
		$base_rules = $this->bundled_and_feed_virtual_patch_rules();
		$local      = $this->local_virtual_patch_rules();

		// Explicit per-id disables — the only lever for a bundled/feed rule that has no local
		// record (an admin can't toggle CustomVirtualPatches for an id it's never heard of).
		$disabled_ids = array_flip( array_map( 'strval', (array) $this->setting( 'disabled_virtual_patches', array() ) ) );

		// A bundled/feed rule whose id the local list already has an opinion on is dropped
		// here — enabled or disabled, the local copy is authoritative and takes its place
		// below, so the two sources never coexist as duplicate entries for the same id. A
		// bundled/feed rule with no local record but an explicit disabled_virtual_patches
		// entry is dropped too.
		$base_rules = array_values( array_filter(
			$base_rules,
			static function ( $rule ) use ( $local, $disabled_ids ) {
				$id = (string) ( $rule['id'] ?? '' );
				return ! isset( $local[ $id ] ) && ! isset( $disabled_ids[ $id ] );
			}
		) );

		// Add back only the ENABLED local rules (and only if not ALSO explicitly disabled by
		// id — belt-and-suspenders against the two mechanisms ever disagreeing on the same
		// id). Disabled ones must stay excluded here too — not just at the UI layer — so a
		// toggle takes effect immediately, for both a purely local rule and one that also
		// exists in the feed cache.
		$base_rules = array_merge(
			$base_rules,
			array_values( array_filter(
				$local,
				static function ( $rule ) use ( $disabled_ids ) {
					return ! empty( $rule['enabled'] ) && ! isset( $disabled_ids[ (string) ( $rule['id'] ?? '' ) ] );
				}
			) )
		);

		return $base_rules;
	}

	/**
	 * Every virtual-patch rule from every source, for the Firewall → Virtual Patches
	 * management UI — unlike merged_virtual_patch_rules() (the enforcement path, which only
	 * returns what's actually active), this returns bundled and feed-sourced rules even when
	 * a local record shadows or explicitly disables them, so the dashboard has something to
	 * show and toggle for a rule an admin never locally suggested.
	 *
	 * Each rule gets an `origin` (`local` | `bundled` | `feed`) and, for bundled/feed rules, a
	 * computed `enabled` (local rules already carry their own from CustomVirtualPatches).
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function list_virtual_patches(): array {
		$local        = $this->local_virtual_patch_rules();
		$disabled_ids = array_flip( array_map( 'strval', (array) $this->setting( 'disabled_virtual_patches', array() ) ) );

		$items = array();
		foreach ( array( 'bundled' => $this->bundled_virtual_patch_rules(), 'feed' => $this->feed_virtual_patch_rules() ) as $origin => $rules ) {
			foreach ( $rules as $rule ) {
				$id = (string) ( $rule['id'] ?? '' );
				if ( '' === $id || isset( $local[ $id ] ) ) {
					continue; // The local record (below) represents this id instead.
				}
				$rule['origin']  = $origin;
				$rule['enabled'] = ! isset( $disabled_ids[ $id ] );
				$items[]         = $rule;
			}
		}

		foreach ( $local as $rule ) {
			$rule['origin'] = 'local';
			$items[]        = $rule; // 'enabled' already set by CustomVirtualPatches::all().
		}

		return $items;
	}

	/**
	 * Enable/disable a bundled or feed-sourced virtual-patch rule that has no local
	 * (CustomVirtualPatches) record — the only override available for a rule an admin never
	 * locally suggested (see merged_virtual_patch_rules()'s docblock). No-op-safe to call for
	 * any id; validate against list_virtual_patches() first if a 404 is wanted for unknown ids.
	 */
	public function set_virtual_patch_disabled( string $id, bool $disabled ): void {
		$ids = array_values( array_unique( array_map( 'strval', (array) $this->setting( 'disabled_virtual_patches', array() ) ) ) );
		$has = in_array( $id, $ids, true );
		if ( $disabled && ! $has ) {
			$ids[] = $id;
		} elseif ( ! $disabled && $has ) {
			$ids = array_values( array_diff( $ids, array( $id ) ) );
		}
		$this->settings()->set( $this->id(), 'disabled_virtual_patches', $ids );
	}

	/**
	 * Whether a bundled or feed-sourced virtual-patch rule with this id exists (used by
	 * FirewallController::toggle_virtual_patch() to validate an id before accepting a
	 * disabled_virtual_patches override for it).
	 */
	public function bundled_or_feed_virtual_patch_exists( string $id ): bool {
		foreach ( $this->bundled_and_feed_virtual_patch_rules() as $rule ) {
			if ( ( $rule['id'] ?? '' ) === $id ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Map of installed plugin slug => version. `get_plugins()` is WordPress-only, so this can
	 * only run in Standard Mode; the prepend instead reads the snapshot this bakes into
	 * `waf-config.php` at the last {@see write_waf_config()} run.
	 *
	 * @return array<string, string>
	 */
	private function installed_plugins_map(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$map = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug         = dirname( $file );
			$slug         = ( '.' === $slug ) ? basename( $file, '.php' ) : $slug;
			$map[ $slug ] = isset( $data['Version'] ) ? (string) $data['Version'] : '0';
		}
		return $map;
	}

	/**
	 * This site's own hostname, from `home_url()` — the WordPress-configured value, not the
	 * request's Host header (which is client-supplied and must never be trusted for a security
	 * exemption check). Used by 'same_host_exempt' WAF rules; see {@see export_waf_config()}.
	 */
	private function site_host(): string {
		return strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	}

	/**
	 * Compares the live database state of virtual-patch config against what's actually on disk
	 * in `prepend/waf-config.php` right now — read the exact same way (a plain `include`) the
	 * prepend itself reads it, so a mismatch here is definitive proof of an OPcache-staleness
	 * problem (or a load-balanced/multi-server setup where this server's `opcache_invalidate()`
	 * never reached the server that actually served the attack request) rather than a guess.
	 *
	 * @return array<string, mixed>
	 */
	public function debug_virtual_patch_state(): array {
		// active() to match what export_waf_config() actually bakes onto disk — a disabled
		// rule showing up as "out of sync" here would be a false alarm, not a real gap.
		$live_custom           = ( new CustomVirtualPatches() )->active();
		$live_virtual_patching = (bool) $this->setting( 'virtual_patching', true );
		$live_installed        = $this->installed_plugins_map();

		$path    = $this->waf_config_path();
		$on_disk = array(
			'file_exists'       => is_file( $path ),
			'custom_patches'    => array(),
			'virtual_patching'  => null,
			'installed_plugins' => array(),
		);
		if ( $on_disk['file_exists'] ) {
			try {
				$cfg = include $path;
				if ( is_array( $cfg ) ) {
					$on_disk['custom_patches']    = isset( $cfg['custom_patches'] ) && is_array( $cfg['custom_patches'] ) ? $cfg['custom_patches'] : array();
					$on_disk['virtual_patching']  = isset( $cfg['virtual_patching'] ) ? (bool) $cfg['virtual_patching'] : null;
					$on_disk['installed_plugins'] = isset( $cfg['installed_plugins'] ) && is_array( $cfg['installed_plugins'] ) ? $cfg['installed_plugins'] : array();
				}
			} catch ( \Throwable $e ) {
				$on_disk['error'] = $e->getMessage();
			}
		}

		$live_ids = array_values( array_map( static fn( $r ) => (string) ( $r['id'] ?? '' ), $live_custom ) );
		$disk_ids = array_values( array_map( static fn( $r ) => (string) ( $r['id'] ?? '' ), $on_disk['custom_patches'] ) );
		sort( $live_ids );
		sort( $disk_ids );

		return array(
			'optimized_active'  => $this->is_optimized_active(),
			'file_exists'       => $on_disk['file_exists'],
			'virtual_patching'  => array( 'live' => $live_virtual_patching, 'on_disk' => $on_disk['virtual_patching'] ),
			'custom_patches'    => array(
				'live_count'    => count( $live_custom ),
				'on_disk_count' => count( $on_disk['custom_patches'] ),
				'live_ids'      => $live_ids,
				'on_disk_ids'   => $disk_ids,
				'in_sync'       => $live_ids === $disk_ids,
			),
			'installed_plugins' => array(
				'live_count'    => count( $live_installed ),
				'on_disk_count' => count( $on_disk['installed_plugins'] ),
			),
		);
	}

	/**
	 * Log a block, emit a response, and terminate.
	 *
	 * @param string               $type    Event type.
	 * @param array<string, mixed> $context Context.
	 * @param int                  $status  HTTP status.
	 */
	private function block( string $type, array $context, int $status ): void {
		$this->logger()->log( $type, $context );

		if ( ! headers_sent() ) {
			status_header( $status );
			nocache_headers();
			header( 'X-LoyalSec-WAF: blocked' );
			if ( 429 === $status ) {
				header( 'Retry-After: 60' );
			}
		}

		$ref    = isset( $context['rule'] ) ? (string) $context['rule'] : ( isset( $context['reason'] ) ? (string) $context['reason'] : 'policy' );
		$credit = false;
		if ( 0 === strpos( $ref, 'geo_' ) ) {
			// The visitor's country stays in the log; the page shows only the kind of rule.
			$ref    = (string) strtok( $ref, ':' );
			$credit = (bool) $this->setting( 'geo_credit_on_block_page', false );
		}
		wp_die(
			sprintf(
				'<h1>%s</h1><p>%s</p><p><code>ref: %s</code></p>',
				esc_html__( 'Request blocked', 'loyal-security' ),
				esc_html__( 'This request was blocked by the Loyal Security firewall.', 'loyal-security' ),
				esc_html( $ref )
			) . ( $credit ? '<p><small><a href="' . esc_url( 'https://db-ip.com' ) . '" rel="noopener">' . esc_html__( 'IP Geolocation by DB-IP', 'loyal-security' ) . '</a></small></p>' : '' ),
			esc_html__( 'Request blocked', 'loyal-security' ),
			array( 'response' => absint( $status ) )
		);
	}

	/* ----------------------------- Maintenance ----------------------------- */

	/**
	 * Pull events recorded by the pre-WordPress prepend into the audit table. Throttled to
	 * once per minute to avoid contending on the log file.
	 */
	public function reconcile_prepend_log(): void {
		if ( get_transient( 'loyalsec_waf_reconcile_lock' ) ) {
			return;
		}
		set_transient( 'loyalsec_waf_reconcile_lock', 1, 60 );

		$dir = BanStore::storage_dir();
		if ( ! $dir || ! is_dir( $dir ) ) {
			return;
		}
		$events = ( new WafLogger( $dir ) )->drain();
		if ( ! $events ) {
			return;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'loyalsec_events';
		foreach ( $events as $ev ) {
			$type = isset( $ev['type'] ) ? (string) $ev['type'] : EventCatalog::WAF_BLOCK;
			$data = array(
				'event_type'  => $type,
				'severity'    => EventCatalog::default_severity( $type ),
				'user_id'     => 0,
				'ip'          => isset( $ev['ip'] ) ? (string) $ev['ip'] : '',
				'method'      => isset( $ev['method'] ) ? (string) $ev['method'] : '',
				'request_uri' => isset( $ev['uri'] ) ? (string) $ev['uri'] : '',
				'user_agent'  => isset( $ev['ua'] ) ? (string) $ev['ua'] : '',
				'context'     => wp_json_encode( array_merge( $ev['context'] ?? array(), array( 'via' => 'prepend' ) ) ),
				'created_at'  => isset( $ev['ts'] ) ? (string) $ev['ts'] : gmdate( 'Y-m-d H:i:s' ),
			);
			$ok = $wpdb->insert( $table, $data ); // phpcs:ignore WordPress.DB
			if ( ! $ok ) {
				continue;
			}

			// The same hook every other event fires through Logger::log(), so alerts, the
			// dashboard and add-ons see blocks made before WordPress loaded too (see
			// PREPEND_EVENTS_FIRE_HOOK).
			/** This action is documented in src/Modules/Audit/Logger.php */
			do_action( 'loyalsec_event_logged', $type, $data, (int) $wpdb->insert_id );
		}
	}

	public function gc(): void {
		( new RateLimiter() )->gc();
	}

	/* --------------------------- WAF config writer -------------------------- */

	/**
	 * Build the configuration array consumed by the standalone prepend.
	 *
	 * @return array<string, mixed>
	 */
	public function export_waf_config(): array {
		$s               = $this->settings();
		$trust_effective = ( new IpResolver( $s ) )->trust();

		// Paths MUST be derived from this server's runtime constants at write time and
		// normalized to forward slashes (never carried over from another machine — a stale
		// Windows path baked into the deployed config silently fails the prepend open).
		$kernel_dir           = trailingslashit( ( new \LoyalSecurity\Setup\WafKernelBundler() )->deploy_dir() );
		$src_dir              = wp_normalize_path( $kernel_dir . 'src' );
		$signatures_file      = wp_normalize_path( $kernel_dir . 'data/waf-signatures.php' );
		$virtual_patches_file = wp_normalize_path( $kernel_dir . 'data/virtual-patches.php' );
		$storage_dir          = wp_normalize_path( BanStore::storage_dir() );

		// Every local rule, enabled or not — see merged_virtual_patch_rules()'s docblock for
		// why the prepend needs the full id list (not just the enabled subset) to correctly
		// suppress a bundled/feed rule that shares an id with a locally-disabled one.
		$custom_patches = ( new CustomVirtualPatches() )->all();

		return array(
			'enabled'              => (bool) $s->get( 'firewall', 'enabled', true ),
			'detection_only'       => (bool) $s->get( 'firewall', 'detection_only', false ),
			'src_dir'              => $src_dir,
			'signatures_file'      => $signatures_file,
			'storage_dir'          => $storage_dir,
			'threshold'            => (int) $s->get( 'firewall', 'threshold', 12 ),
			'block_status'         => (int) $s->get( 'firewall', 'block_status', 403 ),
			'disabled_rules'       => (array) $s->get( 'firewall', 'disabled_rules', array() ),
			'allow_params'         => (array) $s->get( 'firewall', 'allow_params', array() ),
			// Snapshotted here (not read live by the prepend, which runs before WordPress and has
			// no home_url()) so 'same_host_exempt' WAF rules can recognise this site's own
			// same-site redirect URLs without trusting the client-controlled Host header.
			'site_host'            => $this->site_host(),
			// The effective trust (configured proxies plus Cloudflare's ranges when trusted), so
			// the prepend resolves the same client IP as Standard Mode.
			'trust_proxy'          => $trust_effective[0],
			'trusted_proxies'      => $trust_effective[1],
			// Manual allowlist + still-valid auto-added admin IPs (aged/capped) so the prepend
			// honours the same effective set as Standard Mode without unbounded growth.
			'ip_whitelist'         => $this->effective_ip_whitelist(),
			'rate_limit'           => array(
				'enabled' => (bool) $s->get( 'firewall', 'rate_limit_enabled', true ),
				'limit'   => (int) $s->get( 'firewall', 'rate_limit_requests', 240 ),
				'window'  => (int) $s->get( 'firewall', 'rate_limit_window', 60 ),
			),
			// Verified-bot rate tier: the prepend only ever READS a cached verdict (never a live
			// DNS lookup — see BotVerifier, which runs this site's only lookup, off the request
			// path, regardless of WAF mode) and queues anything unverified for that cron.
			'bot_verify'           => array(
				'enabled'  => (bool) $s->get( 'firewall', 'bot_verify_enabled', true ),
				'requests' => (int) $s->get( 'firewall', 'bot_verify_requests', 600 ),
				'window'   => (int) $s->get( 'firewall', 'bot_verify_window', 60 ),
				'ttl_days' => (int) $s->get( 'firewall', 'bot_verify_ttl_days', 30 ),
			),
			// Merged bot rules (builtin GOOD_AGENTS minus disabled_builtin_bots, plus every
			// active CustomBotRules entry), fully pre-resolved here — including each trusted
			// signature's effective requests/window (its bot_rate_overrides entry, or the
			// bot_verify default above) — so the prepend never needs to re-run this merge/lookup
			// logic itself, just read the baked result. Mirrors BotBlocker's trusted_signatures()/
			// custom_blocked_signatures() (Standard Mode's live equivalent of this same merge).
			'bot_rules'            => $this->export_bot_rules(),
			'server_ips'           => $this->server_ips(),
			// This site's requests to itself carry this key (see mark_loopback_request()); the
			// file holding it is never web-readable.
			'loopback_key'         => $this->loopback_key(),
			// Signs the cookie that marks administrators and editors (see TrustCookie), so the
			// prepend gives them the same pass as Standard Mode. Empty when that pass is off.
			'trust_key'            => (bool) $s->get( 'firewall', 'whitelist_admins', true ) ? TrustCookie::key() : '',
			'rest_prefix'          => $this->rest_path_prefix(),
			// Built-in attack-tool signatures plus the opt-in groups and the admin's own list.
			'bad_agents'           => array_values( array_filter( array_map(
				'strtolower',
				array_merge(
					BotSignatures::blocked_agents(
						(bool) $s->get( 'firewall', 'block_http_clients', false ),
						(bool) $s->get( 'firewall', 'block_seo_crawlers', false )
					),
					array_map( 'strval', (array) $s->get( 'firewall', 'custom_bad_agents', array() ) )
				)
			) ) ),
			'query_cardinality'    => array(
				'enabled' => (bool) $s->get( 'firewall', 'query_cardinality_enabled', true ),
				'max'     => (int) $s->get( 'firewall', 'query_cardinality_max', 120 ),
				'window'  => (int) $s->get( 'firewall', 'query_cardinality_window', 600 ),
			),
			// Virtual patching (Optimized Mode): get_plugins() is WordPress-only, so the
			// installed slug => version map is snapshotted here (Standard Mode context) and
			// re-baked every time this config is written — see the write_waf_config() triggers
			// in register_hooks() (settings save, plugin activate/deactivate/upgrade, and each
			// ThreatIntel 'waf'/'patches' feed sync) for how fresh that snapshot stays.
			'virtual_patching'     => (bool) $s->get( 'firewall', 'virtual_patching', true ),
			'virtual_patches_file' => $virtual_patches_file,
			'installed_plugins'    => $this->installed_plugins_map(),
			// Site-local admin-approved patches (see CustomVirtualPatches) — small by nature
			// (a handful of reviewed rules), so inlined directly rather than a separate file.
			// Enabled only: a disabled rule must not ship into the prepend's enforced set.
			'custom_patches'       => array_values( array_filter(
				$custom_patches,
				static fn( $rule ) => ! empty( $rule['enabled'] )
			) ),
			// Every id the local list has an opinion on, enabled or disabled — lets the prepend
			// drop a bundled/feed rule sharing that id before merging 'custom_patches' in, the
			// same dedupe FirewallModule::merged_virtual_patch_rules() does for Standard Mode.
			// Without this, disabling a rule that also exists in the synced `patches` feed (e.g.
			// a locally auto-suggested rule later redistributed back down through it) would be
			// a no-op under Optimized Mode: the feed's identical-id copy would keep enforcing.
			'custom_patch_ids'     => array_values( array_unique( array_filter( array_map(
				static fn( $rule ) => (string) ( $rule['id'] ?? '' ),
				$custom_patches
			) ) ) ),
			// Explicit per-id disables for a bundled/feed rule that has no local record at all
			// (see set_virtual_patch_disabled()) — the prepend excludes these the same way it
			// excludes 'custom_patch_ids', just from a different source of "an admin turned
			// this off".
			'disabled_virtual_patch_ids' => array_values( array_unique( array_map(
				'strval',
				(array) $s->get( 'firewall', 'disabled_virtual_patches', array() )
			) ) ),
		);
	}

	/**
	 * Pre-resolve the merged bot-rules list for export_waf_config() — the Optimized-Mode
	 * equivalent of BotBlocker::trusted_signatures()/custom_blocked_signatures(), but baked into
	 * a flat structure the prepend can read directly instead of re-deriving at request time
	 * (the prepend has no Settings/CustomBotRules access — everything it needs must already be
	 * in this array).
	 *
	 * Public (not just for export_waf_config()'s own use) so other consumers of the same merged
	 * blocked-signature list — e.g. CloudflareSync's bot-rule push — read one authoritative
	 * source instead of re-deriving the builtin/custom/disabled merge a second time.
	 *
	 * @return array{trusted: array<int, array{signature:string, suffixes: array<string>, requests: int, window: int}>, blocked: array<int, string>}
	 */
	public function export_bot_rules(): array {
		$s              = $this->settings();
		$disabled       = array_map( 'strtolower', (array) $s->get( 'firewall', 'disabled_builtin_bots', array() ) );
		$overrides      = (array) $s->get( 'firewall', 'bot_rate_overrides', array() );
		$default_limit  = (int) $s->get( 'firewall', 'bot_verify_requests', 600 );
		$default_window = (int) $s->get( 'firewall', 'bot_verify_window', 60 );

		$rate_for = static function ( string $sig ) use ( $overrides, $default_limit, $default_window ): array {
			$o = $overrides[ $sig ] ?? null;
			if ( is_array( $o ) && isset( $o['requests'], $o['window'] ) ) {
				return array( (int) $o['requests'], (int) $o['window'] );
			}
			return array( $default_limit, $default_window );
		};

		$trusted = array();
		foreach ( BotSignatures::GOOD_AGENTS as $sig ) {
			if ( in_array( $sig, $disabled, true ) ) {
				continue;
			}
			list( $requests, $window ) = $rate_for( $sig );
			$trusted[] = array(
				'signature' => $sig,
				'suffixes'  => array_values( BotSignatures::TRUSTED_SUFFIXES[ $sig ] ?? array() ),
				'requests'  => $requests,
				'window'    => $window,
			);
		}

		$custom  = ( new CustomBotRules() )->active();
		$blocked = array();
		foreach ( $custom as $rule ) {
			$sig = strtolower( (string) ( $rule['signature'] ?? '' ) );
			if ( '' === $sig ) {
				continue;
			}
			if ( 'blocked' === ( $rule['type'] ?? '' ) ) {
				$blocked[] = $sig;
				continue;
			}
			if ( 'verified' !== ( $rule['type'] ?? '' ) ) {
				continue;
			}
			list( $requests, $window ) = $rate_for( $sig );
			$suffix    = trim( (string) ( $rule['trusted_suffix'] ?? '' ) );
			$trusted[] = array(
				'signature' => $sig,
				// No suffix = not DNS-verifiable = never eligible for the bonus tier — same rule
				// as Standard Mode's verified_bot_signature(); an empty suffixes array here means
				// the prepend's read-only check never queues/verifies this one, it's just always
				// allowed (never blocked) via the same 'trusted' membership check.
				'suffixes'  => '' === $suffix ? array() : array( $suffix ),
				'requests'  => $requests,
				'window'    => $window,
			);
		}

		return array(
			'trusted' => $trusted,
			'blocked' => array_values( array_unique( $blocked ) ),
		);
	}

	/**
	 * Fired on `loyalsec_feed_dataset_updated` after every ThreatIntel sync. Only 'waf' and
	 * 'patches' datasets are relevant to the prepend's config snapshot — 'malware' and 'cve'
	 * are consumed elsewhere and don't need a WAF config rewrite.
	 *
	 * @param string               $dataset One of: waf | malware | patches | cve.
	 * @param array<string, mixed> $rules   Unused here — the prepend reads the feed cache file
	 *                                      directly; this only needs to know *that* a relevant
	 *                                      dataset changed, to keep the config snapshot fresh.
	 */
	public function maybe_resync_waf_config( string $dataset, array $rules = array() ): void {
		if ( in_array( $dataset, array( 'waf', 'patches' ), true ) ) {
			$this->write_waf_config();
		}
	}

	/** Option flag raised when Optimized Mode's config could not be written (stale/drifted). */
	public const CONFIG_STALE_OPTION = 'loyalsec_waf_config_stale';

	/** Which LOYALSEC_VERSION the deployed Optimized-Mode bundle was last synced from. */
	private const WAF_KERNEL_VERSION_OPTION = 'loyalsec_waf_kernel_version';

	/**
	 * Absolute path to the deployed `waf-config.php` — inside the relocated bundle
	 * ({@see \LoyalSecurity\Setup\WafKernelBundler::deploy_dir()}), never inside the plugin
	 * directory (see that class's docblock for why).
	 */
	private function waf_config_path(): string {
		return trailingslashit( ( new \LoyalSecurity\Setup\WafKernelBundler() )->deploy_dir() ) . 'waf-config.php';
	}

	/**
	 * Write the WAF config to the deployed bundle's `waf-config.php`.
	 *
	 * Returns whether the file was actually (re)written. This matters because on a properly
	 * hardened host the plugin directory is often NOT writable by the web user: after the
	 * wizard's initial deploy, every later change that must re-bake this file (an approved
	 * custom virtual patch, a threshold/detection-only change, a refreshed installed-plugins
	 * snapshot) would otherwise fail SILENTLY here — the operator sees success in the dashboard
	 * while Optimized Mode keeps enforcing the old config. When that happens under Optimized
	 * Mode we raise a persistent flag (surfaced by Admin\Notices) instead of failing quietly.
	 */
	public function write_waf_config(): bool {
		$config = $this->export_waf_config();
		$php    = "<?php\n// Auto-generated by Loyal Security. Do not edit.\nreturn "
			. var_export( $config, true ) . ";\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- deliberate PHP-literal serialization of the WAF config array for the generated prepend/waf-config.php file, not debug output.

		$path     = $this->waf_config_path();
		$writable = is_writable( dirname( $path ) ) || ( is_file( $path ) && is_writable( $path ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check, not a write.

		if ( $writable && false !== file_put_contents( $path, $php, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			// Without this, a server running opcache.validate_timestamps=0 (common in
			// production for performance) keeps serving the OLD compiled bytecode of this file
			// forever — a freshly-approved virtual patch would silently never take effect in
			// the prepend (which `include`s this file on every request) despite the file on
			// disk being correct.
			if ( function_exists( 'opcache_invalidate' ) ) {
				opcache_invalidate( $path, true );
			}
			// A previously-flagged stale state is now resolved.
			if ( false !== get_option( self::CONFIG_STALE_OPTION, false ) ) {
				delete_option( self::CONFIG_STALE_OPTION );
			}
			return true;
		}

		// Write needed but couldn't happen. Only a problem when Optimized Mode is the intended
		// enforcement path — in Standard Mode this file is unused, so a non-writable prepend dir
		// is harmless and must not nag the operator. (Checked against the stored preference, not
		// is_optimized_active(): LOYALSEC_WAF_PREPEND is only defined on requests the prepend
		// actually ran, which a settings-save admin request is not.)
		if ( 'optimized' === get_option( 'loyalsec_waf_mode', 'standard' ) ) {
			update_option(
				self::CONFIG_STALE_OPTION,
				array(
					'at'   => gmdate( 'Y-m-d H:i:s' ),
					'path' => wp_normalize_path( dirname( $path ) ),
				),
				false
			);
		}
		return false;
	}

	/**
	 * Keep the deployed Optimized-Mode bundle (uploads/loyal-security/waf-kernel/ — see
	 * {@see \LoyalSecurity\Setup\WafKernelBundler}) in sync with this plugin's own WAF kernel
	 * source. Registered on `init` (cheap on the common path: one option string compare) as the
	 * PRIMARY trigger, plus the activate/deactivate/upgrade lifecycle hooks as a faster-reacting
	 * secondary one. Filesystem/redeploy work only happens on an actual version mismatch, and
	 * only when Optimized Mode is enabled — nothing is deployed to keep in sync otherwise.
	 *
	 * `init` has to be the primary trigger because `upgrader_process_complete` only fires for
	 * WordPress's own dashboard "Update now" flow — it never fires when plugin files are updated
	 * by direct copy (FTP, git pull, etc.), which is how this project is actually deployed. Without
	 * an `init`-based check, an already-Optimized site that gets its plugin files replaced this
	 * way would keep its `auto_prepend_file` directive pointed at whatever `prepend/loyalsec-waf.php`
	 * used to be — now deleted — which is a hard PHP fatal on every single request, before this
	 * plugin's own fail-open handling can even run.
	 */
	public function maybe_resync_deployed_kernel(): void {
		if ( 'optimized' !== get_option( 'loyalsec_waf_mode', 'standard' ) ) {
			return;
		}
		if ( get_option( self::WAF_KERNEL_VERSION_OPTION, '' ) === LOYALSEC_VERSION ) {
			return;
		}

		$bundler = new \LoyalSecurity\Setup\WafKernelBundler();
		if ( ! $bundler->sync() ) {
			return; // Leave the version option unset so this retries next request.
		}
		$this->write_waf_config();

		// Redeploy the auto_prepend_file directive unconditionally — idempotent (PrependInstaller
		// strips and re-adds its own marked block) and the only way to guarantee an install whose
		// directive still points at an old/removed in-plugin path gets migrated, with the existing
		// self-test + auto-rollback as a safety net against a bad redeploy.
		( new \LoyalSecurity\Setup\PrependInstaller( new \LoyalSecurity\Setup\ServerProbe() ) )->deploy();

		update_option( self::WAF_KERNEL_VERSION_OPTION, LOYALSEC_VERSION, false );
	}
}
