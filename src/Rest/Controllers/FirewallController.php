<?php
/**
 * Firewall REST controller — bans, stats, live activity.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Modules\Firewall\CompetitorImporter;
use TotalSecurityWP\Modules\Firewall\CustomBotRules;
use TotalSecurityWP\Modules\Firewall\CustomVirtualPatches;
use TotalSecurityWP\Modules\Firewall\FirewallModule;
use TotalSecurityWP\Waf\BotSignatures;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Scanner\ScannerModule;
use TotalSecurityWP\Plugin;
use TotalSecurityWP\Support\Ip;
use WP_REST_Request;

/**
 * Exposes ban management and firewall activity to the dashboard.
 */
class FirewallController extends AbstractController {

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route(
			$ns,
			'/firewall/bans',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'list_bans' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'add_ban' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			$ns,
			'/firewall/bans/delete',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'remove_ban' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/firewall/stats',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'stats' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		// Auto-drafted virtual-patch suggestions (see PatchSuggester). Review actions
		// (approve/reject/submit_cloud) reuse the existing POST /scan/findings/patch endpoint —
		// this only needs a listing route scoped to findings that actually carry a suggestion.
		register_rest_route(
			$ns,
			'/firewall/patch-suggestions',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'patch_suggestions' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		// Diagnostic: live DB state vs. what's actually on disk in prepend/waf-config.php right
		// now (including whatever OPcache currently has cached for it) — see
		// FirewallModule::debug_virtual_patch_state().
		register_rest_route(
			$ns,
			'/firewall/patch-debug',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'patch_debug' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		// Active virtual patches (approved suggestions + anything added by hand) — management
		// list distinct from /firewall/patch-suggestions, which is the pending-review queue.
		register_rest_route(
			$ns,
			'/firewall/virtual-patches',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'virtual_patches' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/firewall/virtual-patches/toggle',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'toggle_virtual_patch' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/firewall/virtual-patches/delete',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'delete_virtual_patch' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		// Bot rules (verified/trusted + blocked) — merged builtin + site-local list, same
		// builtin/local two-tier pattern as virtual patches above.
		register_rest_route(
			$ns,
			'/firewall/bot-rules',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'bot_rules' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'add_bot_rule' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			$ns,
			'/firewall/bot-rules/toggle',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'toggle_bot_rule' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/firewall/bot-rules/delete',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'delete_bot_rule' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/firewall/bot-rules/rate-limit',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'set_bot_rate_limit' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);

		register_rest_route(
			$ns,
			'/firewall/import/detect',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'import_detect' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);
		register_rest_route(
			$ns,
			'/firewall/import/run',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'import_run' ),
				'permission_callback' => array( $this, 'permission_check' ),
			)
		);
	}

	/**
	 * Which other security plugins have detectable IP list data on this site.
	 */
	public function import_detect( WP_REST_Request $request ) {
		return $this->ok( array( 'sources' => ( new CompetitorImporter() )->detect() ) );
	}

	/**
	 * Run the one-time IP allow/block list import from every detected source and report exactly
	 * what was found and applied, per source.
	 */
	public function import_run( WP_REST_Request $request ) {
		return $this->ok( array( 'results' => ( new CompetitorImporter() )->import() ) );
	}

	/**
	 * Convenience accessor for the settings repository.
	 */
	private function settings(): \TotalSecurityWP\Core\Settings {
		return $this->container->make( 'settings' );
	}

	public function list_bans( WP_REST_Request $request ) {
		$store  = new BanStore();
		$limit  = max( 1, min( 200, (int) $request->get_param( 'per_page' ) ?: 50 ) );
		$offset = max( 0, (int) $request->get_param( 'offset' ) );
		return $this->ok(
			array(
				'items' => $store->list( $limit, $offset ),
				'total' => $store->count(),
			)
		);
	}

	public function add_ban( WP_REST_Request $request ) {
		$ip     = trim( (string) $request->get_param( 'ip' ) );
		$reason = (string) ( $request->get_param( 'reason' ) ?: 'Manual ban' );
		$type   = 'permanent' === $request->get_param( 'type' ) ? 'permanent' : 'temporary';
		$ttl    = (int) ( $request->get_param( 'ttl' ) ?: 3600 );
		$cidr   = '';

		if ( false !== strpos( $ip, '/' ) ) {
			[ $subnet, $bits ] = array_pad( explode( '/', $ip, 2 ), 2, null );
			$max = ( false !== strpos( (string) $subnet, ':' ) ) ? 128 : 32;
			if ( ! Ip::is_valid( (string) $subnet ) || ! ctype_digit( (string) $bits ) || (int) $bits < 0 || (int) $bits > $max ) {
				return $this->fail( 'totalsecwp_bad_ip', __( 'Invalid IP address or CIDR range.', 'loyal-security' ), 422 );
			}
			$cidr = $subnet . '/' . (int) $bits;
			$ip   = (string) $subnet;
		} elseif ( ! Ip::is_valid( $ip ) ) {
			return $this->fail( 'totalsecwp_bad_ip', __( 'Invalid IP address or CIDR range.', 'loyal-security' ), 422 );
		}

		$store = new BanStore();
		$ok    = $store->add( $ip, $reason, $type, 'permanent' === $type ? null : $ttl, 'manual', $cidr );
		if ( ! $ok ) {
			return $this->fail( 'totalsecwp_ban_failed', __( 'Could not add the ban.', 'loyal-security' ), 500 );
		}

		$this->logger()->log( EventCatalog::WAF_BAN_ADDED, array( 'ip' => $ip, 'type' => $type, 'reason' => $reason ) );
		return $this->ok( array( 'banned' => $ip ) );
	}

	public function remove_ban( WP_REST_Request $request ) {
		$ip = trim( (string) $request->get_param( 'ip' ) );
		( new BanStore() )->remove( $ip );
		$this->logger()->log( EventCatalog::WAF_BAN_REMOVED, array( 'ip' => $ip ) );
		return $this->ok( array( 'removed' => $ip ) );
	}

	public function stats( WP_REST_Request $request ) {
		global $wpdb;
		$events = $wpdb->prefix . 'totalsecwp_events';
		$since  = gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS );

		$by_type = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT event_type, COUNT(*) AS c FROM %i WHERE event_type LIKE %s AND created_at > %s GROUP BY event_type ORDER BY c DESC", $events,
				'waf.%',
				$since
			),
			ARRAY_A
		);

		$top_ips = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT ip, COUNT(*) AS c FROM %i WHERE event_type LIKE %s AND created_at > %s GROUP BY ip ORDER BY c DESC LIMIT 10", $events,
				'waf.%',
				$since
			),
			ARRAY_A
		);

		// Patch-gap coverage: how many installed plugins are currently shielded by an early
		// virtual patch. Guarded so the firewall stats never fail if ThreatIntel is absent.
		$patch_gap = 0;
		if ( class_exists( \TotalSecurityWP\Modules\ThreatIntel\PatchGap::class ) ) {
			try {
				$summary   = ( new \TotalSecurityWP\Modules\ThreatIntel\PatchGap() )->summary();
				$patch_gap = (int) ( $summary['count'] ?? 0 );
			} catch ( \Throwable $e ) {
				$patch_gap = 0;
			}
		}

		return $this->ok(
			array(
				'mode'      => get_option( 'totalsecwp_waf_mode', 'standard' ),
				'by_type'   => is_array( $by_type ) ? $by_type : array(),
				'top_ips'   => is_array( $top_ips ) ? $top_ips : array(),
				'patch_gap' => $patch_gap,
			)
		);
	}

	/**
	 * Convenience accessor for the audit logger.
	 */
	private function logger(): Logger {
		return $this->container->make( 'logger' );
	}

	/**
	 * List findings that carry an auto-drafted virtual-patch suggestion.
	 */
	public function patch_suggestions( WP_REST_Request $request ) {
		$scanner = Plugin::instance()->module( 'scanner' );
		if ( ! $scanner instanceof ScannerModule ) {
			return $this->ok( array( 'items' => array() ) );
		}
		$status = (string) ( $request->get_param( 'patch_status' ) ?: '' );
		return $this->ok( array( 'items' => $this->mask_paths_in( $scanner->patch_suggestions( $status ), array( 'path' ) ) ) );
	}

	/**
	 * Diagnostic: live DB state vs. what's actually on disk in prepend/waf-config.php right now.
	 */
	public function patch_debug( WP_REST_Request $request ) {
		$firewall = Plugin::instance()->module( 'firewall' );
		if ( ! $firewall instanceof FirewallModule ) {
			return $this->fail( 'totalsecwp_firewall_off', __( 'The firewall module is disabled.', 'loyal-security' ), 409 );
		}
		return $this->ok( $firewall->debug_virtual_patch_state() );
	}

	/**
	 * List every virtual patch from every source (local, bundled, and cloud-feed), enabled or
	 * not — the management view, as opposed to /firewall/patch-suggestions' pending-review
	 * queue. Bundled/feed-only rules (never locally suggested) are included here, tagged with
	 * `origin`, so there's something in the dashboard for an admin to disable even when no
	 * local record exists for it — see FirewallModule::list_virtual_patches().
	 */
	public function virtual_patches( WP_REST_Request $request ) {
		$firewall = Plugin::instance()->module( 'firewall' );
		if ( ! $firewall instanceof FirewallModule ) {
			return $this->ok( array( 'items' => ( new CustomVirtualPatches() )->all() ) );
		}
		return $this->ok( array( 'items' => $firewall->list_virtual_patches() ) );
	}

	/**
	 * Enable/disable a virtual patch without deleting it. Re-syncs prepend/waf-config.php
	 * immediately so Optimized Mode reflects the change on the very next request, same as
	 * ScannerController::finding_patch()'s approve action.
	 *
	 * A rule with a local (CustomVirtualPatches) record toggles there as before. A bundled or
	 * feed-sourced rule with no local record — one this site never locally suggested, e.g. a
	 * curated `patches` feed entry for a plugin it has installed — has nothing to toggle
	 * there, so it goes through FirewallModule::set_virtual_patch_disabled() instead, which
	 * both merged_virtual_patch_rules() and the prepend already honour.
	 */
	public function toggle_virtual_patch( WP_REST_Request $request ) {
		$id      = (string) $request->get_param( 'id' );
		$enabled = (bool) $request->get_param( 'enabled' );
		if ( '' === $id ) {
			return $this->fail( 'totalsecwp_bad_request', __( 'Missing rule id.', 'loyal-security' ), 422 );
		}

		$firewall = Plugin::instance()->module( 'firewall' );
		if ( ! $firewall instanceof FirewallModule ) {
			return $this->fail( 'totalsecwp_firewall_off', __( 'The firewall module is disabled.', 'loyal-security' ), 409 );
		}

		$custom = new CustomVirtualPatches();
		if ( $custom->exists( $id ) ) {
			$custom->set_enabled( $id, $enabled );
		} elseif ( $firewall->bundled_or_feed_virtual_patch_exists( $id ) ) {
			$firewall->set_virtual_patch_disabled( $id, ! $enabled );
		} else {
			return $this->fail( 'totalsecwp_not_found', __( 'Virtual patch not found.', 'loyal-security' ), 404 );
		}

		$firewall->write_waf_config();
		return $this->ok( array( 'id' => $id, 'enabled' => $enabled ) );
	}

	/**
	 * Permanently remove a virtual patch. Re-syncs prepend/waf-config.php immediately, same
	 * reasoning as toggle_virtual_patch().
	 */
	public function delete_virtual_patch( WP_REST_Request $request ) {
		$id = (string) $request->get_param( 'id' );
		if ( '' === $id ) {
			return $this->fail( 'totalsecwp_bad_request', __( 'Missing rule id.', 'loyal-security' ), 422 );
		}

		if ( ! ( new CustomVirtualPatches() )->remove( $id ) ) {
			return $this->fail( 'totalsecwp_not_found', __( 'Virtual patch not found.', 'loyal-security' ), 404 );
		}

		$firewall = Plugin::instance()->module( 'firewall' );
		if ( $firewall instanceof FirewallModule ) {
			$firewall->write_waf_config();
		}
		return $this->ok( array( 'id' => $id, 'deleted' => true ) );
	}

	/**
	 * Merged bot-rules list: the bundled trusted-crawler baseline (BotSignatures::GOOD_AGENTS)
	 * tagged `origin: builtin`, plus every site-local rule (admin-added or Sentinel-accepted)
	 * tagged `origin: custom`. Builtin malicious-signature/scanner-tool patterns
	 * (BotSignatures::BAD_AGENTS) are deliberately not surfaced here — they're not "bots" in the
	 * sense this list manages, just attack-tool fingerprints.
	 */
	public function bot_rules( WP_REST_Request $request ) {
		$disabled       = array_map( 'strtolower', (array) $this->settings()->get( 'firewall', 'disabled_builtin_bots', array() ) );
		$overrides      = (array) $this->settings()->get( 'firewall', 'bot_rate_overrides', array() );
		$default_limit  = (int) $this->settings()->get( 'firewall', 'bot_verify_requests', 600 );
		$default_window = (int) $this->settings()->get( 'firewall', 'bot_verify_window', 60 );

		// Resolved requests/window this signature actually gets right now — the override if one
		// exists, otherwise the shared default — so the UI can show and edit the real effective
		// value per row without duplicating this fallback logic client-side.
		$rate_for = static function ( string $sig ) use ( $overrides, $default_limit, $default_window ) {
			$o = $overrides[ $sig ] ?? null;
			$has_override = is_array( $o ) && isset( $o['requests'], $o['window'] );
			return array(
				'rate_limit_requests' => $has_override ? (int) $o['requests'] : $default_limit,
				'rate_limit_window'   => $has_override ? (int) $o['window'] : $default_window,
				'rate_limit_custom'   => $has_override,
			);
		};

		$items = array();
		foreach ( BotSignatures::GOOD_AGENTS as $sig ) {
			$items[] = array_merge(
				array(
					'id'             => $sig,
					'signature'      => $sig,
					'type'           => 'verified',
					'trusted_suffix' => implode( ', ', BotSignatures::TRUSTED_SUFFIXES[ $sig ] ?? array() ),
					'note'           => '',
					'enabled'        => ! in_array( $sig, $disabled, true ),
					'origin'         => 'builtin',
				),
				$rate_for( $sig )
			);
		}
		foreach ( ( new CustomBotRules() )->all() as $rule ) {
			$rule['origin'] = 'custom';
			if ( 'verified' === ( $rule['type'] ?? '' ) ) {
				$rule = array_merge( $rule, $rate_for( (string) ( $rule['signature'] ?? '' ) ) );
			}
			$items[] = $rule;
		}

		return $this->ok( array( 'items' => $items ) );
	}

	/**
	 * Set or clear a per-signature rate-limit override — applies to any verified signature,
	 * builtin or custom, since the override lives in a flat `bot_rate_overrides` settings map
	 * keyed by signature rather than inside either bot-rules storage location. Pass `requests`
	 * and `window` to set an override, or omit both (or pass `clear: true`) to remove it and
	 * fall back to the shared bot_verify_requests/window default.
	 */
	public function set_bot_rate_limit( WP_REST_Request $request ) {
		$signature = strtolower( trim( (string) $request->get_param( 'signature' ) ) );
		if ( '' === $signature ) {
			return $this->fail( 'totalsecwp_bad_request', __( 'Missing signature.', 'loyal-security' ), 422 );
		}

		$overrides = (array) $this->settings()->get( 'firewall', 'bot_rate_overrides', array() );

		if ( $request->get_param( 'clear' ) ) {
			unset( $overrides[ $signature ] );
		} else {
			$requests = (int) $request->get_param( 'requests' );
			$window   = (int) $request->get_param( 'window' );
			if ( $requests <= 0 || $window <= 0 ) {
				return $this->fail( 'totalsecwp_bad_request', __( 'requests and window must both be positive numbers.', 'loyal-security' ), 422 );
			}
			$overrides[ $signature ] = array( 'requests' => $requests, 'window' => $window );
		}

		$this->settings()->update_module( 'firewall', array( 'bot_rate_overrides' => $overrides ) );

		$firewall = Plugin::instance()->module( 'firewall' );
		if ( $firewall instanceof FirewallModule ) {
			$firewall->write_waf_config();
		}
		return $this->ok( array( 'signature' => $signature, 'override' => $overrides[ $signature ] ?? null ) );
	}

	/**
	 * Add (or replace, by signature) a site-local bot rule. `type: verified` with a
	 * `trusted_suffix` is real-DNS-verifiable (see BotVerifier); without one it's still always
	 * trusted (never blocked) but never earns the bonus rate tier, since nothing confirms the
	 * claim — see BotBlocker::verified_bot_signature()'s docblock.
	 */
	public function add_bot_rule( WP_REST_Request $request ) {
		$signature = strtolower( trim( (string) $request->get_param( 'signature' ) ) );
		$type      = (string) $request->get_param( 'type' );
		$suffix    = trim( (string) $request->get_param( 'trusted_suffix' ) );
		$note      = sanitize_text_field( (string) $request->get_param( 'note' ) );

		if ( '' === $signature || ! in_array( $type, array( 'verified', 'blocked' ), true ) ) {
			return $this->fail( 'totalsecwp_bad_request', __( 'A signature and a valid type (verified or blocked) are required.', 'loyal-security' ), 422 );
		}

		$rule = array(
			'id'             => sanitize_title( $signature ),
			'signature'      => $signature,
			'type'           => $type,
			'trusted_suffix' => 'verified' === $type ? strtolower( $suffix ) : '',
			'note'           => $note,
			'enabled'        => true,
			'source'         => 'custom',
		);

		( new CustomBotRules() )->add( $rule );

		$firewall = Plugin::instance()->module( 'firewall' );
		if ( $firewall instanceof FirewallModule ) {
			$firewall->write_waf_config();
		}

		$rule['origin'] = 'custom';
		return $this->ok( array( 'item' => $rule ) );
	}

	/**
	 * Enable/disable a bot rule without deleting it. A rule with a local (CustomBotRules) record
	 * toggles there. A builtin signature with no local record has nothing to toggle there, so
	 * "disabling" it instead adds/removes it from the `disabled_builtin_bots` settings override —
	 * mirrors toggle_virtual_patch()'s exact builtin-vs-local branching.
	 */
	public function toggle_bot_rule( WP_REST_Request $request ) {
		$id      = (string) $request->get_param( 'id' );
		$enabled = (bool) $request->get_param( 'enabled' );
		if ( '' === $id ) {
			return $this->fail( 'totalsecwp_bad_request', __( 'Missing rule id.', 'loyal-security' ), 422 );
		}

		$custom = new CustomBotRules();
		if ( $custom->exists( $id ) ) {
			$custom->set_enabled( $id, $enabled );
		} elseif ( in_array( $id, BotSignatures::GOOD_AGENTS, true ) ) {
			$disabled = array_map( 'strtolower', (array) $this->settings()->get( 'firewall', 'disabled_builtin_bots', array() ) );
			$disabled = array_values( array_diff( $disabled, array( $id ) ) );
			if ( ! $enabled ) {
				$disabled[] = $id;
			}
			$this->settings()->update_module( 'firewall', array( 'disabled_builtin_bots' => $disabled ) );
		} else {
			return $this->fail( 'totalsecwp_not_found', __( 'Bot rule not found.', 'loyal-security' ), 404 );
		}

		$firewall = Plugin::instance()->module( 'firewall' );
		if ( $firewall instanceof FirewallModule ) {
			$firewall->write_waf_config();
		}
		return $this->ok( array( 'id' => $id, 'enabled' => $enabled ) );
	}

	/**
	 * Permanently remove a site-local bot rule. Builtin signatures aren't deletable (there's
	 * nothing local to delete) — disable them via toggle_bot_rule() instead.
	 */
	public function delete_bot_rule( WP_REST_Request $request ) {
		$id = (string) $request->get_param( 'id' );
		if ( '' === $id ) {
			return $this->fail( 'totalsecwp_bad_request', __( 'Missing rule id.', 'loyal-security' ), 422 );
		}

		if ( ! ( new CustomBotRules() )->remove( $id ) ) {
			return $this->fail( 'totalsecwp_not_found', __( 'Bot rule not found (builtin rules can be disabled but not removed).', 'loyal-security' ), 404 );
		}

		$firewall = Plugin::instance()->module( 'firewall' );
		if ( $firewall instanceof FirewallModule ) {
			$firewall->write_waf_config();
		}
		return $this->ok( array( 'id' => $id, 'deleted' => true ) );
	}
}
