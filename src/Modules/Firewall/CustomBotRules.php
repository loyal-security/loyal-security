<?php
/**
 * Site-local, admin-managed bot rules.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Stores bot rules an admin added by hand (a specific scraper noticed in the logs, a crawler
 * they want fully trusted) or accepted from a Sentinel AI suggestion. Distinct from the
 * plugin-bundled baseline in {@see \LoyalSecurity\Waf\BotSignatures} — this is the local,
 * site-specific layer on top of it, following the exact same "local overrides/extends bundled"
 * pattern {@see CustomVirtualPatches} already uses for virtual patches. Merged into both
 * Standard Mode (BotBlocker/BotVerifier) and the Optimized-Mode prepend (baked into
 * `waf-config.php`).
 *
 * Rule shape: `{id, signature, type: 'verified'|'blocked', trusted_suffix, note, enabled,
 * source: 'custom'|'sentinel'}`. `signature` is matched the same way as the builtin list — a
 * lowercase UA substring. `trusted_suffix` is optional and only meaningful for `type: verified`:
 * without it, a custom "verified" entry is UA-substring-match-only (never gets the generous rate
 * tier, since nothing confirms the claim) — see BotBlocker's merged-rules consumer for exactly
 * how that distinction is enforced.
 */
class CustomBotRules {

	private const OPTION = 'loyalsec_custom_bot_rules';

	/**
	 * Every rule, enabled or not — for the management UI, which needs to show (and let an admin
	 * re-enable) disabled rules too. Enforcement call sites should use {@see active()} instead.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function all(): array {
		$rules = get_option( self::OPTION, array() );
		if ( ! is_array( $rules ) ) {
			return array();
		}
		return array_values( array_map(
			static function ( $r ) {
				$r['enabled'] = ! isset( $r['enabled'] ) || (bool) $r['enabled'];
				return $r;
			},
			$rules
		) );
	}

	/**
	 * Enabled rules only — what BotBlocker/BotVerifier's merged-rules helper and the
	 * Optimized-Mode config export should actually enforce.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function active(): array {
		return array_values( array_filter( $this->all(), static fn( $r ) => ! empty( $r['enabled'] ) ) );
	}

	/**
	 * Whether a rule with this id has a local record at all (enabled or disabled) — used to
	 * decide whether a toggle should go through set_enabled() here or, for a builtin-only id
	 * with no local record, through the `disabled_builtin_bots` settings override instead.
	 */
	public function exists( string $id ): bool {
		foreach ( $this->all() as $r ) {
			if ( ( $r['id'] ?? '' ) === $id ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Add (or replace, by id) a rule. New rules default to enabled.
	 *
	 * @param array<string, mixed> $rule Bot rule (see class docblock for shape).
	 */
	public function add( array $rule ): bool {
		if ( empty( $rule['id'] ) ) {
			return false;
		}
		if ( ! isset( $rule['enabled'] ) ) {
			$rule['enabled'] = true;
		}
		$rules   = $this->all();
		$rules   = array_filter( $rules, static fn( $r ) => ( $r['id'] ?? '' ) !== $rule['id'] );
		$rules[] = $rule;
		return update_option( self::OPTION, array_values( $rules ), false );
	}

	/**
	 * Flip a rule's enabled state without touching anything else about it.
	 */
	public function set_enabled( string $id, bool $enabled ): bool {
		$found = false;
		$rules = array_map(
			static function ( $r ) use ( $id, $enabled, &$found ) {
				if ( ( $r['id'] ?? '' ) === $id ) {
					$r['enabled'] = $enabled;
					$found        = true;
				}
				return $r;
			},
			$this->all()
		);
		if ( ! $found ) {
			return false;
		}
		return update_option( self::OPTION, $rules, false );
	}

	public function remove( string $id ): bool {
		$rules = array_filter( $this->all(), static fn( $r ) => ( $r['id'] ?? '' ) !== $id );
		return update_option( self::OPTION, array_values( $rules ), false );
	}
}
