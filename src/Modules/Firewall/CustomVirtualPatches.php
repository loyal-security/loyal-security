<?php
/**
 * Site-local, admin-approved virtual-patch rules.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Stores virtual-patch rules approved from a {@see PatchSuggester} suggestion (or added by
 * hand). Distinct from `data/virtual-patches.php` (plugin-bundled, ships with releases) and
 * the ThreatIntel-synced `patches` feed (cloud-curated) — this is the third, purely local
 * source: things *this* site's admin approved for *this* site, right now, without waiting on
 * either. Merged into both Standard Mode (`FirewallModule::merged_virtual_patch_rules()`) and
 * the Optimized-Mode prepend (baked into `waf-config.php`).
 */
class CustomVirtualPatches {

	private const OPTION = 'totalsecwp_custom_virtual_patches';

	/**
	 * Every rule, enabled or not — for the management UI, which needs to show (and let an
	 * admin re-enable) disabled rules too. Enforcement call sites should use {@see active()}
	 * instead. Rules saved before the enable/disable toggle existed have no `enabled` key at
	 * all; those are treated as enabled (they were live before this feature existed, and
	 * silently disabling them on upgrade would be a surprising, unrequested behavior change).
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
	 * Enabled rules only — what Standard Mode's merged_virtual_patch_rules() and the
	 * Optimized-Mode config export should actually enforce.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function active(): array {
		return array_values( array_filter( $this->all(), static fn( $r ) => ! empty( $r['enabled'] ) ) );
	}

	/**
	 * Whether a rule with this id has a local record at all (enabled or disabled) — used to
	 * decide whether a toggle should go through set_enabled() here or, for a bundled/feed-only
	 * id with no local record, through FirewallModule::set_virtual_patch_disabled() instead.
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
	 * @param array<string, mixed> $rule Virtual-patch rule (see VirtualPatch's rule shape).
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
