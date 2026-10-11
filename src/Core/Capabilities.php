<?php
/**
 * Capability management.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Grants the plugin's own management capability to administrators so it can gate its admin UI
 * and REST endpoints on that rather than the generic `manage_options`.
 */
class Capabilities {

	/**
	 * Add the capability to the administrator role.
	 */
	public static function grant(): void {
		$role = get_role( 'administrator' );
		if ( $role && ! $role->has_cap( LOYALSEC_CAP ) ) {
			$role->add_cap( LOYALSEC_CAP );
		}
	}

	/**
	 * Remove the capability from all roles (on uninstall).
	 */
	/**
	 * Whether the current user may manage Loyal Security.
	 *
	 * On a multisite network only super admins may: the plugin changes files shared by every
	 * site (.htaccess, .user.ini, wp-config.php), backs up the whole network's database and
	 * repairs or quarantines files anywhere, so a site administrator must not reach it.
	 *
	 * @since 1.5.1
	 */
	public static function can_manage(): bool {
		if ( is_multisite() ) {
			return is_super_admin();
		}
		return current_user_can( LOYALSEC_CAP ) || current_user_can( 'manage_options' );
	}

	/**
	 * `map_meta_cap`: on multisite, the plugin's capability belongs to super admins only, even
	 * when a role on a site was given it.
	 *
	 * @param string[] $caps    Primitive capabilities required.
	 * @param string   $cap     Capability being checked.
	 * @param int      $user_id User id.
	 * @return string[]
	 */
	public static function restrict_on_multisite( $caps, $cap, $user_id ) {
		if ( LOYALSEC_CAP === $cap && is_multisite() && ! is_super_admin( (int) $user_id ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	public static function revoke(): void {
		foreach ( array_keys( wp_roles()->roles ) as $slug ) {
			$role = get_role( $slug );
			if ( $role && $role->has_cap( LOYALSEC_CAP ) ) {
				$role->remove_cap( LOYALSEC_CAP );
			}
		}
	}
}
