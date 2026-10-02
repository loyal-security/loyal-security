<?php
/**
 * Capability management.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Grants the custom `manage_total_security_wp` capability to administrators so the plugin
 * gates its admin UI and REST endpoints on it rather than the generic `manage_options`.
 */
class Capabilities {

	/**
	 * Add the capability to the administrator role.
	 */
	public static function grant(): void {
		$role = get_role( 'administrator' );
		if ( $role && ! $role->has_cap( TOTALSECWP_CAP ) ) {
			$role->add_cap( TOTALSECWP_CAP );
		}
	}

	/**
	 * Remove the capability from all roles (on uninstall).
	 */
	public static function revoke(): void {
		foreach ( wp_roles()->roles as $slug => $info ) {
			$role = get_role( $slug );
			if ( $role && $role->has_cap( TOTALSECWP_CAP ) ) {
				$role->remove_cap( TOTALSECWP_CAP );
			}
		}
	}
}
