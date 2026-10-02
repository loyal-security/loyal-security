<?php
/**
 * Whether the separate Loyal Security Pro plugin is active.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Reports whether the separate Loyal Security Pro plugin is active. The free plugin performs no
 * license verification and unlocks nothing with this answer: every feature in this plugin works
 * the same either way. It only selects the threat-intelligence feed channel (a subscription to
 * the external feed service, described in the readme's "External services" section) and the
 * wording of the dashboard's pointers to Pro.
 */
class ProStatus {

	/**
	 * True when the Pro plugin reports itself active.
	 */
	public function active(): bool {
		/**
		 * Filters whether the Loyal Security Pro plugin is active. Pro hooks this; nothing in the
		 * free plugin sets it.
		 *
		 * @param bool $active Default false.
		 */
		return (bool) apply_filters( 'totalsecwp_pro_active', false );
	}

	/**
	 * 'pro' or 'free'.
	 */
	public function tier(): string {
		return $this->active() ? 'pro' : 'free';
	}
}
