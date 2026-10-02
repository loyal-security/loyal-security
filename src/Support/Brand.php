<?php
/**
 * Product name shown in admin screens, alert emails and passkey prompts.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Single source for the display name, filterable so a site owner (or an add-on) can rename it.
 */
final class Brand {

	public const NAME = 'Loyal Security';

	public static function name(): string {
		/**
		 * Filters the product name shown in the dashboard, admin menu, admin bar, alert emails and
		 * passkey prompts.
		 *
		 * @param string $name Default 'Loyal Security'.
		 */
		$name = apply_filters( 'totalsecwp_brand_name', self::NAME );
		$name = is_string( $name ) ? trim( wp_strip_all_tags( $name ) ) : '';
		return '' !== $name ? $name : self::NAME;
	}
}
