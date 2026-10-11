<?php
/**
 * Upgrade / pricing REST controller.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\LicenseKit;
use LoyalSecurity\Rest\AbstractController;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Routes:
 *   GET /upgrade/pricing — live plan data for the Upgrade-to-Pro panel, proxied server-side
 *   from LicenseKit and cached briefly so the dashboard renders real prices natively instead
 *   of iframing LicenseKit's own pricing page (see UpgradePanel.js).
 */
class UpgradeController extends AbstractController {

	/** Transient key + TTL for the proxied pricing payload. */
	private const CACHE_KEY = 'loyalsec_upgrade_pricing';
	private const CACHE_TTL = HOUR_IN_SECONDS;

	public function register_routes(): void {
		register_rest_route( $this->namespace(), '/upgrade/pricing', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'get_pricing' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
	}

	public function get_pricing( WP_REST_Request $request ): WP_REST_Response {
		$cached = get_transient( self::CACHE_KEY );
		if ( is_array( $cached ) ) {
			return $this->ok( $cached );
		}

		$slug = defined( 'LOYALSEC_LICENSE_ITEM_SLUG' ) ? (string) \LOYALSEC_LICENSE_ITEM_SLUG : 'loyal-security';
		$data = LicenseKit::pricing( $slug );

		if ( null === $data ) {
			// Fail open with an explicit "unavailable" shape rather than a 5xx — the panel falls
			// back to a plain link-out to LicenseKit's own pricing page in this case.
			return $this->ok(
				array(
					'available' => false,
					'plans'     => array(),
				)
			);
		}

		$payload = array(
			'available'    => true,
			'product'      => $data['product'] ?? null,
			'plans'        => $data['plans'] ?? array(),
			'pricing_url'  => $data['pricing_url'] ?? '',
			'checkout_url' => $data['checkout_url'] ?? '',
		);

		set_transient( self::CACHE_KEY, $payload, self::CACHE_TTL );

		return $this->ok( $payload );
	}
}
