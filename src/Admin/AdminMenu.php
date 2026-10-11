<?php
/**
 * Admin menu registration.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Admin;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Container;
use LoyalSecurity\Core\Assets;

/**
 * Registers the top-level "Loyal Security" menu. The whole dashboard is a single-page
 * React app, so there is one rendered page; sub-navigation happens client-side. Submenu
 * entries are deep-links into the SPA via a `#/route` hash.
 */
class AdminMenu {

	private Container $container;

	public function __construct( Container $container ) {
		$this->container = $container;
	}

	public function register_hooks(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
	}

	public function register_menu(): void {
		// On multisite only super admins manage the plugin (see Capabilities::can_manage()).
		$cap  = is_multisite() ? 'manage_network_options' : ( current_user_can( LOYALSEC_CAP ) ? LOYALSEC_CAP : 'manage_options' );
		$name = \LoyalSecurity\Support\Brand::name();

		$hook = add_menu_page(
			$name,
			$name,
			$cap,
			'loyal-security',
			array( $this, 'render' ),
			'dashicons-shield',
			100
		);

		// The dashboard is a single-page app; in-app sidebar navigation handles routing, so
		// we register just the one page (WordPress auto-adds the duplicate submenu label).

		/** @var Assets $assets */
		$assets = $this->container->make( 'assets' );
		$assets->register_pages( $hook, 'toplevel_page_loyal-security' );
	}

	public function render(): void {
		( new DashboardPage() )->render();
	}
}
