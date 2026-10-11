<?php
/**
 * Dashboard page shell (React mount point).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Renders the minimal HTML shell that the React app mounts into. All UI is rendered
 * client-side; this just provides the root node and a no-JS fallback message.
 */
class DashboardPage {

	public function render(): void {
		// Stamped server-side so the first paint already reflects the admin's saved Basic/
		// Advanced preference, instead of the app defaulting to Advanced and visibly
		// re-rendering to Basic once the preference fetch resolves client-side.
		$ui_view = 'basic' === get_user_meta( get_current_user_id(), 'loyalsec_ui_view', true ) ? 'basic' : 'advanced';
		// Same reasoning for the light/dark/system theme choice — stamped up front so an admin
		// who explicitly picked "Dark" never sees a flash of the OS/WP-core-driven theme before
		// their own choice applies. "system" is stamped as-is (not resolved server-side) so the
		// CSS's existing prefers-color-scheme / admin-color-midnight triggers keep deciding it.
		$theme = get_user_meta( get_current_user_id(), 'loyalsec_theme', true );
		$theme = in_array( $theme, array( 'light', 'dark' ), true ) ? $theme : 'system';
		?>
		<div class="wrap loyalsec-wrap">
			<div id="loyalsec-app" data-ui-view="<?php echo esc_attr( $ui_view ); ?>" data-theme="<?php echo esc_attr( $theme ); ?>">
				<div class="loyalsec-boot">
					<span class="loyalsec-spinner" aria-hidden="true"></span>
					<p><?php
						$brand_name = \LoyalSecurity\Support\Brand::name();
						/* translators: %s: plugin name. */
						printf( esc_html__( 'Loading %s…', 'loyal-security' ), esc_html( $brand_name ) );
					?></p>
					<noscript>
						<p><?php esc_html_e( 'Loyal Security requires JavaScript to be enabled.', 'loyal-security' ); ?></p>
					</noscript>
				</div>
			</div>
		</div>
		<?php
	}
}
