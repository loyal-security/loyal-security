<?php
/**
 * Public "Protected by" trust badge — a floating widget and a shortcode for manual placement.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * A small, optional badge advertising that the site runs Loyal Security, with a real (not
 * made-up) stat pulled from this site's own 30-day activity. Every install that displays it is a
 * small piece of organic distribution — social proof that costs the plugin nothing.
 *
 * Two independent placements, both gated on the same master `trust_badge_enabled` switch:
 *  - Floating (default when enabled) — auto-injected bottom-corner widget via `wp_footer`, the
 *    same "just appears" pattern as a cookie-consent banner or the reCAPTCHA badge. No shortcode
 *    needed; this is what most admins actually want.
 *  - Shortcode (`[loyal_security_badge]`) — for an admin who wants it in a specific spot
 *    instead (a widget area, inline in a page) rather than floating. Switching floating off
 *    doesn't disable the feature, just the auto-placement; the shortcode keeps working either way
 *    so nothing already pasted somewhere silently breaks.
 *
 * Deliberately renders entirely server-side from data already on this site (no REST call, no new
 * public unauthenticated API surface, no dependency on an external image-generation service).
 */
class TrustBadge {

	private const STYLE_HANDLE = 'totalsecwp-trust-badge';

	public function register_hooks(): void {
		add_shortcode( 'loyal_security_badge', array( $this, 'render' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
		add_action( 'wp_footer', array( $this, 'maybe_render_floating' ) );
	}

	/**
	 * Register the badge stylesheet, and enqueue it up front when the floating badge will show.
	 * The shortcode enqueues it itself when it renders (WordPress then prints it in the footer).
	 */
	public function enqueue_style(): void {
		$settings = $this->settings();
		if ( ! $settings->get( 'firewall', 'trust_badge_enabled', false ) ) {
			return;
		}
		wp_register_style(
			self::STYLE_HANDLE,
			plugins_url( 'assets/css/trust-badge.css', TOTALSECWP_FILE ),
			array(),
			TOTALSECWP_VERSION
		);
		if ( $settings->get( 'firewall', 'trust_badge_floating', true ) ) {
			wp_enqueue_style( self::STYLE_HANDLE );
		}
	}

	/**
	 * @param array<string,mixed>|string $atts Shortcode attributes ('style' => 'light'|'dark', default 'dark').
	 */
	public function render( $atts = array() ): string {
		// The shortcode stays registered even when the admin has this switched off (Firewall →
		// Trust Badge toggle) — so a page that already has it pasted in just quietly renders
		// nothing instead of leaving a dangling, WordPress-native "shortcode not found" notice.
		if ( ! $this->settings()->get( 'firewall', 'trust_badge_enabled', false ) ) {
			return '';
		}

		wp_enqueue_style( self::STYLE_HANDLE );
		$atts = shortcode_atts( array( 'style' => 'dark' ), (array) $atts, 'loyal_security_badge' );
		return wp_kses( $this->badge_markup( 'light' !== $atts['style'] ), self::allowed_html() );
	}

	/**
	 * Auto-injects the badge as a fixed-position corner widget on public-facing pages, mirroring
	 * how a cookie-consent banner or the reCAPTCHA badge appears without the site owner having to
	 * place anything by hand. Two settings gate this independently of the shortcode: the master
	 * `trust_badge_enabled` switch, and `trust_badge_floating` specifically for this placement —
	 * an admin who wants the badge only in one hand-picked spot switches floating off and uses the
	 * shortcode instead, without losing the feature entirely.
	 */
	public function maybe_render_floating(): void {
		if ( is_admin() ) {
			return;
		}
		$settings = $this->settings();
		if ( ! $settings->get( 'firewall', 'trust_badge_enabled', false ) ) {
			return;
		}
		if ( ! $settings->get( 'firewall', 'trust_badge_floating', true ) ) {
			return;
		}

		$corner = 'bottom-left' === $settings->get( 'firewall', 'trust_badge_position', 'bottom-right' ) ? 'left' : 'right';
		$dark   = 'light' !== $settings->get( 'firewall', 'trust_badge_style', 'dark' );

		echo wp_kses(
			'<div class="loysec-badge-float loysec-badge-float--' . $corner . '">' . $this->badge_markup( $dark ) . '</div>',
			self::allowed_html()
		);
	}

	/**
	 * The badge itself — shared by both the shortcode and the floating widget so the two
	 * placements can never visually drift apart. All presentation lives in
	 * assets/css/trust-badge.css; the markup only carries classes.
	 */
	private function badge_markup( bool $dark ): string {
		$blocked = $this->blocked_last_30_days();

		$label = $blocked > 0
			? sprintf(
				/* translators: %s: number of blocked attacks in the last 30 days, formatted with thousands separator. */
				__( '%s attacks blocked (30d)', 'loyal-security' ),
				number_format_i18n( $blocked )
			)
			: __( 'Actively monitored', 'loyal-security' );

		return sprintf(
			'<a class="loysec-badge %1$s" href="%2$s" target="_blank" rel="noopener noreferrer" aria-label="%3$s">'
				. '<svg class="loysec-badge__icon" width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2l8 3.5v6c0 5-3.4 8.9-8 10.5-4.6-1.6-8-5.5-8-10.5v-6L12 2z" stroke-width="1.8" fill="none"/></svg>'
				. '<span>%4$s <strong>%5$s</strong></span>'
				. '</a>',
			esc_attr( $dark ? 'loysec-badge--dark' : 'loysec-badge--light' ),
			esc_url( 'https://loyalsecuritywp.com/?utm_source=badge&utm_medium=referral' ),
			esc_attr__( 'Protected by Loyal Security', 'loyal-security' ),
			esc_html__( 'Protected by Loyal Security', 'loyal-security' ),
			esc_html( $label )
		);
	}

	/**
	 * The only tags and attributes the badge markup may contain.
	 *
	 * @return array<string, array<string, bool>>
	 */
	private static function allowed_html(): array {
		return array(
			'div'    => array( 'class' => true ),
			'a'      => array( 'class' => true, 'href' => true, 'target' => true, 'rel' => true, 'aria-label' => true ),
			'svg'    => array( 'class' => true, 'width' => true, 'height' => true, 'viewbox' => true, 'fill' => true, 'aria-hidden' => true ),
			'path'   => array( 'd' => true, 'stroke-width' => true, 'fill' => true ),
			'span'   => array(),
			'strong' => array(),
		);
	}

	private function settings(): \TotalSecurityWP\Core\Settings {
		return \TotalSecurityWP\Plugin::instance()->container()->make( 'settings' );
	}

	/**
	 * Real 30-day WAF block count from this site's own audit trail — never a placeholder number.
	 * A zero (or a site where the table is briefly unavailable) falls back to "Actively
	 * monitored" in badge_markup() rather than showing a hollow "0 attacks blocked", which would
	 * read as broken rather than reassuring.
	 */
	private function blocked_last_30_days(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'totalsecwp_events';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			return 0;
		}
		$since = gmdate( 'Y-m-d H:i:s', time() - 30 * DAY_IN_SECONDS );
		return (int) $wpdb->get_var( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE event_type LIKE %s AND created_at >= %s", $table,
				'waf.%',
				$since
			)
		);
	}
}
