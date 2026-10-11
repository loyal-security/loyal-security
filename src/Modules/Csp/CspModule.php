<?php
/**
 * CSP Manager module.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Csp;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\AbstractModule;

/**
 * Emits a configurable Content-Security-Policy header on every frontend response.
 * Completely skips wp-admin pages (WordPress core and our own React panel both require
 * unsafe-inline; enforcing CSP there would break the admin UI).
 */
class CspModule extends AbstractModule {

	public function id(): string {
		return 'csp';
	}

	public function title(): string {
		return 'CSP Manager';
	}

	/** Cron hook name for the pending-domain notification check. */
	public const CRON_NOTIFY = 'loyalsec_csp_notify_check';

	/** User meta: pending-domain count at which the user dismissed the CSP notice. */
	private const PENDING_DISMISS_META = 'loyalsec_csp_notice_dismissed_at';

	public function default_settings(): array {
		return array(
			'enabled'              => false, // opt-in; first-time users should scan before enforcing
			'mode'                 => 'report-only', // 'report-only' or 'enforce'
			'presets'              => array(), // enabled preset slugs
			'custom_directives'    => array(), // directive → [extra sources]
			'violations_log'       => true,
			// Learning-system settings.
			'notify_new_domains'   => true,  // email admin when new external domains appear
			'cooldown_hours'       => 24,    // hours with no new domains → "ready to apply" notification
			// Strict inline protection: tags every inline <script>/<style> with a per-request
			// nonce so modern browsers stop honouring 'unsafe-inline', without breaking older
			// ones (see CspPolicy::build()'s docblock). Off by default — existing sites with CSP
			// already in 'enforce' shouldn't have their inline-script coverage change under them
			// on a plugin update; an admin opts in after (ideally) validating in report-only.
			'nonce_protect_inline' => false,
			// Drops 'unsafe-eval' from script-src. No graceful degrade exists for this one (see
			// CspPolicy::build()) — a real behavior change for anything that calls eval(), so
			// it's opt-in same as the nonce setting, independently of it.
			'strict_eval'          => false,
		);
	}

	public function boot(): void {
		// Register the hourly cron for pending-domain notification checks.
		if ( ! wp_next_scheduled( self::CRON_NOTIFY ) ) {
			wp_schedule_event( time(), 'hourly', self::CRON_NOTIFY );
		}
		add_action( self::CRON_NOTIFY, array( $this, 'run_notify_check' ) );

		// Show admin notice when there are pending domains to review.
		add_action( 'admin_notices', array( $this, 'maybe_show_pending_notice' ) );
		add_action( 'admin_init', array( $this, 'maybe_dismiss_pending_notice' ) );

		// Never emit CSP headers on wp-admin pages — WP core and the plugin's own React app
		// require unsafe-inline for styles and scripts; enforcing CSP there breaks the admin UI.
		if ( is_admin() ) {
			return;
		}

		add_action( 'send_headers', array( $this, 'emit_header' ), 5 );

		if ( (bool) $this->setting( 'nonce_protect_inline', false ) ) {
			( new CspInlineTagger() )->register();
		}
	}

	/**
	 * Build and send the CSP header.
	 * Priority 5 so it runs before most other send_headers callbacks.
	 */
	public function emit_header(): void {
		if ( headers_sent() ) {
			return;
		}

		try {
			$policy = $this->build_policy();

			if ( (bool) $this->setting( 'violations_log', true ) ) {
				$report_uri = rest_url( LOYALSEC_REST_NAMESPACE . '/csp/report' );
				$policy    .= '; report-uri ' . $report_uri;
			}

			$mode   = $this->setting( 'mode', 'report-only' );
			$header = 'enforce' === $mode
				? 'Content-Security-Policy'
				: 'Content-Security-Policy-Report-Only';

			header( $header . ': ' . $policy );
		} catch ( \Throwable $e ) {
			// Silently fail rather than break the site's frontend.
		}
	}

	/**
	 * Build the policy string from current settings.
	 */
	public function build_policy(): string {
		$nonce = (bool) $this->setting( 'nonce_protect_inline', false ) ? CspNonce::value() : '';
		return CspPolicy::build(
			array(
				'presets'           => (array) $this->setting( 'presets', array() ),
				'custom_directives' => (array) $this->setting( 'custom_directives', array() ),
			),
			$nonce,
			(bool) $this->setting( 'strict_eval', false )
		);
	}

	/**
	 * Return a scanner instance.
	 */
	public function scanner(): CspScanner {
		return new CspScanner();
	}

	/* ------------------------------------------------------------------ */
	/* Learning-system: notification cron                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Hourly cron callback: decide whether to email the admin about pending domains.
	 *
	 * Two triggers:
	 *   (a) New domains arrived since the last notification → send "new resources" alert
	 *       (throttled to at most once per hour).
	 *   (b) Cooldown elapsed with no new domains AND there are still pending entries →
	 *       send "policy is stable and ready to apply" alert.
	 */
	public function run_notify_check(): void {
		if ( ! $this->setting( 'notify_new_domains', true ) ) {
			return;
		}

		$store   = new CspPendingStore();
		$pending = $store->count_pending();

		if ( $pending === 0 ) {
			return;
		}

		$now           = time();
		$last_new      = $store->last_new_ts();
		$last_notified = $store->last_notified_ts();
		$cooldown      = (int) $this->setting( 'cooldown_hours', 24 ) * 3600;

		$send_new      = $store->has_new_flag() && ( $last_notified + 3600 ) < $now;
		$send_cooldown = ! $store->has_new_flag()
			&& $last_new > 0
			&& ( $last_new + $cooldown ) < $now
			&& ( $last_notified + $cooldown ) < $now;

		if ( ! $send_new && ! $send_cooldown ) {
			return;
		}

		$this->send_pending_email( $pending, $send_cooldown );
		$store->clear_new_flag();
	}

	/**
	 * Email the admin about pending CSP domains.
	 *
	 * @param int  $count      Number of pending domains.
	 * @param bool $is_stable  True → "ready to apply" message; false → "new resources" message.
	 */
	private function send_pending_email( int $count, bool $is_stable ): void {
		$to   = (string) get_option( 'admin_email' );
		$blog = wp_strip_all_tags( (string) get_option( 'blogname' ) );
		$url  = esc_url( (string) admin_url( 'admin.php?page=loyal-security#/csp' ) );
		$noun = $count !== 1 ? 'domains' : 'domain';

		if ( $is_stable ) {
			$subject = sprintf( '[%s] CSP policy ready to apply — %d resource %s pending', $blog, $count, $noun );
			$intro   = sprintf(
				'<p>Your Content Security Policy monitor has been collecting data and detected <strong>%d external resource %s</strong> that need review. '
				. 'No new resources have appeared for <strong>%d hour%s</strong>, which means the policy is stable and ready to enforce.</p>',
				$count, $noun,
				(int) $this->setting( 'cooldown_hours', 24 ),
				(int) $this->setting( 'cooldown_hours', 24 ) !== 1 ? 's' : ''
			);
		} else {
			$subject = sprintf( '[%s] CSP monitor: %d new external resource %s detected', $blog, $count, $noun );
			$intro   = sprintf(
				'<p>Loyal Security detected <strong>%d external resource %s</strong> on your site that %s not yet '
				. 'reviewed in your Content Security Policy.</p>',
				$count, $noun,
				$count !== 1 ? 'are' : 'is'
			);
		}

		$body = '<html><body style="font-family:sans-serif;color:#222;max-width:600px;margin:auto;">'
			. '<h2 style="border-left:4px solid #0073aa;padding-left:12px;">Loyal Security — CSP Monitor</h2>'
			. $intro
			. '<p>Open the CSP Manager to approve resources you want to allow or dismiss ones you want to keep blocked:</p>'
			. '<p><a href="' . $url . '" style="background:#0073aa;color:#fff;padding:8px 18px;text-decoration:none;border-radius:4px;display:inline-block;">Review Pending Resources &rarr;</a></p>'
			. '<p style="font-size:11px;color:#999;margin-top:28px;">Sent by Loyal Security on <a href="' . esc_url( (string) home_url() ) . '">' . esc_html( $blog ) . '</a>. '
			. '<a href="' . esc_url( (string) admin_url( 'admin.php?page=loyal-security#/csp' ) ) . '">Manage CSP settings</a></p>'
			. '</body></html>';

		wp_mail( $to, $subject, $body, array( 'Content-Type: text/html; charset=UTF-8' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Learning-system: admin notice                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Show a dismissible admin notice when there are pending domains to review.
	 * Only shown to admins and only when the current screen isn't already the plugin page.
	 */
	public function maybe_show_pending_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Dashboard and Plugins screens only (the CSP screen itself lists pending domains).
		if ( ! \LoyalSecurity\Admin\Notices::on_overview_screen() ) {
			return;
		}

		$count = ( new CspPendingStore() )->count_pending();
		if ( $count === 0 ) {
			return;
		}

		// Dismissed by this user at this count or higher: stay quiet until more domains arrive.
		if ( (int) get_user_meta( get_current_user_id(), self::PENDING_DISMISS_META, true ) >= $count ) {
			return;
		}

		$dismiss = wp_nonce_url( add_query_arg( 'loyalsec_dismiss_csp_pending', (string) $count ), 'loyalsec_dismiss_csp_pending' );
		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a> <a href="%5$s" class="button-link">%6$s</a></p></div>',
			esc_html__( 'Loyal Security CSP Monitor:', 'loyal-security' ),
			esc_html(
				sprintf(
					/* translators: %d: number of external resource domains awaiting review. */
					_n( '%d external resource domain is pending review.', '%d external resource domains are pending review.', $count, 'loyal-security' ),
					$count
				)
			),
			esc_url( admin_url( 'admin.php?page=loyal-security#/csp' ) ),
			esc_html__( 'Review and approve →', 'loyal-security' ),
			esc_url( $dismiss ),
			esc_html__( 'Dismiss', 'loyal-security' )
		);
	}

	/**
	 * Record the pending count at which the current user dismissed the CSP notice.
	 */
	public function maybe_dismiss_pending_notice(): void {
		if ( empty( $_GET['loyalsec_dismiss_csp_pending'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'loyalsec_dismiss_csp_pending' );
		update_user_meta( get_current_user_id(), self::PENDING_DISMISS_META, absint( wp_unslash( $_GET['loyalsec_dismiss_csp_pending'] ) ) );
	}
}
