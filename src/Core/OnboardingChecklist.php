<?php
/**
 * Onboarding Checklist — a post-activation setup guide for the dashboard.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Core;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Plugin;

/**
 * Evaluates a fixed list of getting-started steps and reports completion progress so the
 * dashboard can surface a guided onboarding banner.
 */
class OnboardingChecklist {

	private const DISMISS_OPTION = 'totalsecwp_onboarding_dismissed';

	/**
	 * Evaluate every step's current state.
	 *
	 * @return array<int,array{id:string,label:string,description:string,done:bool,action_url:string,optional:bool}>
	 */
	public function get_steps(): array {
		$steps = array(
			array(
				'id'          => 'enable_firewall',
				'label'       => __( 'Enable the firewall', 'loyal-security' ),
				'description' => __( 'Turn on the Web Application Firewall to block malicious requests.', 'loyal-security' ),
				'done'        => $this->module_enabled( 'firewall' ),
				'action_url'  => '#/firewall',
				'optional'    => false,
			),
			array(
				'id'          => 'run_first_scan',
				'label'       => __( 'Run your first malware scan', 'loyal-security' ),
				'description' => __( 'Scan your files for malware, backdoors, and suspicious code.', 'loyal-security' ),
				'done'        => $this->has_scan_history(),
				'action_url'  => '#/scanner',
				'optional'    => false,
			),
			array(
				'id'          => 'enable_2fa',
				'label'       => __( 'Enable two-factor authentication', 'loyal-security' ),
				'description' => __( 'Protect logins with a second authentication factor.', 'loyal-security' ),
				'done'        => $this->module_enabled( 'auth' ),
				'action_url'  => '#/2fa',
				'optional'    => false,
			),
			array(
				'id'          => 'setup_notifications',
				'label'       => __( 'Set up notifications', 'loyal-security' ),
				'description' => __( 'Get alerted by email when security events occur.', 'loyal-security' ),
				'done'        => $this->module_enabled( 'notifications' ) && $this->has_notification_email(),
				'action_url'  => '#/notifications',
				'optional'    => false,
			),
			array(
				'id'          => 'enable_hardening',
				'label'       => __( 'Apply system hardening', 'loyal-security' ),
				'description' => __( 'Lock down WordPress with recommended hardening measures.', 'loyal-security' ),
				'done'        => $this->module_enabled( 'hardening' ),
				'action_url'  => '#/hardening',
				'optional'    => false,
			),
			array(
				'id'          => 'setup_backup',
				'label'       => __( 'Configure backups', 'loyal-security' ),
				'description' => __( 'Schedule backups so you can recover after an incident.', 'loyal-security' ),
				'done'        => $this->module_enabled( 'backup' ),
				'action_url'  => '#/backup',
				'optional'    => false,
			),
		);

		/**
		 * Filters the onboarding steps after their done-state has been evaluated.
		 *
		 * @since 1.0.0
		 *
		 * @param array<int,array<string,mixed>> $steps Step list.
		 */
		return apply_filters( 'totalsecwp_onboarding_steps', $steps );
	}

	/**
	 * Percentage of non-optional steps that are complete (0–100).
	 */
	public function completion_percent(): int {
		$required = array_filter( $this->get_steps(), static fn( $s ) => empty( $s['optional'] ) );
		$total    = count( $required );
		if ( 0 === $total ) {
			return 100;
		}
		$done = count( array_filter( $required, static fn( $s ) => ! empty( $s['done'] ) ) );
		return (int) round( ( $done / $total ) * 100 );
	}

	/**
	 * Mark the onboarding banner as dismissed.
	 */
	public function dismiss(): void {
		update_option( self::DISMISS_OPTION, true, false );
	}

	/**
	 * Whether the banner has been dismissed.
	 */
	public function is_dismissed(): bool {
		return (bool) get_option( self::DISMISS_OPTION, false );
	}

	/**
	 * Whether a module exists and is enabled.
	 */
	private function module_enabled( string $module_id ): bool {
		if ( ! class_exists( Plugin::class ) ) {
			return false;
		}
		$module = Plugin::instance()->module( $module_id );
		return $module ? $module->is_enabled() : false;
	}

	/**
	 * Whether at least one scan has been recorded.
	 */
	private function has_scan_history(): bool {
		$history = get_option( 'totalsecwp_scan_history', array() );
		return is_array( $history ) && ! empty( $history );
	}

	/**
	 * Whether a notification recipient email is configured.
	 */
	private function has_notification_email(): bool {
		if ( ! class_exists( Plugin::class ) ) {
			return false;
		}
		$settings = Plugin::instance()->container()->make( 'settings' );
		// An explicit recipient, or the admin_email fallback the mailer uses when empty.
		$email = trim( (string) $settings->get( 'notifications', 'email_to', '' ) );
		if ( '' !== $email ) {
			return true;
		}
		return '' !== trim( (string) get_option( 'admin_email', '' ) );
	}
}
