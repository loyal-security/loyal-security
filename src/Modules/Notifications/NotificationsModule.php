<?php
/**
 * Notifications module — email alerts for security events.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Notifications;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\AbstractModule;
use LoyalSecurity\Core\Cron;
use LoyalSecurity\Modules\Audit\EventCatalog;

/**
 * Sends real-time email alerts when security events are logged.
 *
 * Hooks onto the `loyalsec_event_logged` action that {@see \LoyalSecurity\Modules\Audit\Logger}
 * fires after every write. Throttling is transient-based (no extra table needed).
 */
class NotificationsModule extends AbstractModule {

	public function id(): string {
		return 'notifications';
	}

	public function title(): string {
		return __( 'Notifications', 'loyal-security' );
	}

	/**
	 * Event types muted by default: blocked-and-handled noise. Attacks on a vulnerable plugin
	 * (virtual patches), lockouts, file changes, new administrators and the like still email.
	 *
	 * @return string[]
	 */
	public static function default_muted_events(): array {
		return array(
			EventCatalog::WAF_BLOCK,
			EventCatalog::WAF_BOT_BLOCK,
			EventCatalog::WAF_RATE_LIMIT,
			EventCatalog::WAF_QUERY_CARDINALITY,
			EventCatalog::WAF_GEO_BLOCK,
			EventCatalog::LOGIN_FAILED,
			EventCatalog::LOGIN_BLOCKED,
			EventCatalog::AUTHOR_ENUM_BLOCKED,
			EventCatalog::LOGIN_URL_PROBE_BLOCKED,
			EventCatalog::XMLRPC_PROBE,
			EventCatalog::XMLRPC_MULTICALL,
			EventCatalog::CORS_BLOCKED,
			EventCatalog::CSRF_ATTEMPT,
			EventCatalog::HOST_INJECTION,
			EventCatalog::HONEYPOT_HIT,
		);
	}

	public function default_settings(): array {
		return array(
			'enabled'              => true,

			/* --- Email channel --- */
			'email_enabled'        => true,
			'email_to'             => '',           // empty → use admin_email
			'email_min_severity'   => 30,           // 30 = warning, 40 = critical
			'email_categories'     => array(),      // empty → all; otherwise ['waf','auth',…]

			/* --- Throttle (applies per channel) --- */
			'throttle_max'         => 10,           // max notifications per window
			'throttle_window'      => 3600,         // window in seconds (1 hour)

			/* --- Muted event types --- */
			// List of event-type strings that should NEVER trigger a notification on any
			// channel (they are still recorded in the audit log). Managed from the UI.
			// By default: requests the firewall already blocked and handled. Every site sees
			// these from bots all day, and a store sees a failed sign-in for every customer
			// typo; emailing each one buried the alerts that need action.
			'muted_events'         => self::default_muted_events(),

			/* --- History --- */
			'history_enabled'      => true,         // record sent notifications for the history view
			'history_retention_days' => 90,         // prune sent-notification history after N days

			/* --- Smart routing --- */
			'routing_rules'        => array(),      // array of {severity_min, channel, quiet_start, quiet_end}
			'quiet_hours_enabled'  => false,
			'quiet_start'          => '23:00',
			'quiet_end'            => '07:00',
		);
	}

	public function register_hooks(): void {
		// Nothing that needs to run while disabled.
	}

	/**
	 * Public accessor so external collaborators (e.g. Dispatcher) can read module settings
	 * without requiring a subclass relationship.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Fallback value.
	 * @return mixed
	 */
	public function get_setting( string $key, $default = null ) {
		return $this->setting( $key, $default );
	}

	public function boot(): void {
		$dispatcher = new Dispatcher( $this );
		add_action( 'loyalsec_event_logged', array( $dispatcher, 'handle' ), 10, 3 );

		// Prune sent-notification history on the shared daily prune cron.
		add_action( Cron::PRUNE_LOGS, array( $this, 'prune_history' ) );
	}

	/**
	 * Delete sent-notification history older than the configured retention window.
	 * Hooked to the plugin's daily prune cron.
	 */
	public function prune_history(): void {
		$days = (int) $this->setting( 'history_retention_days', 90 );
		( new NotificationLog() )->prune( $days > 0 ? $days : 90 );
	}
}
