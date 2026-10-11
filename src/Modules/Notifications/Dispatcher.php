<?php
/**
 * Notification dispatcher — sends email alerts.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Notifications;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Audit\EventCatalog;

/**
 * Receives a logged event and fans it out to each configured channel, subject to
 * per-channel severity thresholds, a mute list, and a shared throttle counter. Every
 * dispatch is recorded to the notification history ({@see NotificationLog}) and the
 * message body is built from the shared {@see EventGuide} so alerts are self-explanatory.
 */
class Dispatcher {

	private NotificationsModule $module;
	private ?NotificationLog $log = null;

	/** Transient key prefix for throttle counters (one per channel). */
	private const TRANSIENT_PREFIX = 'loyalsec_notif_throttle_';

	public function __construct( NotificationsModule $module ) {
		$this->module = $module;
	}

	/**
	 * Display name for outbound notifications.
	 */
	private function brand_name(): string {
		return \LoyalSecurity\Support\Brand::name();
	}

	/**
	 * Entry-point hooked to `loyalsec_event_logged`.
	 *
	 * @param string               $type  Event type constant.
	 * @param array<string, mixed> $data  Full row data as written to DB (already scrubbed).
	 * @param int                  $id    Inserted row id.
	 */
	public function handle( string $type, array $data, int $id ): void {
		$severity = (int) ( $data['severity'] ?? EventCatalog::default_severity( $type ) );

		// A muted event type is suppressed on every channel. It stays in the audit log; we
		// simply do not alert on it and do not clutter the notification history.
		if ( $this->is_muted( $type ) ) {
			return;
		}

		// Decode context once and build shared guidance for every channel + the history row.
		$context = $this->decode_context( $data );
		$guide   = EventGuide::for_event( $type, $context, $severity );

		if ( $this->module->get_setting( 'email_enabled', true ) ) {
			$this->maybe_send_email( $type, $data, $severity, $guide, $id );
		}

		/**
		 * Fires for every event that passed the mute list, after the email channel ran, so an
		 * add-on can deliver it through channels of its own.
		 *
		 * @param array<string,mixed> $event   { type, data, severity, guide, id }.
		 * @param NotificationsModule $module  The notifications module (settings access).
		 */
		do_action(
			'loyalsec_notification_event',
			array( 'type' => $type, 'data' => $data, 'severity' => $severity, 'guide' => $guide, 'id' => $id ),
			$this->module
		);
	}

	/* ------------------------------------------------------------------ *
	 * Mute list
	 * ------------------------------------------------------------------ */

	/**
	 * Whether an event type has been muted by the site owner.
	 */
	private function is_muted( string $type ): bool {
		$muted = (array) $this->module->get_setting( 'muted_events', array() );
		foreach ( $muted as $m ) {
			if ( (string) $m === $type ) {
				return true;
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ *
	 * Quiet hours
	 * ------------------------------------------------------------------ */

	/**
	 * Whether the site is currently within its configured quiet-hours window.
	 *
	 * CRITICAL alerts bypass this (handled by callers); routine alerts are suppressed.
	 */
	private function is_quiet_hours(): bool {
		if ( ! $this->module->get_setting( 'quiet_hours_enabled', false ) ) {
			return false;
		}
		$start = (string) $this->module->get_setting( 'quiet_start', '23:00' );
		$end   = (string) $this->module->get_setting( 'quiet_end', '07:00' );
		// Compare current time (site timezone) against start/end HH:MM.
		$now = (int) current_time( 'H' ) * 60 + (int) current_time( 'i' );
		$s   = $this->hhmm_to_minutes( $start );
		$e   = $this->hhmm_to_minutes( $end );
		if ( $s > $e ) {
			// Crosses midnight.
			return $now >= $s || $now < $e;
		}
		return $now >= $s && $now < $e;
	}

	private function hhmm_to_minutes( string $hhmm ): int {
		$parts = explode( ':', $hhmm, 2 );
		return (int) ( $parts[0] ?? 0 ) * 60 + (int) ( $parts[1] ?? 0 );
	}

	/* ------------------------------------------------------------------ *
	 * Email channel
	 * ------------------------------------------------------------------ */

	/**
	 * @param string                                                                             $type     Event type.
	 * @param array<string, mixed>                                                               $data     Row data.
	 * @param int                                                                                 $severity Severity.
	 * @param array{title:string,icon:string,severity_label:string,meaning:string,legit:string,fix:string[],facts:array} $guide Shared guidance.
	 * @param int                                                                                 $event_id Audit row id.
	 */
	private function maybe_send_email( string $type, array $data, int $severity, array $guide, int $event_id ): void {
		$min = (int) $this->module->get_setting( 'email_min_severity', 30 );
		if ( $severity < $min ) {
			return;
		}

		$cats = (array) $this->module->get_setting( 'email_categories', array() );
		if ( $cats && ! $this->matches_category( $type, $cats ) ) {
			return;
		}

		// Quiet hours suppress routine alerts; CRITICAL always goes through.
		if ( $severity < EventCatalog::SEV_CRITICAL && $this->is_quiet_hours() ) {
			return;
		}

		/**
		 * Filters whether an event is emailed. An add-on that already sends its own, more
		 * specific email for an event can return false here so the owner gets one email, not two.
		 *
		 * @since 1.5.0
		 *
		 * @param bool                 $send     Whether to email the event.
		 * @param string               $type     Event type.
		 * @param array<string, mixed> $data     Event row.
		 * @param int                  $severity Severity.
		 */
		if ( ! apply_filters( 'loyalsec_notification_email', true, $type, $data, $severity ) ) {
			return;
		}

		if ( ! $this->allow( 'email' ) ) {
			return;
		}

		$to      = (string) $this->module->get_setting( 'email_to', '' );
		$to      = $to ?: (string) get_option( 'admin_email' );
		$subject = $this->email_subject( $guide, $severity );
		$body    = $this->email_body( $type, $data, $severity, $guide );

		$ok = wp_mail(
			$to,
			$subject,
			$body,
			array( 'Content-Type: text/html; charset=UTF-8' )
		);

		$this->record( $event_id, $type, $severity, 'email', $to, $subject, $guide['meaning'], (bool) $ok );
	}

	/**
	 * Credit line for emails whose details include a country (country blocks, impossible travel,
	 * anything with a country in its context): country data comes from DB-IP Lite, whose
	 * licence (CC BY 4.0) asks for a link wherever its results are shown.
	 *
	 * @param string               $type Event type.
	 * @param array<string, mixed> $data Event row.
	 */
	private function country_credit( string $type, array $data ): string {
		$context = isset( $data['context'] ) ? (string) $data['context'] : '';
		if ( 0 !== strpos( $type, 'waf.geo' ) && false === stripos( $context, 'country' ) ) {
			return '';
		}
		return '<p style="font-size:11px;color:#999;margin:8px 0 0;">Country data: <a href="' . esc_url( 'https://db-ip.com' ) . '" style="color:#999;">IP Geolocation by DB-IP</a></p>';
	}

	/**
	 * Subject line: friendly title first, so the inbox is scannable.
	 *
	 * @param array{title:string} $guide Guidance.
	 */
	private function email_subject( array $guide, int $severity ): string {
		$label = EventCatalog::severity_label( $severity );
		$blog  = wp_strip_all_tags( (string) get_option( 'blogname' ) );
		return sprintf( '[%s] %s: %s', $blog, strtoupper( $label ), $guide['title'] );
	}

	/**
	 * Build a self-explanatory HTML email: what happened, whether it is normal, what to do,
	 * and the technical details — no raw event codes or serialized blobs.
	 *
	 * @param string               $type     Event type.
	 * @param array<string, mixed> $data     Row data.
	 * @param int                  $severity Severity.
	 * @param array{title:string,icon:string,meaning:string,legit:string,fix:string[],facts:array} $guide Guidance.
	 */
	private function email_body( string $type, array $data, int $severity, array $guide ): string {
		$accent = $severity >= EventCatalog::SEV_CRITICAL ? '#c0392b' : ( $severity >= EventCatalog::SEV_WARNING ? '#e67e22' : '#2980b9' );
		$label  = EventCatalog::severity_label( $severity );

		$blog     = esc_html( (string) get_option( 'blogname' ) );
		$blog_url = esc_url( (string) home_url() );
		$logs_url = esc_url( (string) admin_url( 'admin.php?page=loyal-security#/logs' ) );
		$notif_url = esc_url( (string) admin_url( 'admin.php?page=loyal-security#/notifications' ) );

		$time = esc_html( (string) ( $data['created_at'] ?? gmdate( 'Y-m-d H:i:s' ) ) );
		$ip   = esc_html( (string) ( $data['ip'] ?? 'N/A' ) );
		$uri  = esc_html( (string) ( $data['request_uri'] ?? '' ) );

		/* --- "What to do" list --- */
		$fix_html = '';
		foreach ( (array) $guide['fix'] as $step ) {
			$fix_html .= '<li style="margin:4px 0;">' . esc_html( (string) $step ) . '</li>';
		}

		/* --- Technical details (humanised facts + core fields) --- */
		$rows  = '';
		$rows .= $this->detail_row( 'Severity', ucfirst( $label ) . ' — technical code: ' . $type, true );
		$rows .= $this->detail_row( 'When (UTC)', $data['created_at'] ?? gmdate( 'Y-m-d H:i:s' ), false );
		if ( ! empty( $data['ip'] ) && 'N/A' !== $data['ip'] ) {
			$rows .= $this->detail_row( 'IP address', $data['ip'], true );
		}
		if ( '' !== $uri ) {
			$rows .= $this->detail_row( 'Request URL', $data['request_uri'], false );
		}
		$striped = true;
		foreach ( (array) $guide['facts'] as $fact ) {
			// Skip a couple of low-value keys already covered above.
			$rows   .= $this->detail_row( (string) $fact['label'], (string) $fact['value'], $striped );
			$striped = ! $striped;
		}

		$sev_badge = '<span style="display:inline-block;padding:2px 10px;border-radius:10px;background:' . $accent . ';color:#fff;font-size:12px;font-weight:bold;">' . esc_html( strtoupper( $label ) ) . '</span>';

		return '<html><body style="margin:0;background:#f2f4f6;padding:24px 0;">'
			. '<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#222;max-width:620px;margin:auto;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #e2e6ea;">'

			/* Header */
			. '<div style="border-left:6px solid ' . $accent . ';padding:18px 22px;background:#fafbfc;">'
			. '<div style="font-size:13px;color:#888;letter-spacing:.5px;text-transform:uppercase;">' . esc_html( $this->brand_name() ) . ' · ' . $blog . '</div>'
			. '<h1 style="margin:6px 0 8px;font-size:20px;line-height:1.3;">' . esc_html( (string) $guide['icon'] ) . ' ' . esc_html( (string) $guide['title'] ) . '</h1>'
			. $sev_badge
			. '</div>'

			. '<div style="padding:22px;">'

			/* What this means */
			. '<h2 style="font-size:15px;margin:0 0 6px;color:#333;">What this means</h2>'
			. '<p style="margin:0 0 18px;line-height:1.5;color:#444;">' . esc_html( (string) $guide['meaning'] ) . '</p>'

			/* Is this normal? */
			. ( $guide['legit']
				? '<h2 style="font-size:15px;margin:0 0 6px;color:#333;">Is this normal, or a false positive?</h2>'
					. '<p style="margin:0 0 18px;line-height:1.5;color:#444;">' . esc_html( (string) $guide['legit'] ) . '</p>'
				: '' )

			/* What to do */
			. ( $fix_html
				? '<h2 style="font-size:15px;margin:0 0 6px;color:#333;">What to do</h2>'
					. '<ol style="margin:0 0 18px;padding-left:20px;line-height:1.5;color:#444;">' . $fix_html . '</ol>'
				: '' )

			/* Details */
			. '<h2 style="font-size:15px;margin:0 0 6px;color:#333;">Details</h2>'
			. '<table style="border-collapse:collapse;width:100%;font-size:13px;border:1px solid #eee;">' . $rows . '</table>'
			. $this->country_credit( $type, $data )

			/* Actions */
			. '<div style="margin:22px 0 6px;">'
			. '<a href="' . $logs_url . '" style="background:' . $accent . ';color:#fff;padding:10px 18px;text-decoration:none;border-radius:5px;font-size:14px;display:inline-block;">Investigate in dashboard</a>'
			. '</div>'
			. '<p style="font-size:12px;color:#888;margin:14px 0 0;line-height:1.5;">Getting too many alerts like this? You can mute this event type from the '
			. '<a href="' . $notif_url . '" style="color:' . $accent . ';">notification centre</a> — it will still be recorded in your audit log.</p>'

			. '</div>'

			/* Footer */
			. '<div style="padding:14px 22px;background:#fafbfc;border-top:1px solid #eee;font-size:11px;color:#999;">'
			. 'Sent by ' . esc_html( $this->brand_name() ) . ' for <a href="' . $blog_url . '" style="color:#999;">' . $blog . '</a>. '
			. '<a href="' . $notif_url . '" style="color:#999;">Manage alerts</a>'
			. '</div>'

			. '</div></body></html>';
	}

	/**
	 * One <tr> for the details table.
	 */
	private function detail_row( string $label, $value, bool $stripe ): string {
		$bg = $stripe ? ' style="background:#f7f9fa;"' : '';
		return '<tr' . $bg . '>'
			. '<td style="padding:7px 10px;font-weight:600;color:#555;width:150px;vertical-align:top;border-bottom:1px solid #eee;">' . esc_html( $label ) . '</td>'
			. '<td style="padding:7px 10px;color:#333;border-bottom:1px solid #eee;word-break:break-word;">' . esc_html( (string) $value ) . '</td>'
			. '</tr>';
	}

	/* ------------------------------------------------------------------ *
	 * History recording
	 * ------------------------------------------------------------------ */

	/**
	 * Record a dispatch attempt to the notification history (if history is enabled).
	 */
	private function record( int $event_id, string $type, int $severity, string $channel, string $recipient, string $subject, string $summary, bool $ok ): void {
		if ( ! $this->module->get_setting( 'history_enabled', true ) ) {
			return;
		}
		$this->history()->record(
			array(
				'event_id'   => $event_id,
				'event_type' => $type,
				'severity'   => $severity,
				'channel'    => $channel,
				'recipient'  => $recipient,
				'subject'    => $subject,
				'summary'    => $summary,
				'status'     => $ok ? NotificationLog::STATUS_SENT : NotificationLog::STATUS_FAILED,
			)
		);
	}

	private function history(): NotificationLog {
		if ( null === $this->log ) {
			$this->log = new NotificationLog();
		}
		return $this->log;
	}

	/**
	 * Decode the stored JSON context back into an array for guidance/summaries.
	 *
	 * @param array<string, mixed> $data Row data (context is a JSON string).
	 * @return array<string, mixed>
	 */
	private function decode_context( array $data ): array {
		if ( ! isset( $data['context'] ) ) {
			return array();
		}
		if ( is_array( $data['context'] ) ) {
			return $data['context'];
		}
		$decoded = json_decode( (string) $data['context'], true );
		return is_array( $decoded ) ? $decoded : array();
	}

	/* ------------------------------------------------------------------ *
	 * Throttle helpers
	 * ------------------------------------------------------------------ */

	/**
	 * Check (and increment) the throttle counter for a channel.
	 * Returns true if the notification is allowed, false if the cap is reached.
	 */
	private function allow( string $channel ): bool {
		$max    = (int) $this->module->get_setting( 'throttle_max', 10 );
		$window = (int) $this->module->get_setting( 'throttle_window', 3600 );

		if ( $max <= 0 ) {
			return true; // 0 = unlimited
		}

		$key   = self::TRANSIENT_PREFIX . $channel;
		$count = (int) get_transient( $key );

		if ( $count >= $max ) {
			return false;
		}

		if ( 0 === $count ) {
			set_transient( $key, 1, $window );
		} else {
			set_transient( $key, $count + 1, $window );
		}

		return true;
	}

	/* ------------------------------------------------------------------ *
	 * Utilities
	 * ------------------------------------------------------------------ */

	/**
	 * Check whether an event type belongs to one of the allowed categories.
	 * Category is the leading segment(s) of the dot-separated type string.
	 * e.g. type "waf.block" matches category "waf".
	 */
	private function matches_category( string $type, array $cats ): bool {
		foreach ( $cats as $cat ) {
			if ( str_starts_with( $type, rtrim( (string) $cat, '.' ) ) ) {
				return true;
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ *
	 * Test helpers (called by REST controller)
	 * ------------------------------------------------------------------ */

	/**
	 * Send a test email immediately, bypassing throttle.
	 */
	public function send_test_email(): bool {
		$to      = (string) $this->module->get_setting( 'email_to', '' );
		$to      = $to ?: (string) get_option( 'admin_email' );
		$context = array( 'note' => 'This is a test notification.' );
		$guide   = EventGuide::for_event( EventCatalog::NOTIFICATION_TEST, $context, EventCatalog::SEV_NOTICE );
		$subject = $this->email_subject( $guide, EventCatalog::SEV_NOTICE );
		$body    = $this->email_body(
			EventCatalog::NOTIFICATION_TEST,
			array(
				'created_at'  => gmdate( 'Y-m-d H:i:s' ),
				'ip'          => '127.0.0.1',
				'request_uri' => wp_parse_url( admin_url( 'admin.php' ), PHP_URL_PATH ) . '?page=loyal-security',
				'context'     => wp_json_encode( $context ),
			),
			EventCatalog::SEV_NOTICE,
			$guide
		);
		$ok = (bool) wp_mail( $to, $subject, $body, array( 'Content-Type: text/html; charset=UTF-8' ) );

		$this->record( 0, EventCatalog::NOTIFICATION_TEST, EventCatalog::SEV_NOTICE, 'email', $to, $subject, 'Test notification', $ok );

		return $ok;
	}
}
