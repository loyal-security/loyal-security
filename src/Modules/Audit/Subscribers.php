<?php
/**
 * Subscribes the audit logger to security-relevant WordPress events.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Audit;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Ip;

/**
 * Attaches to core WordPress hooks and forwards meaningful events to the {@see Logger}.
 * Login events are handled by the Firewall's BruteForce class to avoid double-logging.
 */
class Subscribers {

	private Logger $logger;

	public function __construct( Logger $logger ) {
		$this->logger = $logger;
	}

	public function register(): void {
		// Plugins.
		add_action( 'activated_plugin', array( $this, 'plugin_activated' ), 10, 1 );
		add_action( 'deactivated_plugin', array( $this, 'plugin_deactivated' ), 10, 1 );
		add_action( 'upgrader_process_complete', array( $this, 'upgrader_complete' ), 10, 2 );

		// Themes.
		add_action( 'switch_theme', array( $this, 'theme_switched' ), 10, 1 );

		// Users.
		add_action( 'user_register', array( $this, 'user_created' ), 10, 1 );
		add_action( 'set_user_role', array( $this, 'user_role_changed' ), 10, 3 );
		add_action( 'profile_update', array( $this, 'profile_updated' ), 10, 1 );

		// User deletion.
		add_action( 'delete_user', array( $this, 'user_deleted' ), 10, 1 );

		// Post creation.
		add_action( 'wp_insert_post', array( $this, 'post_created' ), 10, 3 );

		// Comment insertion.
		add_action( 'wp_insert_comment', array( $this, 'comment_inserted' ), 10, 2 );

		// Mail rate-limit / audit.
		add_filter( 'wp_mail', array( $this, 'mail_sent' ), 10, 1 );

		// Core update.
		add_action( '_core_updated_successfully', array( $this, 'core_updated' ), 10, 1 );

		// Option writes — detect PHP code / exec primitives smuggled into the options table.
		// added_option passes ( $option, $value ); updated_option passes ( $option, $old_value, $value ).
		add_action( 'added_option', array( $this, 'option_added' ), 10, 2 );
		add_action( 'updated_option', array( $this, 'option_updated' ), 10, 3 );

		// Unauthenticated AJAX — fires early in admin-ajax.php before the action hook.
		add_action( 'admin_init', array( $this, 'maybe_log_nopriv_ajax' ), 1 );

		// Cron scheduling — pre_schedule_event fires BEFORE the event is committed, so we can
		// check wp_next_scheduled() to distinguish first-time registrations from recurring
		// reschedules. Recurring reschedules are expected WordPress behavior and would spam the log.
		add_filter( 'pre_schedule_event', array( $this, 'cron_pre_scheduled' ), 10, 2 );
	}

	/**
	 * @param string $plugin Plugin file.
	 */
	public function plugin_activated( $plugin ): void {
		$this->logger->log( EventCatalog::PLUGIN_ACTIVATED, array( 'plugin' => (string) $plugin ) );
	}

	/**
	 * @param string $plugin Plugin file.
	 */
	public function plugin_deactivated( $plugin ): void {
		$this->logger->log( EventCatalog::PLUGIN_DEACTIVATED, array( 'plugin' => (string) $plugin ) );
	}

	/**
	 * @param \WP_Upgrader $upgrader Upgrader instance.
	 * @param array        $extra    Context.
	 */
	public function upgrader_complete( $upgrader, $extra ): void {
		if ( ! is_array( $extra ) ) {
			return;
		}
		$type = isset( $extra['type'] ) ? (string) $extra['type'] : '';
		if ( 'plugin' === $type && 'install' === ( $extra['action'] ?? '' ) ) {
			$this->logger->log( EventCatalog::PLUGIN_INSTALLED, array( 'context' => $extra ) );
		}
	}

	/**
	 * @param string $new_name New theme name.
	 */
	public function theme_switched( $new_name ): void {
		$this->logger->log( EventCatalog::THEME_SWITCHED, array( 'theme' => (string) $new_name ) );
	}

	/**
	 * @param int $user_id New user id.
	 */
	public function user_created( $user_id ): void {
		$user = get_userdata( (int) $user_id );
		$this->logger->log(
			EventCatalog::USER_CREATED,
			array(
				'user_id' => (int) $user_id,
				'login'   => $user ? $user->user_login : '',
				'roles'   => $user ? $user->roles : array(),
			)
		);
		// Immediately escalate if the new user already has admin role.
		if ( $user && in_array( 'administrator', (array) $user->roles, true ) ) {
			$this->logger->log(
				EventCatalog::USER_ADMIN_CREATED,
				array(
					'user_id'  => (int) $user_id,
					'username' => $user->user_login,
					'email'    => $user->user_email,
				),
				EventCatalog::SEV_CRITICAL
			);
		}
	}

	/**
	 * @param int      $user_id   User id.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Previous roles.
	 */
	public function user_role_changed( $user_id, $role, $old_roles ): void {
		// Highlight privilege escalation to administrator.
		$severity = ( 'administrator' === $role ) ? EventCatalog::SEV_CRITICAL : EventCatalog::SEV_WARNING;
		$this->logger->log(
			EventCatalog::USER_ROLE_CHANGED,
			array(
				'user_id'   => (int) $user_id,
				'new_role'  => (string) $role,
				'old_roles' => (array) $old_roles,
			),
			$severity
		);
		// Extra CRITICAL event when a non-admin is promoted to administrator.
		if ( 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true ) ) {
			$user = get_userdata( (int) $user_id );
			$this->logger->log(
				EventCatalog::USER_ADMIN_CREATED,
				array(
					'user_id'   => (int) $user_id,
					'username'  => $user ? $user->user_login : '',
					'new_role'  => $role,
					'old_roles' => (array) $old_roles,
				),
				EventCatalog::SEV_CRITICAL
			);
		}
	}

	/**
	 * @param int $user_id User id.
	 */
	public function profile_updated( $user_id ): void {
		$this->logger->log( EventCatalog::SETTING_CHANGED, array( 'profile_update' => (int) $user_id ), EventCatalog::SEV_INFO );
	}

	/**
	 * @param string $version WordPress version.
	 */
	public function core_updated( $version ): void {
		$this->logger->log( EventCatalog::CORE_UPDATED, array( 'version' => (string) $version ) );
	}

	/**
	 * @param int $user_id Deleted user id.
	 */
	public function user_deleted( $user_id ): void {
		$this->logger->log(
			EventCatalog::USER_DELETED,
			array( 'user_id' => (int) $user_id ),
			EventCatalog::SEV_WARNING
		);
	}

	/**
	 * Log post creation; flag suspicious content.
	 *
	 * @param int      $post_id Post id.
	 * @param \WP_Post $post    Post object.
	 * @param bool     $update  True = update, false = insert.
	 */
	public function post_created( $post_id, $post, $update ): void {
		if ( $update || ! is_object( $post ) ) {
			return;
		}
		// Only log published/draft/private; skip revisions, nav-menus, etc.
		if ( ! in_array( $post->post_type, array( 'post', 'page' ), true ) ) {
			return;
		}

		$context = array(
			'post_id'   => (int) $post_id,
			'title'     => (string) $post->post_title,
			'status'    => (string) $post->post_status,
			'author_id' => (int) $post->post_author,
		);

		$this->logger->log( EventCatalog::POST_CREATED, $context );

		// Flag suspicious: pharma/gambling keyword in title or content.
		$spam_pattern = '/\b(viagra|cialis|casino|poker|slots|payday\s+loan|cheap\s+pills|online\s+pharmacy|buy\s+cheap|weight\s+loss\s+pill)\b/i';
		$haystack     = $post->post_title . ' ' . $post->post_content;
		if ( preg_match( $spam_pattern, $haystack ) ) {
			$this->logger->log( EventCatalog::POST_SUSPICIOUS, array_merge( $context, array( 'reason' => 'spam_keywords' ) ), EventCatalog::SEV_WARNING );
		}
		// Flag hidden content: display:none in content.
		if ( false !== stripos( $post->post_content, 'display:none' ) || false !== stripos( $post->post_content, 'display: none' ) ) {
			$this->logger->log( EventCatalog::POST_SUSPICIOUS, array_merge( $context, array( 'reason' => 'hidden_content' ) ), EventCatalog::SEV_WARNING );
		}
	}

	/**
	 * Log comment insertion; flag bulk inserts and suspicious URLs.
	 *
	 * @param int        $comment_id Comment id.
	 * @param \WP_Comment $comment   Comment object.
	 */
	public function comment_inserted( $comment_id, $comment ): void {
		if ( ! is_object( $comment ) ) {
			return;
		}

		$email = (string) $comment->comment_author_email;
		$url   = (string) $comment->comment_author_url;

		// Bulk-insert rate check: track count per email in a 5-min window transient.
		$transient_key = 'totalsecwp_ci_' . md5( $email );
		$count         = (int) get_transient( $transient_key );
		$count++;
		set_transient( $transient_key, $count, 5 * MINUTE_IN_SECONDS );

		if ( $count > 5 ) {
			$this->logger->log(
				EventCatalog::COMMENT_BULK_INSERT,
				array( 'email' => $email, 'count_5min' => $count, 'comment_id' => (int) $comment_id ),
				EventCatalog::SEV_WARNING
			);
		}

		// Flag suspicious commenter URL (known spam TLDs) or multi-link content.
		$spam_tlds = array( '.xyz', '.top', '.click', '.loan', '.work', '.gdn', '.stream', '.download' );
		$url_lower = strtolower( $url );
		$tld_match = '';
		foreach ( $spam_tlds as $tld ) {
			if ( $url && false !== strpos( $url_lower, $tld ) ) {
				$tld_match = $tld;
				break;
			}
		}
		$link_count = substr_count( strtolower( $comment->comment_content ), '<a href=' );
		if ( $tld_match || $link_count > 2 ) {
			$this->logger->log(
				EventCatalog::COMMENT_SUSPICIOUS,
				array(
					'comment_id'  => (int) $comment_id,
					'url'         => $url,
					'tld_matched' => $tld_match,
					'link_count'  => $link_count,
				),
				EventCatalog::SEV_WARNING
			);
		}
	}

	/**
	 * wp_mail filter — rate-limit and audit outbound email.
	 * Returns the unmodified $atts array (we never block, only log).
	 *
	 * @param array<string,mixed> $atts wp_mail args (to, subject, message, headers, attachments).
	 * @return array<string,mixed>
	 */
	public function mail_sent( array $atts ): array {
		$transient_key = 'totalsecwp_mail_rate';
		$count         = (int) get_transient( $transient_key );
		$count++;
		set_transient( $transient_key, $count, MINUTE_IN_SECONDS );

		$subject = (string) ( $atts['subject'] ?? '' );
		$message = (string) ( $atts['message'] ?? '' );

		if ( $count > 10 ) {
			$this->logger->log(
				EventCatalog::MAIL_BULK_SEND,
				array( 'count_per_min' => $count, 'to' => $atts['to'] ?? '' ),
				EventCatalog::SEV_WARNING
			);
		}

		$spam_pattern = '/\b(cheap pills|online pharmacy|casino bonus|click here|free money|phishing|winner|claim your prize)\b/i';
		if ( preg_match( $spam_pattern, $subject . ' ' . $message ) ) {
			$this->logger->log(
				EventCatalog::MAIL_SUSPICIOUS,
				array( 'subject' => substr( $subject, 0, 200 ), 'to' => $atts['to'] ?? '' ),
				EventCatalog::SEV_WARNING
			);
		}

		return $atts; // Always pass through.
	}

	/**
	 * added_option callback. Normalizes to the shared scanner.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  New value.
	 */
	public function option_added( $option, $value ): void {
		$this->option_written( (string) $option, $value, true );
	}

	/**
	 * updated_option callback. Normalizes to the shared scanner (drops the old value).
	 *
	 * @param string $option    Option name.
	 * @param mixed  $old_value Previous value (unused).
	 * @param mixed  $value     New value.
	 */
	public function option_updated( $option, $old_value, $value ): void {
		$this->option_written( (string) $option, $value );
	}

	/**
	 * Scan a newly written option value for code-execution primitives.
	 *
	 * A "fileless" backdoor can stash PHP source in the options table for a separate
	 * eval(get_option()) to run later. We flag the write itself so it surfaces in the
	 * audit log even though no file changed.
	 *
	 * Only string values are scanned. We deliberately skip our own settings option and
	 * the transient namespace to avoid log spam / recursion, and we never write back to
	 * the options table from here (logging goes to the custom events table via Logger).
	 *
	 * @param string $option  Option name.
	 * @param mixed  $value   New option value.
	 * @param bool   $created Whether the option was just added rather than updated.
	 */
	private function option_written( string $option, $value, bool $created = false ): void {
		// Guardrails: skip our own settings and transient namespace.
		if ( 'totalsecwp_settings' === $option
			|| 0 === strpos( $option, '_transient' )
			|| 0 === strpos( $option, '_site_transient' ) ) {
			return;
		}

		/*
		 * The `cron` option is rewritten by WordPress on *every* WP-Cron run (each time a
		 * task is rescheduled), so treating every write as a critical change produced a
		 * constant stream of false-positive alerts. Instead we inspect the cron array and
		 * only alert when it contains something that looks like an injected backdoor (an
		 * eval/base64 payload, a dangerous callback, or a remote URL in the task args).
		 */
		if ( 'cron' === $option ) {
			$this->scan_cron_option( $value );
			return;
		}

		/* ── 1. CRITICAL option keys: always log regardless of value ─────────── */
		$critical_keys = array(
			'siteurl', 'blogurl', 'admin_email', 'blogdescription', 'blogname',
			'active_plugins', 'template', 'stylesheet',
		);
		// Authentication keys and salts. WordPress creates these options itself the first time
		// it needs one that wp-config.php doesn't define, so only a change is worth an alert,
		// and the value is a secret that must never be written to the log.
		$secret_keys = array(
			'auth_key', 'secure_auth_key', 'logged_in_key', 'nonce_key',
			'auth_salt', 'secure_auth_salt', 'logged_in_salt', 'nonce_salt',
		);
		if ( in_array( $option, $secret_keys, true ) ) {
			if ( ! $created ) {
				$this->logger->log(
					EventCatalog::CRITICAL_OPTION_CHANGED,
					array( 'option' => $option, 'preview' => '(secret value not logged)' ),
					EventCatalog::SEV_CRITICAL
				);
			}
			return;
		}
		if ( in_array( $option, $critical_keys, true ) ) {
			$preview = is_string( $value ) ? substr( $value, 0, 200 ) : substr( serialize( $value ), 0, 200 ); // phpcs:ignore
			$this->logger->log(
				EventCatalog::CRITICAL_OPTION_CHANGED,
				array( 'option' => $option, 'preview' => $preview ),
				EventCatalog::SEV_CRITICAL
			);
		}

		/* ── 2. Convert array/object values to a scannable string ────────────── */
		if ( is_array( $value ) || is_object( $value ) ) {
			// For widget_text and theme_mods_* only: serialize and scan for HTML injection.
			if ( 'widget_text' === $option || 0 === strpos( $option, 'theme_mods_' ) ) {
				$serialized = serialize( $value ); // phpcs:ignore
				$this->scan_option_string( $option, $serialized );
			}
			return;
		}

		if ( ! is_string( $value ) || '' === $value ) {
			return;
		}

		$this->scan_option_string( $option, $value );
	}

	/**
	 * Inspect a write to the WordPress `cron` option for signs of a scheduled-task backdoor.
	 *
	 * WP-Cron persists its entire schedule to this option and rewrites it on every run, so a
	 * plain "it changed" alert is useless noise. Attackers, however, abuse WP-Cron to run a
	 * payload periodically — either by scheduling a hook whose args carry an eval/base64
	 * blob, or by pointing a task at a dangerous callback. We serialise the schedule and look
	 * only for those markers; a clean reschedule is ignored silently.
	 *
	 * @param mixed $value New cron option value (normally an array).
	 */
	private function scan_cron_option( $value ): void {
		if ( ! is_array( $value ) ) {
			return;
		}

		$serialized = strtolower( serialize( $value ) ); // phpcs:ignore

		// Payload markers that should never appear in a legitimate cron schedule.
		$markers = array(
			'eval(', 'base64_decode(', 'gzinflate(', 'gzuncompress(', 'str_rot13(',
			'assert(', 'system(', 'shell_exec(', 'passthru(', 'exec(', 'popen(',
			'create_function(', 'call_user_func', 'file_get_contents(', 'fopen(',
			'<?php', 'http://', 'https://',
		);

		$hit = '';
		foreach ( $markers as $needle ) {
			if ( false !== strpos( $serialized, $needle ) ) {
				$hit = $needle;
				break;
			}
		}

		if ( '' === $hit ) {
			return; // Routine reschedule — no alert.
		}

		// Collect the scheduled hook names for a human-readable preview.
		$hooks = array();
		foreach ( $value as $bucket ) {
			if ( is_array( $bucket ) ) {
				foreach ( array_keys( $bucket ) as $hook ) {
					if ( is_string( $hook ) ) {
						$hooks[ $hook ] = true;
					}
				}
			}
		}

		$this->logger->log(
			EventCatalog::CRITICAL_OPTION_CHANGED,
			array(
				'option'  => 'cron',
				'reason'  => sprintf( 'A scheduled task contained a suspicious pattern (%s).', $hit ),
				'hooks'   => array_slice( array_keys( $hooks ), 0, 20 ),
				'preview' => substr( serialize( $value ), 0, 200 ), // phpcs:ignore
			),
			EventCatalog::SEV_CRITICAL
		);
	}

	/**
	 * Scan a stringified option value for dangerous patterns.
	 *
	 * @param string $option Option name.
	 * @param string $value  String value to scan.
	 */
	private function scan_option_string( string $option, string $value ): void {
		$haystack = strtolower( $value );

		/* ── PHP code-execution primitives ────── */
		$php_patterns = array(
			'<?php', 'eval(', 'base64_decode(', 'system(', 'shell_exec(',
			'assert(', 'passthru(', 'create_function(',
		);
		$matched = '';
		foreach ( $php_patterns as $needle ) {
			if ( false !== strpos( $haystack, strtolower( $needle ) ) ) {
				$matched = $needle;
				break;
			}
		}
		if ( '' !== $matched ) {
			$this->logger->log(
				EventCatalog::SUSPICIOUS_OPTION,
				array(
					'option'  => $option,
					'matched' => $matched,
					'sample'  => substr( $value, 0, 200 ),
				),
				EventCatalog::SEV_WARNING
			);
			return; // Already flagged — skip further checks.
		}

		/* ── PHP serialized object (potential deserialization gadget) ─────── */
		if ( preg_match( '/O:\d+:"[A-Za-z_\\\\]/', $value ) ) {
			$this->logger->log(
				EventCatalog::SUSPICIOUS_OPTION,
				array(
					'option'  => $option,
					'matched' => 'serialized_object',
					'sample'  => substr( $value, 0, 200 ),
				),
				EventCatalog::SEV_WARNING
			);
			return;
		}

		/* ── HTML/JS injection in widget_text / theme_mods ───────────────── */
		$html_patterns = array(
			'<script'      => 'script_tag',
			'display:none' => 'hidden_content',
			'display: none' => 'hidden_content',
		);
		// For href spam detection only in widget_text.
		if ( 'widget_text' === $option && substr_count( $haystack, '<a href=' ) > 1 ) {
			$this->logger->log(
				EventCatalog::SUSPICIOUS_OPTION,
				array(
					'option'  => $option,
					'matched' => 'spam_links',
					'sample'  => substr( $value, 0, 200 ),
				),
				EventCatalog::SEV_WARNING
			);
			return;
		}
		if ( 0 === strpos( $option, 'theme_mods_' ) || 'widget_text' === $option ) {
			foreach ( $html_patterns as $needle => $label ) {
				if ( false !== strpos( $haystack, $needle ) ) {
					$this->logger->log(
						EventCatalog::SUSPICIOUS_OPTION,
						array(
							'option'  => $option,
							'matched' => $label,
							'sample'  => substr( $value, 0, 200 ),
						),
						EventCatalog::SEV_WARNING
					);
					return;
				}
			}
		}
	}

	/**
	 * Log unauthenticated (nopriv) admin-ajax.php dispatches.
	 * Fires at admin_init priority 1 — before the actual wp_ajax_nopriv_{action} callback.
	 */
	public function maybe_log_nopriv_ajax(): void {
		if ( ! wp_doing_ajax() || is_user_logged_in() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = sanitize_key( wp_unslash( $_REQUEST['action'] ?? '' ) );
		if ( '' === $action ) {
			return;
		}

		// Skip actions the admin has explicitly whitelisted as false positives.
		$firewall_module = \TotalSecurityWP\Plugin::instance()->module( 'firewall' );
		if ( $firewall_module ) {
			$wl = (array) \TotalSecurityWP\Plugin::instance()->container()->make( 'settings' )->get( 'firewall', 'ajax_action_whitelist', array() );
			if ( in_array( $action, $wl, true ) ) {
				return;
			}
		}

		// Detect whether any plugin actually registered this public AJAX action.
		// An unregistered action is far more suspicious than a registered one.
		global $wp_filter;
		$registered = isset( $wp_filter[ 'wp_ajax_nopriv_' . $action ] );

		// By default, skip registered endpoints — a plugin intentionally exposed them as
		// public, so unauthenticated calls are expected normal behaviour (e.g. WooCommerce
		// cart, Contact Form 7 submissions, Elementor widgets). Logging them generates noise
		// without security value; the WAF and virtual-patch layers already protect registered
		// endpoints against payload-based exploits.
		// Admins can opt into logging registered calls via Audit → monitor_registered_nopriv_ajax.
		if ( $registered ) {
			$audit_module = \TotalSecurityWP\Plugin::instance()->module( 'audit' );
			$monitor_all  = $audit_module && (bool) $audit_module->setting_public( 'monitor_registered_nopriv_ajax', false );
			if ( ! $monitor_all ) {
				return;
			}
		}

		$this->logger->log(
			EventCatalog::NOPRIV_AJAX_CALL,
			array(
				'action'     => $action,
				'ip'         => Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() ),
				'ua'         => substr( sanitize_text_field( wp_unslash( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ) ), 0, 200 ),
				'registered' => $registered,
			),
			EventCatalog::SEV_WARNING
		);
	}

	/**
	 * Log a WP-Cron event being scheduled for the first time.
	 *
	 * Uses the pre_schedule_event filter (WP 5.1+) so we can call wp_next_scheduled()
	 * BEFORE the event is committed. Recurring events already present in the cron table
	 * are being rescheduled by WordPress after they run — that is normal behaviour and
	 * would flood the log. We only care about genuinely new registrations.
	 *
	 * Single-fire events (schedule === false) are always logged: they are unusual and
	 * are a common backdoor persistence technique.
	 *
	 * @param null|bool|\WP_Error $pre   Short-circuit value from earlier filters.
	 * @param \stdClass           $event Cron event object with hook, timestamp, schedule, args.
	 * @return null|bool|\WP_Error Unchanged $pre — we never block scheduling.
	 */
	public function cron_pre_scheduled( $pre, $event ) {
		if ( ! is_object( $event ) ) {
			return $pre;
		}

		$hook = (string) ( $event->hook ?? '' );
		$args = isset( $event->args ) ? (array) $event->args : array();

		// For recurring events: skip logging when the hook is already in the cron table
		// (this is a normal reschedule after the task ran — not a new registration).
		if ( ! empty( $event->schedule ) && false !== wp_next_scheduled( $hook, $args ) ) {
			return $pre;
		}

		$this->logger->log(
			EventCatalog::CRON_SCHEDULED,
			array(
				'hook'      => $hook,
				'schedule'  => isset( $event->schedule ) && $event->schedule ? (string) $event->schedule : 'single',
				'timestamp' => (int) ( $event->timestamp ?? 0 ),
			),
			EventCatalog::SEV_NOTICE
		);

		return $pre; // Never block scheduling — detection only.
	}
}
