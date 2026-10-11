<?php
/**
 * System & environment hardening module.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\AbstractModule;
use LoyalSecurity\Modules\Audit\EventCatalog;

/**
 * Registers the runtime hardening guards (version obfuscation, XML-RPC, REST, author
 * enumeration) based on settings, and provides apply/revert actions for the filesystem-
 * level hardening (server rules and wp-config constants).
 */
class HardeningModule extends AbstractModule {

	public function id(): string {
		return 'hardening';
	}

	public function title(): string {
		return __( 'System Hardening', 'loyal-security' );
	}

	/**
	 * Default honeypot bait URLs: common scanner targets, with the content and plugins folders
	 * taken from this site's own URLs (so a renamed wp-content or a subdirectory install gets
	 * the right paths).
	 *
	 * @return string[]
	 */
	private static function default_honeypot_paths(): array {
		$content = untrailingslashit( (string) wp_parse_url( content_url(), PHP_URL_PATH ) );
		$plugins = untrailingslashit( (string) wp_parse_url( plugins_url(), PHP_URL_PATH ) );
		return array(
			'/.env',
			'/config.php',
			'/phpinfo.php',
			'/server-status',
			$content . '/debug.log',
			$plugins . '/wp-file-manager/readme.txt',
			$plugins . '/akismet/admin.php',
		);
	}

	public function default_settings(): array {
		return array(
			'enabled'              => true,
			'obfuscate_version'    => true,
			'disable_xmlrpc'       => true,
			'disable_pingback'     => true,
			'restrict_rest_users'      => true,
			'restrict_rest_all'        => false,
			// REST API CORS: reflect the requesting Origin (+ allow credentials) only for
			// the site itself or an explicitly trusted origin, instead of WP core's default
			// of reflecting any origin unconditionally.
			'restrict_rest_cors'       => true,
			'rest_cors_allowlist'      => array(),
			// Namespaces exempted from restrict_rest_all (always public regardless of auth).
			'rest_public_namespaces'   => array( 'wc/store', 'wc/blocks', 'contact-form-7', 'wp-site-health' ),
			// While true, restrict_rest_all never blocks — it only logs which anonymous
			// namespace would have been blocked, so an admin can review before enforcing.
			'rest_learning_mode'       => true,
			'block_author_enum'    => true,
			'safe_browsing_api_key' => '',
			// CSRF: log (and optionally block) admin AJAX requests from a foreign-origin Referer.
			'csrf_referer_check'   => true,
			'csrf_block'           => false,
			// Open redirect: log (and optionally block) off-site wp_redirect() calls.
			'block_open_redirect'  => true,
			'redirect_block'       => true,
			// Honeypot trap URLs: log (CRITICAL) and optionally ban scanners hitting bait paths.
			'honeypot_enabled'     => true,
			'honeypot_ban'         => false,
			'honeypot_paths'       => self::default_honeypot_paths(),
			// Security response headers (each gated by its own toggle). CSP is owned by CspModule.
			'add_xfo'                => true,
			'add_xcto'               => true,
			'add_referrer_policy'    => true,
			'add_permissions_policy' => true,
			// Outbound request guard (SSRF prevention).
			'block_ssrf'            => true,
			'ssrf_allowlist'        => array(),
			// Login error normalisation.
			'normalize_login_errors' => true,
			// Host header validation.
			'validate_host_header'  => true,
		);
	}

	public function boot(): void {
		if ( $this->setting( 'obfuscate_version', true ) ) {
			( new VersionObfuscator() )->register();
		}

		if ( $this->setting( 'disable_xmlrpc', true ) || $this->setting( 'disable_pingback', true ) ) {
			( new XmlRpcGuard(
				(bool) $this->setting( 'disable_xmlrpc', true ),
				(bool) $this->setting( 'disable_pingback', true ),
				$this->logger()
			) )->register();
		}

		if ( $this->setting( 'restrict_rest_users', true ) || $this->setting( 'restrict_rest_all', false ) ) {
			( new RestApiGuard(
				(bool) $this->setting( 'restrict_rest_users', true ),
				(bool) $this->setting( 'restrict_rest_all', false ),
				(array) $this->setting( 'rest_public_namespaces', array( 'wc/store', 'wc/blocks', 'contact-form-7', 'wp-site-health' ) ),
				(bool) $this->setting( 'rest_learning_mode', true ),
				$this->logger()
			) )->register();
		}

		if ( $this->setting( 'restrict_rest_cors', true ) ) {
			( new CorsGuard(
				(array) $this->setting( 'rest_cors_allowlist', array() ),
				$this->logger()
			) )->register();
		}

		if ( $this->setting( 'block_author_enum', true ) ) {
			( new DirectoryGuard( $this->logger() ) )->register();
		}

		if ( $this->setting( 'csrf_referer_check', true ) ) {
			( new CsrfGuard(
				$this->logger(),
				(bool) $this->setting( 'csrf_block', false )
			) )->register();
		}

		if ( $this->setting( 'block_open_redirect', true ) ) {
			( new RedirectGuard(
				$this->logger(),
				(bool) $this->setting( 'redirect_block', true )
			) )->register();
		}

		if ( $this->setting( 'honeypot_enabled', true ) ) {
			$paths = (array) $this->setting( 'honeypot_paths', array() );
			( new HoneypotGuard(
				$this->logger(),
				$paths,
				(bool) $this->setting( 'honeypot_ban', false )
			) )->register();
		}

		$header_opts = array(
			'add_xfo'                => (bool) $this->setting( 'add_xfo', true ),
			'add_xcto'               => (bool) $this->setting( 'add_xcto', true ),
			'add_referrer_policy'    => (bool) $this->setting( 'add_referrer_policy', true ),
			'add_permissions_policy' => (bool) $this->setting( 'add_permissions_policy', true ),
		);

		if ( $header_opts['add_xfo'] || $header_opts['add_xcto']
			|| $header_opts['add_referrer_policy'] || $header_opts['add_permissions_policy'] ) {
			( new SecurityHeaders( $header_opts ) )->register();
		}

		if ( $this->setting( 'block_ssrf', true ) ) {
			$allowlist = (array) $this->setting( 'ssrf_allowlist', array() );
			( new OutboundRequestGuard( $this->logger(), $allowlist ) )->register();
		}

		if ( $this->setting( 'normalize_login_errors', true ) ) {
			add_action( 'wp_login_failed', array( $this, 'remember_failed_login' ), 1, 1 );
			add_filter( 'wp_login_errors', array( $this, 'normalize_login_errors' ), 99 );
			add_filter( 'login_error_shake_user_ids', '__return_empty_array' );
		}

		if ( $this->setting( 'validate_host_header', true ) ) {
			( new HostHeaderGuard( $this->logger() ) )->register();
		}
	}

	/**
	 * Username of a sign-in that failed during this request, or null when none did.
	 *
	 * @var string|null
	 */
	private static ?string $failed_login = null;

	/**
	 * `wp_login_failed`: note that this request's sign-in failed, and for which username.
	 *
	 * @param string $username Submitted username or email address.
	 */
	public function remember_failed_login( $username ): void {
		self::$failed_login = sanitize_user( (string) $username );
	}

	/**
	 * Replace the result of a failed sign-in with one neutral message, so the login page never
	 * reveals whether a username exists or a password was right (WordPress's own messages, and
	 * a "now enter your code" prompt, both do). Errors that reveal nothing about the account,
	 * such as a failed CAPTCHA or an empty field, are left as they are so people can fix them.
	 * Notes from other features (for example the two-factor hint) are appended to the message.
	 *
	 * @param mixed $errors The WP_Error shown on wp-login.php.
	 * @return mixed
	 */
	public function normalize_login_errors( $errors ) {
		// Only after a failed sign-in: other wp-login.php messages ("You are now logged out")
		// stay. WordPress fires wp_login_failed for every failed attempt except empty fields.
		if ( null === self::$failed_login || ! $errors instanceof \WP_Error || ! $errors->has_errors() ) {
			return $errors;
		}

		/**
		 * Filters the login error codes shown as they are, because they say nothing about
		 * whether the account exists or the password was right.
		 *
		 * @since 1.5.0
		 *
		 * @param string[] $codes Error codes.
		 */
		$shown = (array) apply_filters( 'loyalsec_login_error_codes_shown', array( 'empty_username', 'empty_password', 'test_cookie', 'loyalsec_captcha', 'loyalsec_banned', 'loyalsec_login_locked' ) );
		if ( ! array_diff( $errors->get_error_codes(), $shown ) ) {
			return $errors;
		}

		/**
		 * Filters extra notes appended to the neutral "Incorrect username or password" message,
		 * for example how to finish a two-factor sign-in. Notes must not depend on whether the
		 * password was right, or they would reveal it.
		 *
		 * @since 1.5.0
		 *
		 * @param string[] $notes Plain-text notes.
		 * @param string   $login The submitted username or email address.
		 */
		$notes   = array_filter( array_map( 'strval', (array) apply_filters( 'loyalsec_login_error_notes', array(), self::$failed_login ) ) );
		$message = esc_html__( 'Incorrect username or password. Please try again.', 'loyal-security' );
		foreach ( $notes as $note ) {
			$message .= '<br />' . esc_html( $note );
		}
		return new \WP_Error( 'loyalsec_login_failed', $message );
	}

	/* ------------------------------ Actions -------------------------------- */

	/**
	 * @return array<string, mixed>
	 */
	public function status(): array {
		$server = new ServerRules();
		$config = new ConfigHardener();
		return array(
			'runtime'      => array(
				'obfuscate_version'   => (bool) $this->setting( 'obfuscate_version', true ),
				'disable_xmlrpc'      => (bool) $this->setting( 'disable_xmlrpc', true ),
				'disable_pingback'    => (bool) $this->setting( 'disable_pingback', true ),
				'restrict_rest_users' => (bool) $this->setting( 'restrict_rest_users', true ),
				'restrict_rest_all'   => (bool) $this->setting( 'restrict_rest_all', false ),
				'restrict_rest_cors'  => (bool) $this->setting( 'restrict_rest_cors', true ),
				'rest_cors_allowlist' => (array) $this->setting( 'rest_cors_allowlist', array() ),
				'rest_learning_mode'  => (bool) $this->setting( 'rest_learning_mode', true ),
				'rest_public_namespaces' => (array) $this->setting( 'rest_public_namespaces', array( 'wc/store', 'wc/blocks', 'contact-form-7', 'wp-site-health' ) ),
				'block_author_enum'   => (bool) $this->setting( 'block_author_enum', true ),
				'csrf_referer_check'  => (bool) $this->setting( 'csrf_referer_check', true ),
				'csrf_block'          => (bool) $this->setting( 'csrf_block', false ),
				'block_open_redirect' => (bool) $this->setting( 'block_open_redirect', true ),
				'redirect_block'      => (bool) $this->setting( 'redirect_block', true ),
				'honeypot_enabled'    => (bool) $this->setting( 'honeypot_enabled', true ),
				'honeypot_ban'        => (bool) $this->setting( 'honeypot_ban', false ),
				'add_xfo'                => (bool) $this->setting( 'add_xfo', true ),
				'add_xcto'               => (bool) $this->setting( 'add_xcto', true ),
				'add_referrer_policy'    => (bool) $this->setting( 'add_referrer_policy', true ),
				'add_permissions_policy' => (bool) $this->setting( 'add_permissions_policy', true ),
				'block_ssrf'             => (bool) $this->setting( 'block_ssrf', true ),
				'normalize_login_errors' => (bool) $this->setting( 'normalize_login_errors', true ),
				'validate_host_header'   => (bool) $this->setting( 'validate_host_header', true ),
			),
			'server_rules' => $server->is_applied(),
			'config'       => $config->status(),
			'nginx'        => $server->nginx_snippet(),
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function apply_server_rules(): array {
		$result = ( new ServerRules() )->apply();

		if ( ! empty( $result['error'] ) ) {
			$this->logger()->log( EventCatalog::HARDENING_REVERTED, array( 'item' => 'server_rules', 'auto' => true, 'reason' => $result['error'] ) );
			return array( 'ok' => false, 'result' => $result );
		}

		$this->logger()->log( EventCatalog::HARDENING_APPLIED, array( 'item' => 'server_rules', 'result' => $result ) );
		return array( 'ok' => true, 'result' => $result );
	}

	public function revert_server_rules(): array {
		( new ServerRules() )->revert();
		$this->logger()->log( EventCatalog::HARDENING_REVERTED, array( 'item' => 'server_rules' ) );
		return array( 'ok' => true );
	}

	/**
	 * @param array<string, bool> $constants Managed constants.
	 * @return array<string, mixed>
	 */
	public function apply_config( array $constants ): array {
		$res = ( new ConfigHardener() )->apply( $constants );
		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::HARDENING_APPLIED, array( 'item' => 'wp_config', 'constants' => array_keys( $constants ) ) );
		}
		return $res;
	}

	public function revert_config(): array {
		$res = ( new ConfigHardener() )->revert();
		if ( ! empty( $res['ok'] ) ) {
			$this->logger()->log( EventCatalog::HARDENING_REVERTED, array( 'item' => 'wp_config' ) );
		}
		return $res;
	}
}
