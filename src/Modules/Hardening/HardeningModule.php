<?php
/**
 * System & environment hardening module.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\AbstractModule;
use TotalSecurityWP\Modules\Audit\EventCatalog;

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
			add_filter( 'login_errors', static function () {
				return __( 'Incorrect username or password. Please try again.', 'loyal-security' );
			} );
			add_filter( 'login_error_shake_user_ids', '__return_empty_array' );
		}

		if ( $this->setting( 'validate_host_header', true ) ) {
			( new HostHeaderGuard( $this->logger() ) )->register();
		}
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
