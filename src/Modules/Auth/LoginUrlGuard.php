<?php
/**
 * Custom Login URL — runtime request guard.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Support\Ip;

/**
 * Hides the credential-entry surface of wp-login.php behind a custom slug. The `/<slug>`
 * → wp-login.php mapping itself is a physical Apache rewrite ({@see LoginUrlInstaller}) so
 * there is no double-bootstrap trick here — this class only decides, once wp-login.php is
 * already executing, whether the request arrived via the intended slug (let it run) or hit
 * the original /wp-login.php path directly (404 it, unless the request is one of the
 * actions that must keep working regardless of the slug: logout links, emailed
 * password-reset links, and the post-logout/check-email landing screens, none of which are
 * brute-forceable and none of which are generated through the `login_url` filter this class
 * also provides).
 */
class LoginUrlGuard {

	/**
	 * Actions (and query-only states) that must always work on the literal /wp-login.php path,
	 * because WordPress core generates them via site_url()/network_site_url() directly rather
	 * than through the wp_login_url() function this class filters.
	 *
	 * @var string[]
	 */
	private const ALLOWED_ACTIONS = array( 'logout', 'rp', 'resetpass', 'postpass', 'confirmaction', 'interim-login', 'register' );

	private string $slug;
	private Logger $logger;

	public function __construct( string $slug, Logger $logger ) {
		$this->slug   = strtolower( trim( $slug, '/' ) );
		$this->logger = $logger;
	}

	public function register(): void {
		if ( '' === $this->slug ) {
			return;
		}
		add_filter( 'login_url', array( $this, 'rewrite_login_url' ), 10, 3 );
		add_filter( 'site_url', array( $this, 'rewrite_login_post_url' ), 10, 3 );
		add_filter( 'network_site_url', array( $this, 'rewrite_login_post_url' ), 10, 3 );
		add_action( 'init', array( $this, 'intercept' ), 0 );
	}

	/**
	 * Point every core-generated plain login link (including auth_redirect()'s redirect of a
	 * logged-out wp-admin visitor) at the custom slug.
	 *
	 * @param string $login_url    Generated login URL.
	 * @param string $redirect     Redirect-to target, if any.
	 * @param bool   $force_reauth Whether reauthentication is being forced.
	 */
	public function rewrite_login_url( $login_url, $redirect, $force_reauth ) {
		$url = home_url( '/' . $this->slug );
		if ( $redirect ) {
			$url = add_query_arg( 'redirect_to', rawurlencode( (string) $redirect ), $url );
		}
		if ( $force_reauth ) {
			$url = add_query_arg( 'reauth', '1', $url );
		}
		return $url;
	}

	/**
	 * Every other wp-login.php link core builds — the login and lost-password <form> targets,
	 * the "Lost your password?" link, the register link — goes through
	 * `site_url( 'wp-login.php?action=…' )` rather than wp_login_url(), so rewrite_login_url()
	 * above never sees it. Left unfiltered, those links point at the literal /wp-login.php
	 * path, which intercept() 404s. They are retargeted at the slug with their query string
	 * (the `action`) kept, so e.g. the lost-password form still submits as a lost-password
	 * request rather than a login attempt.
	 *
	 * URLs for ALLOWED_ACTIONS are left on the literal path, which intercept() already lets
	 * through. That keeps each of those flows on a single path — which the password-reset flow
	 * needs: core sets its `wp-resetpass-*` cookie on the path the emailed `rp` link was
	 * opened on, so the `resetpass` form must post back to that same path for the browser to
	 * send the cookie.
	 *
	 * @param string $url    Filtered URL.
	 * @param string $path   Path relative to the site URL.
	 * @param string $scheme Scheme context.
	 */
	public function rewrite_login_post_url( $url, $path, $scheme ) {
		if ( ! preg_match( '#^/?wp-login\.php(?:\?|$)#', (string) $path ) ) {
			return $url;
		}
		$query = (string) wp_parse_url( $url, PHP_URL_QUERY );
		$args  = array();
		wp_parse_str( $query, $args );
		$action = isset( $args['action'] ) ? sanitize_key( (string) $args['action'] ) : '';
		if ( in_array( $action, self::ALLOWED_ACTIONS, true ) ) {
			return $url;
		}
		$target = home_url( '/' . $this->slug );
		return '' === $query ? $target : $target . '?' . $query;
	}

	/**
	 * Gate direct requests to wp-login.php. Requests that arrived via the Apache rewrite from
	 * `/<slug>` carry the original path in REQUEST_URI (Apache rewrites the served script, not
	 * the visible URL), so they're distinguished here from a literal hit on /wp-login.php.
	 *
	 * Nginx has no equivalent guarantee: on a proxied/multi-hop vhost (e.g. a CloudPanel-style
	 * vhost that proxy_passes to a second internal server block before fastcgi_pass), nginx's
	 * `rewrite ... last` genuinely replaces REQUEST_URI by the time PHP sees it — confirmed by
	 * direct testing, not assumed — so request_path() alone would 404 a legitimate slug hit
	 * exactly like a direct one. `nginx_snippet()` now has the Nginx admin forward the original
	 * URI in a header before the rewrite; request_path() prefers that header when present and
	 * only falls back to REQUEST_URI (the Apache-correct signal) when it's absent.
	 */
	public function intercept(): void {
		if ( defined( 'TOTALSECWP_DISABLE_LOGIN_URL' ) && TOTALSECWP_DISABLE_LOGIN_URL ) {
			return; // wp-config.php escape hatch — always available, zero new attack surface.
		}

		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? basename( sanitize_text_field( wp_unslash( (string) $_SERVER['SCRIPT_FILENAME'] ) ) ) : '';
		if ( 'wp-login.php' !== $script ) {
			return;
		}

		if ( $this->request_path() === $this->slug ) {
			return; // Arrived via the intended rewrite — let wp-login.php run normally.
		}

		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing decision on wp-login.php (core's own login form carries no nonce).
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( in_array( $action, self::ALLOWED_ACTIONS, true ) || isset( $_GET['loggedout'] ) || isset( $_GET['checkemail'] ) ) {
			return;
		}

		$this->logger->log(
			EventCatalog::LOGIN_URL_PROBE_BLOCKED,
			array( 'ip' => Ip::client_ip( \TotalSecurityWP\Support\RequestVars::ip_headers() ), 'action' => $action ?: 'login' ), // phpcs:ignore WordPress.Security.NonceVerification
			EventCatalog::SEV_WARNING
		);

		status_header( 404 );
		nocache_headers();
		exit;
	}

	/**
	 * Lower-cased request path, relative to the site's own (sub-directory-aware) home path,
	 * with the query string and surrounding slashes stripped.
	 */
	private function request_path(): string {
		// Nginx signal, preferred when present — see intercept()'s docblock for why REQUEST_URI
		// alone isn't trustworthy on every Nginx vhost topology. Absent on Apache (and on Nginx
		// vhosts that haven't added the header from nginx_snippet()), where REQUEST_URI is
		// already correct.
		$raw = isset( $_SERVER['HTTP_X_TOTALSECWP_ORIGINAL_URI'] )
			? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_X_TOTALSECWP_ORIGINAL_URI'] ) )
			: ( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : '' );
		$uri = (string) strtok( $raw, '?' );
		$home_path = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		if ( '' !== $home_path && 0 === strpos( $uri, $home_path ) ) {
			$uri = substr( $uri, strlen( $home_path ) );
		}
		return strtolower( trim( $uri, '/' ) );
	}
}
