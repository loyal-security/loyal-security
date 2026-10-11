<?php
/**
 * Server + PHP SAPI detection for WAF deployment.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Setup;

defined( 'ABSPATH' ) || exit;

/**
 * Inspects the runtime to recommend how to deploy the `auto_prepend_file` directive:
 *   - mod_php (Apache):      via `php_value auto_prepend_file` in .htaccess
 *   - CGI/FastCGI/PHP-FPM:   via a `.user.ini` file in the web root
 *   - LiteSpeed:             behaves like Apache/.htaccess or .user.ini depending on handler
 *   - Other/unknown:         guided manual instructions
 */
class ServerProbe {

	/**
	 * @return array<string, mixed>
	 */
	public function detect(): array {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( (string) $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		$sapi     = PHP_SAPI;

		$server = 'unknown';
		if ( false !== strpos( $software, 'apache' ) ) {
			$server = 'apache';
		} elseif ( false !== strpos( $software, 'nginx' ) ) {
			$server = 'nginx';
		} elseif ( false !== strpos( $software, 'litespeed' ) ) {
			$server = 'litespeed';
		} elseif ( false !== strpos( $software, 'microsoft-iis' ) ) {
			$server = 'iis';
		}

		$is_mod_php = ( 'apache2handler' === $sapi );
		$is_fcgi    = in_array( $sapi, array( 'cgi-fcgi', 'fpm-fcgi', 'cgi' ), true );

		if ( $is_mod_php ) {
			$strategy = 'htaccess';
		} elseif ( $is_fcgi || 'litespeed' === $server ) {
			$strategy = 'user_ini';
		} else {
			$strategy = 'manual';
		}

		$user_ini_name = ini_get( 'user_ini.filename' ) ?: '.user.ini';

		return array(
			'server'        => $server,
			'software'      => $software,
			'sapi'          => $sapi,
			'strategy'      => $strategy,
			'user_ini_name' => $user_ini_name,
			'doc_root'      => \LoyalSecurity\Support\RequestVars::text( 'DOCUMENT_ROOT' ),
			'abspath'       => \LoyalSecurity\Support\Paths::root(),
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check, not a write.
			'htaccess_writable' => is_writable( \LoyalSecurity\Support\Paths::root() . '.htaccess' ) || is_writable( \LoyalSecurity\Support\Paths::root() ),
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check, not a write.
			'userini_writable'  => is_writable( \LoyalSecurity\Support\Paths::root() . $user_ini_name ) || is_writable( \LoyalSecurity\Support\Paths::root() ),
			// Deployed under the private uploads storage dir, never inside the plugin directory
			// — see WafKernelBundler's docblock for why (WordPress.org Plugin Check compliance).
			'prepend_path'  => trailingslashit( ( new WafKernelBundler() )->deploy_dir() ) . 'loyalsec-waf.php',
		);
	}
}
