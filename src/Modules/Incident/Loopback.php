<?php
/**
 * Post-repair site health probe.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Incident;

defined( 'ABSPATH' ) || exit;

/**
 * Verifies the site still loads after a repair by issuing loopback requests to the front
 * page and the admin login screen — the same defensive pattern WordPress core uses in its
 * theme/plugin file editor ({@see wp_edit_theme_plugin_file()}). A repair that introduces a
 * fatal error will surface here as an HTTP 5xx or a WordPress "fatal error" notice, letting
 * the caller roll the change back before the operator ever sees a broken site.
 */
class Loopback {

	/**
	 * Probe the site's health.
	 *
	 * @return array{ok:bool,checks:array<int,array{url:string,code:int,healthy:bool}>}
	 */
	public function check(): array {
		$targets = array(
			home_url( '/' ),
			wp_login_url(),
		);

		$checks   = array();
		$all_ok   = true;
		$any_done = false;

		foreach ( $targets as $url ) {
			$result = $this->probe( $url );
			$checks[] = $result;
			if ( $result['code'] > 0 ) {
				$any_done = true;
				if ( ! $result['healthy'] ) {
					$all_ok = false;
				}
			}
		}

		// If every probe failed to even connect (e.g. loopback disabled on the host) we
		// cannot prove the site is broken — report healthy so we never roll back a good
		// repair on a host that simply blocks self-requests. A genuine fatal returns a 500.
		if ( ! $any_done ) {
			return array( 'ok' => true, 'checks' => $checks );
		}

		return array( 'ok' => $all_ok, 'checks' => $checks );
	}

	/**
	 * Issue one loopback GET and judge the response.
	 *
	 * @return array{url:string,code:int,healthy:bool}
	 */
	private function probe( string $url ): array {
		$url = add_query_arg( 'loyalsec-loopback', (string) time(), $url );

		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 10,
				'redirection' => 2,
				'sslverify'   => \LoyalSecurity\Support\Http::local_sslverify(),
				'blocking'    => true,
				'user-agent'  => 'LoyalSecurity-Loopback/' . LOYALSEC_VERSION,
				'cookies'     => array(),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array( 'url' => $url, 'code' => 0, 'healthy' => false );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = (string) wp_remote_retrieve_body( $response );

		$healthy = $code > 0 && $code < 500 && ! $this->looks_fatal( $body );

		return array( 'url' => $url, 'code' => $code, 'healthy' => $healthy );
	}

	/**
	 * Detect WordPress' fatal-error white screen / recovery markers in a 200 body
	 * (a fatal handled by WP's shutdown handler still returns 200 with this text).
	 */
	private function looks_fatal( string $body ): bool {
		if ( '' === $body ) {
			return false;
		}
		$needles = array(
			'There has been a critical error on this website',
			'Error establishing a database connection',
			'Parse error:',
			'Fatal error:',
		);
		foreach ( $needles as $needle ) {
			if ( false !== stripos( $body, $needle ) ) {
				return true;
			}
		}
		return false;
	}
}
