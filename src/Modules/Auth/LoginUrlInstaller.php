<?php
/**
 * Custom Login URL — Apache rewrite deployment (with backup, verify, rollback).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Writes the .htaccess rewrite that lets `/<slug>` serve wp-login.php, then confirms it
 * actually works with a live self-test request before the runtime guard starts blocking the
 * original `/wp-login.php` path — mirrors {@see \LoyalSecurity\Setup\PrependInstaller}'s
 * apply → verify → auto-rollback pattern so a server that can't support the rewrite (no
 * mod_rewrite, AllowOverride off) can never leave the site locked out.
 *
 * Deliberately uses native file_get_contents()/file_put_contents() rather than
 * Support\Filesystem/WP_Filesystem: this class prepends to and rewrites the site's root
 * .htaccess, which also carries WordPress's own rewrite rules. A silent failure/behavioural
 * difference from a WP_Filesystem fallback method here breaks all pretty-permalink routing
 * (including the REST API), a far bigger blast radius than the discouraged-function lint
 * finding this trades for. Every read is checked for `false` before use, and apply() refuses
 * to proceed if it can't positively read the existing file.
 *
 * Also trips Plugin Check's `WriteFile.ABSPATHDetected` ("consider wp_upload_dir() instead") —
 * a false positive here specifically: the file being written IS `ABSPATH . '.htaccess'` by
 * definition (that's where Apache looks for it), not an arbitrary generated/user file that could
 * live anywhere. Suppressed inline at each write site rather than restructured.
 */
class LoginUrlInstaller {

	private const MARK_BEGIN = '# BEGIN Loyal Security Login URL';
	private const MARK_END   = '# END Loyal Security Login URL';

	/** The markers this plugin wraps its own blocks in. */
	private const MARKERS = array(
		array( self::MARK_BEGIN, self::MARK_END ),
	);

	/**
	 * @return array{ok:bool,message:string}
	 */
	public function apply( string $slug ): array {
		$slug = trim( $slug, '/' );
		if ( '' === $slug ) {
			return array( 'ok' => false, 'message' => __( 'A slug is required.', 'loyal-security' ) );
		}

		$file = \LoyalSecurity\Support\Paths::root() . '.htaccess';
		$dir  = dirname( $file );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check on a server-root path; not a WP_Filesystem-abstracted write.
		if ( ! is_writable( $dir ) && ! ( is_file( $file ) && is_writable( $file ) ) ) {
			return array(
				'ok'      => false,
				'message' => __( '.htaccess is not writable — add the rewrite manually using the Nginx/Apache snippet, or grant write access.', 'loyal-security' ),
			);
		}

		$existing = '';
		if ( is_file( $file ) ) {
			$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note.
			if ( false === $raw ) {
				return array( 'ok' => false, 'message' => __( 'Could not read the existing .htaccess — refusing to overwrite it blind.', 'loyal-security' ) );
			}
			$existing = $raw;
		}
		$this->backup( $file, $existing );

		$block = self::MARK_BEGIN . "\n"
			. "<IfModule mod_rewrite.c>\n"
			. "RewriteEngine On\n"
			. 'RewriteRule ^' . $slug . '/?$ wp-login.php [QSA,L]' . "\n"
			. "</IfModule>\n"
			. self::MARK_END . "\n";

		// Prepend — same as ServerRules' root block — so it wins over WordPress's own block.
		$content = $block . "\n" . ltrim( $this->strip( $existing ) );

		if ( false === file_put_contents( $file, $content, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- see class docblock note; this writes the site-root .htaccess itself, which has no wp_upload_dir() alternative location.
			return array( 'ok' => false, 'message' => __( 'Could not write .htaccess.', 'loyal-security' ) );
		}

		$check = $this->verify( $slug );
		if ( ! $check['ok'] ) {
			$this->revert();
			return array(
				'ok'      => false,
				'message' => __( 'Self-test failed — automatically rolled back. ', 'loyal-security' ) . $check['message'],
			);
		}

		return array( 'ok' => true, 'message' => __( 'Custom login URL verified and active.', 'loyal-security' ) );
	}

	/**
	 * Remove the rewrite block, restoring the original /wp-login.php as the only entry point.
	 */
	public function revert(): void {
		$file = \LoyalSecurity\Support\Paths::root() . '.htaccess';
		if ( is_file( $file ) ) {
			$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note.
			if ( false === $raw ) {
				return; // Couldn't read it — refuse to overwrite blind.
			}
			$content = $this->strip( $raw );
			file_put_contents( $file, $content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- see class docblock note; this writes the site-root .htaccess itself, which has no wp_upload_dir() alternative location.
		}
	}

	public function is_applied(): bool {
		$file = \LoyalSecurity\Support\Paths::root() . '.htaccess';
		if ( ! is_file( $file ) ) {
			return false;
		}
		$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note.
		return false !== $raw && \LoyalSecurity\Support\Markers::present( $raw, self::MARKERS );
	}

	/**
	 * Confirm the new slug actually serves the login form (not a 404) before the guard starts
	 * blocking the original path. Best-effort: a host that blocks loopback HTTP requests (or a
	 * local dev box on localhost, subject to the SSRF guard) may report a false failure here —
	 * same known limitation as PrependInstaller::verify().
	 *
	 * @return array{ok:bool,message:string}
	 */
	public function verify( string $slug ): array {
		$response = wp_remote_get(
			home_url( '/' . $slug ),
			array( 'timeout' => 8, 'sslverify' => \LoyalSecurity\Support\Http::local_sslverify(), 'redirection' => 0 )
		);
		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'message' => $response->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = (string) wp_remote_retrieve_body( $response );
		$looks_like_login = false !== strpos( $body, 'loginform' ) || false !== strpos( $body, 'user_login' );
		if ( 200 !== $code || ! $looks_like_login ) {
			return array(
				'ok'      => false,
				'message' => sprintf( /* translators: %d: HTTP status code */ __( 'Expected the login form at the new URL but got HTTP %d.', 'loyal-security' ), $code ),
			);
		}
		return array( 'ok' => true, 'message' => __( 'Verified.', 'loyal-security' ) );
	}

	/**
	 * Manual Nginx equivalent (Nginx has no .htaccess).
	 *
	 * A bare `rewrite ... last;` is not sufficient on every Nginx vhost topology: confirmed by
	 * direct testing, some setups (e.g. a CloudPanel-style vhost that proxy_passes to a second
	 * internal server block before fastcgi_pass) genuinely lose the original request path by
	 * the time PHP sees REQUEST_URI, which breaks LoginUrlGuard's slug-vs-direct-hit check —
	 * it would 404 legitimate requests through the slug exactly like it 404s a direct hit on
	 * /wp-login.php. The header line below carries the original path across that gap;
	 * LoginUrlGuard::request_path() prefers it when present. Harmless to include even on a
	 * simple single-block vhost where it isn't strictly needed.
	 */
	public function nginx_snippet( string $slug ): string {
		$slug = trim( $slug, '/' );
		return '# Loyal Security — add to your server block (Nginx has no .htaccess)' . "\n"
			. '#' . "\n"
			. '# A bare `rewrite ... last;` is not enough on every vhost: on some setups (e.g. a' . "\n"
			. '# CloudPanel-style vhost that proxies to a second internal server block before' . "\n"
			. '# fastcgi_pass) Nginx loses the original request path by the time PHP sees it,' . "\n"
			. '# confirmed by direct testing — the plugin then cannot tell a legitimate hit on' . "\n"
			. '# this slug apart from someone probing /wp-login.php directly, and blocks both.' . "\n"
			. '# This location handles the slug with its own copy of your existing wp-login.php' . "\n"
			. '# handling (fastcgi_pass or proxy_pass — whichever your setup already uses),' . "\n"
			. '# rather than `rewrite ... last` into a shared location, because directives added' . "\n"
			. '# here would not carry across that internal re-match. Copy your site\'s normal' . "\n"
			. '# wp-login.php location\'s contents in below the marked line, keeping the header' . "\n"
			. '# line so the plugin can see the real request path.' . "\n"
			. 'location = /' . $slug . ' {' . "\n"
			. '    # fastcgi_pass setups: fastcgi_param HTTP_X_LOYALSEC_ORIGINAL_URI $request_uri;' . "\n"
			. '    # proxy_pass setups:   proxy_set_header X-LoyalSec-Original-Uri $request_uri;' . "\n"
			. '    # --- paste your existing wp-login.php location\'s directives below ---' . "\n"
			. '}' . "\n";
	}

	private function backup( string $file, string $content ): void {
		// Stored under wp-content/uploads, never alongside the live .htaccess itself — a
		// same-directory backup of a server-root config file is a predictable-filename
		// plaintext leak on any web server that doesn't specifically deny it. See
		// Filesystem::backup_config_file()'s own docblock for the full reasoning.
		\LoyalSecurity\Support\Filesystem::backup_config_file( $file, $content );
	}

	private function strip( string $content ): string {
		return \LoyalSecurity\Support\Markers::strip( $content, self::MARKERS );
	}
}
