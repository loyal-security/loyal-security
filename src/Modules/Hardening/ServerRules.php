<?php
/**
 * Server rule generation (.htaccess / Nginx).
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Generates and applies hardening directives:
 *   - disable directory browsing,
 *   - block direct access to sensitive files,
 *   - block PHP execution in uploads/ and wp-includes/.
 *
 * On Apache/LiteSpeed the rules are written into marked blocks in .htaccess files; for
 * Nginx (which has no per-directory config) an equivalent snippet is produced for the
 * operator to paste into their server block.
 *
 * Deliberately uses native file_get_contents()/file_put_contents() rather than
 * Support\Filesystem/WP_Filesystem for these specific reads/writes: WP_Filesystem can fall
 * back to FTP/SSH-based methods on some hosts depending on file-ownership detection, and a
 * write through that path silently failing or behaving unexpectedly on the site's root
 * .htaccess is a much bigger blast radius (breaks all pretty-permalink routing, including the
 * REST API) than the discouraged-function lint finding this trades for. write_block()/revert()
 * additionally refuse to write if the existing file couldn't be read, or if doing so would
 * collapse a previously non-trivial file down to just our own block.
 */
class ServerRules {

	private const MARK_BEGIN = '# BEGIN Loyal Security';
	private const MARK_END   = '# END Loyal Security';

	/** Current markers plus the ones earlier versions wrote. */
	private const MARKERS = array(
		array( self::MARK_BEGIN, self::MARK_END ),
		array( '# BEGIN Total Security WP', '# END Total Security WP' ),
	);

	/**
	 * Build the root .htaccess hardening block.
	 */
	public function root_block(): string {
		$lines   = array();
		$lines[] = self::MARK_BEGIN;
		$lines[] = '# Disable directory browsing';
		$lines[] = 'Options -Indexes';
		$lines[] = '';
		$lines[] = '# Block access to sensitive files';
		$lines[] = '<FilesMatch "(^\.|wp-config\.php|wp-config-sample\.php|readme\.html|license\.txt|\.(sql|bak|old|swp|orig|log|ini|sh|zip)$)">';
		$lines[] = '  <IfModule mod_authz_core.c>';
		$lines[] = '    Require all denied';
		$lines[] = '  </IfModule>';
		$lines[] = '  <IfModule !mod_authz_core.c>';
		$lines[] = '    Order allow,deny';
		$lines[] = '    Deny from all';
		$lines[] = '  </IfModule>';
		$lines[] = '</FilesMatch>';
		$lines[] = '';
		$lines[] = '# Block the installer scripts once the site is configured';
		$lines[] = '<FilesMatch "^(install|setup-config)\.php$">';
		$lines[] = '  <IfModule mod_authz_core.c>';
		$lines[] = '    Require all denied';
		$lines[] = '  </IfModule>';
		$lines[] = '  <IfModule !mod_authz_core.c>';
		$lines[] = '    Order allow,deny';
		$lines[] = '    Deny from all';
		$lines[] = '  </IfModule>';
		$lines[] = '</FilesMatch>';
		$lines[] = '';
		$lines[] = '# Block author enumeration via redirect is handled in PHP';
		$lines[] = self::MARK_END;
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Build the "no PHP execution here" .htaccess block for uploads/wp-includes.
	 */
	public function no_php_block(): string {
		$lines   = array();
		$lines[] = self::MARK_BEGIN;
		$lines[] = '<FilesMatch "\.(?i:php|phtml|php3|php4|php5|php7|phar|pht)$">';
		$lines[] = '  <IfModule mod_authz_core.c>';
		$lines[] = '    Require all denied';
		$lines[] = '  </IfModule>';
		$lines[] = '  <IfModule !mod_authz_core.c>';
		$lines[] = '    Deny from all';
		$lines[] = '  </IfModule>';
		$lines[] = '</FilesMatch>';
		// php_flag is mod_php only — silently ignored on FastCGI/FPM but causes HTTP 500
		// on some Apache+FPM setups. Wrap so it only fires when mod_php is active.
		$lines[] = '<IfModule mod_php.c>';
		$lines[] = '  php_flag engine off';
		$lines[] = '</IfModule>';
		$lines[] = '<IfModule mod_php7.c>';
		$lines[] = '  php_flag engine off';
		$lines[] = '</IfModule>';
		$lines[] = '<IfModule mod_php8.c>';
		$lines[] = '  php_flag engine off';
		$lines[] = '</IfModule>';
		$lines[] = self::MARK_END;
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Apply all server rules (Apache/LiteSpeed). Returns a per-target result.
	 *
	 * @return array<string, bool>
	 */
	public function apply(): array {
		$results = array();

		// Root: prepend our block above the WordPress block.
		$results['root'] = $this->write_block( \TotalSecurityWP\Support\Paths::root() . '.htaccess', $this->root_block(), true );

		// uploads/.
		$uploads = wp_upload_dir();
		if ( empty( $uploads['error'] ) ) {
			$results['uploads'] = $this->write_block( trailingslashit( $uploads['basedir'] ) . '.htaccess', $this->no_php_block(), false );
		}

		// wp-includes/.
		$results['wp-includes'] = $this->write_block( \TotalSecurityWP\Support\Paths::includes() . '/.htaccess', $this->no_php_block(), false );

		// A malformed root block on a host with an unusual AllowOverride/mod_rewrite config can
		// 500 the entire site — the same class of risk LoginUrlInstaller::verify() already
		// guards for the login-URL rewrite. Confirm the site still answers before leaving the
		// new rules in place; auto-revert (all three files) if it doesn't.
		if ( ! empty( $results['root'] ) ) {
			$check = $this->verify();
			if ( ! $check['ok'] ) {
				$this->revert();
				$results['root']  = false;
				$results['error'] = $check['message'];
			}
		}

		return $results;
	}

	/**
	 * Confirm the site still answers (no 5xx) after writing the root .htaccess block.
	 * Best-effort: a host that blocks loopback requests may report a false failure here — same
	 * known limitation noted on {@see \TotalSecurityWP\Modules\Auth\LoginUrlInstaller::verify()}.
	 *
	 * @return array{ok:bool,message:string}
	 */
	private function verify(): array {
		$response = wp_remote_get( home_url( '/' ), array( 'timeout' => 8, 'sslverify' => \TotalSecurityWP\Support\Http::local_sslverify(), 'redirection' => 0 ) );
		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'message' => $response->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code >= 500 ) {
			return array(
				'ok'      => false,
				/* translators: %d: HTTP status code */
				'message' => sprintf( __( 'The site returned HTTP %d after applying server rules.', 'loyal-security' ), $code ),
			);
		}
		return array( 'ok' => true, 'message' => __( 'Verified.', 'loyal-security' ) );
	}

	/**
	 * Remove all applied rules.
	 */
	public function revert(): void {
		$targets = array( \TotalSecurityWP\Support\Paths::root() . '.htaccess', \TotalSecurityWP\Support\Paths::includes() . '/.htaccess' );
		$uploads = wp_upload_dir();
		if ( empty( $uploads['error'] ) ) {
			$targets[] = trailingslashit( $uploads['basedir'] ) . '.htaccess';
		}
		foreach ( $targets as $file ) {
			if ( is_file( $file ) ) {
				$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note on why WP_Filesystem is deliberately not used for these files.
				if ( false === $raw ) {
					continue; // Unreadable — never touch a file we can't verify the contents of.
				}
				$content = $this->strip( $raw );
				if ( '' === trim( $content ) ) {
					wp_delete_file( $file );
				} else {
					file_put_contents( $file, $content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- see class docblock note.
				}
			}
		}
	}

	/**
	 * Detect whether the root rules are currently applied.
	 */
	public function is_applied(): bool {
		$file = \TotalSecurityWP\Support\Paths::root() . '.htaccess';
		if ( ! is_file( $file ) ) {
			return false;
		}
		$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note.
		return false !== $raw && \TotalSecurityWP\Support\Markers::present( $raw, self::MARKERS );
	}

	/**
	 * Equivalent Nginx snippet for manual installation.
	 */
	public function nginx_snippet(): string {
		$path     = static function ( string $url ): string {
			return trailingslashit( (string) wp_parse_url( $url, PHP_URL_PATH ) );
		};
		$uploads  = wp_upload_dir( null, false );
		$admin    = preg_quote( $path( admin_url() ), '#' );
		$includes = preg_quote( $path( includes_url() ), '#' );
		$uploaded = preg_quote( $path( (string) ( $uploads['baseurl'] ?? content_url( 'uploads' ) ) ), '#' );

		return '# Loyal Security — add to your server block' . "\n"
			. 'location ~* /(?:\.|wp-config\.php|readme\.html|license\.txt|.*\.(?:sql|bak|old|swp|orig|log|ini|sh|zip))$ { deny all; }' . "\n"
			. 'location ~* ^' . $admin . '(install|setup-config)\.php$ { deny all; }' . "\n"
			. 'location ~* ^' . $uploaded . '.*\.(?:php|phtml|php[3457]|phar|pht)$ { deny all; }' . "\n"
			. 'location ~* ^' . $includes . '.*\.php$ { deny all; }' . "\n"
			. 'autoindex off;' . "\n";
	}

	/**
	 * Write a marked block into a file, optionally prepending (root) vs replacing.
	 */
	private function write_block( string $file, string $block, bool $prepend ): bool {
		$file_exists = is_file( $file );
		$existing    = '';
		if ( $file_exists ) {
			$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note on why WP_Filesystem is deliberately not used for these files.
			if ( false === $raw ) {
				// The file exists but couldn't be read (permissions, transient I/O error, etc).
				// Refuse to proceed rather than risk writing our block over a truncated/blank
				// version of a file that may contain WordPress's own rewrite rules.
				return false;
			}
			$existing = $raw;
		}
		$cleaned = $this->strip( $existing );

		if ( $prepend ) {
			$content = $block . "\n" . ltrim( $cleaned );
		} else {
			$content = $cleaned . ( '' === trim( $cleaned ) ? '' : "\n" ) . $block;
		}

		// Safety net: never let a previously non-trivial file collapse to (near-)nothing but our
		// own block. If that would happen, something upstream mis-read the file — bail instead
		// of destroying whatever else lived in it (e.g. WordPress's own rewrite rules).
		if ( $file_exists && strlen( trim( $existing ) ) > 40 && strlen( trim( $cleaned ) ) === 0 ) {
			return false;
		}

		$dir = dirname( $file );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check on a server-root path; not a WP_Filesystem-abstracted write.
		if ( ! is_dir( $dir ) || ! is_writable( $dir ) && ! ( is_file( $file ) && is_writable( $file ) ) ) {
			return false;
		}
		return false !== file_put_contents( $file, $content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- see class docblock note.
	}

	private function strip( string $content ): string {
		return \TotalSecurityWP\Support\Markers::strip( $content, self::MARKERS );
	}
}
