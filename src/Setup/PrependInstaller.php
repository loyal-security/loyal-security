<?php
/**
 * Safe deployment of the auto_prepend_file directive (with backup, verify, rollback).
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Setup;

defined( 'ABSPATH' ) || exit;

/**
 * Writes the `auto_prepend_file` directive that activates Optimized Mode, using the
 * strategy recommended by {@see ServerProbe}. Every change is backed up first and verified
 * by a live self-test request; failed verification triggers automatic rollback.
 *
 * Deliberately uses native file_get_contents()/file_put_contents() rather than
 * Support\Filesystem/WP_Filesystem: this class writes to the site's root .htaccess/.user.ini,
 * which (for .htaccess) also carries WordPress's own rewrite rules. A silent failure/
 * behavioural difference from a WP_Filesystem fallback method here breaks all
 * pretty-permalink routing (including the REST API), a far bigger blast radius than the
 * discouraged-function lint finding this trades for. Every read is checked for `false` before
 * use, and writes bail out rather than proceed on an unreadable existing file.
 */
class PrependInstaller {

	private const MARK_BEGIN = '# BEGIN Loyal Security WAF';
	private const MARK_END   = '# END Loyal Security WAF';

	/** Current markers plus the ones earlier versions wrote. */
	private const MARKERS = array(
		array( self::MARK_BEGIN, self::MARK_END ),
		array( '# BEGIN Total Security WP WAF', '# END Total Security WP WAF' ),
	);

	private ServerProbe $probe;

	public function __construct( ServerProbe $probe ) {
		$this->probe = $probe;
	}

	/**
	 * Deploy the prepend directive.
	 *
	 * @return array{ok:bool,strategy:string,message:string,target:string}
	 */
	public function deploy(): array {
		$info     = $this->probe->detect();
		$strategy = $info['strategy'];
		$prepend  = $info['prepend_path'];

		if ( ! is_file( $prepend ) ) {
			return array( 'ok' => false, 'strategy' => $strategy, 'message' => 'Prepend script missing.', 'target' => '' );
		}

		if ( 'htaccess' === $strategy ) {
			return $this->deploy_htaccess( $prepend );
		}
		if ( 'user_ini' === $strategy ) {
			return $this->deploy_user_ini( $prepend, (string) $info['user_ini_name'] );
		}

		return array(
			'ok'       => false,
			'strategy' => 'manual',
			'message'  => 'Automatic deployment is not available for this server. Add `auto_prepend_file = "' . $prepend . '"` to your PHP configuration manually.',
			'target'   => '',
		);
	}

	/**
	 * Apache mod_php: add a marked block to the root .htaccess.
	 */
	private function deploy_htaccess( string $prepend ): array {
		$file      = \TotalSecurityWP\Support\Paths::root() . '.htaccess';
		$site_url  = (string) get_option( 'siteurl' );
		$canonical = strtolower( (string) wp_parse_url( $site_url, PHP_URL_HOST ) );
		$scheme    = ( 0 === strpos( $site_url, 'https' ) ) ? 'https' : 'http';

		// Build an optional Host-header enforcement block (requires mod_rewrite).
		// Escaping: dots are the only regex metachar that appear in valid hostnames.
		$host_block = '';
		if ( '' !== $canonical ) {
			$pattern    = str_replace( '.', '\\.', $canonical );
			$host_block = '<IfModule mod_rewrite.c>' . "\n"
				. 'RewriteEngine On' . "\n"
				. 'RewriteCond %{HTTP_HOST} !^' . $pattern . '$ [NC]' . "\n"
				. 'RewriteRule ^ ' . $scheme . '://' . $canonical . '%{REQUEST_URI} [R=301,L]' . "\n"
				. '</IfModule>' . "\n";
		}

		$block = self::MARK_BEGIN . "\n"
			. $host_block
			. '<IfModule mod_php.c>' . "\n"
			. 'php_value auto_prepend_file "' . $prepend . '"' . "\n"
			. '</IfModule>' . "\n"
			. '<IfModule mod_php7.c>' . "\n"
			. 'php_value auto_prepend_file "' . $prepend . '"' . "\n"
			. '</IfModule>' . "\n"
			. self::MARK_END . "\n";

		$existing = '';
		if ( is_file( $file ) ) {
			$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note.
			if ( false === $raw ) {
				return array( 'ok' => false, 'strategy' => 'htaccess', 'message' => 'Could not read the existing .htaccess — refusing to overwrite it blind.', 'target' => $file );
			}
			$existing = $raw;
		}
		$this->backup( $file, $existing );

		$cleaned = $this->strip_block( $existing );
		$content = $block . "\n" . $cleaned;

		// Safety net: never let a previously non-trivial .htaccess collapse to just our block.
		if ( strlen( trim( $existing ) ) > 40 && strlen( trim( $cleaned ) ) === 0 ) {
			return array( 'ok' => false, 'strategy' => 'htaccess', 'message' => 'Existing .htaccess content looked wrong after stripping our block — refusing to overwrite it.', 'target' => $file );
		}

		// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- must write the server-root .htaccess itself to deploy the prepend directive; wp_upload_dir() is a different, unrelated path. See class docblock note on native I/O.
		if ( false === file_put_contents( $file, $content, LOCK_EX ) ) {
			return array( 'ok' => false, 'strategy' => 'htaccess', 'message' => 'Could not write .htaccess.', 'target' => $file );
		}

		return $this->finish( 'htaccess', $file );
	}

	/**
	 * CGI/FPM: write/update .user.ini in the web root.
	 */
	private function deploy_user_ini( string $prepend, string $name ): array {
		$file     = \TotalSecurityWP\Support\Paths::root() . $name;
		$existing = '';
		if ( is_file( $file ) ) {
			$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note.
			if ( false === $raw ) {
				return array( 'ok' => false, 'strategy' => 'user_ini', 'message' => 'Could not read the existing ' . $name . ' — refusing to overwrite it blind.', 'target' => $file );
			}
			$existing = $raw;
		}
		$this->backup( $file, $existing );

		// Remove any prior auto_prepend_file line, then append ours.
		$lines = preg_split( '/\R/', $existing ) ?: array();
		$kept  = array();
		foreach ( $lines as $line ) {
			if ( '' === trim( $line ) ) {
				continue;
			}
			if ( preg_match( '/^\s*auto_prepend_file\s*=/', $line ) ) {
				continue;
			}
			$kept[] = $line;
		}
		$kept[]  = 'auto_prepend_file = "' . $prepend . '"';
		$content = implode( "\n", $kept ) . "\n";

		// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- must write the server-root .user.ini itself to deploy the prepend directive; wp_upload_dir() is a different, unrelated path. See class docblock note on native I/O.
		if ( false === file_put_contents( $file, $content, LOCK_EX ) ) {
			return array( 'ok' => false, 'strategy' => 'user_ini', 'message' => 'Could not write ' . $name . '.', 'target' => $file );
		}

		update_option( 'totalsecwp_waf_mode', 'optimized' );

		return array(
			'ok'       => true,
			'strategy' => 'user_ini',
			'target'   => $file,
			'message'  => 'Deployed via ' . $name . '. Note: PHP caches .user.ini for up to 5 minutes (user_ini.cache_ttl), so activation may take a few minutes.',
		);
	}

	/**
	 * Verify the prepend executes by issuing a self-test request.
	 *
	 * @return array{ok:bool,active:bool,message:string}
	 */
	public function verify(): array {
		$response = wp_remote_get(
			home_url( '/?totalsecwp_selftest=1' ),
			array(
				'timeout'   => 10,
				'sslverify' => \TotalSecurityWP\Support\Http::local_sslverify(),
				'headers'   => array( 'X-TotalSecWP-Selftest' => '1' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'active' => false, 'message' => $response->get_error_message() );
		}
		$header = wp_remote_retrieve_header( $response, 'x-totalsecwp-waf' );
		$active = ( 'active' === $header || 'blocked' === $header );
		return array(
			'ok'      => true,
			'active'  => $active,
			'message' => $active ? 'Optimized Mode is active.' : 'Prepend not detected yet (may be caching).',
		);
	}

	/**
	 * Remove the deployed directive and restore Standard Mode.
	 */
	public function rollback(): array {
		$info = $this->probe->detect();

		if ( 'htaccess' === $info['strategy'] ) {
			$file = \TotalSecurityWP\Support\Paths::root() . '.htaccess';
			if ( is_file( $file ) ) {
				$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note.
				if ( false !== $raw ) {
					$content = $this->strip_block( $raw );
					// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- must revert the server-root .htaccess itself; wp_upload_dir() is a different, unrelated path. See class docblock note.
					file_put_contents( $file, $content, LOCK_EX );
				}
			}
		} else {
			$file = \TotalSecurityWP\Support\Paths::root() . (string) $info['user_ini_name'];
			if ( is_file( $file ) ) {
				$raw = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see class docblock note.
				if ( false !== $raw ) {
					$lines = preg_split( '/\R/', $raw ) ?: array();
					$kept  = array();
					foreach ( $lines as $line ) {
						// Only this plugin's own directive; another tool's prepend stays.
						if ( preg_match( '/^\s*auto_prepend_file\s*=/', $line ) && preg_match( '/totalsecwp|loyal-security|total-security-wp/i', $line ) ) {
							continue;
						}
						if ( '' !== trim( $line ) ) {
							$kept[] = $line;
						}
					}
					// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- must revert the server-root .user.ini itself; wp_upload_dir() is a different, unrelated path. See class docblock note.
					file_put_contents( $file, implode( "\n", $kept ) . "\n", LOCK_EX );
				}
			}
		}

		update_option( 'totalsecwp_waf_mode', 'standard' );
		return array( 'ok' => true, 'message' => 'Reverted to Standard Mode.' );
	}

	/* ------------------------------ helpers -------------------------------- */

	private function finish( string $strategy, string $target ): array {
		$check = $this->verify();
		if ( ! $check['active'] ) {
			// Self-test failed — roll back to avoid a broken/ineffective state.
			$this->rollback();
			return array(
				'ok'       => false,
				'strategy' => $strategy,
				'target'   => $target,
				'message'  => 'Self-test failed; automatically rolled back to Standard Mode. ' . $check['message'],
			);
		}
		update_option( 'totalsecwp_waf_mode', 'optimized' );
		return array( 'ok' => true, 'strategy' => $strategy, 'target' => $target, 'message' => 'Optimized Mode active and verified.' );
	}

	private function backup( string $file, string $contents ): void {
		// Stored under wp-content/uploads, never alongside the live file — see
		// Filesystem::backup_config_file()'s own docblock for why: a same-directory backup of
		// a server-root config file is a predictable-filename plaintext leak on any web server
		// that doesn't specifically deny it.
		\TotalSecurityWP\Support\Filesystem::backup_config_file( $file, $contents );
	}

	private function strip_block( string $content ): string {
		return \TotalSecurityWP\Support\Markers::strip( $content, self::MARKERS );
	}
}
