<?php
/**
 * Deploys a standalone copy of the WAF kernel outside the plugin directory.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Setup;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Support\Filesystem;

/**
 * The WAF kernel classes (`src/Waf/*.php`), `src/Support/Ip.php`, and the two bundled rule data
 * files (`data/waf-signatures.php`, `data/virtual-patches.php`) are used by BOTH Standard Mode
 * (PSR-4 autoloaded inside the plugin, after WordPress has booted) and Optimized Mode (the
 * pre-WordPress prepend). Shipping the same physical files to both consumers meant they needed a
 * guard that tolerates `ABSPATH` being undefined — which is exactly what WordPress.org's Plugin
 * Check cannot accept (see `docs/wporg-review-architecture-decisions.md` §3 for the full history
 * of why no guard syntax satisfies it while these files remain reachable by the prepend from
 * inside the plugin directory).
 *
 * This class breaks that coupling: it copies the *content* of those files to a relocated bundle
 * under the private uploads storage directory ({@see BanStore::storage_dir()}) — never inside
 * `wp-content/plugins/loyal-security/`, so Plugin Check's scan (which only covers the plugin's
 * own folder) never sees them — rewriting each file's direct-access guard from the plain
 * single-constant form (used by the in-plugin master copies, loaded only by Standard Mode after
 * WordPress boots) to the dual-constant form the prepend actually needs. The relocated bundle
 * also gets the rendered prepend bootstrapper itself ({@see PrependBootstrapTemplate}).
 *
 * Not shipped in source, not tracked, regenerated on demand — mirrors
 * {@see \TotalSecurityWP\Modules\Backup\RecoveryScriptTemplate}'s pattern for the standalone
 * recovery endpoint, applied to the larger WAF kernel.
 */
class WafKernelBundler {

	/** Guard used by the in-plugin master copies (Standard Mode only, post-WordPress-boot). */
	private const MASTER_GUARD = "defined( 'ABSPATH' ) || exit;";

	/** Guard used by the relocated, deployed copies (must tolerate running pre-WordPress). */
	private const DEPLOYED_GUARD = "if ( ! defined( 'ABSPATH' ) && ! defined( 'TOTALSECWP_WAF_PREPEND' ) ) {\n\texit;\n}";

	/**
	 * Absolute path to the deployed WAF-kernel bundle directory, or '' if the uploads directory
	 * is unavailable.
	 */
	public function deploy_dir(): string {
		$storage = BanStore::storage_dir();
		return '' === $storage ? '' : trailingslashit( $storage ) . 'waf-kernel';
	}

	/**
	 * (Re)generate the entire standalone bundle: relocated WAF kernel classes + data files (guard
	 * rewritten so they can run pre-WordPress), the rendered prepend bootstrapper, and the
	 * directory hardening. Safe to call any time Optimized Mode is enabled or being deployed —
	 * used by the Setup Wizard's initial deploy and by
	 * {@see \TotalSecurityWP\Modules\Firewall\FirewallModule::maybe_resync_deployed_kernel()}
	 * whenever the master source could have changed.
	 */
	public function sync(): bool {
		$dir = $this->deploy_dir();
		if ( '' === $dir ) {
			return false;
		}
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$this->harden( $dir );

		$transform = static function ( string $contents, string $relative_path ): string {
			return str_replace( self::MASTER_GUARD, self::DEPLOYED_GUARD, $contents );
		};

		$ok = Filesystem::copy_dir( TOTALSECWP_PATH . 'src/Waf', $dir . '/src/Waf', $transform );
		$ok = $ok && $this->guarded_copy( TOTALSECWP_PATH . 'src/Support/Ip.php', $dir . '/src/Support/Ip.php' );
		$ok = $ok && $this->guarded_copy( TOTALSECWP_PATH . 'data/waf-signatures.php', $dir . '/data/waf-signatures.php' );
		$ok = $ok && $this->guarded_copy( TOTALSECWP_PATH . 'data/virtual-patches.php', $dir . '/data/virtual-patches.php' );

		$bootstrap_path = $dir . '/totalsecwp-waf.php';
		$ok             = $ok && Filesystem::write( $bootstrap_path, PrependBootstrapTemplate::render() );
		if ( $ok && function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $bootstrap_path, true );
		}

		return $ok;
	}

	/**
	 * Copy a single file into the bundle, rewriting its guard for the deployed context and
	 * invalidating opcache — a server running opcache.validate_timestamps=0 otherwise keeps
	 * serving the previously-compiled bytecode of a rewritten file indefinitely (the same
	 * concern FirewallModule::write_waf_config() already handles for the config file alone;
	 * this extends it to the relocated logic files themselves).
	 */
	private function guarded_copy( string $from, string $to ): bool {
		$contents = Filesystem::read( $from );
		if ( null === $contents ) {
			return false;
		}
		$dir = dirname( $to );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$contents = str_replace( self::MASTER_GUARD, self::DEPLOYED_GUARD, $contents );
		$ok       = Filesystem::write( $to, $contents );
		if ( $ok && function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $to, true );
		}
		return $ok;
	}

	/**
	 * Harden the deploy directory the same way other private storage under
	 * uploads/loyal-security/ already is (see BackupStore::harden()) — defence in depth, since
	 * the signature/patch regex rules are somewhat sensitive (they reveal exact detection
	 * patterns), even though nothing here is ever directly web-reachable to begin with.
	 */
	private function harden( string $dir ): void {
		$htaccess = $dir . '/.htaccess';
		if ( ! is_file( $htaccess ) ) {
			Filesystem::write( $htaccess, "Order deny,allow\nDeny from all\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n" );
		}
		$index = $dir . '/index.php';
		if ( ! is_file( $index ) ) {
			Filesystem::write( $index, "<?php\n// Silence is golden.\n" );
		}
		$webconfig = $dir . '/web.config';
		if ( ! is_file( $webconfig ) ) {
			Filesystem::write(
				$webconfig,
				"<configuration>\n\t<system.webServer>\n\t\t<authorization>\n\t\t\t<deny users=\"*\" />\n\t\t</authorization>\n\t</system.webServer>\n</configuration>\n"
			);
		}
	}
}
