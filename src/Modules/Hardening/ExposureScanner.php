<?php
/**
 * Attack-surface / information-disclosure scanner.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Plugin;

/**
 * Detects common WordPress recon/information-disclosure vectors (exposed backup files,
 * readme/license version disclosure, a reachable debug.log, and settings that leave
 * XML-RPC/author-enumeration open) and offers a single, explicit fix action per finding.
 * Nothing here is auto-applied — every remediation is a distinct opt-in button dispatched
 * via {@see fix()}.
 */
class ExposureScanner {

	private const OPT_CACHE = 'totalsecwp_exposure_findings';

	/** Backup/secret file patterns checked in the web root (non-recursive). */
	private const BACKUP_PATTERNS = array(
		'wp-config.php.bak',
		'wp-config.php.old',
		'wp-config.php.save',
		'wp-config.php.txt',
		'wp-config.php.swp',
		'wp-config.php~',
		'wp-config.zip',
		'wp-config.php.orig',
		'.env',
	);

	private Logger $logger;

	public function __construct( Logger $logger ) {
		$this->logger = $logger;
	}

	/**
	 * Cached results from the last scan (runs an initial scan if none exists yet).
	 *
	 * @return array<string, mixed>
	 */
	public function cached(): array {
		$cache = get_option( self::OPT_CACHE, array() );
		if ( ! is_array( $cache ) || empty( $cache['items'] ) ) {
			return $this->scan();
		}
		return $cache;
	}

	/**
	 * Run every check now, cache, and log newly-critical findings.
	 *
	 * @return array<string, mixed>
	 */
	public function scan(): array {
		$previous       = get_option( self::OPT_CACHE, array() );
		$previous_items = is_array( $previous ) && isset( $previous['items'] ) ? (array) $previous['items'] : array();
		$previously_exposed = array();
		foreach ( $previous_items as $row ) {
			if ( is_array( $row ) && 'exposed' === ( $row['status'] ?? '' ) ) {
				$previously_exposed[ (string) ( $row['id'] ?? '' ) ] = true;
			}
		}

		$items = array_merge(
			$this->check_backup_files(),
			array(
				$this->check_readme_license(),
				$this->check_installer_scripts(),
				$this->check_debug_log(),
				$this->check_xmlrpc(),
				$this->check_author_enum(),
			)
		);

		foreach ( $items as $item ) {
			if ( 'exposed' === $item['status'] && $item['severity'] >= EventCatalog::SEV_WARNING
				&& empty( $previously_exposed[ $item['id'] ] ) ) {
				$this->logger->log(
					EventCatalog::EXPOSURE_FINDING,
					array( 'id' => $item['id'], 'title' => $item['title'], 'detail' => $item['detail'] ),
					$item['severity']
				);
			}
		}

		$result = array( 'items' => $items, 'scanned_at' => time() );
		update_option( self::OPT_CACHE, $result, false );
		return $result;
	}

	/**
	 * Dispatch the fix action for one finding id.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public function fix( string $id, ?HardeningModule $module ): array {
		if ( 0 === strpos( $id, 'backup_file:' ) ) {
			return $this->fix_backup_file( substr( $id, strlen( 'backup_file:' ) ) );
		}

		if ( in_array( $id, array( 'readme_license', 'installer_scripts' ), true ) ) {
			if ( null === $module ) {
				return array( 'ok' => false, 'message' => __( 'Hardening module is unavailable.', 'loyal-security' ) );
			}
			$res = $module->apply_server_rules();
			$this->scan(); // Refresh cache so the dashboard reflects the fix immediately.
			// apply_server_rules() itself carries 'ok' — a failed post-apply health check
			// auto-reverts and reports ok:false, which must win here, not the optimistic default
			// this array literal used to always return regardless of what actually happened.
			if ( empty( $res['ok'] ) ) {
				$reason = (string) ( $res['result']['error'] ?? '' );
				return array(
					'ok'      => false,
					'message' => '' !== $reason ? $reason : __( 'Could not apply server rules.', 'loyal-security' ),
					'result'  => $res['result'] ?? array(),
				);
			}
			return array( 'ok' => true, 'message' => __( 'Server rules applied.', 'loyal-security' ), 'result' => $res['result'] ?? array() );
		}

		if ( 'debug_log' === $id ) {
			$res = $this->relocate_debug_log();
			$this->scan();
			return $res;
		}

		if ( 'xmlrpc' === $id || 'author_enum' === $id ) {
			if ( null === $module ) {
				return array( 'ok' => false, 'message' => __( 'Hardening module is unavailable.', 'loyal-security' ) );
			}
			$key = 'xmlrpc' === $id ? 'disable_xmlrpc' : 'block_author_enum';
			Plugin::instance()->container()->make( 'settings' )->set( 'hardening', $key, true );
			$this->scan();
			return array( 'ok' => true, 'message' => __( 'Setting enabled — applies on the next page load.', 'loyal-security' ) );
		}

		return array( 'ok' => false, 'message' => __( 'Unknown finding id.', 'loyal-security' ) );
	}

	/* ------------------------------------------------------------------ *
	 * Checks
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<int, array<string, mixed>>
	 */
	private function check_backup_files(): array {
		$items = array();
		foreach ( self::BACKUP_PATTERNS as $rel ) {
			$path = \TotalSecurityWP\Support\Paths::root() . $rel;
			if ( ! is_file( $path ) ) {
				continue;
			}

			$reachable = $this->probe_reachable( $rel );

			$items[] = array(
				'id'       => 'backup_file:' . $rel,
				'title'    => sprintf( /* translators: %s: file name */ __( 'Exposed backup/secret file: %s', 'loyal-security' ), $rel ),
				'severity' => EventCatalog::SEV_CRITICAL,
				'status'   => 'exposed',
				'detail'   => true === $reachable
					? __( 'This file exists in the web root and was confirmed publicly downloadable — it can leak database credentials or secret keys. Quarantine it now.', 'loyal-security' )
					: __( 'This file exists in the web root. Its public reachability could not be confirmed, but it should not be there — quarantine it now.', 'loyal-security' ),
				'fix'      => array( 'id' => 'backup_file:' . $rel, 'label' => __( 'Quarantine file', 'loyal-security' ) ),
			);
		}
		return $items;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function check_readme_license(): array {
		$readme  = is_file( \TotalSecurityWP\Support\Paths::root() . 'readme.html' );
		$license = is_file( \TotalSecurityWP\Support\Paths::root() . 'license.txt' );
		$applied = ( new ServerRules() )->is_applied();

		if ( ( ! $readme && ! $license ) || $applied ) {
			return array(
				'id'       => 'readme_license',
				'title'    => __( 'Version disclosure via readme.html / license.txt', 'loyal-security' ),
				'severity' => EventCatalog::SEV_WARNING,
				'status'   => 'protected',
				'detail'   => $applied
					? __( 'Server rules are applied and block direct access to these files.', 'loyal-security' )
					: __( 'readme.html and license.txt were not found.', 'loyal-security' ),
				'fix'      => null,
			);
		}

		return array(
			'id'       => 'readme_license',
			'title'    => __( 'Version disclosure via readme.html / license.txt', 'loyal-security' ),
			'severity' => EventCatalog::SEV_WARNING,
			'status'   => 'exposed',
			'detail'   => __( 'readme.html/license.txt are present and directly reachable, revealing the exact WordPress version to attackers. Apply server rules to block them.', 'loyal-security' ),
			'fix'      => array( 'id' => 'readme_license', 'label' => __( 'Apply server rules', 'loyal-security' ) ),
		);
	}

	/**
	 * install.php/setup-config.php are inherently guarded by WordPress core once the site is
	 * installed (they refuse to re-run against a configured DB), so this is an always-shown
	 * defense-in-depth advisory rather than a live-probed finding — avoids an unreliable
	 * self-HTTP-request for a scenario core already mitigates in the common case.
	 *
	 * @return array<string, mixed>
	 */
	private function check_installer_scripts(): array {
		$applied = ( new ServerRules() )->is_applied();
		return array(
			'id'       => 'installer_scripts',
			'title'    => __( 'Installer scripts reachable (wp-admin/install.php, setup-config.php)', 'loyal-security' ),
			'severity' => EventCatalog::SEV_NOTICE,
			'status'   => $applied ? 'protected' : 'exposed',
			'detail'   => $applied
				? __( 'Server rules block direct access to the installer scripts.', 'loyal-security' )
				: __( 'WordPress core normally refuses to re-run these once installed, but if the database connection ever drops they briefly become live. Apply server rules for defense-in-depth.', 'loyal-security' ),
			'fix'      => $applied ? null : array( 'id' => 'installer_scripts', 'label' => __( 'Apply server rules', 'loyal-security' ) ),
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function check_debug_log(): array {
		$debug_log_on = defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG;
		// Where PHP actually writes the log (WordPress points error_log at it when WP_DEBUG_LOG
		// is on); falls back to WordPress's default location.
		$ini_path     = (string) ini_get( 'error_log' );
		$log_path     = '' !== $ini_path ? wp_normalize_path( $ini_path ) : \TotalSecurityWP\Support\Paths::content() . '/debug.log';
		$under_root   = 0 === strpos( $log_path, wp_normalize_path( \TotalSecurityWP\Support\Paths::root() ) )
			|| 0 === strpos( $log_path, wp_normalize_path( \TotalSecurityWP\Support\Paths::content() ) );
		// The plugin's private storage folder (deny-all, see Activator) is where
		// relocate_debug_log() moves the log.
		$storage      = wp_normalize_path( BanStore::storage_dir() );
		$private      = '' !== $storage && 0 === strpos( $log_path, trailingslashit( $storage ) );
		$exists       = $under_root && ! $private && is_file( $log_path );
		$relocated    = defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && ( $private || ! $under_root );
		$applied      = ( new ServerRules() )->is_applied();

		if ( $relocated || ! $exists || ! $debug_log_on || $applied ) {
			return array(
				'id'       => 'debug_log',
				'title'    => __( 'debug.log exposure', 'loyal-security' ),
				'severity' => EventCatalog::SEV_WARNING,
				'status'   => 'protected',
				'detail'   => $relocated
					? __( 'debug.log has been relocated to private, non-web-served storage.', 'loyal-security' )
					: ( $applied
						? __( 'Server rules block direct access to .log files.', 'loyal-security' )
						: __( 'No web-reachable debug.log was found.', 'loyal-security' ) ),
				'fix'      => null,
			);
		}

		return array(
			'id'       => 'debug_log',
			'title'    => __( 'debug.log exposure', 'loyal-security' ),
			'severity' => EventCatalog::SEV_WARNING,
			'status'   => 'exposed',
			'detail'   => sprintf(
				/* translators: %s: path of the log file, relative to the WordPress root. */
				__( '%s exists and is web-reachable — it can contain DB errors, API keys, or other sensitive data printed during debugging. Relocate it to private storage.', 'loyal-security' ),
				(string) ( \TotalSecurityWP\Support\Paths::display( $log_path ) ?? 'debug.log' )
			),
			'fix'      => array( 'id' => 'debug_log', 'label' => __( 'Relocate debug.log', 'loyal-security' ) ),
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function check_xmlrpc(): array {
		$disabled = (bool) Plugin::instance()->container()->make( 'settings' )->get( 'hardening', 'disable_xmlrpc', true );
		return array(
			'id'       => 'xmlrpc',
			'title'    => __( 'XML-RPC reachable', 'loyal-security' ),
			'severity' => EventCatalog::SEV_NOTICE,
			'status'   => $disabled ? 'protected' : 'exposed',
			'detail'   => $disabled
				? __( 'XML-RPC is disabled.', 'loyal-security' )
				: __( 'xmlrpc.php is enabled and is a common brute-force amplification target (system.multicall).', 'loyal-security' ),
			'fix'      => $disabled ? null : array( 'id' => 'xmlrpc', 'label' => __( 'Disable XML-RPC', 'loyal-security' ) ),
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function check_author_enum(): array {
		$blocked = (bool) Plugin::instance()->container()->make( 'settings' )->get( 'hardening', 'block_author_enum', true );
		return array(
			'id'       => 'author_enum',
			'title'    => __( 'Author/username enumeration', 'loyal-security' ),
			'severity' => EventCatalog::SEV_NOTICE,
			'status'   => $blocked ? 'protected' : 'exposed',
			'detail'   => $blocked
				? __( 'Author enumeration (?author=N and the REST users endpoint) is blocked.', 'loyal-security' )
				: __( '?author=N and the REST users endpoint can reveal valid usernames for credential-stuffing/brute-force targeting.', 'loyal-security' ),
			'fix'      => $blocked ? null : array( 'id' => 'author_enum', 'label' => __( 'Block author enumeration', 'loyal-security' ) ),
		);
	}

	/* ------------------------------------------------------------------ *
	 * Fix actions
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{ok:bool,message:string}
	 */
	private function fix_backup_file( string $rel ): array {
		$path = \TotalSecurityWP\Support\Paths::root() . $rel;
		if ( ! is_file( $path ) ) {
			return array( 'ok' => true, 'message' => __( 'File is already gone.', 'loyal-security' ) );
		}

		$incident = Plugin::instance()->module( 'incident' );
		if ( ! $incident instanceof \TotalSecurityWP\Modules\Incident\IncidentModule ) {
			return array( 'ok' => false, 'message' => __( 'The Incident module is unavailable, so the file cannot be quarantined automatically. Remove it manually via FTP/SSH.', 'loyal-security' ) );
		}

		$res = $incident->quarantine_file( $path, 'Exposed backup/secret file (Attack Surface Scan)' );
		if ( empty( $res['ok'] ) ) {
			return array( 'ok' => false, 'message' => (string) ( $res['message'] ?? __( 'Could not quarantine the file.', 'loyal-security' ) ) );
		}
		return array( 'ok' => true, 'message' => __( 'File quarantined.', 'loyal-security' ) );
	}

	/**
	 * Point WP_DEBUG_LOG at a private, non-web-served path (same storage root used by backups
	 * and bans) via the wp-config constant hardener, instead of leaving it at the default,
	 * web-reachable wp-content/debug.log.
	 *
	 * @return array{ok:bool,message:string}
	 */
	private function relocate_debug_log(): array {
		$storage = BanStore::storage_dir();
		if ( '' === $storage ) {
			return array( 'ok' => false, 'message' => __( 'Could not resolve private storage directory.', 'loyal-security' ) );
		}
		if ( ! wp_mkdir_p( $storage ) ) {
			return array( 'ok' => false, 'message' => __( 'Could not create the private storage directory.', 'loyal-security' ) );
		}
		$target = trailingslashit( $storage ) . 'debug.log';
		return ( new ConfigHardener() )->set_debug_log_path( $target );
	}

	/**
	 * Best-effort confirmation that a web-root file is actually publicly downloadable.
	 * Never load-bearing for a finding's severity — filesystem presence alone is already
	 * actionable — this only upgrades the finding's detail text when it succeeds, and fails
	 * closed (returns null = "unknown") on any error, including the SSRF guard blocking a
	 * loopback host on local/dev installs.
	 */
	private function probe_reachable( string $rel ): ?bool {
		$url = home_url( '/' . ltrim( $rel, '/' ) );
		$res = wp_remote_get( $url, array( 'timeout' => 3, 'redirection' => 0, 'sslverify' => \TotalSecurityWP\Support\Http::local_sslverify() ) );
		if ( is_wp_error( $res ) ) {
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $res );
		return $code >= 200 && $code < 300;
	}
}
