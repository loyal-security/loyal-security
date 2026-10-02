<?php
/**
 * Fatal-error safety net for in-flight file fixes.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Modules\Audit\EventCatalog;

/**
 * A {@see FileFix} or plugin reinstall verifies its work with a loopback request, but that only
 * exercises the front page and login screen. This guard closes the gap: while a repair is still
 * inside its grace window, it watches for a fatal error related to the repaired file/folder on
 * *any* request and restores the backup automatically, so a route-specific (or
 * dependent-plugin) break self-heals. Once the grace window lapses without incident the pending
 * entry is pruned and the repair becomes permanent. When it does roll back, it records an audit
 * event (routed to the admin's notification channels) and a dismissible admin-notice flag.
 */
class RepairGuard {

	private const FATAL = array( E_ERROR, E_PARSE, E_COMPILE_ERROR, E_CORE_ERROR, E_USER_ERROR );

	/** Persisted so the dashboard / admin notice can tell the admin a repair was auto-reverted. */
	public const NOTICE_OPTION = 'totalsecwp_autorollback_notice';

	/** Registered at most once per request (the guard can be armed early *and* at plugins_loaded). */
	private static bool $armed = false;

	private ?Logger $logger;

	public function __construct( ?Logger $logger = null ) {
		$this->logger = $logger;
	}

	/**
	 * Arm the guard for this request if any repair is pending. Cheap no-op otherwise. Safe to call
	 * multiple times — only the first registration sticks.
	 */
	public function arm(): void {
		if ( self::$armed ) {
			return;
		}
		$pending = ( new RepairBackup() )->pending();
		if ( empty( $pending ) ) {
			return;
		}
		self::$armed = true;
		register_shutdown_function( array( $this, 'on_shutdown' ) );
	}

	/**
	 * On request shutdown: roll back a pending fix whose file just fataled, and prune fixes
	 * that have safely outlived their grace window.
	 */
	public function on_shutdown(): void {
		// The guard itself must never be the thing that breaks the site.
		try {
			$this->run_shutdown();
		} catch ( \Throwable $e ) {
			// Swallow — a recovery attempt must not cascade into another fatal.
			return;
		}
	}

	private function run_shutdown(): void {
		$backups = new RepairBackup();
		$pending = $backups->pending();
		if ( empty( $pending ) ) {
			return;
		}

		$err   = error_get_last();
		$fatal = is_array( $err ) && in_array( (int) $err['type'], self::FATAL, true );
		$file  = ( $fatal && isset( $err['file'] ) ) ? wp_normalize_path( (string) $err['file'] ) : '';
		$msg   = ( $fatal && isset( $err['message'] ) ) ? (string) $err['message'] : '';
		$now   = time();

		$changed = false;
		foreach ( $pending as $path => $entry ) {
			$backup = is_array( $entry ) ? (string) ( $entry['backup'] ?? '' ) : '';
			$until  = is_array( $entry ) ? (int) ( $entry['until'] ?? 0 ) : 0;

			// Blame this repair when a fatal points at the repaired file/folder directly, OR the
			// error message mentions it — the latter catches a *dependent* plugin fataling because
			// the file it needs from the repaired folder is now missing (e.g. a WooCommerce add-on
			// breaking after a WooCommerce reinstall references "…/plugins/woocommerce/…").
			$blamed = $fatal && '' !== $path && (
				( '' !== $file && ( $file === $path || 0 === strpos( $file, rtrim( $path, '/' ) . '/' ) ) ) ||
				false !== strpos( $msg, $path )
			);

			if ( $blamed ) {
				$restored = false;
				if ( '' !== $backup ) {
					$res      = $backups->restore( $backup );
					$restored = ! empty( $res['ok'] );
				}
				unset( $pending[ $path ] );
				$changed = true;
				$this->announce_rollback( $path, $msg, $restored );
				continue;
			}

			// Repair has proven stable — stop watching it.
			if ( $until > 0 && $until < $now ) {
				unset( $pending[ $path ] );
				$changed = true;
			}
		}

		if ( $changed ) {
			$backups->save_pending( $pending );
		}
	}

	/**
	 * Record an auto-rollback so the admin is told what happened — via the audit log (which the
	 * Notifications module routes to email/webhook) and a dismissible admin-notice flag.
	 */
	private function announce_rollback( string $path, string $error, bool $restored ): void {
		update_option(
			self::NOTICE_OPTION,
			array(
				'path'     => $path,
				'error'    => mb_substr( $error, 0, 300 ),
				'restored' => $restored,
				'at'       => gmdate( 'Y-m-d H:i:s' ),
			),
			false
		);

		$logger = $this->logger ?: $this->resolve_logger();
		if ( $logger ) {
			$logger->log(
				EventCatalog::REPAIR_AUTO_ROLLED_BACK,
				array(
					'path'     => $path,
					'error'    => mb_substr( $error, 0, 300 ),
					'restored' => $restored,
				)
			);
		}
	}

	/**
	 * Best-effort logger lookup for the early-bootstrap arm, which has no injected logger. By
	 * shutdown the container is built, so the audit/notification path is usually available.
	 */
	private function resolve_logger(): ?Logger {
		try {
			$logger = \TotalSecurityWP\Plugin::instance()->container()->make( 'logger' );
			return $logger instanceof Logger ? $logger : null;
		} catch ( \Throwable $e ) {
			return null;
		}
	}
}
