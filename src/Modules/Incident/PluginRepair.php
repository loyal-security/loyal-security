<?php
/**
 * Clean reinstall of WordPress.org-hosted plugins.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Support\Filesystem;

/**
 * Classifies installed plugins into those that can be auto-repaired (hosted on WordPress.org,
 * so a verified clean copy of the installed version can be re-fetched) and those that cannot
 * (premium/custom code) and therefore need a manual reinstall or a per-file fix. Repairing a
 * plugin re-downloads its exact version, backs up the live folder, then swaps the clean code
 * in — which also removes any malware-dropped extra files in the plugin directory.
 */
class PluginRepair {

	private const WPORG_CACHE_TTL = 12 * HOUR_IN_SECONDS;

	private function findings_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_scan_findings';
	}

	/**
	 * Build the plugin inventory for the Repair Center.
	 *
	 * @return array{repairable:array<int,array<string,mixed>>,unrepairable:array<int,array<string,mixed>>}
	 */
	public function inventory(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$provider     = new PackageProvider();
		$repairable   = array();
		$unrepairable = array();

		foreach ( get_plugins() as $file => $data ) {
			$slug    = dirname( $file );
			$version = isset( $data['Version'] ) ? (string) $data['Version'] : '';
			$name    = isset( $data['Name'] ) ? (string) $data['Name'] : $file;

			$issues = $this->find_issues( $slug, $file );
			$entry  = array(
				'slug'     => $slug,
				'file'     => $file,
				'name'     => $name,
				'version'  => $version,
				'active'   => is_plugin_active( $file ),
				'findings' => count( $issues ),
				'issues'   => $issues,
			);

			// Single-file plugins (no own directory) and versionless plugins can't be
			// reliably mapped to a WordPress.org package — treat as manual.
			$on_wporg = '.' !== $slug && '' !== $version && $this->is_on_wporg( $provider, $slug, $version );

			if ( $on_wporg ) {
				$entry['reason'] = '';
				$repairable[]    = $entry;
			} else {
				$entry['reason'] = ( '.' === $slug )
					? __( 'Single-file plugin — reinstall manually.', 'loyal-security' )
					: __( 'Not on WordPress.org (premium/custom) — reinstall manually.', 'loyal-security' );
				$unrepairable[] = $entry;
			}
		}

		return array( 'repairable' => $repairable, 'unrepairable' => $unrepairable );
	}

	/**
	 * Slugs of every installed plugin that can be auto-repaired from WordPress.org. Used by the
	 * bulk-reinstall job so it can enumerate work without rebuilding the full inventory payload.
	 *
	 * @return array<int,string>
	 */
	public function repairable_slugs(): array {
		$slugs = array();
		foreach ( $this->inventory()['repairable'] as $entry ) {
			if ( ! empty( $entry['slug'] ) ) {
				$slugs[] = (string) $entry['slug'];
			}
		}
		return $slugs;
	}

	/**
	 * Reinstall a plugin's clean code for its installed version.
	 *
	 * @param string        $slug     Plugin directory slug.
	 * @param callable|null $progress fn(int $pct, string $message): void — emits plain-language
	 *                                steps (downloading, extracting, …) for the dashboard feed.
	 * @return array{ok:bool,message:string,backup_id?:string,resolved_count?:int}
	 */
	public function repair( string $slug, ?callable $progress = null ): array {
		$say = static function ( int $pct, string $msg ) use ( $progress ): void {
			if ( $progress ) {
				$progress( $pct, $msg );
			}
		};

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$version = '';
		$name    = $slug;
		foreach ( get_plugins() as $file => $data ) {
			if ( dirname( $file ) === $slug ) {
				$version = isset( $data['Version'] ) ? (string) $data['Version'] : '';
				$name    = isset( $data['Name'] ) ? (string) $data['Name'] : $slug;
				break;
			}
		}

		if ( '.' === $slug || '' === $version ) {
			return array( 'ok' => false, 'message' => __( 'This plugin must be reinstalled manually.', 'loyal-security' ) );
		}

		$say( 5, sprintf( /* translators: plugin name */ __( 'Checking “%s” on WordPress.org…', 'loyal-security' ), $name ) );
		$provider = new PackageProvider();
		if ( ! $this->is_on_wporg( $provider, $slug, $version ) ) {
			return array( 'ok' => false, 'message' => __( 'This plugin is not on WordPress.org and must be reinstalled manually.', 'loyal-security' ) );
		}

		$plugin_dir = \LoyalSecurity\Support\Paths::plugin( $slug );
		if ( ! is_dir( $plugin_dir ) ) {
			return array( 'ok' => false, 'message' => __( 'Plugin directory not found.', 'loyal-security' ) );
		}

		// 1) Download + extract the verified-clean copy first; abort before touching the
		//    live folder if anything goes wrong.
		$say( 20, sprintf( /* translators: %1$s: plugin name, %2$s: plugin version. */ __( 'Downloading a clean copy of “%1$s” (v%2$s)…', 'loyal-security' ), $name, $version ) );
		$extracted = $provider->download_and_extract( $provider->plugin_zip_url( $slug, $version ) );
		if ( null === $extracted ) {
			return array( 'ok' => false, 'message' => __( 'Could not download the clean plugin from WordPress.org; nothing changed.', 'loyal-security' ) );
		}
		$say( 45, __( 'Extracting the downloaded package…', 'loyal-security' ) );
		$clean = $provider->inner_dir( $extracted );
		if ( null === $clean ) {
			$provider->cleanup( $extracted );
			return array( 'ok' => false, 'message' => __( 'Downloaded plugin package looked malformed; nothing changed.', 'loyal-security' ) );
		}

		// 2) Back up the current (possibly infected) folder so we can roll back. Prefer moving it
		//    aside (an instant rename on the same volume) over a slow recursive copy — copying a
		//    large plugin like WooCommerce twice is what made this look like it was hanging.
		$say( 60, __( 'Backing up the current files so this can be undone…', 'loyal-security' ) );
		$backups = new RepairBackup();
		$backup  = $backups->backup_tree_move( $plugin_dir, 'plugin:' . $slug );
		$moved   = ( '' !== $backup );
		if ( ! $moved ) {
			// Cross-device or move not permitted — fall back to the (slower) copy backup.
			$backup = $backups->backup_tree( $plugin_dir, 'plugin:' . $slug );
		}
		if ( '' === $backup ) {
			$provider->cleanup( $extracted );
			return array( 'ok' => false, 'message' => __( 'Could not back up the current plugin; aborting for safety.', 'loyal-security' ) );
		}

		// Flag the reinstall as in-flight: if the process is killed mid-swap (e.g. a worker
		// timeout) and the next request fatals, RepairGuard auto-restores this backup. The flag is
		// cleared the moment the swap is confirmed healthy (or rolled back) below.
		$backups->mark_pending( $plugin_dir, $backup, 300 );

		// 3) Install the clean code. If we moved the old folder aside, the live path is now empty,
		//    so move the freshly-extracted copy straight into place (another instant rename);
		//    otherwise empty the live folder and copy clean code in.
		$say( 75, __( 'Installing the clean files…', 'loyal-security' ) );
		$copied = $moved
			? $this->place_clean( $clean, $plugin_dir )
			: ( Filesystem::delete_dir( $plugin_dir, true ) && Filesystem::copy_dir( $clean, $plugin_dir ) );
		$provider->cleanup( $extracted );

		if ( ! $copied ) {
			$backups->restore( $backup );
			$backups->clear_pending( $plugin_dir );
			return array( 'ok' => false, 'message' => __( 'Failed to write clean plugin files; the original was restored from backup.', 'loyal-security' ) );
		}

		// 4) Confirm the site still loads; roll back on failure. The loopback exercises the front
		//    page + login, so a fatal in this plugin OR in another plugin that depends on it (e.g.
		//    a payments add-on that needs WooCommerce) is caught here and reverted.
		$say( 90, __( 'Verifying the site still loads…', 'loyal-security' ) );
		$health = ( new Loopback() )->check();
		if ( ! $health['ok'] ) {
			$backups->restore( $backup );
			$backups->clear_pending( $plugin_dir );
			return array(
				'ok'      => false,
				'fatal'   => true,
				'message' => __( 'The reinstall caused a fatal error on the site, so the previous version was automatically restored from backup. Nothing was left broken.', 'loyal-security' ),
			);
		}

		// Swap confirmed healthy — stop the fatal-error watchdog from second-guessing it.
		$backups->clear_pending( $plugin_dir );

		// 5) Resolve related findings.
		$resolved_count = $this->resolve_findings( $slug );

		$say( 100, sprintf( /* translators: plugin name */ __( 'Reinstalled clean copy of “%s”.', 'loyal-security' ), $name ) );

		return array(
			'ok'             => true,
			'message'        => sprintf( /* translators: plugin slug */ __( 'Reinstalled clean copy of "%s".', 'loyal-security' ), $slug ),
			'backup_id'      => $backup,
			'resolved_count' => $resolved_count,
		);
	}

	/**
	 * Put the freshly-extracted clean copy at $plugin_dir. Tries an instant rename first (the
	 * extracted tree lives under the same storage volume), falling back to a recursive copy if
	 * the move isn't possible. The caller guarantees $plugin_dir was moved aside first.
	 */
	private function place_clean( string $clean, string $plugin_dir ): bool {
		// Target must not exist for a rename; it shouldn't (it was moved aside), but be safe.
		if ( is_dir( $plugin_dir ) ) {
			Filesystem::delete_dir( $plugin_dir, false );
		}
		if ( Filesystem::move( $clean, $plugin_dir ) ) {
			return true;
		}
		// Cross-device fallback.
		wp_mkdir_p( $plugin_dir );
		return Filesystem::copy_dir( $clean, $plugin_dir );
	}

	/**
	 * Cached WordPress.org availability check (the API call is relatively expensive).
	 */
	private function is_on_wporg( PackageProvider $provider, string $slug, string $version ): bool {
		$key    = 'loyalsec_wporg_' . md5( $slug . '|' . $version );
		$cached = get_transient( $key );
		if ( '1' === $cached ) {
			return true;
		}
		if ( '0' === $cached ) {
			return false;
		}
		$on = $provider->plugin_on_wporg( $slug, $version );
		set_transient( $key, $on ? '1' : '0', self::WPORG_CACHE_TTL );
		return $on;
	}

	/**
	 * Open findings that fall under a plugin (scanner uses absolute paths; integrity uses
	 * "slug/file" — match either), capped for the UI.
	 *
	 * @return array<int,array{id:int,path:string,rule:string}>
	 */
	private function find_issues( string $slug, string $file ): array {
		global $wpdb;
		$abs  = wp_normalize_path( \LoyalSecurity\Support\Paths::plugins() . '/' . ( '.' === $slug ? $file : $slug ) );
		$like = ( '.' === $slug ) ? '%' . $wpdb->esc_like( $file ) : '%' . $wpdb->esc_like( $slug . '/' ) . '%';
		// Stored paths can use OS-native separators (backslashes on Windows); normalise the
		// column to forward slashes so matching is platform-independent.
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"SELECT id, path, rule FROM %i WHERE status = 'open' AND ( REPLACE( path, '\\\\', '/' ) LIKE %s OR REPLACE( path, '\\\\', '/' ) LIKE %s ) ORDER BY severity DESC, id DESC LIMIT 25", $this->findings_table(),
				$wpdb->esc_like( $abs ) . '%',
				$like
			),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			return array();
		}
		return array_map(
			static function ( $r ) {
				return array(
					'id'   => (int) $r['id'],
					'path' => (string) $r['path'],
					'rule' => (string) $r['rule'],
				);
			},
			$rows
		);
	}

	/**
	 * Mark a repaired plugin's open findings as resolved.
	 *
	 * @return int Number of finding rows resolved by this call — the caller (CleanupOrchestrator)
	 *             needs this because this single bulk UPDATE can resolve many rows at once
	 *             (every open finding under the plugin's directory), not just the one finding
	 *             that triggered the reinstall.
	 */
	private function resolve_findings( string $slug ): int {
		global $wpdb;
		$abs  = wp_normalize_path( \LoyalSecurity\Support\Paths::plugin( $slug ) );
		return (int) $wpdb->query( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name built from $wpdb->prefix, not user input.
			$wpdb->prepare(
				"UPDATE %i SET status = 'resolved' WHERE status = 'open' AND ( REPLACE( path, '\\\\', '/' ) LIKE %s OR REPLACE( path, '\\\\', '/' ) LIKE %s )", $this->findings_table(),
				$wpdb->esc_like( $abs ) . '%',
				'%' . $wpdb->esc_like( $slug . '/' ) . '%'
			)
		);
	}
}
