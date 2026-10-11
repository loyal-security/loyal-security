<?php
/**
 * One-time IP allow/block list migration from other security plugins.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;
use LoyalSecurity\Support\Ip;

/**
 * Switching security plugins is the single biggest thing that keeps an unhappy admin on a
 * plugin they don't like — nobody wants to manually retype a hand-curated IP block list. This
 * reads the most stable, well-documented storage locations Wordfence, Sucuri, and iThemes
 * Security use for IP allow/block lists (never their scan history, settings, or anything more
 * fragile than that) and merges what it finds into this plugin's own ban list / whitelist.
 *
 * Deliberately defensive: each source is read independently, wrapped so one plugin's storage
 * shape changing (or not being installed at all) never breaks detection of the others. Every
 * import is additive and reported back in full — nothing already in this plugin's lists is
 * ever removed or overwritten, and the admin sees exactly what was found before it's applied.
 */
class CompetitorImporter {

	private Settings $settings;
	private BanStore $bans;

	public function __construct( ?Settings $settings = null, ?BanStore $bans = null ) {
		// A bare `new Settings()` wouldn't have per-module defaults registered (that happens once,
		// at boot, on the container's shared instance) — pull the real shared instance instead.
		$this->settings = $settings ?? \LoyalSecurity\Plugin::instance()->container()->make( 'settings' );
		$this->bans     = $bans ?? new BanStore();
	}

	/**
	 * Which supported competitor plugins have detectable data on this site right now — shown
	 * before import so the admin knows what will actually be scanned, not a fixed list of three
	 * regardless of what's actually installed.
	 *
	 * @return array<string, array{name:string, detected:bool}>
	 */
	public function detect(): array {
		return array(
			'wordfence' => array( 'name' => 'Wordfence', 'detected' => $this->wordfence_present() ),
			'sucuri'    => array( 'name' => 'Sucuri Security', 'detected' => $this->sucuri_present() ),
			'ithemes'   => array( 'name' => 'iThemes / Solid Security', 'detected' => $this->ithemes_present() ),
		);
	}

	/**
	 * Read every source, merge into this plugin's ban list + IP whitelist, and report exactly
	 * what was found and applied per source.
	 *
	 * @return array<string, array{found:int, imported:int, whitelisted:int, error:?string}>
	 */
	public function import(): array {
		$report = array();
		foreach ( array( 'wordfence', 'sucuri', 'ithemes' ) as $slug ) {
			$report[ $slug ] = $this->import_source( $slug );
		}
		return $report;
	}

	/**
	 * @return array{found:int, imported:int, whitelisted:int, error:?string}
	 */
	private function import_source( string $slug ): array {
		$result = array( 'found' => 0, 'imported' => 0, 'whitelisted' => 0, 'error' => null );
		try {
			$data = $this->read_source( $slug );
		} catch ( \Throwable $e ) {
			$result['error'] = $e->getMessage();
			return $result;
		}

		$result['found'] = count( $data['blocked'] ) + count( $data['whitelisted'] );

		foreach ( array_unique( $data['blocked'] ) as $ip ) {
			if ( ! Ip::is_valid( $ip ) ) {
				continue;
			}
			if ( $this->bans->add( $ip, 'Imported from ' . $this->label( $slug ), 'permanent', null, 'imported' ) ) {
				++$result['imported'];
			}
		}

		if ( ! empty( $data['whitelisted'] ) ) {
			$current = (array) $this->settings->get( 'firewall', 'ip_whitelist', array() );
			$merged  = $current;
			foreach ( array_unique( $data['whitelisted'] ) as $ip ) {
				if ( Ip::is_valid( $ip ) && ! in_array( $ip, $merged, true ) ) {
					$merged[]                = $ip;
					++$result['whitelisted'];
				}
			}
			if ( $result['whitelisted'] > 0 ) {
				$this->settings->update_module( 'firewall', array( 'ip_whitelist' => array_values( $merged ) ) );
			}
		}

		return $result;
	}

	private function label( string $slug ): string {
		$labels = array( 'wordfence' => 'Wordfence', 'sucuri' => 'Sucuri Security', 'ithemes' => 'iThemes/Solid Security' );
		return $labels[ $slug ] ?? $slug;
	}

	/**
	 * @return array{blocked: array<int,string>, whitelisted: array<int,string>}
	 */
	private function read_source( string $slug ): array {
		switch ( $slug ) {
			case 'wordfence':
				return $this->read_wordfence();
			case 'sucuri':
				return $this->read_sucuri();
			case 'ithemes':
				return $this->read_ithemes();
			default:
				return array( 'blocked' => array(), 'whitelisted' => array() );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Wordfence                                                             */
	/* ------------------------------------------------------------------ */

	private function wordfence_present(): bool {
		if ( defined( 'WORDFENCE_VERSION' ) || false !== get_option( 'wordfence_wfLocked_options', false ) || false !== get_option( 'wordfence_globalOptions', false ) ) {
			return true;
		}
		// Also true whenever any of the exact options read_wordfence() reads actually has data —
		// otherwise a real install using only one of these (Wordfence's option names have shifted
		// across major versions) could have real importable data with detect() never saying so,
		// leaving the admin with no way to know the import button would do anything.
		foreach ( array( 'wordfence_wfBlockedIPs', 'wordfence_wfIPBlocksSaved', 'wordfence_blockedIPs', 'wordfence_whitelisted', 'wordfence_wfWAFIPWhitelist', 'wordfence_neverBlockIP' ) as $opt ) {
			if ( '' !== trim( (string) get_option( $opt, '' ) ) || is_array( get_option( $opt, null ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Wordfence keeps its manually-blocked-IP list in the `wordfence_wfLockedIPRanges` /
	 * `wordfence_wfBlockedIPs` style options (naming has shifted across major versions), and its
	 * "never block" allowlist in `wordfence_whitelisted`. All three are read defensively — a
	 * missing or differently-shaped option on a given Wordfence version yields an empty result
	 * for that one, not a fatal error.
	 *
	 * @return array{blocked: array<int,string>, whitelisted: array<int,string>}
	 */
	private function read_wordfence(): array {
		$blocked    = array();
		$whitelisted = array();

		foreach ( array( 'wordfence_wfBlockedIPs', 'wordfence_wfIPBlocksSaved', 'wordfence_blockedIPs' ) as $opt ) {
			$blocked = array_merge( $blocked, $this->extract_ips( get_option( $opt, '' ) ) );
		}
		foreach ( array( 'wordfence_whitelisted', 'wordfence_wfWAFIPWhitelist', 'wordfence_neverBlockIP' ) as $opt ) {
			$whitelisted = array_merge( $whitelisted, $this->extract_ips( get_option( $opt, '' ) ) );
		}

		return array( 'blocked' => $blocked, 'whitelisted' => $whitelisted );
	}

	/* ------------------------------------------------------------------ */
	/* Sucuri                                                                */
	/* ------------------------------------------------------------------ */

	private function sucuri_present(): bool {
		return defined( 'SUCURISCAN_VERSION' ) || false !== get_option( 'sucuriscan_bruteforce_whitelist', false ) || false !== get_option( 'sucuriscan_ignored_events', false );
	}

	/**
	 * Sucuri's own firewall is cloud-based (CloudProxy) rather than storing a local IP block
	 * list, so the only stable local data worth migrating is its brute-force IP allowlist.
	 *
	 * @return array{blocked: array<int,string>, whitelisted: array<int,string>}
	 */
	private function read_sucuri(): array {
		$whitelisted = $this->extract_ips( get_option( 'sucuriscan_bruteforce_whitelist', '' ) );
		return array( 'blocked' => array(), 'whitelisted' => $whitelisted );
	}

	/* ------------------------------------------------------------------ */
	/* iThemes / Solid Security                                              */
	/* ------------------------------------------------------------------ */

	private function ithemes_present(): bool {
		return defined( 'ITSEC_VERSION' ) || false !== get_option( 'itsec_storage', false ) || false !== get_option( 'itsec_global', false );
	}

	/**
	 * iThemes stores most module settings inside one serialized `itsec_storage` option, keyed
	 * per-module — the allowlist lives under `global.white_list`, and locked-out IPs under the
	 * `lockout_white_list`/`lockouts` shape used by different plugin versions. Both are read
	 * from whatever's actually present rather than assuming one exact structure.
	 *
	 * @return array{blocked: array<int,string>, whitelisted: array<int,string>}
	 */
	private function read_ithemes(): array {
		$whitelisted = array();
		$blocked     = array();

		$storage = get_option( 'itsec_storage', array() );
		if ( is_array( $storage ) ) {
			$global = $storage['global'] ?? array();
			if ( is_array( $global ) ) {
				$whitelisted = array_merge(
					$whitelisted,
					$this->extract_ips( $global['white_list'] ?? '' ),
					$this->extract_ips( $global['lockout_white_list'] ?? '' )
				);
			}
		}

		// Older/alternate installs keep the same shape under a flat `itsec_global` option.
		$global_flat = get_option( 'itsec_global', array() );
		if ( is_array( $global_flat ) ) {
			$whitelisted = array_merge(
				$whitelisted,
				$this->extract_ips( $global_flat['white_list'] ?? '' ),
				$this->extract_ips( $global_flat['lockout_white_list'] ?? '' )
			);
		}

		global $wpdb;
		$table = $wpdb->prefix . 'itsec_lockouts';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name is a fixed, well-known third-party plugin table (iThemes Security), not user input; existence is checked before querying, and this whole read is wrapped by the caller's try/catch since the table's presence and shape are outside our control.
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $table verified to exist and be this exact fixed name immediately above; not user input, so there's nothing here for $wpdb->prepare() to protect against.
			$rows = $wpdb->get_col( $wpdb->prepare( "SELECT lockout_host FROM %i WHERE lockout_active = 1 AND lockout_host IS NOT NULL", $table ) );
			foreach ( (array) $rows as $host ) {
				if ( Ip::is_valid( (string) $host ) ) {
					$blocked[] = (string) $host;
				}
			}
		}

		return array( 'blocked' => $blocked, 'whitelisted' => $whitelisted );
	}

	/* ------------------------------------------------------------------ */
	/* Shared helpers                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Pull IPv4/IPv6 addresses out of whatever shape a competitor plugin's option happens to be
	 * in — a newline/comma-separated string, or a nested array of strings — without assuming a
	 * single fixed format. Anything that isn't a syntactically valid IP is dropped by the caller
	 * via Ip::is_valid(), so a stray label or comment in a text-area option is harmless.
	 *
	 * @param mixed $raw
	 * @return array<int,string>
	 */
	private function extract_ips( $raw ): array {
		if ( is_array( $raw ) ) {
			$out = array();
			array_walk_recursive( $raw, static function ( $v ) use ( &$out ) {
				if ( is_string( $v ) ) {
					$out[] = trim( $v );
				}
			} );
			return $out;
		}
		if ( ! is_string( $raw ) || '' === trim( $raw ) ) {
			return array();
		}
		return array_map( 'trim', preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY ) ?: array() );
	}
}
