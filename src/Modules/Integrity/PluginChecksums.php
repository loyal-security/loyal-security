<?php
/**
 * Plugin file integrity verification via the WordPress.org checksum API.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Integrity;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Support\Http;

/**
 * Verifies installed plugins hosted on WordPress.org against published per-file checksums.
 * Plugins not on WordPress.org (premium/custom — Loyal Security Pro included) can't be
 * checked that way, but "we can't verify it against WordPress.org" must never mean "we don't
 * watch it at all": that's exactly where a malicious or tampered plugin would hide, since it's
 * already outside the one trust source most integrity tooling relies on. Each unverifiable
 * plugin instead falls back to the same custom {@see Baseline} drift-detection themes use — an
 * operator-initiated snapshot, then drift-from-that-snapshot on every later run.
 */
class PluginChecksums {

	private const API = 'https://downloads.wordpress.org/plugin-checksums/';

	private Baseline $baseline;

	public function __construct( ?Baseline $baseline = null ) {
		$this->baseline = $baseline ?? new Baseline();
	}

	/** Cache lifetime for the per-plugin flattened hash list (see {@see official_hash_set()}). */
	private const HASHSET_CACHE_TTL = 6 * HOUR_IN_SECONDS;

	/**
	 * Cache lifetime when a fetch comes back empty. An empty result means either "not hosted
	 * on WordPress.org" (permanently empty, harmless to re-ask) or a transient API/network
	 * failure — and the two are indistinguishable here. Caching a failure for the full 6 hours
	 * blinds the scanner's trust allowlist for that whole window, which is exactly how
	 * heuristic false positives on unmodified vendor code (e.g. WooCommerce) get persisted:
	 * one timeout on a large checksum file and every scan batch for the next 6 hours runs
	 * without that plugin's hashes. Kept short so the allowlist heals on the next batch.
	 */
	private const HASHSET_EMPTY_TTL = 15 * MINUTE_IN_SECONDS;

	/**
	 * Verify every active/installed plugin.
	 *
	 * @return array{verified:int,unverifiable:array<int,array{slug:string,has_baseline:bool,modified:string[],added:string[],deleted:string[]}>,modified:array<int,array{slug:string,file:string}>}
	 */
	public function verify_all(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$verified      = 0;
		$unverifiable  = array();
		$modified      = array();

		foreach ( get_plugins() as $file => $data ) {
			$slug    = dirname( $file );
			$version = isset( $data['Version'] ) ? (string) $data['Version'] : '';
			if ( '.' === $slug || '' === $version ) {
				$unverifiable[] = $this->baseline_diff( $file );
				continue;
			}

			$result = $this->verify_plugin( $slug, $version );
			if ( null === $result ) {
				$unverifiable[] = $this->baseline_diff( $file );
				continue;
			}
			$verified++;
			foreach ( $result as $bad ) {
				$modified[] = array( 'slug' => $slug, 'file' => $bad );
			}
		}

		return array(
			'verified'     => $verified,
			'unverifiable' => $unverifiable,
			'modified'     => $modified,
		);
	}

	/**
	 * Snapshot the custom baseline for every currently-unverifiable plugin (operator-initiated,
	 * alongside the theme/mu-plugin/drop-in snapshot). Re-derives the unverifiable set itself
	 * rather than accepting one from the caller — a plugin's WordPress.org status can only be
	 * known by attempting the same checksum lookup {@see verify_all()} does.
	 *
	 * @return int Total files recorded.
	 */
	public function snapshot_unverifiable(): int {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$total = 0;
		foreach ( get_plugins() as $file => $data ) {
			$slug    = dirname( $file );
			$version = isset( $data['Version'] ) ? (string) $data['Version'] : '';
			if ( '.' === $slug || '' === $version || null === $this->verify_plugin( $slug, $version ) ) {
				$total += $this->baseline_snapshot( $file );
			}
		}
		return $total;
	}

	/**
	 * A plugin's baseline source key and root: directory-based for a normal `slug/main.php`
	 * plugin, single-file for the rarer case of a bare `.php` file dropped directly into
	 * `wp-content/plugins/` (dirname() there is `.`, so it can't share a source key with
	 * anything else — the plugin file's own basename is used instead).
	 *
	 * @return array{0:string,1:string,2:bool} [ source key, base dir, is_dir_based ]
	 */
	private function baseline_target( string $file ): array {
		$slug = dirname( $file );
		if ( '.' === $slug ) {
			return array( 'plugin:' . basename( $file ), trailingslashit( \LoyalSecurity\Support\Paths::plugins() ), false );
		}
		return array( 'plugin:' . $slug, \LoyalSecurity\Support\Paths::plugin( $slug ), true );
	}

	/**
	 * Re-take a plugin's baseline after WordPress itself updated it, if it has one.
	 *
	 * @param string $file Plugin file, e.g. "my-plugin/my-plugin.php".
	 * @return int Files recorded (0 when the plugin had no baseline).
	 */
	public function refresh_baseline( string $file ): int {
		[ $source ] = $this->baseline_target( $file );
		return $this->baseline->has( $source ) ? $this->baseline_snapshot( $file ) : 0;
	}

	private function baseline_snapshot( string $file ): int {
		[ $source, $root, $is_dir ] = $this->baseline_target( $file );
		return $is_dir
			? $this->baseline->snapshot( $source, $root )
			: $this->baseline->snapshot_files( $source, $root, array( basename( $file ) ) );
	}

	/**
	 * @return array{slug:string,has_baseline:bool,modified:string[],added:string[],deleted:string[]}
	 */
	private function baseline_diff( string $file ): array {
		[ $source, $root, $is_dir ] = $this->baseline_target( $file );
		$diff         = $is_dir
			? $this->baseline->diff( $source, $root )
			: $this->baseline->diff_files( $source, $root, array( basename( $file ) ) );
		$diff['slug'] = dirname( $file ) === '.' ? basename( $file ) : dirname( $file );
		return $diff;
	}

	/**
	 * Verify one plugin against WordPress.org checksums.
	 *
	 * @return string[]|null List of modified files, or null if unverifiable.
	 */
	public function verify_plugin( string $slug, string $version ): ?array {
		$url  = self::API . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$data = Http::get_json( $url );

		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return null; // Not on WordPress.org (premium/custom) or no data.
		}

		$plugin_dir = \LoyalSecurity\Support\Paths::plugin( $slug );
		$modified   = array();

		foreach ( $data['files'] as $rel => $hashes ) {
			$path = $plugin_dir . '/' . $rel;
			if ( ! file_exists( $path ) ) {
				continue; // Missing optional file — skip.
			}
			$expected_sha = isset( $hashes['sha256'] ) ? (array) $hashes['sha256'] : array();
			$expected_md5 = isset( $hashes['md5'] ) ? (array) $hashes['md5'] : array();

			if ( $expected_sha ) {
				$actual = hash_file( 'sha256', $path );
				if ( ! in_array( $actual, $expected_sha, true ) ) {
					$modified[] = $rel;
				}
			} elseif ( $expected_md5 ) {
				$actual = md5_file( $path );
				if ( ! in_array( $actual, $expected_md5, true ) ) {
					$modified[] = $rel;
				}
			}
		}

		return $modified;
	}

	/**
	 * Flattened set of every official WordPress.org sha256 file hash for every installed,
	 * WordPress.org-hosted plugin at its currently-installed version — content-addressed (by
	 * hash, not path), so it can be handed straight to {@see \LoyalSecurity\Modules\Scanner\HeuristicScanner}'s
	 * `$allow_hashes` allowlist to trust any file whose content provably matches an official
	 * release, regardless of where it lives. Cached per slug+version (so an upgrade invalidates
	 * automatically) to avoid hitting the WordPress.org checksum API on every scan batch.
	 *
	 * @return array<string, bool> sha256 (lowercase hex) => true
	 */
	public function official_hash_set(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$hashes = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug    = dirname( $file );
			$version = isset( $data['Version'] ) ? (string) $data['Version'] : '';
			if ( '.' === $slug || '' === $version ) {
				continue;
			}

			foreach ( $this->hash_list_for( $slug, $version ) as $hash ) {
				$hashes[ $hash ] = true;
			}
		}

		return $hashes;
	}

	/**
	 * Official sha256 hash list for one plugin at one version, transient-cached. Shared by
	 * {@see official_hash_set()} (all plugins, for the scanner allowlist) and
	 * {@see \LoyalSecurity\Modules\Firewall\PatchSuggester} (single slug, to recognise a
	 * pristine official file before drafting a virtual-patch suggestion against it).
	 * Non-empty lists cache for {@see HASHSET_CACHE_TTL}; empty ones (not on WordPress.org,
	 * or a fetch failure) only for {@see HASHSET_EMPTY_TTL} — see that constant for why.
	 *
	 * @return string[] Lowercase sha256 hex hashes ([] when unverifiable).
	 */
	public function hash_list_for( string $slug, string $version ): array {
		$key    = 'loyalsec_officialhashes_' . md5( $slug . '|' . $version );
		$cached = get_transient( $key );
		if ( ! is_array( $cached ) ) {
			$cached = $this->fetch_hash_list( $slug, $version );
			set_transient( $key, $cached, $cached ? self::HASHSET_CACHE_TTL : self::HASHSET_EMPTY_TTL );
		}
		return $cached;
	}

	/**
	 * Fetch and flatten every file's sha256 hash(es) for one plugin/version from the
	 * WordPress.org checksums API. Returns an empty array when the plugin isn't on
	 * WordPress.org or the API has no data (cached by {@see hash_list_for()}).
	 *
	 * @return string[]
	 */
	private function fetch_hash_list( string $slug, string $version ): array {
		$url  = self::API . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$data = Http::get_json( $url );

		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return array();
		}

		$out = array();
		foreach ( $data['files'] as $file_hashes ) {
			foreach ( (array) ( $file_hashes['sha256'] ?? array() ) as $hash ) {
				$out[] = strtolower( (string) $hash );
			}
		}
		return $out;
	}
}
