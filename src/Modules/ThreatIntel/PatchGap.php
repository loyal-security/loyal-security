<?php
/**
 * Patch-gap intelligence — maps early-virtual-patch rules to installed plugins.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\ThreatIntel;

defined( 'ABSPATH' ) || exit;

/**
 * Consumer side of LicenseKit's "patch-gap intelligence" pipeline.
 *
 * When a plugin ships a security fix, LicenseKit analyses the update diff and publishes a
 * virtual-patch rule tagged `source: patch_gap` through the existing signed `patches` feed.
 * Those rules are already *enforced* by {@see \TotalSecurityWP\Waf\VirtualPatch} (which honours
 * `slug` + `max_version`, in both Standard Mode and the Optimized-Mode prepend). This class
 * provides the *visibility* layer: it reads the cached patch feed, keeps only patch-gap rules,
 * and reports which of the site's installed
 * plugins are currently shielded by one — powering the dashboard card, the firewall badge, and
 * the "you're protected, update when you can" notification.
 *
 * It never enforces anything and has no side effects, so it is safe to call on any request.
 */
class PatchGap {

	/**
	 * Patch-gap coverage for plugins that are installed *and* still within the vulnerable
	 * version window (i.e. the operator has not yet applied the real fix).
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function active_for_installed(): array {
		$rules = $this->patch_gap_rules();
		if ( empty( $rules ) ) {
			return array();
		}

		$installed = $this->installed_plugins();
		$out       = array();

		foreach ( $rules as $rule ) {
			$slug = (string) ( $rule['slug'] ?? '' );
			if ( '' === $slug || ! isset( $installed[ $slug ] ) ) {
				continue;
			}
			$version = $installed[ $slug ]['version'];
			if ( ! $this->is_vulnerable( $version, $rule ) ) {
				continue; // Already updated past the patch — no longer in the gap.
			}

			$out[] = array(
				'rule_id'            => (string) ( $rule['id'] ?? '' ),
				'slug'               => $slug,
				'name'               => $installed[ $slug ]['name'],
				'installed_version'  => $version,
				'version_from'       => (string) ( $rule['plugin_version_from'] ?? '' ),
				'version_to'         => (string) ( $rule['plugin_version_to'] ?? $rule['max_version'] ?? '' ),
				'confidence'         => isset( $rule['confidence'] ) ? (float) $rule['confidence'] : null,
				'vulnerability_type' => (string) ( $rule['vulnerability_type'] ?? '' ),
				'summary'            => (string) ( $rule['summary'] ?? $rule['desc'] ?? '' ),
				'detected_at'        => (string) ( $rule['detected_at'] ?? '' ),
				'cve_id'             => (string) ( $rule['cve_id'] ?? '' ),
			);
		}

		return $out;
	}

	/**
	 * Compact summary for status endpoints.
	 *
	 * @return array{count:int,items:array<int,array<string,mixed>>}
	 */
	public function summary(): array {
		$items = $this->active_for_installed();
		return array(
			'count' => count( $items ),
			'items' => $items,
		);
	}

	/**
	 * Whether an installed version still sits inside the rule's vulnerable window.
	 *
	 * Prefers `plugin_version_to` (the version that contains the fix): anything below it is
	 * unpatched. Falls back to the WAF engine's `max_version` (last vulnerable version), then
	 * treats the rule as always-applicable if neither bound is given.
	 *
	 * @param string               $installed Installed plugin version.
	 * @param array<string, mixed> $rule      Patch-gap rule.
	 */
	private function is_vulnerable( string $installed, array $rule ): bool {
		$fixed_in = (string) ( $rule['plugin_version_to'] ?? '' );
		if ( '' !== $fixed_in ) {
			return version_compare( $installed, $fixed_in, '<' );
		}
		$max = (string) ( $rule['max_version'] ?? '' );
		if ( '' !== $max ) {
			return version_compare( $installed, $max, '<=' );
		}
		return true;
	}

	/**
	 * Patch-gap rules from the cached (verified) `patches` feed dataset.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function patch_gap_rules(): array {
		$rules = array();
		try {
			if ( class_exists( FeedStore::class ) ) {
				$remote = ( new FeedStore() )->get_rules( 'patches' );
				if ( is_array( $remote ) ) {
					$rules = $remote;
				}
			}
		} catch ( \Throwable $e ) {
			return array();
		}

		$gap = array();
		foreach ( $rules as $rule ) {
			if ( is_array( $rule ) && 'patch_gap' === (string) ( $rule['source'] ?? '' ) ) {
				$gap[] = $rule;
			}
		}
		return $gap;
	}

	/**
	 * Map of installed plugin slug => { version, name }.
	 *
	 * @return array<string, array{version:string,name:string}>
	 */
	private function installed_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$map = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug         = dirname( $file );
			$slug         = ( '.' === $slug ) ? basename( $file, '.php' ) : $slug;
			$map[ $slug ] = array(
				'version' => isset( $data['Version'] ) ? (string) $data['Version'] : '0',
				'name'    => isset( $data['Name'] ) ? (string) $data['Name'] : $slug,
			);
		}
		return $map;
	}
}
