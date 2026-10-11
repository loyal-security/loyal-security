<?php
/**
 * Groups open findings into one-click repair actions.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Incident;

defined( 'ABSPATH' ) || exit;

/**
 * Maps the scanner/integrity findings onto the repair tools so the operator can remediate by
 * intent instead of file by file: everything under the WordPress core directories collapses
 * into a single "reinstall core" action, files belonging to a WordPress.org plugin collapse
 * into a per-plugin "reinstall" action, and anything else (premium/custom/theme code) is left
 * for the conservative per-file fix. Database findings carry no file to repair.
 */
class FindingTriage {

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_scan_findings';
	}

	/**
	 * Build the triage groups for all open findings.
	 *
	 * @return array{
	 *   core:array{count:int,ids:int[]},
	 *   plugins:array<int,array{slug:string,name:string,version:string,on_wporg:bool,count:int,ids:int[]}>,
	 *   covered_ids:int[]
	 * }
	 */
	public function build(): array {
		global $wpdb;
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT id, path FROM %i WHERE status = 'open' ORDER BY severity DESC, id DESC LIMIT 500", $this->table() ),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			$rows = array();
		}

		$pmap    = $this->plugin_map();
		$core    = array( 'count' => 0, 'ids' => array() );
		$plugins = array();
		$covered = array();

		foreach ( $rows as $r ) {
			$id  = (int) $r['id'];
			$cls = $this->classify( (string) $r['path'], array_keys( $pmap ) );

			if ( 'core' === $cls['kind'] ) {
				$core['count']++;
				$core['ids'][] = $id;
				$covered[]     = $id;
				continue;
			}

			if ( 'plugin' === $cls['kind'] ) {
				$slug = $cls['slug'];
				if ( ! isset( $plugins[ $slug ] ) ) {
					$meta              = $pmap[ $slug ] ?? array( 'name' => $slug, 'version' => '', 'on_wporg' => false );
					$plugins[ $slug ]  = array(
						'slug'     => $slug,
						'name'     => $meta['name'],
						'version'  => $meta['version'],
						'on_wporg' => (bool) $meta['on_wporg'],
						'count'    => 0,
						'ids'      => array(),
					);
				}
				$plugins[ $slug ]['count']++;
				$plugins[ $slug ]['ids'][] = $id;
				if ( ! empty( $plugins[ $slug ]['on_wporg'] ) ) {
					$covered[] = $id; // Reinstall handles every file under it.
				}
			}
			// Themes / custom / mu-plugins / database findings are left to per-file fix.
		}

		return array(
			'core'        => $core,
			'plugins'     => array_values( $plugins ),
			'covered_ids' => array_values( array_unique( $covered ) ),
		);
	}

	/**
	 * Installed-plugin metadata keyed by slug, reusing the repair inventory (which already
	 * resolves WordPress.org availability, cached).
	 *
	 * @return array<string,array{name:string,version:string,on_wporg:bool}>
	 */
	private function plugin_map(): array {
		$inv = ( new PluginRepair() )->inventory();
		$map = array();
		foreach ( array( 'repairable' => true, 'unrepairable' => false ) as $bucket => $on_wporg ) {
			foreach ( $inv[ $bucket ] as $p ) {
				$map[ $p['slug'] ] = array(
					'name'     => $p['name'],
					'version'  => $p['version'],
					'on_wporg' => $on_wporg,
				);
			}
		}
		return $map;
	}

	/**
	 * Classify a finding path into a repair kind.
	 *
	 * @param string   $raw          Stored finding path (absolute, or integrity-relative, or a `post:`/`option:` pseudo-path).
	 * @param string[] $known_slugs  Installed plugin slugs (to catch integrity's "slug/file" form).
	 * @return array{kind:string,slug?:string}
	 */
	private function classify( string $raw, array $known_slugs ): array {
		if ( preg_match( '/^(post|postmeta|term|termmeta|option|user|usermeta|comment|snippet|db|theme):/i', $raw ) ) {
			return array( 'kind' => 'db' );
		}

		$p = wp_normalize_path( $raw );

		// Absolute paths: match against where this site actually keeps each directory, so a
		// renamed or relocated content directory is still classified correctly.
		$plugins = wp_normalize_path( \LoyalSecurity\Support\Paths::plugins() ) . '/';
		if ( 0 === strpos( $p, $plugins ) ) {
			$first = (string) strtok( substr( $p, strlen( $plugins ) ), '/' );
			return array( 'kind' => 'plugin', 'slug' => ( substr( $first, -4 ) === '.php' ? '.' : $first ) );
		}
		if ( 0 === strpos( $p, wp_normalize_path( \LoyalSecurity\Support\Paths::themes() ) . '/' ) ) {
			return array( 'kind' => 'theme' );
		}
		if ( 0 === strpos( $p, wp_normalize_path( \LoyalSecurity\Support\Paths::content() ) . '/' ) ) {
			return array( 'kind' => 'other' );
		}
		if ( 0 === strpos( $p, wp_normalize_path( \LoyalSecurity\Support\Paths::admin() ) . '/' ) || 0 === strpos( $p, wp_normalize_path( \LoyalSecurity\Support\Paths::includes() ) . '/' ) ) {
			return array( 'kind' => 'core' );
		}

		// Integrity findings store paths relative to the WordPress root / the plugins dir;
		// absolute root-level files are reduced to the same relative form.
		$rel = ltrim( \LoyalSecurity\Support\Paths::relative( $p ), '/' );
		if ( 0 === strpos( $rel, \LoyalSecurity\Support\Paths::admin_name() . '/' ) || 0 === strpos( $rel, WPINC . '/' ) ) {
			return array( 'kind' => 'core' );
		}
		if ( preg_match( '#^(index\.php|xmlrpc\.php|wp-[a-z0-9-]+\.php)$#', $rel ) ) {
			return array( 'kind' => 'core' );
		}
		$first = strtok( $rel, '/' );
		if ( $first && in_array( $first, $known_slugs, true ) ) {
			return array( 'kind' => 'plugin', 'slug' => $first );
		}

		return array( 'kind' => 'other' );
	}
}
