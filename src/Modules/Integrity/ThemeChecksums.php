<?php
/**
 * Theme integrity verification.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Integrity;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress.org does not expose per-file theme checksums, so theme integrity relies on the
 * custom {@see Baseline}: the operator snapshots each theme, and subsequent runs report any
 * drift. This wrapper provides a theme-oriented API over the baseline.
 */
class ThemeChecksums {

	private Baseline $baseline;

	public function __construct( ?Baseline $baseline = null ) {
		$this->baseline = $baseline ?? new Baseline();
	}

	/**
	 * Snapshot all installed themes.
	 *
	 * @return int Total files recorded.
	 */
	public function snapshot_all(): int {
		$total = 0;
		foreach ( $this->theme_roots() as $source => $root ) {
			$total += $this->baseline->snapshot( $source, $root );
		}
		return $total;
	}

	/**
	 * Re-take a theme's baseline after WordPress itself updated it, if it has one.
	 *
	 * @param string $stylesheet Theme directory name.
	 * @return int Files recorded (0 when the theme had no baseline).
	 */
	public function refresh_baseline( string $stylesheet ): int {
		$roots  = $this->theme_roots();
		$source = 'theme:' . $stylesheet;
		if ( ! isset( $roots[ $source ] ) || ! $this->baseline->has( $source ) ) {
			return 0;
		}
		return $this->baseline->snapshot( $source, $roots[ $source ] );
	}

	/**
	 * Diff all themes against their baselines.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function verify_all(): array {
		$out = array();
		foreach ( $this->theme_roots() as $source => $root ) {
			$diff           = $this->baseline->diff( $source, $root );
			$diff['source'] = $source;
			$out[]          = $diff;
		}
		return $out;
	}

	/**
	 * Map of source-key => theme directory.
	 *
	 * @return array<string, string>
	 */
	private function theme_roots(): array {
		$roots = array();
		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			$roots[ 'theme:' . $stylesheet ] = $theme->get_stylesheet_directory();
		}
		return $roots;
	}
}
