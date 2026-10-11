<?php
/**
 * Must-Use plugin and drop-in integrity verification.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Integrity;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress.org publishes no checksums for must-use plugins or drop-ins, and `get_plugins()`
 * (used by {@see PluginChecksums}) does not enumerate them at all. Yet both auto-execute on
 * every request without appearing in the normal plugin list, which makes them a favourite
 * malware persistence spot. This wrapper baselines them with the custom {@see Baseline} so
 * later tampering — or a freshly-planted drop-in — is reported as drift.
 */
class MuPluginChecksums {

	/**
	 * WordPress drop-ins that execute automatically when present in wp-content. The mere
	 * appearance of one that was absent at baseline is a strong backdoor signal.
	 *
	 * @var string[]
	 */
	private const DROPINS = array(
		'advanced-cache.php',
		'object-cache.php',
		'db.php',
		'db-error.php',
		'php-error.php',
		'fatal-error-handler.php',
		'maintenance.php',
		'sunrise.php',
		'blog-deleted.php',
		'blog-inactive.php',
		'blog-suspended.php',
	);

	private Baseline $baseline;

	public function __construct( ?Baseline $baseline = null ) {
		$this->baseline = $baseline ?? new Baseline();
	}

	/**
	 * Snapshot the mu-plugins tree and all present drop-ins.
	 *
	 * @return int Total files recorded.
	 */
	public function snapshot_all(): int {
		$total = 0;

		$mu = $this->mu_dir();
		if ( null !== $mu ) {
			$total += $this->baseline->snapshot( 'mu-plugins', $mu );
		}

		// Always snapshot drop-ins (even if none exist yet) so a later addition is detected.
		$total += $this->baseline->snapshot_files( 'dropins', \LoyalSecurity\Support\Paths::content(), $this->present_dropins() );

		return $total;
	}

	/**
	 * Diff mu-plugins and drop-ins against their baselines.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function verify_all(): array {
		$out = array();

		$mu = $this->mu_dir();
		if ( null !== $mu ) {
			$diff           = $this->baseline->diff( 'mu-plugins', $mu );
			$diff['source'] = 'mu-plugins';
			$out[]          = $diff;
		}

		$diff           = $this->baseline->diff_files( 'dropins', \LoyalSecurity\Support\Paths::content(), $this->present_dropins() );
		$diff['source'] = 'dropins';
		$out[]          = $diff;

		return $out;
	}

	/**
	 * The mu-plugins directory, or null if it does not exist.
	 */
	private function mu_dir(): ?string {
		$dir = \LoyalSecurity\Support\Paths::mu_plugins();
		return is_dir( $dir ) ? $dir : null;
	}

	/**
	 * Known drop-in filenames that currently exist in wp-content.
	 *
	 * @return string[]
	 */
	private function present_dropins(): array {
		$present = array();
		foreach ( self::DROPINS as $name ) {
			if ( is_file( \LoyalSecurity\Support\Paths::content() . '/' . $name ) ) {
				$present[] = $name;
			}
		}
		return $present;
	}
}
