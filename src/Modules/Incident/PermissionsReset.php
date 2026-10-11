<?php
/**
 * Recursive file-permission normalization.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Support\Filesystem;

/**
 * Forces correct UNIX permissions across a tree (directories 0755, files 0644), with a
 * tighter mode for wp-config.php. Work is bounded per run so it never exhausts time/memory
 * on very large installs; callers can re-run to continue.
 */
class PermissionsReset {

	private int $dir_mode;
	private int $file_mode;

	public function __construct( int $dir_mode = 0755, int $file_mode = 0644 ) {
		$this->dir_mode  = $dir_mode;
		$this->file_mode = $file_mode;
	}

	/**
	 * Apply permissions under a root.
	 *
	 * @param string $root      Absolute directory (defaults to the WordPress root).
	 * @param int    $max_items Safety cap on items processed per run.
	 * @return array{dirs:int,files:int,changed:int,capped:bool}
	 */
	public function apply( string $root = '', int $max_items = 20000 ): array {
		$root = wp_normalize_path( '' === $root ? \LoyalSecurity\Support\Paths::root() : $root );
		$dirs = 0;
		$files = 0;
		$changed = 0;
		$count = 0;
		$capped = false;

		if ( ! is_dir( $root ) ) {
			return array( 'dirs' => 0, 'files' => 0, 'changed' => 0, 'capped' => false );
		}

		$iter = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iter as $item ) {
			if ( ++$count > $max_items ) {
				$capped = true;
				break;
			}
			$path = $item->getPathname();

			if ( $item->isDir() ) {
				$dirs++;
				if ( $this->set_mode( $path, $this->dir_mode ) ) {
					$changed++;
				}
			} elseif ( $item->isFile() ) {
				$files++;
				$mode = $this->file_mode;
				// Lock down wp-config.php more tightly.
				if ( 'wp-config.php' === $item->getFilename() ) {
					$mode = 0600;
				}
				if ( $this->set_mode( $path, $mode ) ) {
					$changed++;
				}
			}
		}

		return array( 'dirs' => $dirs, 'files' => $files, 'changed' => $changed, 'capped' => $capped );
	}

	private function set_mode( string $path, int $mode ): bool {
		$current = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $current ) {
			return false;
		}
		if ( ( $current & 0777 ) === $mode ) {
			return false; // Already correct.
		}
		return Filesystem::chmod( $path, $mode );
	}
}
