<?php
/**
 * Filesystem enumeration for scans.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Recursively enumerates candidate files under one or more roots, filtered by extension and
 * skipping the plugin's own storage and irrelevant directories. Yields lazily so memory
 * stays bounded on large installs.
 */
class FileWalker {

	/** Extensions worth scanning for PHP malware. */
	private array $extensions;

	/** Directory basenames to skip. */
	private array $skip_dirs = array( 'node_modules', '.git', '.svn', 'cache', 'loyal-security' );

	/**
	 * @param string[] $extensions File extensions (without dot).
	 */
	public function __construct( array $extensions = array( 'php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'js' ) ) {
		$this->extensions = array_map( 'strtolower', $extensions );
	}

	/**
	 * Yield absolute file paths under a root.
	 *
	 * @param string $root Absolute directory.
	 * @return \Generator<string>
	 */
	public function walk( string $root ): \Generator {
		if ( ! is_dir( $root ) ) {
			return;
		}

		// No FOLLOW_SYMLINKS: following links lets enumeration escape the root entirely
		// (scanning arbitrary paths outside ABSPATH) and a link cycle (`foo -> ..`) recurses
		// until timeout — BackupEngine already refuses symlinks for the same reasons, and the
		// two walkers must agree. Symlinked FILES are also skipped via the isLink() check so a
		// planted link can't point the scanner at /etc or another site's tree.
		$dir_iter = new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS );
		$filter   = new \RecursiveCallbackFilterIterator(
			$dir_iter,
			function ( $current ) {
				if ( $current->isLink() ) {
					return false;
				}
				if ( $current->isDir() ) {
					return ! in_array( $current->getBasename(), $this->skip_dirs, true );
				}
				return true;
			}
		);

		// CATCH_GET_CHILD: an unreadable subdirectory (permissions) otherwise throws
		// UnexpectedValueException mid-iteration, which escaped ScannerModule::start() and
		// 500'd POST /scan/start (and killed the scheduled-scan cron run). With the flag the
		// unreadable subtree is simply skipped and the walk continues.
		$iter = new \RecursiveIteratorIterator(
			$filter,
			\RecursiveIteratorIterator::LEAVES_ONLY,
			\RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		foreach ( $iter as $file ) {
			try {
				if ( ! $file->isFile() ) {
					continue;
				}
				$ext = strtolower( $file->getExtension() );
				if ( in_array( $ext, $this->extensions, true ) ) {
					yield $file->getPathname();
				}
			} catch ( \Throwable $e ) {
				continue; // A single unstatable entry must never abort the whole enumeration.
			}
		}
	}

	/**
	 * Roots for a given scan type.
	 *
	 * @param string $type full | content | uploads | core.
	 * @return string[]
	 */
	public function roots_for( string $type ): array {
		switch ( $type ) {
			case 'uploads':
				$uploads = \TotalSecurityWP\Support\Paths::uploads();
				return '' !== $uploads ? array( $uploads ) : array();
			case 'content':
				return array( \TotalSecurityWP\Support\Paths::content() );
			case 'core':
				return array( \TotalSecurityWP\Support\Paths::admin(), \TotalSecurityWP\Support\Paths::includes() );
			case 'full':
			default:
				return array( \TotalSecurityWP\Support\Paths::root() );
		}
	}
}
