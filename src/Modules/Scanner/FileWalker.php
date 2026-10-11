<?php
/**
 * Filesystem enumeration for scans.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Recursively enumerates candidate files under one or more roots, filtered by extension and
 * skipping the plugin's own private storage and development folders. Yields lazily so memory
 * stays bounded on large installs.
 *
 * Folders are skipped by their full path, never by name alone: a name-only rule ("skip every
 * folder called cache") also skips every folder an attacker gives that name, and cache folders
 * are a common place to drop a web shell.
 */
class FileWalker {

	/** Extensions that can run as PHP on a typical server. */
	private const PHP_EXTENSIONS = array( 'php', 'phtml', 'php5', 'php7', 'phar', 'inc' );

	/** Extensions worth scanning for PHP malware. */
	private array $extensions;

	/** Development folders skipped wherever they are (never served as part of a site). */
	private array $skip_dirs = array( 'node_modules', '.git', '.svn' );

	/**
	 * Inside a folder named "cache", only PHP files are yielded by default: cached assets
	 * (minified, concatenated JS) are rewritten constantly and would flood a scan with noise,
	 * but a PHP file there can still run. Set false to skip cache folders entirely (the
	 * integrity baseline does, since their contents change all the time by design).
	 */
	private bool $include_cache_php = true;

	/**
	 * @param string[] $extensions        File extensions (without dot).
	 * @param bool     $include_cache_php Whether to yield PHP files inside "cache" folders.
	 */
	public function __construct( array $extensions = array( 'php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'js' ), bool $include_cache_php = true ) {
		$this->extensions        = array_map( 'strtolower', $extensions );
		$this->include_cache_php = $include_cache_php;
	}

	/**
	 * Absolute folders this plugin writes itself and never needs scanning: the generated
	 * firewall bundle (a copy of the plugin's own rules), the signed threat-feed rules (they
	 * are detection patterns, so they match themselves), backups and quarantined files.
	 *
	 * @return string[] Normalized paths without a trailing slash.
	 */
	private function skip_paths(): array {
		$storage = \LoyalSecurity\Modules\Firewall\BanStore::storage_dir();
		if ( '' === $storage ) {
			return array();
		}
		$storage = untrailingslashit( wp_normalize_path( $storage ) );
		return array( $storage . '/waf-kernel', $storage . '/feed', $storage . '/backups', $storage . '/quarantine' );
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
		$skip_paths = $this->skip_paths();
		$dir_iter   = new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS );
		$filter     = new \RecursiveCallbackFilterIterator(
			$dir_iter,
			function ( $current ) use ( $skip_paths ) {
				if ( $current->isLink() ) {
					return false;
				}
				if ( $current->isDir() ) {
					if ( in_array( $current->getBasename(), $this->skip_dirs, true ) ) {
						return false;
					}
					if ( ! $this->include_cache_php && 'cache' === strtolower( $current->getBasename() ) ) {
						return false;
					}
					return ! in_array( wp_normalize_path( $current->getPathname() ), $skip_paths, true );
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
				if ( ! in_array( $ext, $this->extensions, true ) ) {
					continue;
				}
				if ( ! in_array( $ext, self::PHP_EXTENSIONS, true ) && $this->in_cache_folder( $file->getPath() ) ) {
					continue;
				}
				yield $file->getPathname();
			} catch ( \Throwable $e ) {
				continue; // A single unstatable entry must never abort the whole enumeration.
			}
		}
	}

	/**
	 * Whether a folder is, or is inside, a folder named "cache".
	 */
	private function in_cache_folder( string $dir ): bool {
		return in_array( 'cache', array_map( 'strtolower', explode( '/', wp_normalize_path( $dir ) ) ), true );
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
				$uploads = \LoyalSecurity\Support\Paths::uploads();
				return '' !== $uploads ? array( $uploads ) : array();
			case 'content':
				return array( \LoyalSecurity\Support\Paths::content() );
			case 'core':
				return array( \LoyalSecurity\Support\Paths::admin(), \LoyalSecurity\Support\Paths::includes() );
			case 'full':
			default:
				return array( \LoyalSecurity\Support\Paths::root() );
		}
	}
}
