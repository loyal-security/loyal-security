<?php
/**
 * Backup creation engine.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Backup;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Filesystem;

/**
 * Creates a backup: a ZIP archive of the site files (optionally excluding heavy uploads) plus
 * an optional SQL dump of the database. Writes a manifest describing the result. The backups
 * directory itself and obvious junk (VCS, caches, node_modules) are always excluded so a
 * backup never recurses into prior backups.
 */
class BackupEngine {

	private BackupStore $store;

	/** Directory basenames never included in a file backup. */
	private array $skip_dirs = array( 'node_modules', '.git', '.svn', 'cache' );

	public function __construct( ?BackupStore $store = null ) {
		$this->store = $store ?? new BackupStore();
	}

	/**
	 * Run a backup.
	 *
	 * @param string        $scope           files | full (full also dumps the database).
	 * @param bool          $include_uploads Include wp-content/uploads (media can be large).
	 * @param callable|null $progress        Optional progress callback: fn(int $pct, string $step).
	 * @return array{ok:bool,message?:string,manifest?:array<string,mixed>,size_human?:string}
	 */
	public function create( string $scope = 'full', bool $include_uploads = true, ?callable $progress = null ): array {
		$p = static function ( int $pct, string $step ) use ( $progress ): void {
			if ( $progress ) {
				$progress( $pct, $step );
			}
		};

		if ( ! class_exists( '\ZipArchive' ) ) {
			return array( 'ok' => false, 'message' => __( 'The PHP Zip extension is required to create backups.', 'loyal-security' ) );
		}

		// A full-site archive + DB dump can far exceed default limits on a real store; being
		// killed mid-run leaves a half-written archive. Lift both budgets for the job (both are
		// best-effort — disabled in some hosting environments, hence the guards).
		if ( function_exists( 'set_time_limit' ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- full-site backup + DB dump can run well past default execution limits.
			@set_time_limit( 0 );
		}
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
		}

		$p( 5, 'Getting ready…' );

		list( $id, $dir ) = $this->store->allocate();
		if ( '' === $dir ) {
			return array( 'ok' => false, 'message' => __( 'Could not create the backup directory.', 'loyal-security' ) );
		}

		$p( 10, 'Scanning files to back up…' );

		$zip_path   = $dir . '/files.zip';
		$file_count = $this->zip_site( $zip_path, $include_uploads, $p );
		if ( $file_count < 0 ) {
			$this->store->delete( $id );
			return array( 'ok' => false, 'message' => __( 'Could not write the file archive.', 'loyal-security' ) );
		}

		$db_included = false;
		$db_bytes    = 0;
		if ( 'full' === $scope ) {
			$p( 78, 'Exporting database…' );
			// Stream straight to disk (paged, one statement at a time) — never hold the whole
			// dump in memory, which OOMs on any sizeable database.
			$db_bytes = ( new DatabaseDump() )->export_to_file( $dir . '/database.sql' );
			if ( $db_bytes > 0 ) {
				Filesystem::chmod( $dir . '/database.sql', 0600 );
				$db_included = true;
			}
		}

		$p( 92, 'Saving backup record…' );

		Filesystem::chmod( $zip_path, 0600 );

		global $wp_version;
		$zip_bytes = is_file( $zip_path ) ? (int) filesize( $zip_path ) : 0;
		$manifest  = array(
			'id'              => $id,
			'created'         => gmdate( 'Y-m-d H:i:s' ),
			'created_ts'      => time(),
			'scope'           => $scope,
			'include_uploads' => $include_uploads,
			'files'           => $file_count,
			'zip_bytes'       => $zip_bytes,
			'zip_sha256'      => \TotalSecurityWP\Support\Filesystem::sha256( $zip_path ),
			'db_included'     => $db_included,
			'db_bytes'        => $db_bytes,
			'db_sha256'       => $db_included ? \TotalSecurityWP\Support\Filesystem::sha256( $dir . '/database.sql' ) : '',
			'abspath'         => wp_normalize_path( \TotalSecurityWP\Support\Paths::root() ),
			'wp_version'      => $wp_version ?? '',
			'plugin_version'  => TOTALSECWP_VERSION,
		);
		$this->store->write_manifest( $id, $manifest );

		return array(
			'ok'        => true,
			'manifest'  => $manifest,
			'size_human' => function_exists( 'size_format' ) ? size_format( $zip_bytes ) : round( $zip_bytes / 1048576, 1 ) . ' MB',
		);
	}

	/**
	 * Zip the site under ABSPATH. Returns the file count, or -1 on failure.
	 *
	 * @param string        $zip_path        Destination archive path.
	 * @param bool          $include_uploads Whether to include the uploads directory.
	 * @param callable|null $progress        Progress callback fn(int $pct, string $step). Archive
	 *                                       phase maps to 15–75% so callers can reserve 0–14 and
	 *                                       76–100 for surrounding steps.
	 */
	private function zip_site( string $zip_path, bool $include_uploads, ?callable $progress = null ): int {
		$zip = new \ZipArchive();
		if ( true !== $zip->open( $zip_path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE ) ) {
			return -1;
		}

		$root         = untrailingslashit( wp_normalize_path( \TotalSecurityWP\Support\Paths::root() ) );
		$storage      = wp_normalize_path( \TotalSecurityWP\Modules\Firewall\BanStore::storage_dir() );
		$uploads_dir  = '';
		$uploads      = wp_upload_dir();
		if ( empty( $uploads['error'] ) ) {
			$uploads_dir = wp_normalize_path( $uploads['basedir'] );
		}

		$count       = 0;
		$next_report = 100; // emit a progress update every N files
		$skip_dirs   = $this->skip_dirs;
		// Exclusions live in a RecursiveCallbackFilterIterator, NOT the consuming loop: with a
		// plain iterator a `continue` only skips the directory's own entry — the iterator still
		// descends into its children, so node_modules/.git/cache contents were archived anyway.
		// Returning false from the filter prunes the whole subtree (same approach as
		// Scanner\FileWalker). NOT FOLLOW_SYMLINKS + the isLink() reject: following symlinks
		// lets the walk archive files OUTSIDE ABSPATH (data leak / archive bloat) and can wedge
		// on a symlink loop.
		$filter = new \RecursiveCallbackFilterIterator(
			new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
			static function ( $item ) use ( $storage, $uploads_dir, $include_uploads, $skip_dirs ) {
				if ( $item->isLink() ) {
					return false;
				}
				$path = wp_normalize_path( $item->getPathname() );
				// Never back up our own private storage (prevents recursion into prior backups).
				if ( '' !== $storage && 0 === strpos( $path, $storage ) ) {
					return false;
				}
				if ( ! $include_uploads && '' !== $uploads_dir && 0 === strpos( $path, $uploads_dir ) ) {
					return false;
				}
				if ( $item->isDir() && in_array( $item->getBasename(), $skip_dirs, true ) ) {
					return false;
				}
				return true;
			}
		);
		$iter = new \RecursiveIteratorIterator( $filter, \RecursiveIteratorIterator::SELF_FIRST );
		foreach ( $iter as $item ) {
			$path = wp_normalize_path( $item->getPathname() );
			$rel  = ltrim( substr( $path, strlen( $root ) ), '/' );
			if ( '' === $rel ) {
				continue;
			}
			if ( $item->isDir() ) {
				$zip->addEmptyDir( $rel );
			} elseif ( $item->isFile() ) {
				$zip->addFile( $item->getPathname(), $rel );
				$count++;
				// Emit a progress ping every 100 files so the dashboard shows activity.
				// Maps loosely to 15–75 % (the archive phase). We don't know the total
				// upfront, so we cap at 75 and let the surrounding milestones cover the rest.
				if ( $progress && $count >= $next_report ) {
					$pct = min( 75, 15 + (int) ( $count / 10 ) );
					$progress( $pct, 'Archiving files… ' . number_format( $count ) . ' so far' );
					$next_report += 100;
				}
			}
		}

		if ( $progress ) {
			$progress( 77, 'Files archived — ' . number_format( $count ) . ' files' );
		}

		// The actual archive write happens at close() — on disk-full (or any write failure) it
		// returns false and the zip is absent/partial. Ignoring that reported a successful
		// backup whose manifest had zip_bytes 0 and an empty sha256, only failing at restore.
		if ( true !== $zip->close() || ! is_file( $zip_path ) ) {
			return -1;
		}
		return $count;
	}
}
