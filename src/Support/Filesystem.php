<?php
/**
 * Filesystem helper built on WP_Filesystem with safe fallbacks.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Provides safe read/write/move/chmod operations. Prefers WP_Filesystem (so it respects
 * host filesystem method config) but falls back to native PHP for read-only operations
 * needed early in the request lifecycle.
 */
final class Filesystem {

	/**
	 * Initialise and return the global WP_Filesystem instance, or null if unavailable.
	 *
	 * @return \WP_Filesystem_Base|null
	 */
	public static function wp() {
		global $wp_filesystem;
		if ( $wp_filesystem ) {
			return $wp_filesystem;
		}
		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( WP_Filesystem() ) {
			return $wp_filesystem;
		}
		return null;
	}

	/**
	 * Read a file's contents (native; safe for large streaming reads handled elsewhere).
	 */
	public static function read( string $path ): ?string {
		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return null;
		}
		$contents = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		return false === $contents ? null : $contents;
	}

	/**
	 * Write contents to a file using WP_Filesystem when possible.
	 */
	public static function write( string $path, string $contents ): bool {
		$fs = self::wp();
		if ( $fs ) {
			return $fs->put_contents( $path, $contents, FS_CHMOD_FILE );
		}
		return false !== file_put_contents( $path, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/**
	 * Move a file, creating the destination directory if needed.
	 */
	public static function move( string $from, string $to ): bool {
		$dir = dirname( $to );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$fs = self::wp();
		if ( $fs && $fs->move( $from, $to, true ) ) {
			return true;
		}
		return @rename( $from, $to ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.rename_rename
	}

	/**
	 * Apply UNIX permissions (no-op on systems that don't support it).
	 */
	public static function chmod( string $path, int $mode ): bool {
		$fs = self::wp();
		if ( $fs ) {
			return $fs->chmod( $path, $mode );
		}
		return @chmod( $path, $mode ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_chmod
	}

	/**
	 * Delete a single file.
	 */
	public static function delete( string $path ): bool {
		$fs = self::wp();
		if ( $fs ) {
			return $fs->delete( $path, false, 'f' );
		}
		return @unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.unlink_unlink
	}

	/**
	 * Create a directory (recursively).
	 */
	public static function mkdir( string $path ): bool {
		return wp_mkdir_p( $path );
	}

	/**
	 * Remove an empty directory.
	 */
	public static function rmdir( string $path ): bool {
		$fs = self::wp();
		if ( $fs ) {
			return $fs->rmdir( $path );
		}
		return @rmdir( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
	}

	/**
	 * SHA-256 of a file, or empty string on failure.
	 */
	public static function sha256( string $path ): string {
		if ( ! is_file( $path ) ) {
			return '';
		}
		$hash = hash_file( 'sha256', $path );
		return false === $hash ? '' : $hash;
	}

	/**
	 * Recursively copy a directory tree. Existing files at the destination are overwritten.
	 *
	 * @param callable|null $transform Optional `fn(string $contents, string $relative_path): string`
	 *                                 applied to each file's contents before it's written to the
	 *                                 destination — e.g. rewriting a direct-access guard for a
	 *                                 relocated copy. Existing callers pass none and get a
	 *                                 byte-identical copy, unchanged.
	 */
	public static function copy_dir( string $from, string $to, ?callable $transform = null ): bool {
		$from = untrailingslashit( wp_normalize_path( $from ) );
		if ( ! is_dir( $from ) ) {
			return false;
		}
		if ( ! is_dir( $to ) ) {
			wp_mkdir_p( $to );
		}
		$iter = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $from, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::SELF_FIRST
		);
		foreach ( $iter as $item ) {
			$rel  = ltrim( str_replace( $from, '', wp_normalize_path( $item->getPathname() ) ), '/' );
			$dest = trailingslashit( $to ) . $rel;
			if ( $item->isDir() ) {
				if ( ! is_dir( $dest ) ) {
					wp_mkdir_p( $dest );
				}
				continue;
			}
			$contents = self::read( $item->getPathname() );
			if ( null === $contents ) {
				return false;
			}
			if ( null !== $transform ) {
				$contents = $transform( $contents, $rel );
			}
			if ( ! self::write( $dest, $contents ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Back up a server-config file's pre-modification contents (wp-config.php, .htaccess,
	 * .user.ini) into a dedicated storage location under wp-content/uploads — deliberately
	 * NEVER alongside the original file. A timestamped copy sitting in the web root under a
	 * guessable name (`wp-config.php.<suffix>-<timestamp>`) is served as plain text by any web
	 * server that doesn't specifically deny it: the original's `.php` extension is what
	 * triggers execution, a renamed copy is just a static file — so a wp-config.php backup
	 * there leaks the live DB password and secret keys to anyone who requests the exact
	 * filename. The uploads directory is writable on every host this plugin supports, and is
	 * protected here with an index.php stub and a .htaccess deny (effective on Apache
	 * automatically; an nginx host's own vhost needs a matching deny rule, since nginx doesn't
	 * read .htaccess — see docs). Callers that used to read this location back for an automatic
	 * restore don't exist: every current caller's own revert/rollback strips the change it made
	 * directly from the live file's content, and only ever treats this backup as a passive,
	 * manual-recovery artifact.
	 *
	 * @param string $path     Absolute path to the file being backed up (only its basename is
	 *                         used in the backup's filename — the original path is never
	 *                         stored, so this can't leak server directory structure).
	 * @param string $contents Pre-modification contents to preserve.
	 * @param int    $keep     How many timestamped backups of this file to retain.
	 */
	public static function backup_config_file( string $path, string $contents, int $keep = 5 ): void {
		if ( '' === $contents ) {
			return;
		}
		$dir = self::config_backup_dir();
		if ( '' === $dir ) {
			return; // Uploads dir unavailable — fail closed (no backup) rather than fall back to the web root.
		}

		$base   = basename( $path );
		$backup = trailingslashit( $dir ) . $base . '.totalsecwp-bak-' . gmdate( 'YmdHis' );
		self::write( $backup, $contents );

		// Keep only the most recent few — deploy/revert cycles otherwise accumulate indefinitely.
		$existing = glob( trailingslashit( $dir ) . $base . '.totalsecwp-bak-*' );
		if ( is_array( $existing ) && count( $existing ) > $keep ) {
			rsort( $existing ); // Timestamped names sort chronologically; newest first.
			foreach ( array_slice( $existing, $keep ) as $old ) {
				self::delete( $old );
			}
		}
	}

	/**
	 * The protected config-backup directory under wp-content/uploads, creating it (with its
	 * index.php stub and .htaccess deny-all) on first use. Returns '' if the uploads directory
	 * itself is unavailable.
	 */
	private static function config_backup_dir(): string {
		$base = \TotalSecurityWP\Modules\Firewall\BanStore::storage_dir();
		if ( '' === $base ) {
			return '';
		}
		$dir = $base . '/config-backups';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$index = trailingslashit( $dir ) . 'index.php';
		if ( ! is_file( $index ) ) {
			self::write( $index, "<?php\n// Silence is golden.\n" );
		}
		$htaccess = trailingslashit( $dir ) . '.htaccess';
		if ( ! is_file( $htaccess ) ) {
			self::write(
				$htaccess,
				"# Loyal Security: these are backups of server config files (wp-config.php,\n"
				. "# .htaccess, .user.ini) that may contain database credentials or secret keys.\n"
				. "Require all denied\n"
				. "\n"
				. "<IfModule !mod_authz_core.c>\n"
				. "\tOrder deny,allow\n"
				. "\tDeny from all\n"
				. "</IfModule>\n"
			);
		}
		return $dir;
	}

	/**
	 * Recursively delete a directory. With $keep_root the directory itself is left in place
	 * (emptied), which is what an in-place tree replacement needs.
	 */
	public static function delete_dir( string $dir, bool $keep_root = false ): bool {
		$dir = untrailingslashit( wp_normalize_path( $dir ) );
		if ( ! is_dir( $dir ) ) {
			return false;
		}
		$iter = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $iter as $item ) {
			if ( $item->isDir() ) {
				@rmdir( $item->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
			} else {
				@unlink( $item->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.unlink_unlink
			}
		}
		if ( ! $keep_root ) {
			@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
		}
		return true;
	}
}
