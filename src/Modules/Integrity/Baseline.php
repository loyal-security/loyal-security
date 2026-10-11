<?php
/**
 * Custom file-integrity baseline (snapshot + diff).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Integrity;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Scanner\FileWalker;

/**
 * For files without an official checksum source (themes, premium plugins, mu-plugins), the
 * baseline records a SHA-256 snapshot and reports additions/modifications/deletions on
 * subsequent runs — catching tampering even where WordPress.org has no reference.
 */
class Baseline {

	/**
	 * Sentinel path stored by {@see snapshot_files()} so that a file-list source is known to
	 * have been snapshotted even when zero files were present at the time. Without it, a source
	 * that had no drop-ins at baseline would report `has_baseline => false`, and a drop-in
	 * planted afterwards (a classic backdoor persistence trick) would never be flagged as
	 * "added". The marker is excluded from the diff itself.
	 */
	private const MARKER = "\0loyalsec-baseline-marker";

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_integrity_baseline';
	}

	/**
	 * Whether a baseline was ever taken for a source.
	 *
	 * @param string $source Source key.
	 */
	public function has( string $source ): bool {
		global $wpdb;
		return (bool) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live baseline state.
			$wpdb->prepare( 'SELECT 1 FROM %i WHERE source = %s LIMIT 1', $this->table(), $source )
		);
	}

	/**
	 * Snapshot a directory tree under a named source.
	 *
	 * @param string $source Logical source key (e.g. 'theme:twentytwentyfive').
	 * @param string $root   Absolute directory.
	 * @return int Number of files recorded.
	 */
	public function snapshot( string $source, string $root ): int {
		global $wpdb;
		$wpdb->delete( $this->table(), array( 'source' => $source ) ); // phpcs:ignore WordPress.DB

		$walker = new FileWalker( array( 'php', 'js', 'css', 'phtml', 'inc' ), false );
		$n      = 0;
		foreach ( $walker->walk( $root ) as $path ) {
			$hash = hash_file( 'sha256', $path );
			if ( false === $hash ) {
				continue;
			}
			$inserted = $wpdb->insert( // phpcs:ignore WordPress.DB
				$this->table(),
				array(
					'path'       => mb_substr( $this->relative( $path, $root ), 0, 255 ),
					'hash'       => $hash,
					'source'     => $source,
					'slug'       => basename( $root ),
					'created_at' => gmdate( 'Y-m-d H:i:s' ),
				)
			);
			// Never count a row the DB actually rejected — a caller trusts this return value to
			// mean "recorded", and diff()'s has_baseline check depends on rows genuinely existing
			// (see the varchar(20)-vs-'theme:<slug>' incident this comment was added for).
			if ( false === $inserted ) {
				if ( function_exists( 'error_log' ) ) {
					\LoyalSecurity\Support\Debug::log( 'integrity baseline insert failed for source "' . $source . '": ' . $wpdb->last_error );
				}
				continue;
			}
			$n++;
		}
		return $n;
	}

	/**
	 * Diff a directory tree against its stored baseline.
	 *
	 * @param string $source Source key.
	 * @param string $root   Absolute directory.
	 * @return array{modified:string[],added:string[],deleted:string[],has_baseline:bool}
	 */
	public function diff( string $source, string $root ): array {
		global $wpdb;
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT path, hash FROM %i WHERE source = %s", $this->table(), $source ),
			ARRAY_A
		);
		if ( empty( $rows ) ) {
			return array( 'modified' => array(), 'added' => array(), 'deleted' => array(), 'has_baseline' => false );
		}

		$baseline = array();
		foreach ( $rows as $r ) {
			$baseline[ $r['path'] ] = $r['hash'];
		}

		$modified = array();
		$added    = array();
		$walker   = new FileWalker( array( 'php', 'js', 'css', 'phtml', 'inc' ), false );
		$current  = array();

		foreach ( $walker->walk( $root ) as $path ) {
			$rel             = $this->relative( $path, $root );
			$current[ $rel ] = true;
			$hash            = hash_file( 'sha256', $path );
			if ( ! isset( $baseline[ $rel ] ) ) {
				$added[] = $rel;
			} elseif ( $baseline[ $rel ] !== $hash ) {
				$modified[] = $rel;
			}
		}

		$deleted = array_values( array_diff( array_keys( $baseline ), array_keys( $current ) ) );

		return array(
			'modified'     => $modified,
			'added'        => $added,
			'deleted'      => $deleted,
			'has_baseline' => true,
		);
	}

	/**
	 * Snapshot an explicit list of files under a base directory.
	 *
	 * Unlike {@see snapshot()} this does not walk a tree — it hashes only the given relative
	 * paths. Used for drop-ins (`object-cache.php`, `advanced-cache.php`, `db.php`, …) which
	 * live loose in `wp-content` and must not trigger a recursive walk of the whole directory.
	 * A sentinel row is always written so the source counts as baselined even if no listed file
	 * currently exists.
	 *
	 * @param string   $source Logical source key.
	 * @param string   $base   Absolute base directory the paths are relative to.
	 * @param string[] $files  Relative file paths under $base.
	 * @return int Number of real files recorded (excludes the sentinel).
	 */
	public function snapshot_files( string $source, string $base, array $files ): int {
		global $wpdb;
		$wpdb->delete( $this->table(), array( 'source' => $source ) ); // phpcs:ignore WordPress.DB

		// Sentinel: marks the source as snapshotted regardless of file count.
		$sentinel_ok = $wpdb->insert( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'path'       => self::MARKER,
				'hash'       => '',
				'source'     => $source,
				'slug'       => $source,
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			)
		);
		if ( false === $sentinel_ok && function_exists( 'error_log' ) ) {
			\LoyalSecurity\Support\Debug::log( 'integrity baseline sentinel insert failed for source "' . $source . '": ' . $wpdb->last_error );
		}

		$base = rtrim( $base, '/\\' );
		$n    = 0;
		foreach ( $files as $rel ) {
			$rel  = ltrim( $rel, '/\\' );
			$path = $base . '/' . $rel;
			if ( ! is_file( $path ) ) {
				continue;
			}
			$hash = hash_file( 'sha256', $path );
			if ( false === $hash ) {
				continue;
			}
			$inserted = $wpdb->insert( // phpcs:ignore WordPress.DB
				$this->table(),
				array(
					'path'       => mb_substr( $rel, 0, 255 ),
					'hash'       => $hash,
					'source'     => $source,
					'slug'       => $source,
					'created_at' => gmdate( 'Y-m-d H:i:s' ),
				)
			);
			if ( false === $inserted ) {
				if ( function_exists( 'error_log' ) ) {
					\LoyalSecurity\Support\Debug::log( 'integrity baseline insert failed for source "' . $source . '": ' . $wpdb->last_error );
				}
				continue;
			}
			$n++;
		}
		return $n;
	}

	/**
	 * Diff an explicit list of files against their stored baseline.
	 *
	 * @param string   $source Source key.
	 * @param string   $base   Absolute base directory.
	 * @param string[] $files  Relative file paths currently present under $base.
	 * @return array{modified:string[],added:string[],deleted:string[],has_baseline:bool}
	 */
	public function diff_files( string $source, string $base, array $files ): array {
		global $wpdb;
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT path, hash FROM %i WHERE source = %s", $this->table(), $source ),
			ARRAY_A
		);
		if ( empty( $rows ) ) {
			return array( 'modified' => array(), 'added' => array(), 'deleted' => array(), 'has_baseline' => false );
		}

		$baseline = array();
		foreach ( $rows as $r ) {
			if ( self::MARKER === $r['path'] ) {
				continue; // Sentinel — not a real file.
			}
			$baseline[ $r['path'] ] = $r['hash'];
		}

		$base     = rtrim( $base, '/\\' );
		$modified = array();
		$added    = array();
		$current  = array();

		foreach ( $files as $rel ) {
			$rel             = ltrim( $rel, '/\\' );
			$current[ $rel ] = true;
			$path            = $base . '/' . $rel;
			$hash            = is_file( $path ) ? hash_file( 'sha256', $path ) : false;
			if ( ! isset( $baseline[ $rel ] ) ) {
				$added[] = $rel;
			} elseif ( $baseline[ $rel ] !== $hash ) {
				$modified[] = $rel;
			}
		}

		$deleted = array_values( array_diff( array_keys( $baseline ), array_keys( $current ) ) );

		return array(
			'modified'     => $modified,
			'added'        => $added,
			'deleted'      => $deleted,
			'has_baseline' => true,
		);
	}

	private function relative( string $path, string $root ): string {
		$root = rtrim( $root, '/\\' );
		return ltrim( str_replace( $root, '', $path ), '/\\' );
	}
}
