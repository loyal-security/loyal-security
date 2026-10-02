<?php
/**
 * SQL dump / import for backups.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Backup;

defined( 'ABSPATH' ) || exit;

/**
 * Produces a portable SQL dump of all tables for the site's `$wpdb` prefix (DROP + CREATE +
 * INSERT), and imports one back. Statements are separated by a unique marker so the importer
 * can split reliably even when row data contains semicolons or newlines.
 */
class DatabaseDump {

	/** Statement delimiter written between every SQL statement in a dump. */
	public const DELIM = "\n-- TOTALSECWP-STATEMENT --\n";

	/**
	 * Dump all of the site's tables to a SQL string.
	 */
	public function export(): string {
		global $wpdb;
		$tables = $wpdb->get_col( 'SHOW TABLES' ); // phpcs:ignore WordPress.DB
		if ( ! is_array( $tables ) ) {
			return '';
		}
		// Only the tables belonging to this install's prefix (avoid clobbering siblings).
		$prefix = $wpdb->prefix;
		$out    = "-- Loyal Security backup dump\nSET FOREIGN_KEY_CHECKS=0;" . self::DELIM;

		foreach ( $tables as $table ) {
			if ( 0 !== strpos( $table, $prefix ) ) {
				continue;
			}
			$out .= 'DROP TABLE IF EXISTS `' . $table . '`;' . self::DELIM;

			$create = $wpdb->get_row( $wpdb->prepare( "SHOW CREATE TABLE %i", $table ), ARRAY_N ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table comes from SHOW TABLES filtered to our own prefix, not user input.
			if ( isset( $create[1] ) ) {
				$out .= $create[1] . ';' . self::DELIM;
			}

			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM %i", $table ), ARRAY_A ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table comes from SHOW TABLES filtered to our own prefix, not user input.
			if ( is_array( $rows ) ) {
				foreach ( $rows as $row ) {
					$out .= $this->insert_statement( $table, $row ) . self::DELIM;
				}
			}
		}

		$out .= 'SET FOREIGN_KEY_CHECKS=1;' . self::DELIM;
		return $out;
	}

	/**
	 * Stream the dump directly to a file, one statement at a time, paging table rows so a large
	 * table is never fully materialised in PHP memory. Preferred over {@see export()} for
	 * backups: export() concatenates the ENTIRE dump into a single string, which OOMs on any
	 * sizeable database (a fatal that cannot be caught, taking the whole request down).
	 *
	 * @param string $path Destination .sql file.
	 * @return int Bytes written (0 on failure).
	 */
	public function export_to_file( string $path ): int {
		global $wpdb;
		$tables = $wpdb->get_col( 'SHOW TABLES' ); // phpcs:ignore WordPress.DB
		if ( ! is_array( $tables ) ) {
			return 0;
		}

		$fh = fopen( $path, 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $fh ) {
			return 0;
		}

		$prefix = $wpdb->prefix;
		$bytes  = 0;
		$write  = static function ( string $s ) use ( $fh, &$bytes ): void {
			$bytes += (int) fwrite( $fh, $s ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		};

		$write( "-- Loyal Security backup dump\nSET FOREIGN_KEY_CHECKS=0;" . self::DELIM );

		foreach ( $tables as $table ) {
			if ( 0 !== strpos( $table, $prefix ) ) {
				continue; // Only this install's prefix — avoid clobbering siblings.
			}
			$write( 'DROP TABLE IF EXISTS `' . $table . '`;' . self::DELIM );

			$create = $wpdb->get_row( $wpdb->prepare( "SHOW CREATE TABLE %i", $table ), ARRAY_N ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table comes from SHOW TABLES filtered to our own prefix, not user input.
			if ( isset( $create[1] ) ) {
				$write( $create[1] . ';' . self::DELIM );
			}

			// Page the rows so an enormous table streams instead of loading all at once. The
			// table name is safe (from SHOW TABLES, filtered to our prefix); only LIMIT/OFFSET
			// are user-independent integers bound via prepare().
			$offset = 0;
			$page   = 500;
			do {
				$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table comes from SHOW TABLES filtered to our own prefix, not user input.
					$wpdb->prepare( "SELECT * FROM %i LIMIT %d OFFSET %d", $table, $page, $offset ), // phpcs:ignore WordPress.DB.PreparedSQL, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table comes from SHOW TABLES filtered to our own prefix, not user input; only LIMIT/OFFSET are parameterised.
					ARRAY_A
				);
				$n = is_array( $rows ) ? count( $rows ) : 0;
				foreach ( (array) $rows as $row ) {
					$write( $this->insert_statement( $table, $row ) . self::DELIM );
				}
				$offset += $page;
			} while ( $n === $page );
		}

		$write( 'SET FOREIGN_KEY_CHECKS=1;' . self::DELIM );
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		return $bytes;
	}

	/**
	 * Build a single INSERT for a row with properly escaped values.
	 *
	 * @param array<string,mixed> $row Column => value.
	 */
	private function insert_statement( string $table, array $row ): string {
		global $wpdb;
		$cols = array();
		$vals = array();
		foreach ( $row as $col => $val ) {
			$cols[] = '`' . str_replace( '`', '``', (string) $col ) . '`';
			if ( null === $val ) {
				$vals[] = 'NULL';
			} else {
				// esc_sql() swaps every '%' for a placeholder token that is only valid for the
				// current request; strip it back, since this dump is replayed in a later one.
				$vals[] = "'" . $wpdb->remove_placeholder_escape( esc_sql( (string) $val ) ) . "'";
			}
		}
		return 'INSERT INTO `' . $table . '` (' . implode( ',', $cols ) . ') VALUES (' . implode( ',', $vals ) . ');';
	}

	/**
	 * Whether a statement is one of the shapes {@see export()}/{@see export_to_file()} write —
	 * the only statements a restore will execute. Anything else in a dump file (a tampered or
	 * foreign file) is skipped and counted as an error, never run.
	 */
	public static function is_dump_statement( string $stmt ): bool {
		global $wpdb;
		$table = '`' . preg_quote( $wpdb->prefix, '/' ) . '[A-Za-z0-9_]+`';
		return 1 === preg_match(
			'/^(?:SET FOREIGN_KEY_CHECKS=[01];?|DROP TABLE IF EXISTS ' . $table . ';?|CREATE TABLE ' . $table . '\s*\(|INSERT INTO ' . $table . '\s*\()/',
			$stmt
		);
	}

	/**
	 * Import a dump string through the live `$wpdb` connection.
	 *
	 * @return array{ok:bool,statements:int,errors:int}
	 */
	public function import( string $sql ): array {
		global $wpdb;
		$statements = array_filter( array_map( 'trim', explode( self::DELIM, $sql ) ) );
		$ok         = 0;
		$errors     = 0;
		foreach ( $statements as $stmt ) {
			if ( '' === $stmt || 0 === strpos( $stmt, '--' ) ) {
				continue;
			}
			if ( ! self::is_dump_statement( $stmt ) ) {
				$errors++;
				continue;
			}
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- replaying a complete statement from this plugin's own checksum-verified dump, restricted by is_dump_statement(); a whole statement cannot be parameterised.
			$res = $wpdb->query( $stmt );
			if ( false === $res ) {
				$errors++;
			} else {
				$ok++;
			}
		}
		return array( 'ok' => 0 === $errors, 'statements' => $ok, 'errors' => $errors );
	}

	/**
	 * Stream-import a dump file without loading it whole into memory. Reads in chunks and
	 * executes each statement as its delimiter is found — the counterpart to
	 * {@see export_to_file()}. Preferred over {@see import()} for restores of large dumps
	 * (import() takes the entire SQL string, so the caller must file_get_contents() the file
	 * first — the exact OOM this avoids).
	 *
	 * @param string $path Path to a .sql dump written by export()/export_to_file().
	 * @return array{ok:bool,statements:int,errors:int}
	 */
	public function import_file( string $path ): array {
		if ( ! is_file( $path ) ) {
			return array( 'ok' => false, 'statements' => 0, 'errors' => 0 );
		}
		$fh = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $fh ) {
			return array( 'ok' => false, 'statements' => 0, 'errors' => 0 );
		}

		$ok     = 0;
		$errors = 0;
		$run    = static function ( string $stmt ) use ( &$ok, &$errors ): void {
			global $wpdb;
			$stmt = trim( $stmt );
			if ( '' === $stmt || 0 === strpos( $stmt, '--' ) ) {
				return;
			}
			if ( ! self::is_dump_statement( $stmt ) ) {
				$errors++;
				return;
			}
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- replaying a complete statement from this plugin's own checksum-verified dump, restricted by is_dump_statement(); a whole statement cannot be parameterised.
			$res = $wpdb->query( $stmt );
			if ( false === $res ) {
				$errors++;
			} else {
				$ok++;
			}
		};

		$buffer  = '';
		$dlen    = strlen( self::DELIM );
		while ( ! feof( $fh ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- streaming read of a large SQL dump in fixed-size chunks; loading the whole file into memory via WP_Filesystem would defeat the point.
			$buffer .= (string) fread( $fh, 1 << 20 ); // 1 MB chunks.
			// Execute every complete statement; keep the trailing partial in the buffer. A single
			// statement larger than one chunk simply accumulates until its delimiter arrives — at
			// most one statement is held in memory at a time, never the whole file.
			while ( false !== ( $pos = strpos( $buffer, self::DELIM ) ) ) {
				$run( substr( $buffer, 0, $pos ) );
				$buffer = substr( $buffer, $pos + $dlen );
			}
		}
		$run( $buffer ); // Trailing statement, if the file didn't end with a delimiter.
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		return array( 'ok' => 0 === $errors, 'statements' => $ok, 'errors' => $errors );
	}
}
