<?php
/**
 * SQL dump / import for backups.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Backup;

defined( 'ABSPATH' ) || exit;

/**
 * Produces a portable SQL dump of all tables for the site's `$wpdb` prefix (DROP + CREATE +
 * INSERT), and imports one back. Statements are separated by a unique marker so the importer
 * can split reliably even when row data contains semicolons or newlines.
 */
class DatabaseDump {

	/** Statement delimiter written between every SQL statement in a dump. */
	public const DELIM = "\n-- LOYALSEC-STATEMENT --\n";

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
	 * Execute one statement from a dump.
	 *
	 * No query here is built from variable text. `prepare()` protects the arguments it is given,
	 * never the query string it is handed — text concatenated into that string reaches MySQL
	 * exactly as written — so each of the four shapes a dump can contain is executed on its own
	 * terms rather than replayed as SQL:
	 *
	 *  - `SET FOREIGN_KEY_CHECKS=0/1` — two fixed literals, picked by the matched digit.
	 *  - `DROP TABLE IF EXISTS` — the literal `DROP TABLE IF EXISTS %i`, table name bound as an
	 *    identifier placeholder.
	 *  - `INSERT INTO` — parsed back into column => value pairs by {@see parse_insert()} and
	 *    written with `$wpdb->insert()`, which composes its own prepared statement. None of the
	 *    dump's SQL text reaches the database.
	 *  - `CREATE TABLE` — the one statement that cannot be expressed as a literal plus
	 *    placeholders; see the note at that branch.
	 *
	 * A statement that does not match one of these shapes exactly is rejected and reported as an
	 * error. Combined with the SHA-256 the restore verifies against the dump before replaying it
	 * ({@see \LoyalSecurity\Modules\Backup\RestoreEngine}), a tampered or foreign dump cannot
	 * introduce a statement of its own.
	 *
	 * @param string      $stmt  One statement from a dump.
	 * @param string|null $table Write to this table instead of the one the statement names —
	 *                           used to restore a dump under a different table prefix.
	 * @return bool Whether the statement ran.
	 */
	public static function run_dump_statement( string $stmt, ?string $table = null ): bool {
		global $wpdb;

		$stmt = trim( $stmt );
		if ( ! self::is_dump_statement( $stmt ) ) {
			return false;
		}

		// Two fixed statements; the matched digit only chooses between them.
		if ( 1 === preg_match( '/^SET FOREIGN_KEY_CHECKS=([01]);?$/', $stmt, $set ) ) {
			$res = '1' === $set[1]
				? $wpdb->query( 'SET FOREIGN_KEY_CHECKS=1' ) // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- restoring a dump; there is nothing to cache.
				: $wpdb->query( 'SET FOREIGN_KEY_CHECKS=0' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- restoring a dump; there is nothing to cache.
			return false !== $res;
		}

		// Literal query, identifier bound as a placeholder.
		if ( 1 === preg_match( '/^DROP TABLE IF EXISTS `([A-Za-z0-9_]+)`;?$/', $stmt, $drop ) ) {
			$res = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- restoring a dump replaces the table it is restoring.
				$wpdb->prepare( 'DROP TABLE IF EXISTS %i', null === $table ? $drop[1] : $table ) // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- the sniff reports on the line carrying the DROP keyword, which is this one; restoring a dump replaces the table it is restoring.
			);
			return false !== $res;
		}

		// Row data: rebuilt through $wpdb->insert(), which prepares the statement itself.
		if ( 0 === strpos( $stmt, 'INSERT INTO ' ) ) {
			$parsed = self::parse_insert( $stmt );
			if ( null === $parsed ) {
				return false;
			}
			$res = $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- restoring a dump; there is nothing to cache.
				null === $table ? $parsed['table'] : $table,
				$parsed['data']
			);
			return false !== $res;
		}

		if ( 1 === preg_match( '/^CREATE TABLE `([A-Za-z0-9_]+)`/', $stmt, $head ) ) {
			// The only statement whose query string cannot be made literal. Its body is a column
			// and index definition — there is no placeholder for a schema, and rebuilding one
			// from parsed parts would silently lose engine, charset, collation, defaults or index
			// details that a backup exists to preserve exactly.
			//
			// What bounds it: the body is DDL that MySQL itself emitted from SHOW CREATE TABLE
			// against a table of this very site, written by export_to_file() in the same plugin;
			// it carries no row data and never contains user input. is_dump_statement() has
			// already required the statement to begin with CREATE TABLE and a table matching this
			// install's own prefix, and RestoreEngine verifies the whole dump file against a
			// SHA-256 held in the database before a single statement is replayed, so the bytes
			// here are the bytes this site wrote. The table name — the only part that varies when
			// restoring under a different prefix — is still bound as a %i placeholder.
			$body  = substr( $stmt, strlen( $head[0] ) );
			$query = 'CREATE TABLE %i' . $wpdb->add_placeholder_escape( $body );
			$res   = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- restoring a dump recreates the table it is restoring.
				(string) $wpdb->prepare( $query, null === $table ? $head[1] : $table ) // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- schema DDL from this site's own SHOW CREATE TABLE, checksum-verified before replay; see the note above. Only the table identifier varies and it is bound as %i.
			);
			return false !== $res;
		}

		return false;
	}

	/**
	 * Parse one `INSERT` written by {@see insert_statement()} back into column => value pairs.
	 *
	 * Deliberately strict rather than general: this reads only the exact shape this plugin
	 * writes — `` INSERT INTO `t` (`c`,...) VALUES (v,...); `` where every value is either the
	 * bare word NULL or a single-quoted string escaped by `esc_sql()`. Any deviation returns null
	 * and the statement is reported as an error instead of being run. A general SQL parser would
	 * be both far larger and far easier to slip something past.
	 *
	 * Values come back unescaped, because `$wpdb->insert()` escapes them again when it prepares
	 * its own statement; leaving them escaped would double every backslash.
	 *
	 * @param string $stmt One INSERT statement from a dump.
	 * @return array{table:string,data:array<string,string|null>}|null Null if it is not the exact
	 *         shape insert_statement() writes.
	 */
	private static function parse_insert( string $stmt ): ?array {
		if ( 1 !== preg_match( '/^INSERT INTO `([A-Za-z0-9_]+)` \(/', $stmt, $m ) ) {
			return null;
		}
		$table = $m[1];
		$i     = strlen( $m[0] );
		$len   = strlen( $stmt );

		// Column list: `name` or `na``me`, comma separated, closed by ')'.
		$cols = array();
		while ( true ) {
			if ( $i >= $len || '`' !== $stmt[ $i ] ) {
				return null;
			}
			++$i;
			$name   = '';
			$closed = false;
			while ( $i < $len ) {
				if ( '`' === $stmt[ $i ] ) {
					if ( $i + 1 < $len && '`' === $stmt[ $i + 1 ] ) {
						$name .= '`';
						$i    += 2;
						continue;
					}
					++$i;
					$closed = true;
					break;
				}
				$name .= $stmt[ $i ];
				++$i;
			}
			if ( ! $closed || '' === $name ) {
				return null;
			}
			$cols[] = $name;

			if ( $i < $len && ',' === $stmt[ $i ] ) {
				++$i;
				continue;
			}
			if ( $i < $len && ')' === $stmt[ $i ] ) {
				++$i;
				break;
			}
			return null;
		}

		if ( 0 !== strpos( substr( $stmt, $i ), ' VALUES (' ) ) {
			return null;
		}
		$i += strlen( ' VALUES (' );

		// Value list: NULL, or a single-quoted string with backslash escapes.
		$vals = array();
		while ( true ) {
			if ( $i >= $len ) {
				return null;
			}
			if ( 0 === substr_compare( $stmt, 'NULL', $i, 4 ) ) {
				$vals[] = null;
				$i     += 4;
			} elseif ( "'" === $stmt[ $i ] ) {
				++$i;
				$val    = '';
				$closed = false;
				while ( $i < $len ) {
					$ch = $stmt[ $i ];
					if ( '\\' === $ch ) {
						if ( $i + 1 >= $len ) {
							return null;
						}
						$val .= self::unescape_sql_char( $stmt[ $i + 1 ] );
						$i   += 2;
						continue;
					}
					if ( "'" === $ch ) {
						++$i;
						$closed = true;
						break;
					}
					$val .= $ch;
					++$i;
				}
				if ( ! $closed ) {
					return null;
				}
				$vals[] = $val;
			} else {
				return null;
			}

			if ( $i < $len && ',' === $stmt[ $i ] ) {
				++$i;
				continue;
			}
			if ( $i < $len && ')' === $stmt[ $i ] ) {
				++$i;
				break;
			}
			return null;
		}

		// Nothing but an optional terminating semicolon may follow.
		$tail = trim( substr( $stmt, $i ) );
		if ( '' !== $tail && ';' !== $tail ) {
			return null;
		}
		if ( count( $cols ) !== count( $vals ) ) {
			return null;
		}

		return array(
			'table' => $table,
			'data'  => array_combine( $cols, $vals ),
		);
	}

	/**
	 * Reverse one backslash escape produced by `esc_sql()`.
	 *
	 * MySQL's string escaping maps NUL, newline, carriage return, backslash, both quote
	 * characters and Ctrl-Z to two-character sequences; every other escaped character stands for
	 * itself.
	 */
	private static function unescape_sql_char( string $ch ): string {
		switch ( $ch ) {
			case '0':
				return "\0";
			case 'n':
				return "\n";
			case 'r':
				return "\r";
			case 'Z':
				return "\x1a";
			default:
				return $ch;
		}
	}

	/**
	 * Stream-import a dump file without loading it whole into memory: reads in chunks and runs
	 * each statement as its delimiter is found — the counterpart to {@see export_to_file()}.
	 * Never holds more than a single statement at a time, so the size of the dump does not
	 * decide whether a restore fits in memory. Each statement runs via
	 * {@see run_dump_statement()}.
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
			$stmt = trim( $stmt );
			if ( '' === $stmt || 0 === strpos( $stmt, '--' ) ) {
				return;
			}
			if ( self::run_dump_statement( $stmt ) ) {
				$ok++;
			} else {
				$errors++;
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
