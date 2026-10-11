<?php
/**
 * Scanner finding whitelist (false-positive suppression).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * A small option-backed allow-list the admin curates to stop known-good files (or whole rules)
 * being re-flagged on every scan. Entries are matched two ways:
 *
 *   - `path` : an exact normalised file path (or a path ending in `/*` to match a whole tree).
 *   - `rule` : a signature id (e.g. `db-admin-audit`) suppressed everywhere.
 *
 * The scanner consults {@see self::is_whitelisted()} before persisting a finding, so whitelisting
 * affects *future* scans; existing open findings are cleared separately by the bulk action that
 * adds the entry.
 */
class Whitelist {

	private const OPTION = 'loyalsec_scan_whitelist';

	/**
	 * @return array<int,array{type:string,value:string,added:string}>
	 */
	public function all(): array {
		$rows = get_option( self::OPTION, array() );
		return is_array( $rows ) ? array_values( $rows ) : array();
	}

	/**
	 * Canonicalise a filesystem path to a form that is comparable whether the caller passed an
	 * absolute server path (e.g. the scanner's stored path) or the masked, ABSPATH-relative path
	 * the dashboard displays. Keeps the whitelist free of absolute server paths too.
	 */
	private function canonical( string $path ): string {
		$short = \LoyalSecurity\Support\Paths::display( $path );
		if ( null !== $short ) {
			return $short;
		}
		return ltrim( wp_normalize_path( trim( $path ) ), '/' );
	}

	/**
	 * Add an entry. $type is 'path' or 'rule'. No-op on duplicates.
	 */
	public function add( string $value, string $type = 'path' ): bool {
		$type  = 'rule' === $type ? 'rule' : 'path';
		$value = 'path' === $type ? $this->canonical( $value ) : trim( $value );
		if ( '' === $value ) {
			return false;
		}

		$rows = $this->all();
		foreach ( $rows as $row ) {
			if ( $row['type'] === $type && $row['value'] === $value ) {
				return true; // already present
			}
		}
		$rows[] = array( 'type' => $type, 'value' => $value, 'added' => gmdate( 'Y-m-d H:i:s' ) );
		update_option( self::OPTION, $rows, false );
		return true;
	}

	/**
	 * Remove an entry by type + value.
	 */
	public function remove( string $value, string $type = 'path' ): bool {
		$type  = 'rule' === $type ? 'rule' : 'path';
		$value = 'path' === $type ? $this->canonical( $value ) : trim( $value );
		$rows  = $this->all();
		$kept  = array();
		$hit   = false;
		foreach ( $rows as $row ) {
			if ( $row['type'] === $type && $row['value'] === $value ) {
				$hit = true;
				continue;
			}
			$kept[] = $row;
		}
		if ( $hit ) {
			if ( empty( $kept ) ) {
				delete_option( self::OPTION );
			} else {
				update_option( self::OPTION, array_values( $kept ), false );
			}
		}
		return $hit;
	}

	/**
	 * Whether a (path, rule) pair is suppressed by any whitelist entry.
	 */
	public function is_whitelisted( string $path, string $rule = '' ): bool {
		$path = $this->canonical( $path );
		foreach ( $this->all() as $row ) {
			if ( 'rule' === $row['type'] ) {
				if ( '' !== $rule && $row['value'] === $rule ) {
					return true;
				}
				continue;
			}
			// Path entry (stored canonical/relative): exact match, or a trailing /* tree match.
			$value = $row['value'];
			if ( $value === $path ) {
				return true;
			}
			if ( '/*' === substr( $value, -2 ) ) {
				$prefix = substr( $value, 0, -1 ); // keep trailing slash
				if ( 0 === strpos( $path, $prefix ) ) {
					return true;
				}
			}
		}
		return false;
	}
}
