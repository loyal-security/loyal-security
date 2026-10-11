<?php
/**
 * Bundled IP-to-country table.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Looks addresses up in `data/geo/country.dat`, built from "IP to Country Lite" by DB-IP
 * (https://db-ip.com, CC BY 4.0) and refreshed with each plugin release. The file is
 * binary-searched on disk (about 20 small reads per lookup), so the 5 MB table is never loaded
 * into memory and no request is made to any outside service.
 *
 * Format (big-endian): "LSGEO1", the 7-byte release month, a uint16 count of 2-letter country
 * codes and the codes themselves (index 0 = "ZZ", unknown), then uint32 IPv4 and IPv6 record
 * counts, then the IPv4 records (first address, 4 bytes + code index, 1 byte) and the IPv6
 * records (first /64, 8 bytes + code index, 1 byte), each list sorted and covering its address
 * space without gaps. The builder is docs/tests/build-geo.py in the development repository.
 */
final class CountryTable {

	/** @var array{codes: string[], n4: int, n6: int, v4_at: int, v6_at: int, month: string}|false|null Parsed header, false when unusable. */
	private static $header = null;

	/**
	 * ISO 3166 alpha-2 country of an address, or '' when unknown (private, reserved or
	 * unallocated addresses, or the table is missing).
	 */
	public static function lookup( string $ip ): string {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an invalid address is simply unknown.
		if ( false === $bin ) {
			return '';
		}
		// An IPv4 address written as IPv6 (::ffff:a.b.c.d) is looked up as IPv4.
		if ( 16 === strlen( $bin ) && str_repeat( "\0", 10 ) . "\xff\xff" === substr( $bin, 0, 12 ) ) {
			$bin = substr( $bin, 12 );
		}
		$header = self::header();
		if ( ! $header ) {
			return '';
		}

		if ( 4 === strlen( $bin ) ) {
			$key   = $bin;
			$count = $header['n4'];
			$at    = $header['v4_at'];
			$size  = 5;
		} else {
			$key   = substr( $bin, 0, 8 );
			$count = $header['n6'];
			$at    = $header['v6_at'];
			$size  = 9;
		}
		if ( $count < 1 ) {
			return '';
		}

		$fh = fopen( self::path(), 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- random-access reads of a bundled data file; WP_Filesystem has no seek.
		if ( ! $fh ) {
			return '';
		}
		$width = $size - 1;
		$lo    = 0;
		$hi    = $count - 1;
		$found = -1;
		while ( $lo <= $hi ) {
			$mid = ( $lo + $hi ) >> 1;
			fseek( $fh, $at + $mid * $size );
			$start = (string) fread( $fh, $width ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- see fopen above.
			if ( strcmp( $start, $key ) <= 0 ) {
				$found = $mid;
				$lo    = $mid + 1;
			} else {
				$hi = $mid - 1;
			}
		}
		$code = '';
		if ( $found >= 0 ) {
			fseek( $fh, $at + $found * $size + $width );
			$idx  = ord( (string) fread( $fh, 1 ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- see fopen above.
			$code = $header['codes'][ $idx ] ?? '';
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- see fopen above.

		return ( '' === $code || 'ZZ' === $code ) ? '' : $code;
	}

	/**
	 * Whether the table is installed and readable.
	 */
	public static function available(): bool {
		return (bool) self::header();
	}

	/**
	 * Release month of the bundled data ("YYYY-MM"), or '' when the table is missing.
	 */
	public static function month(): string {
		$header = self::header();
		return $header ? $header['month'] : '';
	}

	private static function path(): string {
		return LOYALSEC_PATH . 'data/geo/country.dat';
	}

	/**
	 * Read and validate the header once per request.
	 *
	 * @return array{codes: string[], n4: int, n6: int, v4_at: int, v6_at: int, month: string}|false
	 */
	private static function header() {
		if ( null !== self::$header ) {
			return self::$header;
		}
		self::$header = false;
		$path         = self::path();
		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return false;
		}
		$fh = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see lookup().
		if ( ! $fh ) {
			return false;
		}
		$head = (string) fread( $fh, 15 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- see lookup().
		if ( 15 !== strlen( $head ) || 'LSGEO1' !== substr( $head, 0, 6 ) ) {
			fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- see lookup().
			return false;
		}
		$ncc   = unpack( 'n', substr( $head, 13, 2 ) )[1];
		$codes = str_split( (string) fread( $fh, $ncc * 2 ), 2 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- see lookup().
		$cnt   = unpack( 'N2', (string) fread( $fh, 8 ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- see lookup().
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- see lookup().
		if ( count( $codes ) !== $ncc || ! is_array( $cnt ) ) {
			return false;
		}

		$v4_at = 15 + $ncc * 2 + 8;
		$v6_at = $v4_at + $cnt[1] * 5;
		if ( filesize( $path ) !== $v6_at + $cnt[2] * 9 ) {
			return false; // Truncated or foreign file.
		}

		self::$header = array(
			'codes' => $codes,
			'n4'    => (int) $cnt[1],
			'n6'    => (int) $cnt[2],
			'v4_at' => $v4_at,
			'v6_at' => $v6_at,
			'month' => substr( $head, 6, 7 ),
		);
		return self::$header;
	}
}
