<?php
/**
 * Known-good files the malware scanner may skip.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * This plugin's own files contain detection patterns (signature lists, the scanner's rules), so
 * scanning them finds "malware" in every one. Skipping the plugin's whole folder would hide
 * anything an attacker planted there, so instead each release ships `data/file-hashes.php`,
 * generated at build time: the SHA-256 of every shipped file. A file is trusted only at its own
 * path and only while its content still matches; added or changed files are scanned as normal.
 *
 * Other plugins (for example an add-on with its own licence code) can register their shipped
 * files the same way through the `loyalsec_scanner_trusted_files` filter.
 */
final class TrustedFiles {

	/**
	 * Path => SHA-256 map of trusted files.
	 *
	 * @return array<string, string> Normalized absolute path => lowercase hex SHA-256.
	 */
	public static function map(): array {
		$map = self::from_manifest( LOYALSEC_PATH, LOYALSEC_PATH . 'data/file-hashes.php' );

		/**
		 * Filters the files the malware scanner trusts without scanning.
		 *
		 * A file is skipped only when it sits at exactly this path and its SHA-256 matches, so a
		 * modified or added file is still scanned. Use {@see TrustedFiles::from_manifest()} to
		 * load a manifest in the same format as this plugin's `data/file-hashes.php`.
		 *
		 * @since 1.5.0
		 *
		 * @param array<string, string> $map Normalized absolute path => SHA-256 (hex).
		 */
		$filtered = apply_filters( 'loyalsec_scanner_trusted_files', $map );
		if ( ! is_array( $filtered ) ) {
			return $map;
		}

		$out = array();
		foreach ( $filtered as $path => $hash ) {
			if ( is_string( $path ) && is_string( $hash ) && 1 === preg_match( '/^[a-f0-9]{64}$/', $hash ) ) {
				$out[ wp_normalize_path( $path ) ] = $hash;
			}
		}
		return $out;
	}

	/**
	 * Read a build-time manifest: a PHP file returning array( 'files' => array( relative path => SHA-256 ) ).
	 *
	 * @param string $base     Absolute folder the relative paths start from.
	 * @param string $manifest Absolute path of the manifest file.
	 * @return array<string, string> Normalized absolute path => SHA-256.
	 */
	public static function from_manifest( string $base, string $manifest ): array {
		if ( ! is_file( $manifest ) ) {
			return array();
		}
		$data = include $manifest;
		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return array();
		}
		$base = trailingslashit( wp_normalize_path( $base ) );
		$out  = array();
		foreach ( $data['files'] as $rel => $hash ) {
			if ( is_string( $rel ) && is_string( $hash ) && false === strpos( $rel, '..' ) ) {
				$out[ $base . ltrim( $rel, '/' ) ] = strtolower( $hash );
			}
		}
		return $out;
	}
}
