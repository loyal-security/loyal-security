<?php
/**
 * Marked blocks in server configuration files (.htaccess, wp-config.php).
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Finds and removes blocks the plugin wrote between a BEGIN and an END marker line. A marker
 * only counts when it is the whole line, so one block's marker can never match the start of
 * another's (e.g. "# BEGIN Loyal Security" vs "# BEGIN Loyal Security WAF"). Every helper takes
 * a list of [ begin, end ] pairs so blocks written under the plugin's earlier name ("Total
 * Security WP") are still recognised and removed.
 *
 * Deliberately free of other WordPress dependencies: uninstall.php loads this file directly.
 */
final class Markers {

	/**
	 * Remove every block delimited by one of the marker pairs.
	 *
	 * @param string                               $content File contents.
	 * @param array<int, array{0:string,1:string}> $pairs   [ begin, end ] marker lines.
	 */
	public static function strip( string $content, array $pairs ): string {
		foreach ( $pairs as $pair ) {
			$pattern = '/^[ \t]*' . preg_quote( $pair[0], '/' ) . '[ \t]*\r?\n.*?^[ \t]*' . preg_quote( $pair[1], '/' ) . '[ \t]*(?:\r?\n|\z)/ms';
			$content = (string) preg_replace( $pattern, '', $content );
		}
		return $content;
	}

	/**
	 * Whether any of the marker pairs' BEGIN line is present.
	 *
	 * @param string                               $content File contents.
	 * @param array<int, array{0:string,1:string}> $pairs   [ begin, end ] marker lines.
	 */
	public static function present( string $content, array $pairs ): bool {
		foreach ( $pairs as $pair ) {
			if ( preg_match( '/^[ \t]*' . preg_quote( $pair[0], '/' ) . '[ \t]*\r?$/m', $content ) ) {
				return true;
			}
		}
		return false;
	}
}
