<?php
/**
 * Append-only file logger for the pre-WordPress WAF layer.
 *
 * Events recorded here (before $wpdb exists) are reconciled into the audit `events` table
 * by the Firewall module on the next WordPress request.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Waf;

defined( 'ABSPATH' ) || exit;

class Logger {

	private string $file;

	public function __construct( string $dir ) {
		$this->file = rtrim( $dir, '/\\' ) . '/waf-events.log';
	}

	/**
	 * Append one event as a JSON line.
	 *
	 * @param string               $type    Event type.
	 * @param RequestContext       $req     Request context.
	 * @param array<string, mixed> $context Extra structured context.
	 */
	public function record( string $type, RequestContext $req, array $context = array() ): void {
		$entry = array(
			'ts'      => gmdate( 'Y-m-d H:i:s' ),
			'type'    => $type,
			'ip'      => $req->ip,
			'method'  => $req->method,
			'uri'     => substr( $req->uri, 0, 512 ),
			'ua'      => substr( $req->user_agent, 0, 256 ),
			'context' => $context,
		);
		@file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
			$this->file,
			json_encode( $entry ) . "\n",
			FILE_APPEND | LOCK_EX
		);
	}

	/**
	 * Read and truncate the pending log (used by the WP-side reconciler).
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function drain(): array {
		if ( ! is_file( $this->file ) ) {
			return array();
		}
		$fh = @fopen( $this->file, 'c+' ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
		if ( ! $fh ) {
			return array();
		}
		@flock( $fh, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$raw = stream_get_contents( $fh );
		ftruncate( $fh, 0 );
		@flock( $fh, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- this WAF kernel class is shared with the pre-WordPress prepend bootstrapper; WP_Filesystem is unavailable there.
		fclose( $fh );

		$events = array();
		foreach ( explode( "\n", (string) $raw ) as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$decoded = json_decode( $line, true );
			if ( is_array( $decoded ) ) {
				$events[] = $decoded;
			}
		}
		return $events;
	}
}
