<?php
/**
 * Live Traffic Monitor module.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Traffic;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\AbstractModule;

/**
 * Owns the Live Traffic feature's settings and boots the all-traffic capture hook. The REST
 * controller reads from the TrafficBuffer while all-traffic recording is on, and from the
 * security-events table otherwise.
 */
class TrafficModule extends AbstractModule {

	/** Allowed range for the configurable buffer size (entries). */
	private const MIN_BUFFER = 50;
	private const MAX_BUFFER = 5000;

	public function id(): string {
		return 'traffic';
	}

	public function title(): string {
		return __( 'Live Traffic', 'loyal-security' );
	}

	/**
	 * Default settings.
	 */
	public function default_settings(): array {
		return array(
			'enabled'     => true,
			'capture_all' => true,  // Record every request (not just security events) for Live Traffic.
			'buffer_size' => 500,   // Most recent requests kept in the circular buffer (50–5000).
			'skip_static' => true,  // Don't record static assets (.css/.js/.png…) to save buffer space.
		);
	}

	public function register_hooks(): void {
		// Nothing at register time; hooks boot when the module is enabled.
	}

	/**
	 * Boot the all-traffic capture hook while recording is on.
	 */
	public function boot(): void {
		if ( ! $this->capture_enabled() ) {
			return;
		}
		( new TrafficCapture( $this->buffer() ) )->register( (bool) $this->setting( 'skip_static', true ) );
	}

	/** Whether every request is being recorded into the Live Traffic buffer. */
	public function capture_enabled(): bool {
		return (bool) $this->setting( 'capture_all', true );
	}

	/**
	 * The Live Traffic buffer, sized from the `buffer_size` setting.
	 *
	 * @param bool $unused Kept for backward compatibility with older callers; ignored.
	 */
	public function buffer( bool $unused = true ): TrafficBuffer {
		unset( $unused );
		$size = (int) $this->setting( 'buffer_size', 500 );
		return new TrafficBuffer( max( self::MIN_BUFFER, min( self::MAX_BUFFER, $size ) ) );
	}
}
