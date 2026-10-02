<?php
/**
 * Standard-Mode rate limiter.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Waf\FileStore;

/**
 * Sliding-window rate limiter that reuses the same flat-file backend as the prepend, so
 * Optimized and Standard modes share one source of truth for per-IP request counts.
 */
class RateLimiter {

	private FileStore $store;

	public function __construct() {
		$this->store = new FileStore( BanStore::storage_dir() );
	}

	/**
	 * Record a hit and report whether the IP has exceeded the limit.
	 *
	 * @return array{exceeded:bool,count:int}
	 */
	public function hit( string $ip, int $limit, int $window ): array {
		return $this->store->hit_rate( $ip, $limit, $window );
	}

	/**
	 * Periodic cleanup hook target.
	 */
	public function gc(): void {
		$this->store->gc_rate();
	}
}
