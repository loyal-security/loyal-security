<?php
/**
 * Application-layer DDoS / burst shield.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;

/**
 * Detects abnormal request bursts from a single IP within a very short window (distinct
 * from the steady-state rate limiter) and escalates to a temporary ban. This mitigates
 * application-layer floods that slip under per-minute thresholds.
 */
class DdosShield {

	private Settings $settings;
	private RateLimiter $limiter;
	private BanStore $bans;

	public function __construct( Settings $settings, RateLimiter $limiter, BanStore $bans ) {
		$this->settings = $settings;
		$this->limiter  = $limiter;
		$this->bans     = $bans;
	}

	/**
	 * @return string|null Reason if the request should be blocked.
	 */
	public function evaluate( string $ip ): ?string {
		if ( ! $this->settings->get( 'firewall', 'ddos_enabled', true ) ) {
			return null;
		}

		$burst  = (int) $this->settings->get( 'firewall', 'ddos_burst', 60 );  // requests…
		$window = (int) $this->settings->get( 'firewall', 'ddos_window', 10 ); // …per N seconds.

		$result = $this->limiter->hit( 'ddos:' . $ip, $burst, $window );
		if ( ! empty( $result['exceeded'] ) ) {
			$ban_secs = (int) $this->settings->get( 'firewall', 'ddos_ban', 900 );
			$this->bans->add( $ip, 'DDoS burst protection', 'temporary', $ban_secs, 'ddos' );
			return 'ddos_burst:' . $result['count'];
		}
		return null;
	}
}
