<?php
/**
 * Login brute-force protection.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Modules\Audit\EventCatalog;

/**
 * Tracks failed/successful logins and escalates repeat offenders to temporary then
 * permanent bans. Hooks into WordPress authentication events.
 */
class BruteForce {

	private Settings $settings;
	private BanStore $bans;
	private IpResolver $ip;
	private Logger $logger;

	public function __construct( Settings $settings, BanStore $bans, IpResolver $ip, Logger $logger ) {
		$this->settings = $settings;
		$this->bans     = $bans;
		$this->ip       = $ip;
		$this->logger   = $logger;
	}

	public function register_hooks(): void {
		add_action( 'wp_login_failed', array( $this, 'on_failed' ), 10, 1 );
		add_action( 'wp_login', array( $this, 'on_success' ), 10, 2 );
		// Block authentication outright for banned IPs before credentials are checked.
		add_filter( 'authenticate', array( $this, 'pre_auth_gate' ), 1 );
	}

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'totalsecwp_login_attempts';
	}

	/**
	 * Reject authentication early if the IP is banned.
	 *
	 * @param mixed $user Current auth result.
	 * @return mixed
	 */
	public function pre_auth_gate( $user ) {
		$ip = $this->ip->current();
		if ( $this->bans->is_banned( $ip ) ) {
			return new \WP_Error(
				'totalsecwp_banned',
				__( 'Access from your IP address has been temporarily blocked due to suspicious activity.', 'loyal-security' )
			);
		}
		return $user;
	}

	/**
	 * @param string $username Attempted username.
	 */
	public function on_failed( $username ): void {
		global $wpdb;
		$ip = $this->ip->current();

		$wpdb->insert( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'ip'         => $ip,
				'username'   => mb_substr( (string) $username, 0, 191 ),
				'success'    => 0,
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			)
		);

		$this->logger->log( EventCatalog::LOGIN_FAILED, array( 'username' => (string) $username, 'ip' => $ip ) );

		/**
		 * Fires on every failed login, after it is recorded.
		 *
		 * @since 1.0.0
		 *
		 * @param string $ip       Source IP address.
		 * @param string $username Attempted username.
		 */
		do_action( 'totalsecwp_login_failed', $ip, (string) $username );

		$window    = (int) $this->settings->get( 'firewall', 'bruteforce_window', 600 );
		$max_fails = (int) $this->settings->get( 'firewall', 'bruteforce_max', 5 );

		$recent = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE ip = %s AND success = 0 AND created_at > %s", $this->table(),
				$ip,
				gmdate( 'Y-m-d H:i:s', time() - $window )
			)
		);

		if ( $recent >= $max_fails ) {
			// Count prior bans for this IP to decide temporary vs permanent escalation.
			$lockout   = (int) $this->settings->get( 'firewall', 'bruteforce_lockout', 1800 );
			$permanent = $recent >= ( $max_fails * 4 );
			$offenses  = 0;

			if ( ! $permanent && (bool) $this->settings->get( 'firewall', 'bruteforce_escalation_enabled', true ) ) {
				// Repeat-offender lockouts grow (base * multiplier^offenses, capped) instead of
				// staying flat — a bot that keeps coming back after its ban expires should meet a
				// longer wait each time. "Offenses" is simply a count of this IP's own past
				// bruteforce lockouts within the escalation window — reusing the existing audit
				// log rather than a new counter, since every past lockout is already logged here.
				$window   = (int) $this->settings->get( 'firewall', 'bruteforce_escalation_window', WEEK_IN_SECONDS );
				$offenses = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live lockout count.
					$wpdb->prepare(
						'SELECT COUNT(*) FROM %i WHERE event_type = %s AND ip = %s AND created_at > %s',
						Logger::table(),
						EventCatalog::WAF_BRUTEFORCE,
						$ip,
						gmdate( 'Y-m-d H:i:s', time() - $window )
					)
				);

				if ( $offenses > 0 ) {
					$multiplier = max( 1.0, (float) $this->settings->get( 'firewall', 'bruteforce_escalation_multiplier', 2 ) );
					$cap        = (int) $this->settings->get( 'firewall', 'bruteforce_escalation_cap', DAY_IN_SECONDS );
					$lockout    = (int) min( $cap, $lockout * ( $multiplier ** $offenses ) );
				}
			}

			$this->bans->add(
				$ip,
				sprintf( 'Brute-force: %d failed logins', $recent ),
				$permanent ? 'permanent' : 'temporary',
				$permanent ? null : $lockout,
				'bruteforce'
			);

			$this->logger->log(
				EventCatalog::WAF_BRUTEFORCE,
				array(
					'ip'              => $ip,
					'fails'           => $recent,
					'permanent'       => $permanent,
					'prior_offenses'  => $offenses,
					'lockout_seconds' => $permanent ? null : $lockout,
				)
			);
		}
	}

	/**
	 * @param string   $user_login Username.
	 * @param \WP_User $user       User object.
	 */
	public function on_success( $user_login, $user = null ): void {
		global $wpdb;
		$ip = $this->ip->current();
		$wpdb->insert( // phpcs:ignore WordPress.DB
			$this->table(),
			array(
				'ip'         => $ip,
				'username'   => mb_substr( (string) $user_login, 0, 191 ),
				'success'    => 1,
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			)
		);
		$this->logger->log( EventCatalog::LOGIN_SUCCESS, array( 'username' => (string) $user_login, 'ip' => $ip ) );
	}
}
