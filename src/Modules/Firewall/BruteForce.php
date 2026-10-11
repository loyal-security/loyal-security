<?php
/**
 * Login brute-force protection.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;
use LoyalSecurity\Modules\Audit\Logger;
use LoyalSecurity\Modules\Audit\EventCatalog;

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
		add_action( 'wp_login_failed', array( $this, 'on_failed' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'on_success' ), 10, 2 );
		// Refuse sign-in for banned or locked-out addresses. Runs after WordPress's own
		// checks: wp_authenticate_username_password() (priority 20) ignores an error returned
		// before it and signs the user in anyway when the password is right.
		add_filter( 'authenticate', array( $this, 'pre_auth_gate' ), 99 );
	}

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_login_attempts';
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
				'loyalsec_banned',
				__( 'Access from your IP address has been temporarily blocked due to suspicious activity.', 'loyal-security' )
			);
		}
		$until = (int) get_transient( self::lock_key( $ip ) );
		if ( $until > time() ) {
			$minutes = max( 1, (int) ceil( ( $until - time() ) / 60 ) );
			return new \WP_Error(
				'loyalsec_login_locked',
				sprintf(
					/* translators: %d: minutes until sign-in is possible again. */
					_n( 'Too many failed sign-in attempts. Please try again in %d minute, or reset your password.', 'Too many failed sign-in attempts. Please try again in %d minutes, or reset your password.', $minutes, 'loyal-security' ),
					$minutes
				)
			);
		}
		return $user;
	}

	/**
	 * Lock sign-in for an address without banning it from the site. For add-ons that tighten
	 * sign-in temporarily (an emergency mode, for example).
	 *
	 * @since 1.5.1
	 *
	 * @param string $ip      Address.
	 * @param int    $seconds Lockout length.
	 */
	public static function lock_sign_in( string $ip, int $seconds ): void {
		if ( '' === $ip || $seconds < 1 ) {
			return;
		}
		$until = time() + $seconds;
		if ( (int) get_transient( self::lock_key( $ip ) ) < $until ) {
			set_transient( self::lock_key( $ip ), $until, $seconds );
		}
	}

	/**
	 * Transient holding the end of an address's sign-in lockout.
	 *
	 * @param string $ip Address.
	 */
	private static function lock_key( string $ip ): string {
		return 'loyalsec_login_lock_' . md5( $ip );
	}

	/**
	 * Login errors that are prompts or incomplete forms, not wrong credentials. WordPress fires
	 * `wp_login_failed` for every login error, including "enter your two-factor code" after a
	 * correct password; counting those let a 2FA user collect failures just by signing in
	 * normally (and get banned outright where a single failure bans).
	 */
	private const NOT_FAILURES = array( 'loyalsec_2fa_required', 'empty_username', 'empty_password', 'loyalsec_login_locked' );

	/**
	 * Whether a login error is a real failed attempt.
	 *
	 * @param mixed $error The WP_Error passed with `wp_login_failed` (WordPress 5.4+), if any.
	 */
	private function counts_as_failure( $error ): bool {
		if ( ! $error instanceof \WP_Error ) {
			return true;
		}
		/**
		 * Filters the login error codes that are not counted as failed logins (prompts such as
		 * "enter your code", rather than wrong credentials).
		 *
		 * @since 1.5.0
		 *
		 * @param string[] $codes Error codes.
		 */
		$ignored = (array) apply_filters( 'loyalsec_login_failure_ignored_codes', self::NOT_FAILURES );
		$codes   = $error->get_error_codes();
		return ! $codes || array_diff( $codes, $ignored );
	}

	/**
	 * @param string $username Attempted username.
	 * @param mixed  $error    The login error (WordPress 5.4+).
	 */
	public function on_failed( $username, $error = null ): void {
		global $wpdb;
		if ( ! $this->counts_as_failure( $error ) ) {
			return;
		}
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
		do_action( 'loyalsec_login_failed', $ip, (string) $username );

		// Behind an unconfigured proxy every visitor shares one internal address; locking it would
		// lock everyone out of sign-in. The attempt is recorded above; the owner is told to add
		// the proxy under Trusted proxies.
		if ( \LoyalSecurity\Support\Ip::behind_unknown_proxy( $ip, \LoyalSecurity\Support\RequestVars::ip_headers() ) ) {
			return;
		}

		$window    = (int) $this->settings->get( 'firewall', 'bruteforce_window', 600 );
		$max_fails = (int) $this->settings->get( 'firewall', 'bruteforce_max', 5 );

		// Count the failures inside the window that came after this address's last successful
		// sign-in: someone who mistyped twice, got in, and mistypes again later is not guessing.
		$since       = time() - $window;
		$last_signin = (string) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live attempt log.
			$wpdb->prepare(
				'SELECT MAX(created_at) FROM %i WHERE ip = %s AND success = 1 AND created_at > %s',
				$this->table(),
				$ip,
				gmdate( 'Y-m-d H:i:s', $since )
			)
		);
		if ( '' !== $last_signin ) {
			$since = max( $since, (int) strtotime( $last_signin . ' UTC' ) );
		}

		$recent = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE ip = %s AND success = 0 AND created_at > %s", $this->table(),
				$ip,
				gmdate( 'Y-m-d H:i:s', $since )
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

			if ( $permanent ) {
				// Four times the limit inside one window is a bot, not a person: the address
				// loses the whole site.
				$this->bans->add(
					$ip,
					sprintf( 'Brute-force: %d failed logins', $recent ),
					'permanent',
					null,
					'bruteforce'
				);
			} else {
				// Otherwise only sign-in is locked (for longer each time it happens again).
				// Banning the whole site would also stop a customer who forgot their password
				// from browsing and checking out, and a whole office or mobile network behind one
				// address.
				set_transient( self::lock_key( $ip ), time() + $lockout, $lockout );
			}

			$this->logger->log(
				EventCatalog::WAF_BRUTEFORCE,
				array(
					'ip'              => $ip,
					'fails'           => $recent,
					'permanent'       => $permanent,
					'prior_offenses'  => $offenses,
					'lockout_seconds' => $permanent ? null : $lockout,
					'scope'           => $permanent ? 'site' : 'login',
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
