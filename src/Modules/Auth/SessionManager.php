<?php
/**
 * Session management — idle timeout, concurrent-login control, global logout.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\Settings;
use TotalSecurityWP\Modules\Audit\Logger;
use TotalSecurityWP\Modules\Audit\EventCatalog;

/**
 * Enforces idle session expiry, optionally blocks concurrent logins (one active session per
 * user), and provides a force-logout-everywhere tool. Built on WordPress's native session
 * token store so it cooperates with core auth.
 */
class SessionManager {

	private Settings $settings;
	private Logger $logger;

	public function __construct( Settings $settings, Logger $logger ) {
		$this->settings = $settings;
		$this->logger   = $logger;
	}

	public function register(): void {
		if ( (int) $this->settings->get( 'auth', 'idle_timeout', 0 ) > 0 ) {
			add_action( 'init', array( $this, 'enforce_idle_timeout' ) );
		}
		if ( $this->settings->get( 'auth', 'block_concurrent', false ) ) {
			add_filter( 'wp_authenticate_user', array( $this, 'block_concurrent' ), 20, 1 );
		}
	}

	/**
	 * Log out sessions idle longer than the configured timeout (minutes).
	 */
	public function enforce_idle_timeout(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}
		$timeout = (int) $this->settings->get( 'auth', 'idle_timeout', 0 ) * MINUTE_IN_SECONDS;
		if ( $timeout <= 0 ) {
			return;
		}

		$user_id = get_current_user_id();
		$last    = (int) get_user_meta( $user_id, 'totalsecwp_last_activity', true );
		$now     = time();

		if ( $last && ( $now - $last ) > $timeout ) {
			$this->logger->log( EventCatalog::SESSION_DESTROYED, array( 'user_id' => $user_id, 'reason' => 'idle_timeout' ) );
			wp_logout();
			wp_safe_redirect( wp_login_url() . '?totalsecwp_idle=1' );
			exit;
		}
		update_user_meta( $user_id, 'totalsecwp_last_activity', $now );
	}

	/**
	 * Destroy other sessions when a user logs in (one active session per user).
	 *
	 * @param mixed $user Authenticated user (or WP_Error).
	 * @return mixed
	 */
	public function block_concurrent( $user ) {
		if ( $user instanceof \WP_User ) {
			$manager = \WP_Session_Tokens::get_instance( $user->ID );
			$manager->destroy_all();
			$this->logger->log( EventCatalog::SESSION_DESTROYED, array( 'user_id' => $user->ID, 'reason' => 'concurrent_block' ) );
		}
		return $user;
	}

	/**
	 * Destroy all sessions for a single user.
	 */
	public function destroy_user_sessions( int $user_id ): void {
		\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		$this->logger->log( EventCatalog::SESSION_DESTROYED, array( 'user_id' => $user_id, 'reason' => 'manual' ) );
	}

	/**
	 * Force logout for every user on the site.
	 *
	 * @return int Number of users affected.
	 */
	public function destroy_all_sessions(): int {
		global $wpdb;
		$user_ids = $wpdb->get_col( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT user_id FROM %i WHERE meta_key = %s", $wpdb->usermeta, 'session_tokens' )
		);
		$count = 0;
		foreach ( (array) $user_ids as $uid ) {
			\WP_Session_Tokens::get_instance( (int) $uid )->destroy_all();
			$count++;
		}
		$this->logger->log( EventCatalog::SESSION_DESTROYED, array( 'reason' => 'force_logout_all', 'users' => $count ) );
		return $count;
	}

	/**
	 * List a user's trusted devices (the "remember this device, skip 2FA" tokens).
	 *
	 * @return array<int, array{token_hash:string,issued_at:int,expires_at:int,user_agent:string}>
	 */
	public function get_trusted_devices( int $user_id ): array {
		return ( new TrustedDevice() )->get_trusted_devices( $user_id );
	}

	/** Every trusted device across every user — see TrustedDevice::get_all_devices(). */
	public function get_all_trusted_devices(): array {
		return ( new TrustedDevice() )->get_all_devices();
	}

	/**
	 * Revoke a single trusted device by its token hash.
	 */
	public function revoke_trusted_device( int $user_id, string $token_hash ): bool {
		$removed = ( new TrustedDevice() )->revoke_token( $user_id, $token_hash );
		if ( $removed ) {
			$this->logger->log( EventCatalog::DEVICE_TRUST_REVOKED, array( 'user_id' => $user_id ) );
		}
		return $removed;
	}
}
