<?php
/**
 * Per-user grace period for enforced two-factor enrollment.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\Settings;

/**
 * Rolling out `force_2fa` immediately locks out every non-enrolled user in an enforced role on
 * their very next admin request, with no warning. This gives each user their own countdown
 * instead: a grace period (site-wide length, but a per-user deadline) during which they see a
 * dismissible reminder, followed by hard enforcement once their personal deadline passes. An
 * administrator can push a specific user's deadline out further without changing the site-wide
 * setting for everyone else.
 *
 * State lives in two user meta keys, both lazily created the first time a given user is
 * actually evaluated (not backfilled for the whole user table up front, so turning the setting
 * on doesn't itself require a migration):
 *   - loyalsec_2fa_grace_until   (int unix timestamp) — hard-enforcement deadline.
 *   - loyalsec_2fa_popup_snoozed_until (int unix timestamp) — reminder popup suppressed until.
 */
class TwoFactorGracePeriod {

	private const DEADLINE_META = 'loyalsec_2fa_grace_until';
	private const SNOOZE_META   = 'loyalsec_2fa_popup_snoozed_until';

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	private function grace_days(): int {
		return max( 0, (int) $this->settings->get( 'auth', 'force_2fa_grace_days', 7 ) );
	}

	/**
	 * This user's enforcement deadline, creating it (grace period starting now) on first
	 * encounter. Stable afterward except via extend() — a later increase to the site-wide
	 * grace_days setting deliberately does not retroactively push out a deadline that was
	 * already assigned, so shortening the window can't un-enforce someone who was already
	 * overdue, and lengthening it can't silently reset a countdown someone already saw.
	 */
	public function deadline_for( int $user_id ): int {
		$existing = (int) get_user_meta( $user_id, self::DEADLINE_META, true );
		if ( $existing > 0 ) {
			return $existing;
		}
		$deadline = time() + ( $this->grace_days() * DAY_IN_SECONDS );
		update_user_meta( $user_id, self::DEADLINE_META, $deadline );
		return $deadline;
	}

	/** Whether this user's grace period has run out — enforcement should be hard now. */
	public function is_enforced_now( int $user_id ): bool {
		return time() >= $this->deadline_for( $user_id );
	}

	/** Whole days remaining before hard enforcement (0 once expired, never negative). */
	public function remaining_days( int $user_id ): int {
		$seconds = $this->deadline_for( $user_id ) - time();
		return max( 0, (int) ceil( $seconds / DAY_IN_SECONDS ) );
	}

	/**
	 * Admin action: push a user's deadline forward by $days from whichever is later — now, or
	 * their existing deadline. Always from "later of the two" so extending an already-expired
	 * user by 3 days gives them 3 real days, not 3 days added to a deadline already in the past
	 * (which would leave them still immediately enforced).
	 */
	public function extend( int $user_id, int $days ): int {
		$base     = max( time(), $this->deadline_for( $user_id ) );
		$deadline = $base + ( max( 0, $days ) * DAY_IN_SECONDS );
		update_user_meta( $user_id, self::DEADLINE_META, $deadline );
		// A fresh extension should show the reminder again promptly, not stay silenced by a
		// snooze set before the admin intervened.
		delete_user_meta( $user_id, self::SNOOZE_META );
		return $deadline;
	}

	/**
	 * Admin action: end this user's grace period immediately — their very next admin request
	 * hits the hard redirect instead of waiting out the countdown. Also clears any snooze, so
	 * the non-dismissible popup state takes effect right away rather than staying suppressed
	 * until whatever snooze window they last set.
	 */
	public function enforce_now( int $user_id ): int {
		$deadline = time();
		update_user_meta( $user_id, self::DEADLINE_META, $deadline );
		delete_user_meta( $user_id, self::SNOOZE_META );
		return $deadline;
	}

	/** Whether the reminder popup should stay hidden right now for this user. */
	public function is_snoozed( int $user_id ): bool {
		return time() < (int) get_user_meta( $user_id, self::SNOOZE_META, true );
	}

	/** Suppress the reminder popup for this user for one day. */
	public function snooze( int $user_id ): void {
		update_user_meta( $user_id, self::SNOOZE_META, time() + DAY_IN_SECONDS );
	}
}
