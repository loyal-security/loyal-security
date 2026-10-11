<?php
/**
 * Two-factor management entry point on the user's own Profile screen.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Renders a small status + "Manage two-factor authentication" section on profile.php — the one
 * wp-admin screen every user, regardless of role or capability, can always reach for their own
 * account. This exists because everywhere else 2FA can be managed (the plugin's own admin page,
 * TwoFactorEnrollPrompt's reminder popup) either requires manage_loyal_security or only shows
 * up for someone who hasn't enrolled yet — once an Editor (say) has enrolled, there was
 * previously no page they could ever reach again to turn it back off.
 *
 * Only renders/acts on the profile being viewed if it's the current user's own — even an
 * administrator editing someone else's profile sees nothing from this section for that other
 * user's 2FA. The button's click listener is attached by 2fa-enroll-prompt.js (by its
 * `data-loyalsec-2fa-open` attribute); this class only renders the trigger and its enqueue is owned by
 * TwoFactorEnrollPrompt, which is what actually loads that script on profile.php.
 */
class TwoFactorProfileSection {

	private TwoFactor $twofa;

	public function __construct( TwoFactor $twofa ) {
		$this->twofa = $twofa;
	}

	public function register_hooks(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'edit_user_profile', array( $this, 'render' ) );
	}

	public function render( \WP_User $user ): void {
		if ( get_current_user_id() !== (int) $user->ID ) {
			return;
		}
		$enabled = $this->twofa->is_enabled( (int) $user->ID );
		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication', 'loyal-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'Status', 'loyal-security' ); ?></th>
				<td>
					<p>
						<?php if ( $enabled ) : ?>
							<strong class="loyalsec-2fa-enabled"><?php esc_html_e( 'Enabled', 'loyal-security' ); ?></strong>
						<?php else : ?>
							<strong><?php esc_html_e( 'Not enabled', 'loyal-security' ); ?></strong>
						<?php endif; ?>
					</p>
					<button type="button" class="button" data-loyalsec-2fa-open="1">
						<?php echo $enabled
							? esc_html__( 'Manage two-factor authentication', 'loyal-security' )
							: esc_html__( 'Set up two-factor authentication', 'loyal-security' ); ?>
					</button>
				</td>
			</tr>
		</table>
		<?php
	}
}
