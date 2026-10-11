<?php
/**
 * Identity, authentication & access-control module.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Auth;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\AbstractModule;

/**
 * Wires two-factor authentication, password policy, login CAPTCHA, and session management
 * based on settings, and exposes the operations the REST controller needs.
 */
class AuthModule extends AbstractModule {

	private ?TwoFactor $twofa = null;
	private ?SessionManager $sessions = null;

	public function id(): string {
		return 'auth';
	}

	public function title(): string {
		return __( 'Identity & Access', 'loyal-security' );
	}

	public function default_settings(): array {
		return array(
			'enabled'            => true,

			// Two-factor.
			'force_2fa'          => false,
			'force_2fa_roles'    => array( 'administrator', 'editor' ),
			'force_2fa_grace_days' => 7,

			// Breached-password check (Have I Been Pwned, k-anonymity — see readme).
			'breach_check'       => true,

			// Password policy.
			'pw_min_length'      => 12,
			'pw_mixed_case'      => true,
			'pw_number'          => true,
			'pw_special'         => true,

			// CAPTCHA.
			'captcha_provider'   => 'none', // none | turnstile | recaptcha_v3.
			'captcha_site_key'   => '',
			'captcha_secret_key' => '',
			'captcha_min_score'  => 0.5,
			// Which forms get the challenge — each is inert until a provider + keys are set
			// (Captcha::register() bails early otherwise), so defaulting all three to true
			// means the moment an admin finishes setup, every form is already protected; these
			// are then purely an opt-*out* per form, not something that needs enabling.
			'captcha_protect_login'        => true,
			'captcha_protect_register'     => true,
			'captcha_protect_lostpassword' => true,

			// Sessions.
			'idle_timeout'       => 0, // minutes; 0 = off.
			'block_concurrent'   => false,

			// Custom login URL (opt-in — see LoginUrlGuard/LoginUrlInstaller).
			'login_url_enabled'  => false,
			'login_url_slug'     => '',
		);
	}

	public function twofa(): TwoFactor {
		if ( null === $this->twofa ) {
			$this->twofa = new TwoFactor();
		}
		return $this->twofa;
	}

	public function sessions(): SessionManager {
		if ( null === $this->sessions ) {
			$this->sessions = new SessionManager( $this->settings(), $this->logger() );
		}
		return $this->sessions;
	}

	public function boot(): void {
		// Each engine is guarded with class_exists so a single missing or quarantined class
		// file degrades just that one feature instead of fataling the whole site. (Some hosts'
		// malware scanners quarantine individual plugin files; without these guards a missing
		// Captcha.php white-screens all of WordPress.) Matches the plugin's fail-open philosophy.

		// Password policy.
		if ( class_exists( PasswordPolicy::class ) ) {
			( new PasswordPolicy( $this->settings() ) )->register();
		}

		// CAPTCHA on login.
		if ( class_exists( Captcha::class ) ) {
			( new Captcha( $this->settings() ) )->register();
		}

		// Two-factor login integration + enforcement.
		if ( class_exists( LoginGuard::class ) && class_exists( TwoFactor::class ) ) {
			( new LoginGuard( $this->settings(), $this->twofa(), $this->logger() ) )->register();
		}

		// Passkey sign-in button — independent of force_2fa/TOTP enrollment, since a passkey is
		// a complete sign-in method on its own, not a second factor on top of a password.
		if ( class_exists( PasskeyLogin::class ) ) {
			( new PasskeyLogin( $this->settings(), $this->logger() ) )->register();
		}

		// Grace-period reminder popup — separate from LoginGuard's hard redirect, and enqueued
		// globally (not just on the plugin's own admin pages) since it has to reach a user
		// wherever they land in wp-admin during their grace period, not only if they happen to
		// visit the React dashboard. Also owns enqueueing that same popup script in "manage"
		// mode on profile.php — see its class docblock for why both live in one place.
		if ( class_exists( TwoFactorEnrollPrompt::class ) && class_exists( TwoFactorGracePeriod::class ) ) {
			( new TwoFactorEnrollPrompt( $this->settings(), $this->twofa(), new TwoFactorGracePeriod( $this->settings() ) ) )->register_hooks();
		}

		// The profile.php trigger button for that "manage" mode — always available, regardless
		// of force_2fa, so any user has a permanent way to remove their own 2FA later.
		if ( class_exists( TwoFactorProfileSection::class ) ) {
			( new TwoFactorProfileSection( $this->twofa() ) )->register_hooks();
		}

		// Session management.
		if ( class_exists( SessionManager::class ) ) {
			$this->sessions()->register();
		}

		// Breached-password detection (HaveIBeenPwned k-anonymity) — flags, never blocks.
		if ( class_exists( BreachCheck::class ) && $this->setting( 'breach_check', true ) ) {
			( new BreachCheck() )->register_hooks();
		}

		// Custom login URL — only once a slug is actually configured (the installer's
		// self-test + auto-rollback runs when the admin saves it; see LoginUrlController).
		$slug = (string) $this->setting( 'login_url_slug', '' );
		if ( class_exists( LoginUrlGuard::class ) && $this->setting( 'login_url_enabled', false ) && '' !== $slug ) {
			( new LoginUrlGuard( $slug, $this->logger() ) )->register();
		}
	}
}
