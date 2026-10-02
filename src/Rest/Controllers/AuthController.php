<?php
/**
 * Identity / 2FA / session REST controller.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Rest\Controllers;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Rest\AbstractController;
use TotalSecurityWP\Plugin;
use TotalSecurityWP\Modules\Auth\AuthModule;
use TotalSecurityWP\Modules\Auth\LoginUrlInstaller;
use TotalSecurityWP\Modules\Auth\TwoFactorGracePeriod;
use TotalSecurityWP\Modules\Auth\Passkey;
use TotalSecurityWP\Modules\Auth\WebAuthnCeremony;
use TotalSecurityWP\Modules\Firewall\BanStore;
use TotalSecurityWP\Modules\Firewall\IpResolver;
use TotalSecurityWP\Modules\Audit\EventCatalog;
use WP_REST_Request;
use WP_Error;

/**
 * Self-service two-factor enrollment for the current user, plus admin session tools.
 */
class AuthController extends AbstractController {

	/** Reserved slugs a custom login URL may never take. */
	private const RESERVED_SLUGS = array(
		'', 'wp-admin', 'wp-login', 'wp-login.php', 'wp-content', 'wp-includes', 'wp-json',
		'xmlrpc.php', 'feed', 'comments', 'embed', 'admin', 'login', 'favicon.ico', 'robots.txt',
		'sitemap.xml', 'wp-cron.php',
	);

	public function register_routes(): void {
		$ns = $this->namespace();

		register_rest_route( $ns, '/auth/login-url', array(
			array( 'methods' => 'GET', 'callback' => array( $this, 'login_url_status' ), 'permission_callback' => array( $this, 'permission_check' ) ),
			array( 'methods' => 'POST', 'callback' => array( $this, 'login_url_save' ), 'permission_callback' => array( $this, 'permission_check' ) ),
		) );

		// 2FA self-service: any logged-in user (so enforced editors can enrol).
		$self = array( $this, 'logged_in_check' );

		register_rest_route( $ns, '/auth/2fa/status', array(
			'methods' => 'GET', 'callback' => array( $this, 'status' ), 'permission_callback' => $self,
		) );
		register_rest_route( $ns, '/auth/2fa/begin', array(
			'methods' => 'POST', 'callback' => array( $this, 'begin' ), 'permission_callback' => $self,
		) );
		register_rest_route( $ns, '/auth/2fa/confirm', array(
			'methods' => 'POST', 'callback' => array( $this, 'confirm' ), 'permission_callback' => $self,
		) );
		register_rest_route( $ns, '/auth/2fa/disable', array(
			'methods' => 'POST', 'callback' => array( $this, 'disable' ), 'permission_callback' => $self,
		) );

		// Grace-period roll-out: who's still pending, and letting an admin extend one user.
		register_rest_route( $ns, '/auth/2fa-grace', array(
			'methods' => 'GET', 'callback' => array( $this, 'grace_list' ), 'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/auth/2fa-grace/extend', array(
			'methods' => 'POST', 'callback' => array( $this, 'grace_extend' ), 'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/auth/2fa-grace/enforce', array(
			'methods' => 'POST', 'callback' => array( $this, 'grace_enforce' ), 'permission_callback' => array( $this, 'permission_check' ),
		) );

		// Session tools: require management capability.
		register_rest_route( $ns, '/auth/sessions/destroy-all', array(
			'methods' => 'POST', 'callback' => array( $this, 'destroy_all' ), 'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/auth/sessions/destroy-mine', array(
			'methods' => 'POST', 'callback' => array( $this, 'destroy_mine' ), 'permission_callback' => $self,
		) );

		// Trusted-device management for the current user.
		register_rest_route( $ns, '/auth/trusted-devices', array(
			'methods' => 'GET', 'callback' => array( $this, 'list_trusted_devices' ), 'permission_callback' => $self,
		) );
		register_rest_route( $ns, '/auth/trusted-devices/(?P<hash>[a-fA-F0-9]{64})', array(
			'methods'             => 'DELETE',
			'callback'            => array( $this, 'revoke_trusted_device' ),
			'permission_callback' => $self,
			'args'                => array(
				'hash' => array(
					'required'          => true,
					'validate_callback' => static fn( $v ) => is_string( $v ) && 1 === preg_match( '/^[a-fA-F0-9]{64}$/', $v ),
				),
			),
		) );

		// Passkeys: self-service registration/management (any logged-in user).
		register_rest_route( $ns, '/auth/passkey/list', array(
			'methods' => 'GET', 'callback' => array( $this, 'passkey_list' ), 'permission_callback' => $self,
		) );
		register_rest_route( $ns, '/auth/passkey/register-options', array(
			'methods' => 'POST', 'callback' => array( $this, 'passkey_register_options' ), 'permission_callback' => $self,
		) );
		register_rest_route( $ns, '/auth/passkey/register', array(
			'methods' => 'POST', 'callback' => array( $this, 'passkey_register' ), 'permission_callback' => $self,
		) );
		register_rest_route( $ns, '/auth/passkey/(?P<id>[A-Za-z0-9_-]+)', array(
			'methods' => 'DELETE', 'callback' => array( $this, 'passkey_remove' ), 'permission_callback' => $self,
		) );

		// Passkey sign-in, step 1 — intentionally public: a visitor who isn't logged in yet asks
		// for a single-use WebAuthn challenge. It returns nothing but that challenge. Step 2 (the
		// signed assertion) is submitted with wp-login.php's own form and verified inside
		// WordPress's sign-in — see PasskeyLogin::authenticate().
		register_rest_route( $ns, '/auth/passkey/login-options', array(
			'methods' => 'GET', 'callback' => array( $this, 'passkey_login_options' ), 'permission_callback' => '__return_true',
		) );

		// Admin-wide view: every trusted device for every user, and revoking any of them (e.g.
		// a device known to be compromised) — distinct route base from the self-service ones
		// above so the two never collide, and gated by the management capability rather than
		// "any logged-in user" since it exposes other people's device lists.
		register_rest_route( $ns, '/auth/trusted-devices-admin', array(
			'methods' => 'GET', 'callback' => array( $this, 'list_all_trusted_devices' ), 'permission_callback' => array( $this, 'permission_check' ),
		) );
		register_rest_route( $ns, '/auth/trusted-devices-admin/(?P<user_id>\d+)/(?P<hash>[a-fA-F0-9]{64})', array(
			'methods'             => 'DELETE',
			'callback'            => array( $this, 'admin_revoke_trusted_device' ),
			'permission_callback' => array( $this, 'permission_check' ),
			'args'                => array(
				'user_id' => array(
					'required'          => true,
					'validate_callback' => static fn( $v ) => is_numeric( $v ) && (int) $v > 0,
				),
				'hash'    => array(
					'required'          => true,
					'validate_callback' => static fn( $v ) => is_string( $v ) && 1 === preg_match( '/^[a-fA-F0-9]{64}$/', $v ),
				),
			),
		) );
	}

	/**
	 * Permission callback: any authenticated user.
	 *
	 * @return bool
	 */
	public function logged_in_check() {
		return is_user_logged_in();
	}

	private function module(): ?AuthModule {
		$m = Plugin::instance()->module( 'auth' );
		return $m instanceof AuthModule ? $m : null;
	}

	public function status( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->ok( array( 'enabled' => false, 'available' => false ) );
		}
		$data              = $m->twofa()->status( get_current_user_id() );
		$data['available'] = true;
		return $this->ok( $data );
	}

	public function begin( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		if ( $m->twofa()->is_enabled( get_current_user_id() ) ) {
			return $this->fail( 'totalsecwp_2fa_already_active', __( 'Two-factor is already active. Disable it before starting a new enrollment.', 'loyal-security' ), 409 );
		}
		return $this->ok( $m->twofa()->begin_enroll( get_current_user_id() ) );
	}

	public function confirm( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		$code = (string) $request->get_param( 'code' );
		$res  = $m->twofa()->confirm_enroll( get_current_user_id(), $code );
		if ( empty( $res['ok'] ) ) {
			return $this->fail( 'totalsecwp_2fa_confirm', $res['message'] ?? 'Failed.', 422 );
		}
		$this->logger()->log( EventCatalog::TWOFA_ENROLLED, array( 'user_id' => get_current_user_id() ) );
		return $this->ok( $res );
	}

	public function disable( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		$m->twofa()->disable( get_current_user_id() );
		$this->logger()->log( EventCatalog::TWOFA_DISABLED, array( 'user_id' => get_current_user_id() ) );
		return $this->ok( array( 'disabled' => true ) );
	}

	public function destroy_all( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		$count = $m->sessions()->destroy_all_sessions();
		return $this->ok( array( 'users_logged_out' => $count ) );
	}

	public function destroy_mine( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		$m->sessions()->destroy_user_sessions( get_current_user_id() );
		return $this->ok( array( 'ok' => true ) );
	}

	/**
	 * List the current user's trusted devices.
	 */
	public function list_trusted_devices( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		$devices = $m->sessions()->get_trusted_devices( get_current_user_id() );
		return $this->ok( array( 'devices' => $devices ) );
	}

	/**
	 * Revoke one of the current user's trusted devices.
	 */
	public function revoke_trusted_device( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		$hash    = (string) $request->get_param( 'hash' );
		$removed = $m->sessions()->revoke_trusted_device( get_current_user_id(), $hash );
		if ( ! $removed ) {
			return $this->fail( 'totalsecwp_td_not_found', __( 'Trusted device not found.', 'loyal-security' ), 404 );
		}
		return $this->ok( array( 'revoked' => true ) );
	}

	/**
	 * Every trusted device across every user, for the admin-wide search/filter/revoke view —
	 * see TrustedDevice::get_all_devices() for why one compromised machine shouldn't require
	 * chasing down whichever user trusted it.
	 */
	public function list_all_trusted_devices( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		return $this->ok( array( 'devices' => $m->sessions()->get_all_trusted_devices() ) );
	}

	/**
	 * Admin action: revoke ANY user's trusted device (e.g. a device reported lost or
	 * compromised) — unlike revoke_trusted_device() above, not limited to the caller's own.
	 */
	public function admin_revoke_trusted_device( WP_REST_Request $request ) {
		$m = $this->module();
		if ( ! $m ) {
			return $this->fail( 'totalsecwp_auth_off', __( 'Auth module disabled.', 'loyal-security' ), 409 );
		}
		$user_id = (int) $request->get_param( 'user_id' );
		$hash    = (string) $request->get_param( 'hash' );
		// SessionManager::revoke_trusted_device() already logs DEVICE_TRUST_REVOKED with the
		// owning user_id — no separate log call needed here, just the admin-specific permission
		// gate and route (see permission_callback above).
		$removed = $m->sessions()->revoke_trusted_device( $user_id, $hash );
		if ( ! $removed ) {
			return $this->fail( 'totalsecwp_td_not_found', __( 'Trusted device not found.', 'loyal-security' ), 404 );
		}
		return $this->ok( array( 'revoked' => true ) );
	}

	/**
	 * Current custom-login-URL status for the settings UI.
	 */
	public function login_url_status( WP_REST_Request $request ) {
		$settings = $this->container->make( 'settings' );
		$enabled  = (bool) $settings->get( 'auth', 'login_url_enabled', false );
		$slug     = (string) $settings->get( 'auth', 'login_url_slug', '' );
		return $this->ok( array(
			'enabled' => $enabled,
			'slug'    => $slug,
			'applied' => ( new LoginUrlInstaller() )->is_applied(),
			'url'     => ( $enabled && '' !== $slug ) ? home_url( '/' . $slug ) : '',
		) );
	}

	/**
	 * Enable/disable the custom login URL. Enabling validates + deploys the rewrite and
	 * self-tests it (auto-rolls back on failure) before anything is persisted or enforced —
	 * see LoginUrlInstaller::apply(). Disabling always reverts the rewrite immediately.
	 */
	public function login_url_save( WP_REST_Request $request ) {
		$settings = $this->container->make( 'settings' );
		$enabled  = (bool) $request->get_param( 'enabled' );

		if ( ! $enabled ) {
			( new LoginUrlInstaller() )->revert();
			$settings->update_module( 'auth', array( 'login_url_enabled' => false ) );
			$this->logger()->log( EventCatalog::LOGIN_URL_DISABLED, array() );
			return $this->ok( array( 'enabled' => false ) );
		}

		$slug = sanitize_title( (string) $request->get_param( 'slug' ) );
		if ( '' === $slug || strlen( $slug ) < 3 || strlen( $slug ) > 64 || ! preg_match( '/^[a-z0-9-]+$/', $slug ) ) {
			return $this->fail( 'totalsecwp_login_url_invalid', __( 'Choose a slug of 3–64 letters, numbers, or hyphens.', 'loyal-security' ), 422 );
		}
		if ( in_array( $slug, self::RESERVED_SLUGS, true ) ) {
			return $this->fail( 'totalsecwp_login_url_reserved', __( 'That slug is reserved — choose another.', 'loyal-security' ), 422 );
		}
		if ( function_exists( 'get_page_by_path' ) && get_page_by_path( $slug, OBJECT, get_post_types( array( 'public' => true ) ) ) ) {
			return $this->fail( 'totalsecwp_login_url_collision', __( 'That slug is already used by a page/post on this site — choose another.', 'loyal-security' ), 422 );
		}

		$installer = new LoginUrlInstaller();
		$res       = $installer->apply( $slug );
		if ( empty( $res['ok'] ) ) {
			// Carry the Nginx fallback snippet on the *failure* path too — this is exactly the
			// case a self-hosted-Apache-rewrite failure implies (no mod_rewrite / AllowOverride,
			// most commonly an Nginx host), and previously only the success response included
			// it, leaving Nginx users with nothing but a bare error and no way to finish enabling
			// the feature.
			return new WP_Error(
				'totalsecwp_login_url_failed',
				$res['message'],
				array(
					'status'        => 500,
					'nginx_snippet' => $installer->nginx_snippet( $slug ),
				)
			);
		}

		$settings->update_module( 'auth', array( 'login_url_enabled' => true, 'login_url_slug' => $slug ) );
		$url = home_url( '/' . $slug );
		$this->logger()->log( EventCatalog::LOGIN_URL_ENABLED, array( 'slug' => $slug ) );

		$admin_email = get_option( 'admin_email' );
		if ( $admin_email ) {
			wp_mail(
				$admin_email,
				__( '[Loyal Security] Your custom login URL', 'loyal-security' ),
				sprintf(
					/* translators: 1: site name, 2: new login URL */
					__( "Loyal Security enabled a custom login URL on %1\$s.\n\nNew login page: %2\$s\n\nThe original /wp-login.php now returns a 404 for the plain login form. Keep this email — if the site becomes unreachable, an administrator with file access can add define('TOTALSECWP_DISABLE_LOGIN_URL', true); to wp-config.php to restore the original URL immediately.", 'loyal-security' ),
					get_bloginfo( 'name' ),
					$url
				)
			);
		}

		return $this->ok( array( 'enabled' => true, 'slug' => $slug, 'url' => $url, 'nginx_snippet' => $installer->nginx_snippet( $slug ) ) );
	}

	/**
	 * Every user in an enforced role, without 2FA enrolled, and their individual grace-period
	 * status — the roll-out list an admin uses to see who's still pending and extend anyone
	 * who needs more time.
	 */
	public function grace_list( WP_REST_Request $request ) {
		/** @var \TotalSecurityWP\Core\Settings $settings */
		$settings = $this->container->make( 'settings' );
		$module   = $this->module();
		if ( ! $module ) {
			return $this->ok( array() );
		}

		$roles = (array) $settings->get( 'auth', 'force_2fa_roles', array( 'administrator', 'editor' ) );
		$grace = new TwoFactorGracePeriod( $settings );
		$twofa = $module->twofa();

		$rows  = array();
		$users = get_users( array( 'role__in' => array_map( 'strval', $roles ), 'fields' => array( 'ID', 'display_name', 'user_login' ) ) );
		foreach ( $users as $u ) {
			if ( $twofa->is_enabled( (int) $u->ID ) ) {
				continue;
			}
			$user_obj = get_userdata( (int) $u->ID );
			$rows[]   = array(
				'id'             => (int) $u->ID,
				'name'           => $u->display_name,
				'login'          => $u->user_login,
				'roles'          => $user_obj ? array_values( $user_obj->roles ) : array(),
				'remaining_days' => $grace->remaining_days( (int) $u->ID ),
				'enforced'       => $grace->is_enforced_now( (int) $u->ID ),
			);
		}

		return $this->ok( $rows );
	}

	/**
	 * Admin action: give one user $days more before enforcement — see
	 * TwoFactorGracePeriod::extend() for why this is always measured from "now or their current
	 * deadline, whichever is later" rather than a flat add.
	 */
	public function grace_extend( WP_REST_Request $request ) {
		$user_id = (int) $request->get_param( 'user_id' );
		$days    = (int) $request->get_param( 'days' );

		if ( $user_id <= 0 || $days <= 0 ) {
			return $this->fail( 'totalsecwp_grace_invalid', __( 'A user and a positive number of days are required.', 'loyal-security' ), 422 );
		}
		if ( ! get_userdata( $user_id ) ) {
			return $this->fail( 'totalsecwp_grace_no_user', __( 'User not found.', 'loyal-security' ), 404 );
		}

		/** @var \TotalSecurityWP\Core\Settings $settings */
		$settings = $this->container->make( 'settings' );
		$grace    = new TwoFactorGracePeriod( $settings );
		$deadline = $grace->extend( $user_id, $days );

		$this->logger()->log( EventCatalog::SETTING_CHANGED, array( 'action' => '2fa_grace_extended', 'user_id' => $user_id, 'days' => $days ) );

		return $this->ok( array( 'user_id' => $user_id, 'deadline' => $deadline, 'remaining_days' => $grace->remaining_days( $user_id ) ) );
	}

	/**
	 * Admin action: skip the rest of one user's grace period — their next admin request is
	 * redirected to enroll instead of waiting out the countdown.
	 */
	public function grace_enforce( WP_REST_Request $request ) {
		$user_id = (int) $request->get_param( 'user_id' );
		if ( $user_id <= 0 || ! get_userdata( $user_id ) ) {
			return $this->fail( 'totalsecwp_grace_no_user', __( 'User not found.', 'loyal-security' ), 404 );
		}

		/** @var \TotalSecurityWP\Core\Settings $settings */
		$settings = $this->container->make( 'settings' );
		$grace    = new TwoFactorGracePeriod( $settings );
		$deadline = $grace->enforce_now( $user_id );

		$this->logger()->log( EventCatalog::SETTING_CHANGED, array( 'action' => '2fa_grace_enforced_now', 'user_id' => $user_id ) );

		return $this->ok( array( 'user_id' => $user_id, 'deadline' => $deadline, 'remaining_days' => 0, 'enforced' => true ) );
	}

	/**
	 * List the current user's registered passkeys — never the public key material itself,
	 * which the UI has no use for and shouldn't need to render.
	 */
	public function passkey_list( WP_REST_Request $request ) {
		$rows = array_map(
			static fn( $r ) => array(
				'id'           => $r['id'],
				'label'        => $r['label'],
				'created_at'   => $r['created_at'],
				'last_used_at' => $r['last_used_at'],
			),
			( new Passkey() )->get_credentials( get_current_user_id() )
		);
		return $this->ok( array( 'passkeys' => $rows ) );
	}

	public function passkey_register_options( WP_REST_Request $request ) {
		try {
			return $this->ok( ( new WebAuthnCeremony() )->begin_registration( get_current_user_id() ) );
		} catch ( \Throwable $e ) {
			return $this->fail( 'totalsecwp_passkey_unsupported', __( 'Passkeys are not available on this server (missing OpenSSL support).', 'loyal-security' ), 500 );
		}
	}

	public function passkey_register( WP_REST_Request $request ) {
		$client_data = (string) $request->get_param( 'clientDataJSON' );
		$attestation = (string) $request->get_param( 'attestationObject' );
		$label       = (string) $request->get_param( 'label' );
		if ( '' === $client_data || '' === $attestation ) {
			return $this->fail( 'totalsecwp_passkey_bad_request', __( 'Missing registration data.', 'loyal-security' ), 400 );
		}

		$res = ( new WebAuthnCeremony() )->complete_registration( get_current_user_id(), $client_data, $attestation, $label );
		if ( empty( $res['ok'] ) ) {
			return $this->fail( 'totalsecwp_passkey_register_failed', $res['message'] ?? __( 'Could not register passkey.', 'loyal-security' ), 422 );
		}

		$this->logger()->log( EventCatalog::PASSKEY_REGISTERED, array( 'user_id' => get_current_user_id() ) );
		return $this->ok( array( 'ok' => true ) );
	}

	public function passkey_remove( WP_REST_Request $request ) {
		$id      = (string) $request->get_param( 'id' );
		$removed = ( new Passkey() )->remove_credential( get_current_user_id(), $id );
		if ( ! $removed ) {
			return $this->fail( 'totalsecwp_passkey_not_found', __( 'Passkey not found.', 'loyal-security' ), 404 );
		}
		$this->logger()->log( EventCatalog::PASSKEY_REMOVED, array( 'user_id' => get_current_user_id() ) );
		return $this->ok( array( 'removed' => true ) );
	}

	/**
	 * Begin a passkey login — unauthenticated. Blocks already-banned IPs outright (the signed
	 * assertion itself is then submitted through wp-login.php, where the `authenticate` chain —
	 * including BruteForce::pre_auth_gate() — applies as for any password login).
	 */
	public function passkey_login_options( WP_REST_Request $request ) {
		if ( $this->passkey_login_ip_banned() ) {
			return $this->fail( 'totalsecwp_banned', __( 'Access from your IP address has been temporarily blocked due to suspicious activity.', 'loyal-security' ), 403 );
		}
		try {
			return $this->ok( ( new WebAuthnCeremony() )->begin_login() );
		} catch ( \Throwable $e ) {
			return $this->fail( 'totalsecwp_passkey_unsupported', __( 'Passkey login is not available on this server.', 'loyal-security' ), 500 );
		}
	}

	private function passkey_login_ip_banned(): bool {
		$ip = ( new IpResolver( $this->container->make( 'settings' ) ) )->current();
		return ( new BanStore() )->is_banned( $ip );
	}

	private function logger() {
		return $this->container->make( 'logger' );
	}
}
