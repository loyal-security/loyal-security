<?php
/**
 * Setup wizard — safely deploys the standalone WAF and finalises onboarding.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Setup;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Plugin;
use TotalSecurityWP\Modules\Firewall\FirewallModule;

/**
 * Orchestrates the onboarding flow: server detection, WAF config generation, prepend
 * deployment with self-test verification and rollback, and completion bookkeeping.
 */
class SetupWizard {

	private ServerProbe $probe;
	private PrependInstaller $installer;

	public function __construct() {
		$this->probe     = new ServerProbe();
		$this->installer = new PrependInstaller( $this->probe );
	}

	/**
	 * Current onboarding status for the wizard UI.
	 *
	 * @return array<string, mixed>
	 */
	public function status(): array {
		$info       = $this->probe->detect();
		$kernel_dir = trailingslashit( ( new WafKernelBundler() )->deploy_dir() );
		return array(
			'server'          => $info,
			'mode'            => get_option( 'totalsecwp_waf_mode', 'standard' ),
			'prepend_exists'  => is_file( $kernel_dir . 'totalsecwp-waf.php' ),
			'config_exists'   => is_file( $kernel_dir . 'waf-config.php' ),
			'setup_complete'  => (bool) get_option( 'totalsecwp_setup_complete', false ),
		);
	}

	/**
	 * Deploy the standalone WAF bundle (relocated kernel + rendered bootstrapper), generate the
	 * config, then deploy the prepend directive (Optimized Mode). Order matters: the bundle sync
	 * must happen first since write_config() checks the deployed directory's writability, and
	 * the installer needs the bootstrapper file to already exist.
	 *
	 * @return array<string, mixed>
	 */
	public function deploy_optimized(): array {
		( new WafKernelBundler() )->sync();
		$this->write_config();
		return $this->installer->deploy();
	}

	/**
	 * Verify Optimized Mode is live.
	 *
	 * @return array<string, mixed>
	 */
	public function verify(): array {
		return $this->installer->verify();
	}

	/**
	 * Revert to Standard Mode.
	 *
	 * @return array<string, mixed>
	 */
	public function rollback(): array {
		return $this->installer->rollback();
	}

	/**
	 * Ensure the prepend config file exists/up-to-date (also used in Standard Mode so the
	 * config is ready if the user later enables Optimized Mode).
	 */
	public function write_config(): void {
		$firewall = Plugin::instance()->module( 'firewall' );
		if ( $firewall instanceof FirewallModule ) {
			$firewall->write_waf_config();
		}
	}

	/**
	 * Mark onboarding complete.
	 */
	public function complete(): void {
		update_option( 'totalsecwp_setup_complete', true );
	}
}
