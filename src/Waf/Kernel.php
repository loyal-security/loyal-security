<?php
/**
 * WAF kernel — the single source of truth for request inspection.
 *
 * Used by BOTH the standalone pre-WordPress prepend bootstrapper and the in-plugin
 * Standard-Mode firewall. Has zero WordPress dependency.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * Composes the signature set, decoder, and rule engine into one inspect() call.
 */
class Kernel {

	private RuleEngine $engine;
	private SignatureSet $signatures;

	/** @var array<string, mixed> */
	private array $config;

	/**
	 * @param SignatureSet         $signatures Signature set.
	 * @param array<string, mixed> $config     Engine config.
	 */
	public function __construct( SignatureSet $signatures, array $config = array() ) {
		$this->signatures = $signatures;
		$this->config     = $config;
		$this->engine     = new RuleEngine( $signatures, new Decoder(), $config );
	}

	/**
	 * Convenience constructor from a signatures file path.
	 *
	 * @param string               $signatures_file Path to signature data file.
	 * @param array<string, mixed> $config          Engine config.
	 */
	public static function from_file( string $signatures_file, array $config = array() ): self {
		return new self( SignatureSet::from_file( $signatures_file ), $config );
	}

	/**
	 * Inspect a request and return a decision.
	 */
	public function inspect( RequestContext $req ): Decision {
		return $this->engine->evaluate( $req );
	}

	public function signature_version(): string {
		return $this->signatures->version();
	}
}
