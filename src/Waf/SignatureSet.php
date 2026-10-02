<?php
/**
 * Compiled WAF signature set.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * Loads the signature ruleset and tests strings against it. Designed to be cheap to build
 * (rules are plain arrays) so it can be instantiated on every request, including in the
 * pre-WordPress prepend.
 */
class SignatureSet {

	/** @var array<int, array<string, mixed>> */
	private array $rules;

	private string $version;

	/**
	 * Hard cap on the bytes any single regex is run against. Bounds the worst-case cost of every
	 * pattern on pathological (very long) input — together with the RuleEngine's PCRE backtrack
	 * limit this defangs ReDoS: per-pattern work is bounded regardless of the rule or the input.
	 */
	const MAX_SCAN_BYTES = 128 * 1024;

	/**
	 * @param array<int, array<string, mixed>> $rules   Rule list.
	 * @param string                           $version Ruleset version.
	 */
	public function __construct( array $rules, string $version = '' ) {
		$this->rules   = $rules;
		$this->version = $version;
	}

	/**
	 * Build from the bundled signature data file.
	 *
	 * @param string $file Absolute path to the signatures PHP file.
	 */
	public static function from_file( string $file ): self {
		$data = is_file( $file ) ? include $file : array();
		$rules = isset( $data['rules'] ) && is_array( $data['rules'] ) ? $data['rules'] : array();
		return new self( $rules, isset( $data['version'] ) ? (string) $data['version'] : '' );
	}

	public function version(): string {
		return $this->version;
	}

	/**
	 * Test a single candidate string and return matched rules.
	 *
	 * @param string   $value         Candidate string.
	 * @param string[] $disabled_ids  Rule ids to skip (per-site tuning).
	 * @return array<int, array<string, mixed>> Matched rule descriptors.
	 */
	public function match( string $value, array $disabled_ids = array() ): array {
		// Bound per-pattern cost on very long input (see MAX_SCAN_BYTES). A malicious payload
		// long enough to matter is detectable within the first 128 KB; anything past that only
		// adds regex cost.
		if ( strlen( $value ) > self::MAX_SCAN_BYTES ) {
			$value = substr( $value, 0, self::MAX_SCAN_BYTES );
		}
		$hits = array();
		foreach ( $this->rules as $rule ) {
			if ( $disabled_ids && in_array( $rule['id'], $disabled_ids, true ) ) {
				continue;
			}
			// Patterns are authored without the trailing i flag in some cases; the engine
			// trusts the rule's own modifiers as written in the data file.
			// Captures the match text (not just a bool) so rules flagged 'same_host_exempt'
			// can be re-checked by the engine against the site's own hostname.
			if ( @preg_match( $rule['regex'], $value, $m ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$rule['matched'] = $m[0];
				$hits[]          = $rule;
			}
		}
		return $hits;
	}
}
