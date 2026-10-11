<?php
/**
 * Virtual patching engine.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * Evaluates the request against the virtual-patch ruleset. Rules scoped to a specific
 * plugin slug only fire when that plugin is installed at or below the affected version,
 * keeping false positives low while shielding unpatched vulnerabilities.
 *
 * Part of the WP-free shared kernel: unlike the class this replaced, it does not call
 * `get_plugins()` (a WordPress-only function unavailable to the pre-WordPress prepend) —
 * the installed slug => version map is resolved by the caller (Standard Mode calls
 * `get_plugins()` directly; the prepend reads a snapshot baked into `waf-config.php` at the
 * last `write_waf_config()` run) and passed in.
 */
class VirtualPatch {

	/** Hard cap on the bytes any single patch regex is run against (ReDoS cost bound). */
	const MAX_SCAN_BYTES = 128 * 1024;

	/** @var array<int, array<string, mixed>> */
	private array $rules;

	/** @var array<string, string> slug => version. */
	private array $installed;

	/**
	 * @param array<int, array<string, mixed>> $rules     Virtual-patch rule set.
	 * @param array<string, string>            $installed Installed plugin slug => version map.
	 */
	public function __construct( array $rules, array $installed = array() ) {
		$this->rules     = $rules;
		$this->installed = $installed;
	}

	/**
	 * @return string|null Matched rule id if blocked, null otherwise.
	 */
	public function evaluate( RequestContext $req ): ?string {
		foreach ( $this->rules as $rule ) {
			// require_auth rules carry no value_regex to test — they're a pure scope+auth
			// gate, and "is this user authenticated" is only answerable once WordPress has
			// booted. Content-matching evaluate() never treats them as a block on its own;
			// see match_auth_gate() for their actual enforcement.
			if ( ! empty( $rule['require_auth'] ) ) {
				continue;
			}
			if ( $this->matches( $rule, $req ) ) {
				return (string) $rule['id'];
			}
		}
		return null;
	}

	/**
	 * Auth-gated rules: block a scoped path unless the visitor is authenticated (optionally
	 * with a specific capability). Unlike evaluate(), this needs `is_user_logged_in()` /
	 * `current_user_can()`, which require WordPress to be booted — so it can only ever be
	 * enforced in Standard Mode, never the pre-WordPress prepend (see
	 * FirewallModule::enforce_auth_gate(), which always runs on `init` regardless of which
	 * mode is active, precisely so these rules are enforced even when Optimized Mode handles
	 * everything else pre-boot).
	 *
	 * Two physical copies of this class exist when Optimized Mode is deployed: this one (loaded
	 * only by Standard Mode, after WordPress boots) and a relocated copy under
	 * uploads/loyal-security/waf-kernel/ that the prepend loads (see
	 * LoyalSecurity\Setup\WafKernelBundler). Only THIS copy's `match_auth_gate()` is ever called
	 * — the prepend calls `evaluate()` exclusively, which skips `require_auth` rules — so the
	 * relocated copy carries this method but never exercises it. Keep it that way; don't add a
	 * prepend-side caller without also solving the "WordPress isn't booted yet" problem this
	 * method depends on.
	 *
	 * @return string|null Matched rule id, or null if nothing in scope requires a check.
	 */
	public function match_auth_gate( RequestContext $req ): ?string {
		foreach ( $this->rules as $rule ) {
			if ( empty( $rule['require_auth'] ) ) {
				continue;
			}
			if ( ! $this->scope_matches( $rule, $req ) ) {
				continue;
			}
			if ( ! is_user_logged_in() ) {
				return (string) $rule['id'];
			}
			$cap = (string) ( $rule['require_cap'] ?? '' );
			if ( '' !== $cap && ! current_user_can( $cap ) ) {
				return (string) $rule['id'];
			}
		}
		return null;
	}

	/**
	 * @param array<string, mixed> $rule Rule descriptor.
	 */
	private function matches( array $rule, RequestContext $req ): bool {
		if ( ! $this->scope_matches( $rule, $req ) ) {
			return false;
		}

		$path_regex  = (string) ( $rule['path_regex'] ?? '' );
		$value_regex = (string) ( $rule['value_regex'] ?? '' );
		if ( '' === $value_regex ) {
			// Path-only rule already satisfied above.
			return '' !== $path_regex;
		}

		// Specific parameter, or scan all values + body.
		$param = (string) ( $rule['param'] ?? '' );
		if ( '' !== $param ) {
			$haystacks = array();
			if ( isset( $req->get[ $param ] ) && is_scalar( $req->get[ $param ] ) ) {
				$haystacks[] = (string) $req->get[ $param ];
			}
			if ( isset( $req->post[ $param ] ) && is_scalar( $req->post[ $param ] ) ) {
				$haystacks[] = (string) $req->post[ $param ];
			}
			foreach ( $haystacks as $h ) {
				if ( @preg_match( $value_regex, self::cap( $h ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					return true;
				}
			}
			return false;
		}

		// No specific param: test URI + raw body.
		if ( @preg_match( $value_regex, self::cap( $req->uri ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return true;
		}
		return $req->raw_body && @preg_match( $value_regex, self::cap( $req->raw_body ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Truncate a haystack to MAX_SCAN_BYTES before it is handed to a patch regex, bounding
	 * per-pattern cost on pathological input.
	 */
	private static function cap( string $value ): string {
		return strlen( $value ) > self::MAX_SCAN_BYTES ? substr( $value, 0, self::MAX_SCAN_BYTES ) : $value;
	}

	/**
	 * Method + plugin-scope + path filters shared by both content matching (matches()) and
	 * the auth gate (match_auth_gate()) — the two enforcement modes differ only in what they
	 * do once a request falls within a rule's scope, not in how that scope is determined.
	 *
	 * @param array<string, mixed> $rule Rule descriptor.
	 */
	private function scope_matches( array $rule, RequestContext $req ): bool {
		// Method filter.
		$methods = (array) ( $rule['methods'] ?? array() );
		if ( $methods && ! in_array( $req->method, $methods, true ) ) {
			return false;
		}

		// Plugin-scope filter.
		$slug = (string) ( $rule['slug'] ?? '' );
		if ( '' !== $slug ) {
			if ( ! isset( $this->installed[ $slug ] ) ) {
				return false;
			}
			$max = (string) ( $rule['max_version'] ?? '' );
			if ( '' !== $max && version_compare( $this->installed[ $slug ], $max, '>' ) ) {
				return false; // Already patched.
			}
		}

		// Path filter.
		$path_regex = (string) ( $rule['path_regex'] ?? '' );
		if ( '' !== $path_regex && ! @preg_match( $path_regex, $req->uri ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}

		return true;
	}
}
