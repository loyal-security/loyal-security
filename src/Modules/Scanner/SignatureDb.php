<?php
/**
 * Malware signature database for the file scanner.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Loads and applies the regex-based malware/webshell signature set.
 */
class SignatureDb {

	/** @var array<int, array<string, mixed>> */
	private array $rules;

	private string $version;

	public function __construct( ?array $rules = null, string $version = '' ) {
		if ( null === $rules ) {
			$file    = LOYALSEC_PATH . 'data/malware-signatures.php';
			$data    = is_file( $file ) ? include $file : array();
			$rules   = isset( $data['rules'] ) ? (array) $data['rules'] : array();
			$version = isset( $data['version'] ) ? (string) $data['version'] : '';
		}
		$this->rules   = $rules;
		$this->version = $version;
	}

	public function version(): string {
		return $this->version;
	}

	/**
	 * Match content; returns Finding objects (line numbers resolved by the caller).
	 *
	 * Rules default to a regex match (`regex`, legacy shape used by the bundled
	 * ruleset) but a rule may instead declare `type => 'hash'` — a LicenseKit-promoted
	 * exact SHA-256 match, where `pattern` is a 64-hex digest of the whole file rather
	 * than a PCRE pattern. Any rule with `enabled => false` (a ThreatIntel benign/false
	 * positive correction) is skipped; each sync ships the full replacement rules array
	 * (see FeedStore::write()), so there is never a stale `enabled => true` copy of the
	 * same id to reconcile against — the latest bundle is trusted wholesale.
	 *
	 * @param string $path    File path (for the finding).
	 * @param string $content File content.
	 * @return Finding[]
	 */
	public function scan( string $path, string $content ): array {
		$findings     = array();
		$content_hash = null;

		foreach ( $this->rules as $rule ) {
			if ( isset( $rule['enabled'] ) && false === $rule['enabled'] ) {
				continue;
			}

			$type = isset( $rule['type'] ) ? (string) $rule['type'] : 'regex';

			if ( 'hash' === $type ) {
				$pattern = isset( $rule['pattern'] ) ? strtolower( trim( (string) $rule['pattern'] ) ) : '';
				if ( '' === $pattern ) {
					continue;
				}
				if ( null === $content_hash ) {
					$content_hash = hash( 'sha256', $content );
				}
				if ( hash_equals( $pattern, $content_hash ) ) {
					$findings[] = new Finding(
						$path,
						(string) $rule['id'],
						(string) $rule['category'],
						(int) $rule['score'],
						1,
						'Exact file hash match (cloud-confirmed malware signature)'
					);
				}
				continue;
			}

			$regex = isset( $rule['regex'] ) ? $rule['regex'] : ( $rule['pattern'] ?? null );
			if ( null === $regex ) {
				continue;
			}
			if ( @preg_match( $regex, $content, $m, PREG_OFFSET_CAPTURE ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$offset  = isset( $m[0][1] ) ? (int) $m[0][1] : 0;
				$line    = substr_count( $content, "\n", 0, min( $offset, strlen( $content ) ) ) + 1;
				$snippet = trim( (string) substr( $content, max( 0, $offset - 20 ), 160 ) );

				$findings[] = new Finding(
					$path,
					(string) $rule['id'],
					(string) $rule['category'],
					(int) $rule['score'],
					$line,
					$snippet
				);
			}
		}
		return $findings;
	}
}
