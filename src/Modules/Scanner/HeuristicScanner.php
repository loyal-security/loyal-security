<?php
/**
 * Heuristic malware scanner engine (regex signatures + token analysis).
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Contracts\ScannerInterface;

/**
 * The core file analyser. Combines the high-confidence regex {@see SignatureDb} with the
 * statistical {@see TokenAnalyzer}, then de-duplicates and applies a known-good checksum
 * allowlist to suppress false positives on legitimate (e.g. minified vendor) files.
 */
class HeuristicScanner implements ScannerInterface {

	private SignatureDb $signatures;
	private TokenAnalyzer $tokens;
	private TaintAnalyzer $taint;

	/** @var array<string, bool> Allowlisted SHA-256 hashes of known-good files. */
	private array $allow_hashes;

	/**
	 * @param array<string, bool> $allow_hashes Optional known-good hash allowlist.
	 */
	public function __construct( ?SignatureDb $signatures = null, ?TokenAnalyzer $tokens = null, array $allow_hashes = array(), ?TaintAnalyzer $taint = null ) {
		$this->signatures   = $signatures ?? new SignatureDb();
		$this->tokens       = $tokens ?? new TokenAnalyzer();
		$this->taint        = $taint ?? new TaintAnalyzer();
		$this->allow_hashes = $allow_hashes;
	}

	/**
	 * Analyse content and return findings.
	 *
	 * @param string $path    File path (reporting).
	 * @param string $content Raw content.
	 * @return Finding[]
	 */
	public function analyse( string $path, string $content ): array {
		if ( '' === $content ) {
			return array();
		}

		// Allowlist by content hash.
		if ( $this->allow_hashes ) {
			$hash = hash( 'sha256', $content );
			if ( isset( $this->allow_hashes[ $hash ] ) ) {
				return array();
			}
		}

		$findings = array_merge(
			$this->signatures->scan( $path, $content ),
			$this->tokens->analyse( $path, $content ),
			$this->taint->analyse( $path, $content )
		);

		return $this->dedupe( $findings );
	}

	/**
	 * Scan a file by path (streams the read, skips oversized/binary files).
	 *
	 * @param string $path      Absolute path.
	 * @param int    $max_bytes Maximum file size to inspect.
	 * @param bool   $skip_core When true (default), core locations (root, wp-admin,
	 *                          wp-includes) are skipped and deferred to integrity checks.
	 *                          Integrity passes false to force-scan a core file it has
	 *                          already found modified or unexpected (trust is broken).
	 * @return Finding[]
	 */
	public function scan_file( string $path, int $max_bytes = 3145728, bool $skip_core = true ): array {
		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return array();
		}
		$size = (int) filesize( $path );
		if ( $size > $max_bytes || 0 === $size ) {
			return array();
		}
		$content = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $content ) {
			return array();
		}
		// Skip clearly binary files (NUL byte in the first 8KB).
		if ( false !== strpos( substr( $content, 0, 8192 ), "\0" ) ) {
			return array();
		}

		// WordPress core files (wp-includes, wp-admin, and root-level wp-*.php files) are
		// verified via integrity checks. By default exclude them from the malware scanner to
		// avoid false positives on legitimate PHP libraries and minified JS files. Integrity
		// passes $skip_core=false to force a content scan once a core file's checksum no
		// longer matches (or it shouldn't exist at all) — at which point trust is broken and
		// the false-positive concern no longer applies.
		if ( $skip_core ) {
			$norm_path    = wp_normalize_path( $path );
			$norm_abspath = untrailingslashit( wp_normalize_path( \TotalSecurityWP\Support\Paths::root() ) );
			$core_dirs    = array( wp_normalize_path( \TotalSecurityWP\Support\Paths::includes() ), wp_normalize_path( \TotalSecurityWP\Support\Paths::admin() ) );
			foreach ( $core_dirs as $core_dir ) {
				if ( 0 === strpos( $norm_path, $core_dir . '/' ) ) {
					return array();
				}
			}
			// Root-level files (directly in ABSPATH, not inside wp-content) are also core.
			if ( dirname( $norm_path ) === $norm_abspath ) {
				return array();
			}
		}

		return $this->analyse( $path, $content );
	}

	/**
	 * Combine the score of multiple findings on the same file/line, keep the strongest.
	 *
	 * @param Finding[] $findings Raw findings.
	 * @return Finding[]
	 */
	private function dedupe( array $findings ): array {
		$seen = array();
		foreach ( $findings as $f ) {
			$key = $f->rule . '@' . $f->line;
			if ( ! isset( $seen[ $key ] ) || $f->score > $seen[ $key ]->score ) {
				$seen[ $key ] = $f;
			}
		}
		return array_values( $seen );
	}
}
