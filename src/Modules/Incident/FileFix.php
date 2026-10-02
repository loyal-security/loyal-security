<?php
/**
 * Best-effort, reversible cleaning of a single infected file.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Incident;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Filesystem;

/**
 * For code that cannot be re-fetched cleanly (premium/custom plugins, theme files), this
 * attempts to surgically remove high-confidence injected payloads while leaving the rest of
 * the file intact. It is deliberately conservative — it only strips well-known malware shapes
 * — and every change is guarded three ways: the original is backed up first, the result is
 * syntax-checked before it is written, and the site is loopback-tested after, rolling the
 * backup back automatically if the fix breaks the site. A {@see RepairGuard} grace window also
 * restores the backup if a fatal surfaces on a route the loopback did not cover.
 */
class FileFix {

	/**
	 * High-confidence injection signatures. A matching line is removed. These target code
	 * *executors* of encoded/remote/user-controlled input — shapes that essentially never
	 * appear in legitimate plugin/theme source.
	 *
	 * @var string[]
	 */
	private const KILL = array(
		'/\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|convert_uudecode)\s*\(/i',
		'/\b(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\b/i',
		'/\b(eval|assert)\s*\(\s*\$\{?[\'"]?_(GET|POST|REQUEST|COOKIE)/i',
		'/preg_replace\s*\(\s*([\'"])(?:(?!\1).)*\1\s*\.\s*[\'"]e/i',
		'/\bcreate_function\s*\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_(GET|POST|REQUEST|COOKIE)/i',
		'/\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
		'/\bmove_uploaded_file\s*\([^)]*\$_(FILES|REQUEST)/i',
		'/\b(gzinflate|gzuncompress|gzdecode)\s*\(\s*base64_decode\s*\(/i',
		'/\$\{\s*[\'"]_(GET|POST|REQUEST|COOKIE)[\'"]\s*\}\s*\[/i',
	);

	/** Obfuscation markers — a very long single line carrying these is treated as a payload. */
	private const OBFUSCATION = '/(base64_decode|gzinflate|str_rot13|eval|\\\\x[0-9a-f]{2})/i';
	private const LONG_LINE   = 1500;

	/**
	 * Attempt to clean a file.
	 *
	 * @param string   $path       Absolute path to the infected file.
	 * @param int|null $finding_id Optional related scan finding.
	 * @return array{ok:bool,message:string,removed?:int,backup_id?:string,reverted?:bool}
	 */
	public function attempt( string $path, ?int $finding_id = null ): array {
		$path = wp_normalize_path( $path );

		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return array( 'ok' => false, 'message' => __( 'File not found or unreadable.', 'loyal-security' ) );
		}
		// Never operate on our own plugin files.
		if ( false !== strpos( $path, wp_normalize_path( TOTALSECWP_PATH ) ) ) {
			return array( 'ok' => false, 'message' => __( 'Refusing to modify Loyal Security\'s own files.', 'loyal-security' ) );
		}
		// Only attempt PHP — the executable surface that matters.
		$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		if ( ! in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'inc' ), true ) ) {
			return array( 'ok' => false, 'message' => __( 'Automatic fixing is only available for PHP files.', 'loyal-security' ) );
		}

		$original = Filesystem::read( $path );
		if ( null === $original ) {
			return array( 'ok' => false, 'message' => __( 'Could not read the file.', 'loyal-security' ) );
		}

		$result  = $this->clean( $original );
		$cleaned = $result['code'];
		$removed = $result['removed'];

		if ( 0 === $removed || $cleaned === $original ) {
			return array(
				'ok'      => false,
				'message' => __( 'No high-confidence injected code was found to remove safely. Reinstall this file/plugin manually.', 'loyal-security' ),
			);
		}

		// Syntax-check before writing; never leave a half-edited file on disk.
		if ( ! $this->lint( $cleaned ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'The cleaned file would not parse, so the change was not applied. Reinstall this file manually.', 'loyal-security' ),
			);
		}

		$backups   = new RepairBackup();
		$backup_id = $backups->backup_file( $path, 'filefix:' . basename( $path ) );
		if ( '' === $backup_id ) {
			return array( 'ok' => false, 'message' => __( 'Could not back up the file; aborting for safety.', 'loyal-security' ) );
		}
		$backups->mark_pending( $path, $backup_id );

		if ( ! Filesystem::write( $path, $cleaned ) ) {
			$backups->clear_pending( $path );
			return array( 'ok' => false, 'message' => __( 'Could not write the cleaned file.', 'loyal-security' ) );
		}

		// Verify the site still loads; roll back immediately on failure.
		$health = ( new Loopback() )->check();
		if ( ! $health['ok'] ) {
			$backups->restore( $backup_id );
			$backups->clear_pending( $path );
			return array(
				'ok'       => false,
				'reverted' => true,
				'message'  => __( 'The fix caused a site error and was automatically reverted. Reinstall this file manually.', 'loyal-security' ),
			);
		}

		// Healthy: leave the pending entry to expire under the guard's grace window so a
		// later route-specific fatal can still trigger an auto-restore.
		return array(
			'ok'        => true,
			'removed'   => $removed,
			'backup_id' => $backup_id,
			'message'   => sprintf(
				/* translators: number of removed code segments */
				_n( 'Removed %d injected segment and verified the site loads.', 'Removed %d injected segments and verified the site loads.', $removed, 'loyal-security' ),
				$removed
			),
		);
	}

	/**
	 * Dry-run the cleaner for the code inspector: read the file and compute what a fix would
	 * remove, **without** writing anything or executing the code. Returns the original and
	 * cleaned source plus a line-level diff so the UI can show exactly what would change.
	 *
	 * @param string $path      Absolute path.
	 * @param int    $max_bytes Cap inspected size (the inspector is for display, not bulk).
	 * @return array{ok:bool,message?:string,removed?:int,original?:string,cleaned?:string,lines?:array<int,array{n:int,text:string,removed:bool}>,truncated?:bool,fixable?:bool}
	 */
	public function preview( string $path, int $max_bytes = 262144 ): array {
		$path = wp_normalize_path( $path );
		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return array( 'ok' => false, 'message' => __( 'File not found or unreadable.', 'loyal-security' ) );
		}
		$original = (string) Filesystem::read( $path );
		$truncated = false;
		if ( strlen( $original ) > $max_bytes ) {
			$original  = substr( $original, 0, $max_bytes );
			$truncated = true;
		}

		$result  = $this->clean( $original );
		$cleaned = $result['code'];
		$removed = $result['removed'];

		// Build a line-level annotation: which source lines the cleaner would drop.
		$src_lines = preg_split( '/\r\n|\n|\r/', $original );
		$lines     = array();
		foreach ( (array) $src_lines as $i => $text ) {
			$is_bad = $this->is_malicious_line( (string) $text );
			$lines[] = array(
				'n'       => $i + 1,
				'text'    => (string) $text,
				'removed' => $is_bad,
			);
		}

		return array(
			'ok'        => true,
			'removed'   => $removed,
			'fixable'   => $removed > 0,
			'original'  => $original,
			'cleaned'   => $cleaned,
			'lines'     => $lines,
			'truncated' => $truncated,
		);
	}

	/**
	 * Conservatively strip injected lines from PHP source.
	 *
	 * @return array{code:string,removed:int}
	 */
	private function clean( string $code ): array {
		$removed = 0;

		// 1) Strip a leading injected PHP block prepended to the very top of a file (a
		//    `<?php @eval(base64_decode('...'));` one-liner closed by its own PHP tag).
		$lead = '/^\xEF\xBB\xBF?\s*<\?php\s+@?(?:eval|assert)\s*\(.*?\)\s*;\s*\?>\s*/is';
		if ( preg_match( $lead, $code ) ) {
			$code = preg_replace( $lead, '', $code, 1 );
			$removed++;
		}

		// 2) Line-oriented removal of high-confidence executors and oversized payload lines.
		$lines = preg_split( '/(\r\n|\n|\r)/', $code, -1, PREG_SPLIT_DELIM_CAPTURE );
		if ( false === $lines ) {
			return array( 'code' => $code, 'removed' => $removed );
		}

		$out = array();
		for ( $i = 0, $n = count( $lines ); $i < $n; $i++ ) {
			// Even indices are content; odd indices are the captured line breaks.
			if ( 1 === ( $i % 2 ) ) {
				$out[] = $lines[ $i ];
				continue;
			}
			$line = $lines[ $i ];
			if ( $this->is_malicious_line( $line ) ) {
				$removed++;
				// Drop the line and its trailing break (the next captured delimiter).
				if ( isset( $lines[ $i + 1 ] ) ) {
					$i++;
				}
				continue;
			}
			$out[] = $line;
		}

		return array( 'code' => implode( '', $out ), 'removed' => $removed );
	}

	private function is_malicious_line( string $line ): bool {
		foreach ( self::KILL as $pattern ) {
			if ( preg_match( $pattern, $line ) ) {
				return true;
			}
		}
		// A single very long line that carries obfuscation markers is almost certainly a
		// packed payload rather than hand-written code.
		if ( strlen( $line ) > self::LONG_LINE && preg_match( self::OBFUSCATION, $line ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Syntax-check PHP source without executing it. Uses the tokenizer in parse mode, which
	 * raises a ParseError on invalid syntax — no shell/`exec` dependency required.
	 */
	private function lint( string $code ): bool {
		if ( ! function_exists( 'token_get_all' ) || ! defined( 'TOKEN_PARSE' ) ) {
			return true; // Can't lint here — defer to the loopback check.
		}
		try {
			token_get_all( $code, TOKEN_PARSE );
			return true;
		} catch ( \ParseError $e ) {
			return false;
		} catch ( \Throwable $e ) {
			return false;
		}
	}
}
