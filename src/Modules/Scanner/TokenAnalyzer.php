<?php
/**
 * PHP-token (AST-ish) obfuscation analysis.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Uses PHP's tokenizer to detect malicious patterns that survive whitespace/comment
 * obfuscation, and applies statistical heuristics (string entropy, concatenation depth,
 * nested decoder depth, dangerous-call-on-input) that plain regexes miss.
 *
 * This is deliberately conservative and additive: each signal contributes a score, and the
 * scanner only flags a file once the combined score crosses a threshold, keeping false
 * positives low on legitimate (but dense) code.
 */
class TokenAnalyzer {

	/** Functions whose use on dynamic input is highly suspicious. */
	private const SINK_FUNCTIONS = array(
		'eval', 'assert', 'create_function', 'system', 'exec', 'shell_exec', 'passthru',
		'popen', 'proc_open', 'pcntl_exec', 'call_user_func', 'call_user_func_array',
	);

	/** Decoder/unpacker functions; nesting several of these is a strong obfuscation signal. */
	private const DECODER_FUNCTIONS = array(
		'base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13', 'rawurldecode',
		'urldecode', 'hex2bin', 'convert_uudecode', 'strrev', 'pack',
	);

	/**
	 * Analyse PHP content and return findings.
	 *
	 * @param string $path    File path.
	 * @param string $content File content.
	 * @return Finding[]
	 */
	public function analyse( string $path, string $content ): array {
		$findings = array();

		// Only tokenize PHP. token_get_all is safe on arbitrary strings but meaningless on
		// pure assets, so we bail early for files with no PHP open tag.
		if ( false === strpos( $content, '<?' ) ) {
			return $findings;
		}

		$tokens = @token_get_all( $content ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $tokens ) || count( $tokens ) < 3 ) {
			return $findings;
		}

		$score          = 0;
		$reasons        = array();
		$first_line     = 0;
		$decoder_calls  = 0;
		$sink_on_input  = false;
		$long_strings   = 0;
		$max_entropy    = 0.0;
		$concat_runs    = 0;
		$cur_concat     = 0;
		$saw_superglobal_in_call = false;

		$count = count( $tokens );
		for ( $i = 0; $i < $count; $i++ ) {
			$tok = $tokens[ $i ];

			if ( is_array( $tok ) ) {
				[ $id, $text, $line ] = array( $tok[0], $tok[1], $tok[2] ?? 0 );

				// Dangerous function usage (identifier-based, defeats whitespace tricks).
				// eval() is its own token (T_EVAL), not T_STRING, so it must be checked too.
				if ( T_STRING === $id || T_EVAL === $id ) {
					$fn = strtolower( $text );
					if ( in_array( $fn, self::DECODER_FUNCTIONS, true ) ) {
						$decoder_calls++;
					}
					if ( in_array( $fn, self::SINK_FUNCTIONS, true ) ) {
						// Does an input superglobal appear within the next ~12 tokens?
						if ( $this->input_near( $tokens, $i, 12 ) ) {
							$sink_on_input = true;
							$first_line    = $first_line ?: (int) $line;
							$reasons[]     = $fn . '() on request input';
							$score        += 18;
						}
					}
				}

				// Long string literals → entropy check (packed payloads).
				if ( T_CONSTANT_ENCAPSED_STRING === $id || T_ENCAPSED_AND_WHITESPACE === $id ) {
					$raw = trim( $text, "\"'" );
					if ( strlen( $raw ) >= 200 ) {
						$long_strings++;
						$e = $this->entropy( $raw );
						if ( $e > $max_entropy ) {
							$max_entropy = $e;
							$first_line  = $first_line ?: (int) $line;
						}
					}
				}

				// Variable-variables / dynamic superglobal access.
				if ( T_VARIABLE === $id && in_array( strtoupper( ltrim( $text, '$' ) ), array( '_GET', '_POST', '_REQUEST', '_COOKIE' ), true ) ) {
					$saw_superglobal_in_call = true;
				}
			} else {
				// Concatenation runs (string built from many pieces).
				if ( '.' === $tok ) {
					$cur_concat++;
					if ( $cur_concat > $concat_runs ) {
						$concat_runs = $cur_concat;
					}
				} else {
					$cur_concat = 0;
				}
			}
		}

		// Nested decoders.
		if ( $decoder_calls >= 2 ) {
			$score    += 8 * min( $decoder_calls, 4 );
			$reasons[] = $decoder_calls . ' nested decode/unpack calls';
		}

		// High-entropy long strings (likely encoded/packed code).
		if ( $max_entropy >= 5.3 && $long_strings >= 1 ) {
			$score    += 14;
			$reasons[] = sprintf( 'High-entropy literal (%.2f bits/byte)', $max_entropy );
		}

		// Excessive concatenation (string-splitting obfuscation).
		if ( $concat_runs >= 15 ) {
			$score    += 10;
			$reasons[] = $concat_runs . '-piece string concatenation';
		}

		if ( $saw_superglobal_in_call && $decoder_calls >= 1 ) {
			$score    += 8;
			$reasons[] = 'Decoded request input';
		}

		if ( $score >= 18 ) {
			$findings[] = new Finding(
				$path,
				'heuristic-token',
				'obfuscation',
				$score,
				$first_line,
				implode( '; ', array_slice( $reasons, 0, 5 ) )
			);
		}

		return $findings;
	}

	/**
	 * Does a request superglobal appear within $window tokens after position $i?
	 *
	 * @param array<int, mixed> $tokens Token list.
	 * @param int               $i      Current index.
	 * @param int               $window Lookahead.
	 */
	private function input_near( array $tokens, int $i, int $window ): bool {
		$end = min( count( $tokens ), $i + $window );
		for ( $j = $i + 1; $j < $end; $j++ ) {
			$t = $tokens[ $j ];
			if ( is_array( $t ) && T_VARIABLE === $t[0] ) {
				$name = strtoupper( ltrim( $t[1], '$' ) );
				if ( in_array( $name, array( '_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_FILES' ), true ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Shannon entropy (bits per byte) of a string.
	 */
	private function entropy( string $s ): float {
		$len = strlen( $s );
		if ( 0 === $len ) {
			return 0.0;
		}
		$freq = count_chars( $s, 1 );
		$entropy = 0.0;
		foreach ( $freq as $count ) {
			$p        = $count / $len;
			$entropy -= $p * log( $p, 2 );
		}
		return $entropy;
	}
}
