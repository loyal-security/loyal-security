<?php
/**
 * Request-to-sink taint tracking for the file scanner.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Traces request input through a simple `$var = <source>;` assignment into a small set of
 * dangerous sinks: command exec, outbound HTTP (SSRF), file I/O (LFI/RFI), raw $wpdb queries,
 * and unserialize() (PHP object injection).
 *
 * {@see TokenAnalyzer} only catches a superglobal used *inline* as the sink's argument
 * (`eval($_GET['x'])`). Real — and realistically vulnerable — code almost always reads the
 * request into a variable first and uses it a few lines later (`$cmd = $r->get_param('cmd');
 * ... shell_exec($cmd);`), which this class follows instead.
 *
 * Deliberately conservative to keep legitimate plugins clean: any recognised sanitizer or
 * numeric/bool cast in the assignment clears the taint, and `$wpdb->prepare(...)` passed
 * directly as the query argument is always treated as safe. Taint tracking is file-scoped
 * (not per-function), so it is a heuristic signal, not a proof — a scan finding, never a block.
 */
class TaintAnalyzer {

	/** Method names on request-like objects (WP_REST_Request et al.) that return raw input. */
	private const SOURCE_METHODS = array(
		'get_param', 'get_params', 'get_json_params', 'get_body', 'get_query_params',
		'get_body_params', 'get_url_params', 'get_file_params',
	);

	/** Function names that neutralise taint when present anywhere in the assignment's RHS. */
	private const SANITIZERS = array(
		'sanitize_text_field', 'sanitize_key', 'sanitize_file_name', 'sanitize_email',
		'sanitize_url', 'esc_url_raw', 'esc_sql', 'esc_attr', 'esc_html', 'wp_kses', 'wp_kses_post',
		'absint', 'intval', 'floatval', 'boolval', 'rawurlencode', 'urlencode', 'md5', 'hash',
		'wp_http_validate_url', 'is_email',
	);

	/** Plain function/language-construct sinks: name => [ rule, category, score, label ]. */
	private const SINKS = array(
		'system'            => array( 'tainted-rce', 'backdoor', 28, 'Command exec' ),
		'exec'              => array( 'tainted-rce', 'backdoor', 28, 'Command exec' ),
		'shell_exec'        => array( 'tainted-rce', 'backdoor', 28, 'Command exec' ),
		'passthru'          => array( 'tainted-rce', 'backdoor', 28, 'Command exec' ),
		'popen'             => array( 'tainted-rce', 'backdoor', 28, 'Command exec' ),
		'proc_open'         => array( 'tainted-rce', 'backdoor', 28, 'Command exec' ),
		'pcntl_exec'        => array( 'tainted-rce', 'backdoor', 28, 'Command exec' ),
		'eval'              => array( 'tainted-rce', 'backdoor', 28, 'eval()' ),
		'assert'            => array( 'tainted-rce', 'backdoor', 28, 'assert()' ),
		'wp_remote_get'     => array( 'tainted-ssrf', 'injection', 24, 'Outbound HTTP request (SSRF)' ),
		'wp_remote_post'    => array( 'tainted-ssrf', 'injection', 24, 'Outbound HTTP request (SSRF)' ),
		'wp_remote_head'    => array( 'tainted-ssrf', 'injection', 24, 'Outbound HTTP request (SSRF)' ),
		'wp_remote_request' => array( 'tainted-ssrf', 'injection', 24, 'Outbound HTTP request (SSRF)' ),
		'file_get_contents' => array( 'tainted-lfi', 'injection', 26, 'File read (LFI)' ),
		'fopen'             => array( 'tainted-lfi', 'injection', 26, 'File open (LFI)' ),
		'readfile'          => array( 'tainted-lfi', 'injection', 26, 'File read (LFI)' ),
		'file'              => array( 'tainted-lfi', 'injection', 26, 'File read (LFI)' ),
		'highlight_file'    => array( 'tainted-lfi', 'injection', 26, 'File read (LFI)' ),
		'show_source'       => array( 'tainted-lfi', 'injection', 26, 'File read (LFI)' ),
		'unserialize'       => array( 'tainted-deserialize', 'backdoor', 24, 'unserialize() (PHP object injection)' ),
	);

	/** $wpdb methods that run raw SQL — flagged unless the argument is a direct ->prepare() call. */
	private const WPDB_SQL_METHODS = array( 'query', 'get_results', 'get_var', 'get_col', 'get_row' );

	/**
	 * @param string $path    File path.
	 * @param string $content File content.
	 * @return Finding[]
	 */
	public function analyse( string $path, string $content ): array {
		if ( false === strpos( $content, '<?' ) ) {
			return array();
		}
		$tokens = @token_get_all( $content ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $tokens ) || count( $tokens ) < 3 ) {
			return array();
		}

		$tainted = $this->find_tainted_vars( $tokens );
		if ( empty( $tainted ) ) {
			return array();
		}

		return $this->find_sinks( $path, $tokens, $tainted );
	}

	/**
	 * Pass 1: collect `$var = <rhs>;` assignments whose RHS reads request input and isn't
	 * cleared by a recognised sanitizer/cast.
	 *
	 * @param array<int, mixed> $tokens
	 * @return array<string, array{line:int, param:string}> Variable name (with '$') => the
	 *         assignment's line number and, when resolvable, the literal request-param key it
	 *         was read from (e.g. 'cmd' for `$r->get_param('cmd')` or `$_GET['cmd']`) — used to
	 *         draft a virtual-patch suggestion later (see PatchSuggester).
	 */
	private function find_tainted_vars( array $tokens ): array {
		$tainted = array();
		$count   = count( $tokens );

		for ( $i = 0; $i < $count; $i++ ) {
			$tok = $tokens[ $i ];
			if ( ! is_array( $tok ) || T_VARIABLE !== $tok[0] ) {
				continue;
			}
			$next = $this->next_significant( $tokens, $i );
			if ( null === $next || '=' !== $tokens[ $next ] ) {
				continue;
			}

			$end = $this->expression_end( $tokens, $next + 1 );
			$rhs = array_slice( $tokens, $next + 1, $end - $next - 1 );

			if ( $this->looks_sanitized( $rhs ) ) {
				unset( $tainted[ $tok[1] ] );
			} elseif ( $this->looks_tainted( $rhs ) ) {
				$tainted[ $tok[1] ] = array(
					'line'  => (int) ( $tok[2] ?? 0 ),
					'param' => $this->extract_param_key( $rhs ),
				);
			}
		}

		return $tainted;
	}

	/**
	 * Best-effort extraction of the literal request-param key a tainted RHS was read from:
	 * `$r->get_param( 'cmd' )` => 'cmd', `$_GET['cmd']` => 'cmd'. Returns '' when the source
	 * used a non-literal key or a whole-request getter (get_params(), get_json_params()) with
	 * no single key to name.
	 *
	 * @param array<int, mixed> $rhs
	 */
	private function extract_param_key( array $rhs ): string {
		$count = count( $rhs );
		for ( $i = 0; $i < $count; $i++ ) {
			$t = $rhs[ $i ];
			if ( ! is_array( $t ) ) {
				continue;
			}

			// ->get_param( 'key' )
			if ( T_STRING === $t[0] && in_array( $t[1], self::SOURCE_METHODS, true ) ) {
				$prev = $i > 0 ? $rhs[ $i - 1 ] : null;
				if ( is_array( $prev ) && T_OBJECT_OPERATOR === $prev[0] ) {
					$key = $this->literal_after_paren( $rhs, $i );
					if ( '' !== $key ) {
						return $key;
					}
				}
			}

			// $_GET['key'] / $_POST['key'] / $_REQUEST['key'] / $_COOKIE['key'] / $_FILES['key']
			if ( T_VARIABLE === $t[0]
				&& in_array( strtoupper( ltrim( $t[1], '$' ) ), array( '_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES' ), true ) ) {
				$key = $this->literal_after_bracket( $rhs, $i );
				if ( '' !== $key ) {
					return $key;
				}
			}
		}
		return '';
	}

	/** First string-literal argument of a `(...)` call starting right after index $i, or ''. */
	private function literal_after_paren( array $rhs, int $i ): string {
		$count = count( $rhs );
		for ( $j = $i + 1; $j < $count; $j++ ) {
			if ( is_array( $rhs[ $j ] ) && ! $this->significant( $rhs[ $j ] ) ) {
				continue;
			}
			if ( '(' !== $rhs[ $j ] ) {
				return '';
			}
			for ( $k = $j + 1; $k < $count; $k++ ) {
				if ( is_array( $rhs[ $k ] ) && ! $this->significant( $rhs[ $k ] ) ) {
					continue;
				}
				if ( is_array( $rhs[ $k ] ) && T_CONSTANT_ENCAPSED_STRING === $rhs[ $k ][0] ) {
					return trim( (string) $rhs[ $k ][1], "\"'" );
				}
				return '';
			}
		}
		return '';
	}

	/** First string-literal key of a `[...]` access starting right after index $i, or ''. */
	private function literal_after_bracket( array $rhs, int $i ): string {
		$count = count( $rhs );
		for ( $j = $i + 1; $j < $count; $j++ ) {
			if ( is_array( $rhs[ $j ] ) && ! $this->significant( $rhs[ $j ] ) ) {
				continue;
			}
			if ( '[' !== $rhs[ $j ] ) {
				return '';
			}
			for ( $k = $j + 1; $k < $count; $k++ ) {
				if ( is_array( $rhs[ $k ] ) && ! $this->significant( $rhs[ $k ] ) ) {
					continue;
				}
				if ( is_array( $rhs[ $k ] ) && T_CONSTANT_ENCAPSED_STRING === $rhs[ $k ][0] ) {
					return trim( (string) $rhs[ $k ][1], "\"'" );
				}
				return '';
			}
		}
		return '';
	}

	/**
	 * Pass 2: find sink calls (plain functions, `eval`, and raw `$wpdb` query methods) whose
	 * argument list contains one of the tainted variables from pass 1.
	 *
	 * @param array<int, mixed>                          $tokens
	 * @param array<string, array{line:int, param:string}> $tainted
	 * @return Finding[]
	 */
	private function find_sinks( string $path, array $tokens, array $tainted ): array {
		$findings = array();
		$count    = count( $tokens );

		for ( $i = 0; $i < $count; $i++ ) {
			$tok = $tokens[ $i ];
			if ( ! is_array( $tok ) ) {
				continue;
			}
			$is_sink_token = T_EVAL === $tok[0] || T_STRING === $tok[0];
			if ( ! $is_sink_token ) {
				continue;
			}

			$name = strtolower( $tok[1] );
			$line = (int) ( $tok[2] ?? 0 );
			$prev = $this->prev_significant( $tokens, $i );
			$is_method = ( null !== $prev && is_array( $tokens[ $prev ] ) && T_OBJECT_OPERATOR === $tokens[ $prev ][0] );

			if ( $is_method && in_array( $name, self::WPDB_SQL_METHODS, true ) ) {
				$obj = $this->prev_significant( $tokens, $prev );
				if ( null === $obj || ! is_array( $tokens[ $obj ] ) || T_VARIABLE !== $tokens[ $obj ][0] || '$wpdb' !== $tokens[ $obj ][1] ) {
					continue;
				}
				$paren = $this->next_significant( $tokens, $i );
				if ( null === $paren || '(' !== $tokens[ $paren ] || $this->wraps_prepare( $tokens, $paren ) ) {
					continue;
				}
				$arg = $this->tainted_arg( $tokens, $paren, $tainted );
				if ( null !== $arg ) {
					$src = $tainted[ '$' . $arg ];
					$findings[] = new Finding(
						$path,
						'tainted-sqli',
						'injection',
						26,
						$line,
						sprintf( '$wpdb->%s() built from unsanitized $%s (traced to request input, line %d) without ->prepare()', $tok[1], $arg, $src['line'] ),
						null,
						$src['param']
					);
				}
				continue;
			}

			if ( $is_method || ! isset( self::SINKS[ $name ] ) ) {
				continue;
			}
			$paren = $this->next_significant( $tokens, $i );
			if ( null === $paren || '(' !== $tokens[ $paren ] ) {
				continue;
			}
			$arg = $this->tainted_arg( $tokens, $paren, $tainted );
			if ( null === $arg ) {
				continue;
			}
			$src = $tainted[ '$' . $arg ];
			[ $rule, $category, $score, $label ] = self::SINKS[ $name ];
			$findings[] = new Finding(
				$path,
				$rule,
				$category,
				$score,
				$line,
				sprintf( '%s — %s(%s) traced to unsanitized request input (line %d)', $label, $tok[1], '$' . $arg, $src['line'] ),
				null,
				$src['param']
			);
		}

		return $findings;
	}

	/** Index of the next token after $i that isn't whitespace/comment, or null. */
	private function next_significant( array $tokens, int $i ): ?int {
		$count = count( $tokens );
		for ( $j = $i + 1; $j < $count; $j++ ) {
			if ( $this->significant( $tokens[ $j ] ) ) {
				return $j;
			}
		}
		return null;
	}

	/** Index of the previous token before $i that isn't whitespace/comment, or null. */
	private function prev_significant( array $tokens, int $i ): ?int {
		for ( $j = $i - 1; $j >= 0; $j-- ) {
			if ( $this->significant( $tokens[ $j ] ) ) {
				return $j;
			}
		}
		return null;
	}

	/** @param mixed $tok */
	private function significant( $tok ): bool {
		if ( ! is_array( $tok ) ) {
			return true;
		}
		return ! in_array( $tok[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true );
	}

	/**
	 * Index of the token that ends the expression starting at $start: the first top-level
	 * ';', or a closing bracket/paren/brace that belongs to an enclosing construct opened
	 * before $start (e.g. the `)` of an `if ( $x = ... )` condition).
	 */
	private function expression_end( array $tokens, int $start ): int {
		$count = count( $tokens );
		$depth = 0;
		for ( $j = $start; $j < $count; $j++ ) {
			$t = $tokens[ $j ];
			if ( is_array( $t ) ) {
				continue;
			}
			if ( '(' === $t || '[' === $t || '{' === $t ) {
				$depth++;
			} elseif ( ')' === $t || ']' === $t || '}' === $t ) {
				if ( 0 === $depth ) {
					return $j;
				}
				$depth--;
			} elseif ( ';' === $t && 0 === $depth ) {
				return $j;
			}
		}
		return $count;
	}

	/** Does this RHS token slice read from a request-ish source? */
	private function looks_tainted( array $rhs ): bool {
		$count = count( $rhs );
		for ( $i = 0; $i < $count; $i++ ) {
			$t = $rhs[ $i ];
			if ( ! is_array( $t ) ) {
				continue;
			}
			if ( T_VARIABLE === $t[0]
				&& in_array( strtoupper( ltrim( $t[1], '$' ) ), array( '_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER' ), true ) ) {
				return true;
			}
			if ( T_STRING === $t[0] && in_array( $t[1], self::SOURCE_METHODS, true ) ) {
				$prev = $i > 0 ? $rhs[ $i - 1 ] : null;
				if ( is_array( $prev ) && T_OBJECT_OPERATOR === $prev[0] ) {
					return true;
				}
			}
		}
		return false;
	}

	/** Does this RHS token slice pass through a recognised sanitizer function or numeric/bool cast? */
	private function looks_sanitized( array $rhs ): bool {
		foreach ( $rhs as $t ) {
			if ( ! is_array( $t ) ) {
				continue;
			}
			if ( T_STRING === $t[0] && in_array( strtolower( $t[1] ), self::SANITIZERS, true ) ) {
				return true;
			}
			if ( in_array( $t[0], array( T_INT_CAST, T_DOUBLE_CAST, T_BOOL_CAST ), true ) ) {
				return true;
			}
		}
		return false;
	}

	/** True when the call opening at $paren is `$wpdb->prepare(` — the safe, parameterised form. */
	private function wraps_prepare( array $tokens, int $paren ): bool {
		$a = $this->next_significant( $tokens, $paren );
		if ( null === $a || ! is_array( $tokens[ $a ] ) || T_VARIABLE !== $tokens[ $a ][0] || '$wpdb' !== $tokens[ $a ][1] ) {
			return false;
		}
		$b = $this->next_significant( $tokens, $a );
		if ( null === $b || '->' !== $tokens[ $b ] ) {
			return false;
		}
		$c = $this->next_significant( $tokens, $b );
		return null !== $c && is_array( $tokens[ $c ] ) && T_STRING === $tokens[ $c ][0] && 'prepare' === $tokens[ $c ][1];
	}

	/**
	 * Scan the sink call's first argument (from the opening '(' to its matching ')' or the
	 * first top-level ',') for a reference to a tainted variable. Bounded to a small window of
	 * significant tokens so a giant argument expression can't make this expensive.
	 *
	 * @param array<string, array{line:int, param:string}> $tainted
	 */
	private function tainted_arg( array $tokens, int $paren, array $tainted ): ?string {
		$count  = count( $tokens );
		$depth  = 0;
		$window = 0;
		for ( $j = $paren; $j < $count && $window < 24; $j++ ) {
			$t = $tokens[ $j ];
			if ( is_array( $t ) && ! $this->significant( $t ) ) {
				continue;
			}
			$window++;
			if ( ! is_array( $t ) ) {
				if ( '(' === $t ) {
					$depth++;
				} elseif ( ')' === $t ) {
					--$depth;
					if ( 0 === $depth ) {
						break;
					}
				} elseif ( ',' === $t && 1 === $depth ) {
					break;
				}
				continue;
			}
			if ( T_VARIABLE === $t[0] && isset( $tainted[ $t[1] ] ) ) {
				return ltrim( $t[1], '$' );
			}
		}
		return null;
	}
}
