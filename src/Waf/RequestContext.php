<?php
/**
 * Normalized snapshot of the current HTTP request.
 *
 * Zero WordPress dependency so it works inside the pre-WordPress WAF prepend.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Waf;

use TotalSecurityWP\Support\Ip;

defined( 'ABSPATH' ) || exit;

/**
 * Flattens the request superglobals into an iterable set of (source, key, value) triples
 * so the rule engine can inspect every scalar in GET/POST/COOKIE/headers and the raw body.
 */
class RequestContext {

	public string $ip = '0.0.0.0';
	public string $method = 'GET';
	public string $uri = '';
	public string $path = '';
	public string $user_agent = '';

	/** @var array<string, mixed> */
	public array $get = array();
	/** @var array<string, mixed> */
	public array $post = array();
	/** @var array<string, mixed> */
	public array $cookie = array();
	/** @var array<string, string> */
	public array $headers = array();

	public string $raw_body = '';

	/**
	 * True when PHP silently truncated the parsed body at `max_input_vars` AND the WAF could
	 * not recover the full raw body to inspect instead. In that state any payload beyond the
	 * limit is invisible to signature scoring, so the engine treats the request as suspicious
	 * (the `waf.body.truncated` heuristic) rather than letting it through unscanned.
	 *
	 * @see https://www.php.net/manual/en/info.configuration.php#ini.max-input-vars
	 */
	public bool $body_truncated = false;

	/** @var array<string, mixed> Raw $_SERVER copy. */
	public array $server = array();

	/** Body cap in bytes — applies to both pre-buffered and lazily-read raw bodies. */
	const BODY_CAP = 256 * 1024;

	/**
	 * Pre-buffered raw request body, captured before PHP consumes `php://input`.
	 *
	 * For `application/x-www-form-urlencoded` (and `multipart/form-data`) requests PHP reads
	 * `php://input` to build `$_POST`, after which the stream is empty for the rest of the
	 * request. The pre-WordPress prepend calls {@see prime_raw_body()} at the very top — before
	 * anything touches `$_POST` — so the COMPLETE body (including params beyond `max_input_vars`)
	 * is available to {@see capture()} no matter the content type. Null = nothing primed yet.
	 *
	 * @var string|null
	 */
	public static ?string $prebuffered_body = null;

	/**
	 * Read and stash the raw request body once, before PHP parses it into `$_POST`.
	 *
	 * MUST be called as early as possible (the prepend does this first thing). Idempotent and
	 * fail-safe: if the stream cannot be read it leaves the buffer untouched and `capture()`
	 * falls back to its own (possibly empty) read — never fatal.
	 *
	 * @param string|null $body Optional already-read body. The prepend reads `php://input` into
	 *                          a local at the very top of its closure (before this class is even
	 *                          autoloaded) and passes it here so the buffer reflects the earliest
	 *                          possible read. When null, this method reads the stream itself.
	 * @return void
	 */
	public static function prime_raw_body( ?string $body = null ): void {
		if ( null !== self::$prebuffered_body ) {
			return; // Already primed this request.
		}
		if ( null === $body ) {
			$body = @file_get_contents( 'php://input' ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
		}
		if ( is_string( $body ) ) {
			self::$prebuffered_body = substr( $body, 0, self::BODY_CAP );
		}
	}

	/**
	 * Build from PHP superglobals.
	 *
	 * @param bool     $trust_proxy     Honour forwarded headers.
	 * @param string[] $trusted_proxies Allowed proxy CIDRs.
	 * @param bool     $strip_slashes   Recursively strip one layer of backslash-escaping from
	 *                                  GET/POST/COOKIE and the request URI before flattening.
	 *                                  Standard Mode passes `true` because it runs on `init`,
	 *                                  after WordPress's `wp_magic_quotes()` has slashed the
	 *                                  superglobals (incl. `$_SERVER['REQUEST_URI']`); without
	 *                                  this, the engine inspects `\'`-escaped quotes and every
	 *                                  quote-based payload bypasses it. The pre-WordPress
	 *                                  prepend keeps the default `false` (it sees raw input).
	 */
	public static function capture( bool $trust_proxy = false, array $trusted_proxies = array(), bool $strip_slashes = false ): self {
		$ctx         = new self();
		$ctx->server = isset( $_SERVER ) ? (array) $_SERVER : array();
		$ctx->get    = isset( $_GET ) ? (array) $_GET : array();         // phpcs:ignore WordPress.Security.NonceVerification
		$ctx->post   = isset( $_POST ) ? (array) $_POST : array();       // phpcs:ignore WordPress.Security.NonceVerification
		$ctx->cookie = isset( $_COOKIE ) ? (array) $_COOKIE : array();

		$ctx->method     = isset( $ctx->server['REQUEST_METHOD'] ) ? (string) $ctx->server['REQUEST_METHOD'] : 'GET';
		$ctx->uri        = isset( $ctx->server['REQUEST_URI'] ) ? (string) $ctx->server['REQUEST_URI'] : '';

		// Undo WordPress magic-quotes when inspecting from a WP context so the engine sees the
		// literal client bytes. Done with a WP-free recursive stripslashes (NOT wp_unslash) so
		// this class stays loadable by the pre-WordPress prepend.
		if ( $strip_slashes ) {
			$ctx->get    = self::strip_slashes_deep( $ctx->get );
			$ctx->post   = self::strip_slashes_deep( $ctx->post );
			$ctx->cookie = self::strip_slashes_deep( $ctx->cookie );
			$ctx->uri    = stripslashes( $ctx->uri );
		}

		$ctx->path       = (string) parse_url( $ctx->uri, PHP_URL_PATH ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- wp_parse_url() is unavailable: this kernel is shared with the pre-WordPress prepend bootstrapper.
		$ctx->user_agent = isset( $ctx->server['HTTP_USER_AGENT'] ) ? (string) $ctx->server['HTTP_USER_AGENT'] : '';
		$ctx->headers    = self::extract_headers( $ctx->server );
		$ctx->ip         = Ip::client_ip( $ctx->server, $trust_proxy, $trusted_proxies );

		// Capture the raw body so the FULL payload is inspected regardless of PHP's parsing.
		// Prefer the pre-buffered body (the prepend primes it before $_POST is built, so it
		// survives even for urlencoded/multipart POSTs where php://input is otherwise empty by
		// the time we run). Only fall back to a live read when nothing was primed — which is the
		// JSON/XML case in Standard Mode, where php://input is still intact.
		if ( in_array( $ctx->method, array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) ) {
			if ( null !== self::$prebuffered_body ) {
				$ctx->raw_body = self::$prebuffered_body;
			} else {
				$body = file_get_contents( 'php://input' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				if ( is_string( $body ) ) {
					$ctx->raw_body = substr( $body, 0, self::BODY_CAP );
				}
			}

			// Detect the max_input_vars bypass: a urlencoded/multipart POST whose parameter
			// count has hit PHP's limit means $_POST is silently truncated and any payload past
			// the limit never reaches signature scoring. If we ALSO have no raw body to inspect
			// as a fallback (php://input already consumed, nothing primed), the request is
			// effectively un-inspectable — flag it so the engine can score it as suspicious.
			$ctx->body_truncated = self::detect_truncation( $ctx ) && '' === $ctx->raw_body;

			// Merge a JSON body into `post` so param-scoped checks (virtual patching's
			// slug+param rules, etc.) see the same params WordPress's own REST layer does. PHP
			// only auto-populates $_POST for x-www-form-urlencoded/multipart — a JSON POST (the
			// norm for REST API clients, including this plugin's own dashboard) leaves $_POST
			// empty, so every per-param check would silently never match a single JSON request
			// without this. Merged after strip_slashes_deep() above: json_decode() output was
			// never subject to WordPress's magic-quotes slashing, so it must not be stripped again.
			if ( '' !== $ctx->raw_body ) {
				$content_type = isset( $ctx->server['CONTENT_TYPE'] )
					? (string) $ctx->server['CONTENT_TYPE']
					: ( isset( $ctx->server['HTTP_CONTENT_TYPE'] ) ? (string) $ctx->server['HTTP_CONTENT_TYPE'] : '' );
				if ( false !== stripos( $content_type, 'application/json' ) ) {
					$decoded = json_decode( $ctx->raw_body, true );
					if ( is_array( $decoded ) ) {
						$ctx->post = array_merge( $ctx->post, $decoded );
					}
				}
			}
		}

		return $ctx;
	}

	/**
	 * A canonical signature identifying "this exact combination of query parameters, on this
	 * exact path" — used by the query-cardinality limiter (faceted-search/archive DoS
	 * detection) to count DISTINCT combinations an IP has requested, not just request volume.
	 * Two requests for the same path+params (any key order) produce the same signature; '' when
	 * there's no query string at all (nothing to track).
	 */
	public function query_signature(): string {
		if ( ! $this->get ) {
			return '';
		}
		$flat = array();
		self::flatten_query( $this->get, '', $flat );
		ksort( $flat );
		$parts = array();
		foreach ( $flat as $k => $v ) {
			$parts[] = $k . '=' . $v;
		}
		return $this->path . '?' . implode( '&', $parts );
	}

	/**
	 * Flatten a (possibly nested, e.g. `?filter[color][]=red`) query array into `key => "value"`
	 * pairs with stable, sortable string keys, so query_signature() doesn't choke on arrays.
	 *
	 * @param mixed                $data   Array or scalar.
	 * @param string               $prefix Dotted key path built up so far.
	 * @param array<string,string> $out    Accumulator (by reference).
	 */
	private static function flatten_query( $data, string $prefix, array &$out ): void {
		if ( is_array( $data ) ) {
			foreach ( $data as $k => $v ) {
				self::flatten_query( $v, '' === $prefix ? (string) $k : $prefix . '.' . $k, $out );
			}
			return;
		}
		$out[ $prefix ] = is_scalar( $data ) ? (string) $data : '';
	}

	/**
	 * Heuristically determine whether PHP truncated the parsed request body at `max_input_vars`.
	 *
	 * PHP applies `max_input_vars` to the COMBINED count of GET + POST + COOKIE input variables
	 * (recursively counted) and silently drops everything past it — no warning reaches userland
	 * in production. We approximate "at the limit" by recursively counting the parsed POST vars
	 * and comparing against the configured limit minus the GET + COOKIE vars already consumed.
	 * A `false` from a disabled/unlimited limit (`0`) means we cannot assert truncation.
	 *
	 * @param self $ctx Partially-built context (post/get/cookie populated).
	 * @return bool True when the parsed input is at/over PHP's limit.
	 */
	private static function detect_truncation( self $ctx ): bool {
		$limit = (int) ini_get( 'max_input_vars' );
		if ( $limit <= 0 ) {
			return false; // Unlimited or unknown — cannot assert truncation.
		}

		$consumed = self::count_vars( $ctx->get ) + self::count_vars( $ctx->cookie );
		$post     = self::count_vars( $ctx->post );

		// No parsed body vars at all means there is nothing that could have been truncated.
		// Without this, a cookie-heavy site whose GET+COOKIE count alone reaches a low
		// max_input_vars flagged every body-less POST/PUT/DELETE (0 >= 0) as truncated, and
		// protect mode blocked legitimate requests with the synthetic at-threshold score.
		if ( $post <= 0 ) {
			return false;
		}

		// PHP stops adding vars once the running total reaches the limit, so a parsed POST count
		// that meets-or-exceeds the remaining budget is the signal that the body was cut short.
		return $post >= max( 0, $limit - $consumed );
	}

	/**
	 * Recursively count scalar input variables the way PHP tallies them against max_input_vars
	 * (each leaf scalar counts as one; nested arrays are descended).
	 *
	 * @param mixed $data Array or scalar.
	 * @return int
	 */
	private static function count_vars( $data ): int {
		if ( ! is_array( $data ) ) {
			return 1;
		}
		$count = 0;
		foreach ( $data as $value ) {
			$count += self::count_vars( $value );
		}
		return $count;
	}

	/**
	 * Recursively strip one layer of backslash-escaping from a value.
	 *
	 * WP-free equivalent of `stripslashes_deep()` / `wp_unslash()`. Kept local (no WordPress
	 * functions) so this class remains usable inside the pre-WordPress WAF prepend. Only the
	 * keys' values are unslashed; array keys are preserved as-is.
	 *
	 * @param mixed $value Scalar or (nested) array.
	 * @return mixed Same shape with each string value stripslashed.
	 */
	private static function strip_slashes_deep( $value ) {
		if ( is_array( $value ) ) {
			foreach ( $value as $k => $v ) {
				$value[ $k ] = self::strip_slashes_deep( $v );
			}
			return $value;
		}
		if ( is_string( $value ) ) {
			return stripslashes( $value );
		}
		return $value;
	}

	/**
	 * Pull HTTP_* headers out of the server array into a clean map.
	 *
	 * @param array<string, mixed> $server Server array.
	 * @return array<string, string>
	 */
	private static function extract_headers( array $server ): array {
		$headers = array();
		foreach ( $server as $key => $value ) {
			if ( 0 === strpos( (string) $key, 'HTTP_' ) ) {
				$name             = strtolower( str_replace( '_', '-', substr( (string) $key, 5 ) ) );
				$headers[ $name ] = (string) $value;
			}
		}
		return $headers;
	}

	/**
	 * Yield every scalar value to inspect as [ source, key, value ].
	 *
	 * @return \Generator<array{0:string,1:string,2:string}>
	 */
	public function values(): \Generator {
		yield from $this->flatten( 'GET', $this->get );
		yield from $this->flatten( 'POST', $this->post );
		yield from $this->flatten( 'COOKIE', $this->cookie );

		// Raw unparsed query string — catches payloads where & in HTML entities (e.g. &lt;script&gt;)
		// causes PHP to split the value across multiple $_GET params, each appearing innocuous.
		$raw_query = isset( $this->server['QUERY_STRING'] ) ? (string) $this->server['QUERY_STRING'] : '';
		if ( '' !== $raw_query ) {
			yield array( 'QUERY_STRING', 'raw', $raw_query );
		}

		// Selected security-relevant headers (UA, referer, etc.).
		foreach ( array( 'user-agent', 'referer', 'x-forwarded-for', 'cookie' ) as $h ) {
			if ( isset( $this->headers[ $h ] ) ) {
				yield array( 'HEADER', $h, $this->headers[ $h ] );
			}
		}

		if ( '' !== $this->raw_body ) {
			yield array( 'BODY', 'raw', $this->raw_body );
		}

		// The request path itself (traversal / LFI in the URL).
		if ( '' !== $this->uri ) {
			yield array( 'URI', 'path', rawurldecode( $this->uri ) );
		}

		// Query string decoded with urldecode so + is treated as space (RFC 1866 form encoding).
		// rawurldecode above decodes %XX but not +, so a UNION+SELECT payload would score 0 on
		// the URI source and might fall below threshold if the GET source alone isn't sufficient.
		$raw_qs = (string) parse_url( $this->uri, PHP_URL_QUERY ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- wp_parse_url() is unavailable: this kernel is shared with the pre-WordPress prepend bootstrapper.
		if ( '' !== $raw_qs ) {
			$decoded_qs = urldecode( $raw_qs );
			if ( $decoded_qs !== $raw_qs ) {
				yield array( 'URI', 'query', $decoded_qs );
			}
		}
	}

	/**
	 * Recursively flatten an array into [source, key-path, scalar] triples.
	 *
	 * @param string $source Source label.
	 * @param mixed  $data   Array or scalar.
	 * @param string $prefix Key path prefix.
	 * @return \Generator<array{0:string,1:string,2:string}>
	 */
	private function flatten( string $source, $data, string $prefix = '' ): \Generator {
		if ( is_array( $data ) ) {
			foreach ( $data as $key => $value ) {
				$path = '' === $prefix ? (string) $key : $prefix . '.' . $key;
				yield from $this->flatten( $source, $value, $path );
			}
			return;
		}
		if ( is_scalar( $data ) ) {
			yield array( $source, $prefix, (string) $data );
		}
	}
}
