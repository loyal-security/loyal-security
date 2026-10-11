<?php
/**
 * Anomaly-scoring rule engine.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * Walks every request value, expands evasion-decoded candidates, runs the signature set,
 * and accumulates an anomaly score. When the score crosses the configured threshold the
 * request is flagged for blocking (OWASP-CRS-style additive scoring).
 */
class RuleEngine {

	private SignatureSet $signatures;
	private Decoder $decoder;

	/** @var array{threshold:int,disabled_rules:string[],allow_params:string[],site_host:string} */
	private array $config;

	/** Synthetic rule id raised when PHP truncated the body past max_input_vars and we are blind. */
	const TRUNCATION_RULE = 'waf.body.truncated';

	/**
	 * PCRE backtrack ceiling applied for the duration of signature matching. A pathological but
	 * VALID pattern (an operational mistake, or a rule pushed under a compromised feed key) would
	 * otherwise backtrack catastrophically and hang every request — in the pre-WordPress prepend
	 * that means a fleet-wide 500. With this ceiling such a pattern trips PREG_BACKTRACK_LIMIT
	 * instead, and @preg_match simply returns "no match" (fail-open). Generous for any legitimate
	 * WAF signature; restored to the site's own value immediately after matching.
	 */
	const PCRE_BACKTRACK_LIMIT = 200000;

	/**
	 * @param SignatureSet         $signatures Signature set.
	 * @param Decoder              $decoder    Decoder.
	 * @param array<string, mixed> $config     Engine config (threshold, disabled_rules, allow_params).
	 */
	public function __construct( SignatureSet $signatures, Decoder $decoder, array $config = array() ) {
		$this->signatures = $signatures;
		$this->decoder    = $decoder;
		$this->config     = array(
			'threshold'      => isset( $config['threshold'] ) ? (int) $config['threshold'] : 12,
			'disabled_rules' => isset( $config['disabled_rules'] ) ? (array) $config['disabled_rules'] : array(),
			'allow_params'   => isset( $config['allow_params'] ) ? (array) $config['allow_params'] : array(),
			// The site's own hostname (from home_url(), baked in at config-write time — NEVER
			// read from the request's own Host header, which is client-controlled and would let
			// an attacker spoof Host to match an internal target and dodge a 'same_host_exempt'
			// rule). Empty when unknown, in which case that exemption never applies.
			'site_host'      => isset( $config['site_host'] ) ? strtolower( (string) $config['site_host'] ) : '',
		);
	}

	/**
	 * Evaluate a request context. Caps PCRE backtracking for the duration of matching (see
	 * PCRE_BACKTRACK_LIMIT) and restores the site's original value afterwards, so a pathological
	 * signature can never hang the request and we never alter regex behaviour for the rest of the
	 * WordPress lifecycle.
	 */
	public function evaluate( RequestContext $req ): Decision {
		$prev = ini_get( 'pcre.backtrack_limit' );
		@ini_set( 'pcre.backtrack_limit', (string) self::PCRE_BACKTRACK_LIMIT ); // phpcs:ignore WordPress.PHP.IniSet, WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- bounds catastrophic-backtracking risk in signature regexes for the duration of one evaluate() call; always restored in the finally block below.
		try {
			return $this->evaluate_inner( $req );
		} finally {
			if ( false !== $prev ) {
				@ini_set( 'pcre.backtrack_limit', (string) $prev ); // phpcs:ignore WordPress.PHP.IniSet, WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- restoring the site's original value, not a new discouraged setting.
			}
		}
	}

	/**
	 * The scoring pipeline, wrapped by {@see evaluate()} for the PCRE guard.
	 */
	private function evaluate_inner( RequestContext $req ): Decision {
		$decision  = new Decision();
		$by_cat    = array();
		$disabled  = $this->config['disabled_rules'];
		$allow     = array_map( 'strtolower', $this->config['allow_params'] );

		// max_input_vars bypass guard: PHP silently dropped part of the body and we have no raw
		// body to inspect instead, so any payload past the limit is invisible to the scoring
		// below. Treat that blind spot as an at-threshold hit (respecting disabled_rules and the
		// allowlist mechanism) so a malicious param hidden beyond var #max_input_vars still
		// blocks instead of sailing through unscanned. Scored as a category of its own so
		// detection-only mode and logging report it accurately.
		if ( ! empty( $req->body_truncated ) && ! in_array( self::TRUNCATION_RULE, $disabled, true ) ) {
			$score               = $this->config['threshold'];
			$decision->score    += $score;
			$by_cat['anomaly']   = ( $by_cat['anomaly'] ?? 0 ) + $score;
			$decision->matches[] = array(
				'source'   => 'BODY',
				'param'    => 'raw',
				'rule'     => self::TRUNCATION_RULE,
				'category' => 'anomaly',
				'score'    => $score,
				'desc'     => 'Request body exceeded PHP max_input_vars and could not be fully inspected.',
			);
		}

		// Each rule scores at most once per request. The same text reaches the engine several
		// times (a form field, the raw body that carries it, each decoded variant), so counting
		// every sighting multiplied one ordinary phrase past the threshold: an order note that
		// matched one rule scored it twice and was blocked. Distinct rules still add up.
		$scored = array();

		foreach ( $req->values() as [ $source, $param, $value ] ) {
			if ( '' === $value ) {
				continue;
			}
			// Per-site allowlist: skip benign params (e.g. rich-text editor fields).
			if ( $allow && in_array( strtolower( (string) $param ), $allow, true ) ) {
				continue;
			}

			foreach ( $this->decoder->candidates( $value ) as $candidate ) {
				$hits = $this->signatures->match( $candidate, $disabled );
				foreach ( $hits as $rule ) {
					// Optional per-rule source allowlist: skip if current input source is
					// not in the list. Lets RFI rules target GET/POST/COOKIE/BODY only,
					// avoiding false positives on legitimate browser-sent headers (e.g.
					// Referer that contains a same-site admin.php URL).
					if ( ! empty( $rule['sources'] ) && ! in_array( $source, (array) $rule['sources'], true ) ) {
						continue;
					}

					// 'same_host_exempt' rules (SSRF/RFI patterns matched against a bare URL) are
					// skipped when the matched URL's host is the site's own hostname. WordPress
					// legitimately carries same-site absolute URLs in params like redirect_to /
					// _wp_http_referer — those are not an attacker directing the server at a
					// remote/internal target, they're this site's own login/redirect flow.
					if ( ! empty( $rule['same_host_exempt'] ) && $this->is_own_host( (string) ( $rule['matched'] ?? '' ) ) ) {
						continue;
					}

					$rule_id = (string) $rule['id'];
					if ( isset( $scored[ $rule_id ] ) ) {
						continue;
					}
					$scored[ $rule_id ] = true;

					$score              = (int) $rule['score'];
					$decision->score   += $score;
					$cat                = (string) $rule['category'];
					$by_cat[ $cat ]     = ( $by_cat[ $cat ] ?? 0 ) + $score;
					$decision->matches[] = array(
						'source'   => $source,
						'param'    => (string) $param,
						'rule'     => (string) $rule['id'],
						'category' => $cat,
						'score'    => $score,
						'desc'     => (string) $rule['desc'],
					);
				}
			}

			// Bound work on pathological inputs.
			if ( count( $decision->matches ) > 50 ) {
				break;
			}
		}

		if ( $by_cat ) {
			arsort( $by_cat );
			$decision->category = (string) array_key_first( $by_cat );
			// Highest-scoring match, not merely the first one hit: the block page's `ref:` and
			// telemetry otherwise name whatever cosmetic score-1 rule happened to match first
			// while a score-12 SQLi rule did the actual blocking.
			$top = null;
			foreach ( $decision->matches as $m ) {
				if ( null === $top || (int) $m['score'] > (int) $top['score'] ) {
					$top = $m;
				}
			}
			$decision->top_rule = $top ? (string) $top['rule'] : '';
		}

		if ( $decision->score >= $this->config['threshold'] ) {
			$decision->blocked = true;
			$decision->action  = 'block';
			$decision->message = 'Request blocked by Loyal Security WAF (' . $decision->category . ').';
		}

		return $decision;
	}

	/**
	 * Whether a matched URL's host is this site's own configured hostname.
	 *
	 * @param string $matched_url The exact substring the rule's regex matched.
	 */
	private function is_own_host( string $matched_url ): bool {
		if ( '' === $this->config['site_host'] ) {
			return false;
		}
		$host = (string) parse_url( $matched_url, PHP_URL_HOST ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- wp_parse_url() is unavailable: this kernel is shared with the pre-WordPress prepend bootstrapper.
		if ( '' === $host ) {
			return false;
		}
		return strtolower( $host ) === $this->config['site_host'];
	}
}
