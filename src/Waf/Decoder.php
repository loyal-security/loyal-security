<?php
/**
 * Input normalization to defeat common WAF-evasion encodings.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * Produces a small set of decoded "candidate" strings for a raw value so signatures match
 * even when an attacker hides a payload behind URL/HTML/base64/hex encoding.
 */
class Decoder {

	/**
	 * Return distinct candidate strings to test against signatures.
	 *
	 * @param string $value Raw input value.
	 * @return string[] Unique candidates (always includes the original).
	 */
	public function candidates( string $value ): array {
		$out = array();
		$this->add( $out, $value );

		// Repeated URL-decode (handles double/triple encoding) — capped to avoid loops.
		$decoded = $value;
		for ( $i = 0; $i < 3; $i++ ) {
			$next = rawurldecode( $decoded );
			if ( $next === $decoded ) {
				break;
			}
			$decoded = $next;
			$this->add( $out, $decoded );
		}

		// HTML entity decode of the most-decoded form.
		$html = html_entity_decode( $decoded, ENT_QUOTES | ENT_HTML5 );
		if ( $html !== $decoded ) {
			$this->add( $out, $html );
		}

		// Strip null bytes and collapse comment-style obfuscation for a normalized view.
		$normal = str_replace( array( "\0", "\r" ), '', $decoded );
		$normal = preg_replace( '#/\*.*?\*/#s', '', $normal );
		if ( null !== $normal && $normal !== $decoded ) {
			$this->add( $out, $normal );
		}

		// Strip invisible / format-control Unicode codepoints (zero-width spaces, BOM, word
		// joiner, soft hyphen, bidi controls) that an attacker can inject *inside* a keyword
		// (e.g. 'UNI\u{200B}ON SELECT' or 'SEL\u{200B}ECT') to break the boundary a signature
		// matches on. We add the stripped form as an ADDITIONAL candidate so 'UNION'/'SELECT'
		// score identically to the un-obfuscated keyword, without losing the original bytes.
		$this->add_invisible_stripped( $out, $decoded );

		// Full-width ASCII (U+FF01–U+FF5E) → half-width (U+0021–U+007E).
		// e.g. 'ＵＮＩＯＮ ＳＥＬＥＣＴ' → 'UNION SELECT' so ASCII signatures fire.
		// Uses raw byte math (no mbstring) so it works in the pre-WordPress prepend on any host.
		if ( strpos( $decoded, "\xEF" ) !== false ) {
			$narrow = preg_replace_callback(
				'/\xEF([\xBC\xBD])([\x80-\xBF])/s',
				static function ( array $m ): string {
					$cp = ( 0x0F << 12 ) | ( ( ord( $m[1] ) & 0x3F ) << 6 ) | ( ord( $m[2] ) & 0x3F );
					return ( $cp >= 0xFF01 && $cp <= 0xFF5E ) ? chr( $cp - 0xFEE0 ) : $m[0];
				},
				$decoded
			);
			if ( is_string( $narrow ) && $narrow !== $decoded ) {
				$this->add( $out, $narrow );
			}
		}

		// Best-effort base64 decode of ALL long base64-looking tokens (catches packed payloads
		// hidden inside JSON values, multi-param strings, etc. — not just the first token).
		if ( preg_match_all( '/[A-Za-z0-9+\/]{24,}={0,2}/', $decoded, $ms ) ) {
			foreach ( $ms[0] as $token ) {
				$maybe = base64_decode( $token, true );
				if ( false !== $maybe && '' !== $maybe && $this->mostly_printable( $maybe ) ) {
					$this->add( $out, $maybe );
				}
			}
		}

		return $out;
	}

	/**
	 * Add a candidate with all invisible / format-control Unicode codepoints removed.
	 *
	 * Targets codepoints that render to nothing but split a keyword's character boundary:
	 *  - Zero-width: U+200B, U+200C, U+200D, U+FEFF (BOM/ZWNBSP), U+2060 (word joiner)
	 *  - Soft hyphen: U+00AD
	 *  - Bidi format controls: U+200E, U+200F, U+202A–U+202E, U+2066–U+2069
	 *
	 * The PCRE uses the `/u` modifier; on invalid UTF-8 `preg_replace` returns null, in which
	 * case we keep the original so we never blank the candidate (and never weaken inspection).
	 *
	 * @param string[] $bucket Reference to candidate list.
	 * @param string   $value  Candidate to normalize.
	 */
	private function add_invisible_stripped( array &$bucket, string $value ): void {
		if ( '' === $value ) {
			return;
		}
		$stripped = preg_replace(
			'/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2069}\x{FEFF}\x{00AD}]/u',
			'',
			$value
		);
		// preg_replace returns null on a UTF-8 error — fall back to the original, never blank.
		if ( ! is_string( $stripped ) ) {
			return;
		}
		if ( $stripped !== $value ) {
			$this->add( $bucket, $stripped );
		}
	}

	/**
	 * Add a candidate if non-empty and not already present (length-capped).
	 *
	 * @param string[] $bucket Reference to candidate list.
	 * @param string   $value  Candidate.
	 */
	private function add( array &$bucket, string $value ): void {
		$value = substr( $value, 0, 64 * 1024 );
		if ( '' !== $value && ! in_array( $value, $bucket, true ) ) {
			$bucket[] = $value;
		}
	}

	/**
	 * Heuristic: is the decoded blob mostly printable (so worth inspecting)?
	 */
	private function mostly_printable( string $s ): bool {
		$len = strlen( $s );
		if ( 0 === $len ) {
			return false;
		}
		$printable = 0;
		$sample    = substr( $s, 0, 512 );
		$slen      = strlen( $sample );
		for ( $i = 0; $i < $slen; $i++ ) {
			$o = ord( $sample[ $i ] );
			if ( $o >= 32 && $o < 127 || 9 === $o || 10 === $o || 13 === $o ) {
				$printable++;
			}
		}
		return ( $printable / $slen ) > 0.85;
	}
}
