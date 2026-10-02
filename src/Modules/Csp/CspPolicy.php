<?php
/**
 * CSP policy builder with service presets.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Csp;

defined( 'ABSPATH' ) || exit;

/**
 * Builds a Content-Security-Policy header value from a base set of directives,
 * user-enabled service presets, and optional custom directive overrides.
 */
class CspPolicy {

	/** Lazily-loaded, memoized copy of the JSON preset data — see {@see presets()}. */
	private static ?array $presets_cache = null;

	/**
	 * Known third-party service presets, loaded from a static JSON data file rather than a PHP
	 * array literal. Each defines directive additions that make the service work without opening
	 * the policy wider than needed. 'wordpress' is always applied when CSP is active (WP core and
	 * most themes need unsafe-inline for scripts/styles and data: for images).
	 *
	 * @return array<string, array{label:string, always?:bool, color:string, directives:array<string, string[]>}>
	 */
	private static function presets(): array {
		if ( null === self::$presets_cache ) {
			$json  = file_get_contents( TOTALSECWP_PATH . 'assets/data/csp-presets.json' );
			$decoded = is_string( $json ) ? json_decode( $json, true ) : null;
			self::$presets_cache = is_array( $decoded ) ? $decoded : array();
		}
		return self::$presets_cache;
	}

	/**
	 * Minimum base directives applied to every policy (before presets or customisations).
	 * Deliberately conservative — presets open what's needed; users can add custom sources.
	 */
	private const BASE = array(
		'default-src'     => array( "'self'" ),
		'script-src'      => array( "'self'" ),
		'style-src'       => array( "'self'" ),
		'img-src'         => array( "'self'", 'data:' ),
		'font-src'        => array( "'self'" ),
		'connect-src'     => array( "'self'" ),
		'frame-src'       => array( "'none'" ),
		'frame-ancestors' => array( "'self'" ),
		'object-src'      => array( "'none'" ),
		'base-uri'        => array( "'self'" ),
		'form-action'     => array( "'self'" ),
	);

	/**
	 * Build a CSP header value string from stored settings.
	 *
	 * @param array{ presets: string[], custom_directives: array<string, string[]> } $settings
	 * @param string $nonce  This request's CSP nonce (see CspNonce), applied to script-src only —
	 *                       see the note below on why style-src deliberately does not get one.
	 * @param bool   $strict_eval Drop 'unsafe-eval' from script-src. Unlike the nonce, there is
	 *                       no graceful-degrade path for eval() — this is a real behavior change
	 *                       for any script that calls eval()/new Function(), so it's opt-in
	 *                       rather than always-on.
	 */
	public static function build( array $settings, string $nonce = '', bool $strict_eval = false ): string {
		$directives = self::BASE;

		$presets = self::presets();

		// WordPress preset is always merged in when CSP is active.
		$directives = self::merge( $directives, $presets['wordpress']['directives'] );

		foreach ( (array) ( $settings['presets'] ?? array() ) as $slug ) {
			if ( isset( $presets[ $slug ] ) && empty( $presets[ $slug ]['always'] ) ) {
				$directives = self::merge( $directives, $presets[ $slug ]['directives'] );
			}
		}

		foreach ( (array) ( $settings['custom_directives'] ?? array() ) as $directive => $values ) {
			if ( is_array( $values ) ) {
				$directives[ $directive ] = self::merge_values( $directives[ $directive ] ?? array(), $values );
			}
		}

		// script-src only. A nonce/hash source in a directive makes CSP-compliant browsers
		// ignore 'unsafe-inline' for that ENTIRE directive — elements AND attributes alike —
		// and there is no nonce mechanism for attributes (only 'unsafe-hashes' + an exact-value
		// hash per attribute, impractical at WordPress/Gutenberg's scale of dynamic inline
		// style="..." attributes). Adding the nonce to style-src doesn't just fail to protect
		// those attributes, it actively BLOCKS every one of them in Enforce mode — that's not a
		// gap, it's a real regression (confirmed live: broke the homepage's site-title layout,
		// which the theme positions via an inline style attribute). script-src has no equivalent
		// attribute surface in modern WP core (no onclick= handlers), so it's safe there.
		if ( '' !== $nonce && isset( $directives['script-src'] ) ) {
			$directives['script-src'][] = "'nonce-{$nonce}'";
		}

		if ( $strict_eval && isset( $directives['script-src'] ) ) {
			$directives['script-src'] = array_values( array_filter(
				$directives['script-src'],
				static fn( $v ) => "'unsafe-eval'" !== $v
			) );
		}

		$parts = array();
		foreach ( $directives as $directive => $values ) {
			$parts[] = $directive . ' ' . implode( ' ', array_unique( $values ) );
		}
		return implode( '; ', $parts );
	}

	/**
	 * Merge additional directive values into an existing directives map.
	 *
	 * @param array<string, string[]> $base
	 * @param array<string, string[]> $additions
	 * @return array<string, string[]>
	 */
	private static function merge( array $base, array $additions ): array {
		foreach ( $additions as $directive => $values ) {
			$base[ $directive ] = self::merge_values( $base[ $directive ] ?? array(), $values );
		}
		return $base;
	}

	/**
	 * Combine two source-list arrays for a single directive, honouring the CSP rule that
	 * 'none' must be the only token in a directive's value list — a directive carrying
	 * 'none' next to a real source isn't "extra strict", the browser silently ignores the
	 * entire directive (https://www.w3.org/TR/CSP3/#grammardef-serialized-source-list),
	 * which is worse than 'none' alone: it looks locked down in this UI while actually
	 * being unenforced. BASE ships 'frame-src'/'object-src' as ["'none'"] and more than a
	 * dozen presets (Google, Cloudflare, Stripe, PayPal, YouTube, Vimeo, …) add real
	 * frame-src sources on top — 'none' has to lose that fight, not sit alongside it.
	 *
	 * @param string[] $existing
	 * @param string[] $incoming
	 * @return string[]
	 */
	private static function merge_values( array $existing, array $incoming ): array {
		$combined = array_values( array_unique( array_merge( $existing, $incoming ) ) );
		if ( count( $combined ) > 1 ) {
			$combined = array_values( array_filter( $combined, static function ( $v ) {
				return "'none'" !== $v;
			} ) );
		}
		return $combined;
	}

	/**
	 * Return the preset list suitable for the REST API (excludes the hidden 'wordpress' entry).
	 *
	 * @return array<array{ slug: string, label: string, color: string }>
	 */
	public static function presets_list(): array {
		$out = array();
		foreach ( self::presets() as $slug => $data ) {
			if ( ! empty( $data['always'] ) ) {
				continue;
			}
			$out[] = array(
				'slug'  => $slug,
				'label' => $data['label'],
				'color' => $data['color'] ?? '#6b7280',
			);
		}
		return $out;
	}
}
