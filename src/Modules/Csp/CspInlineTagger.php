<?php
/**
 * Nonce-tags inline <script> tags for strict CSP enforcement.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Csp;

defined( 'ABSPATH' ) || exit;

/**
 * <script> only — see CspPolicy::build()'s docblock for why <style> deliberately doesn't get a
 * nonce: style-src keeps plain 'unsafe-inline' so inline style="..." attributes (which have no
 * nonce mechanism at all) keep working, so there is nothing useful for this class to tag there.
 *
 * Two layers, because WordPress only gives a filter for one of them:
 *
 *  1. `wp_inline_script_attributes` (WP core, since 5.7) — the clean path. Every inline
 *     script added the correct way (wp_add_inline_script()) goes through
 *     wp_get_inline_script_tag(), which applies this filter before printing the tag. No
 *     output buffering needed for these.
 *
 *  2. Everything else — inline <script> a theme or plugin echoes directly in a template or a
 *     wp_head/wp_footer hook, bypassing the Scripts API entirely (very common in the wild).
 *     Layer 1 can't reach any of this, so it's handled on WordPress's own template output
 *     buffer (the `wp_template_enhancement_output_buffer` filter, WordPress 6.9+), where the
 *     HTML API adds the nonce to every <script> tag that doesn't already carry one. On older
 *     WordPress versions only layer 1 applies.
 *
 * A tag that ships with the nonce validates against CSP's nonce source; anything that slips
 * past both layers still fails safe — report-only mode logs it as a violation instead of
 * silently breaking, which is exactly how this should be rolled out and observed before ever
 * switching a site to enforce.
 */
class CspInlineTagger {

	public function register(): void {
		add_filter( 'wp_inline_script_attributes', array( $this, 'tag_registered_inline_script' ), 10, 1 );

		// WordPress 6.9+ buffers the rendered template itself and exposes it through this filter;
		// adding a callback is what turns that buffer on. Nothing is buffered by this plugin.
		if ( function_exists( 'wp_should_output_buffer_template_for_enhancement' ) && class_exists( 'WP_HTML_Tag_Processor' ) ) {
			add_filter( 'wp_template_enhancement_output_buffer', array( $this, 'tag_raw_inline_tags' ) );
		}
	}

	/**
	 * @param array<string, string|bool> $attributes
	 * @return array<string, string|bool>
	 */
	public function tag_registered_inline_script( array $attributes ): array {
		if ( ! isset( $attributes['nonce'] ) ) {
			$attributes['nonce'] = CspNonce::value();
		}
		return $attributes;
	}

	/**
	 * Template-output filter: add the request's nonce to every <script> tag that doesn't already
	 * have one, using WordPress's HTML API rather than pattern matching. Fail-open by design —
	 * any unexpected problem returns the page untouched rather than breaking rendering, since
	 * this runs on every front-end response.
	 *
	 * @param string $html Full template output.
	 */
	public function tag_raw_inline_tags( $html ) {
		if ( ! is_string( $html ) || '' === $html ) {
			return $html;
		}
		try {
			$nonce     = CspNonce::value();
			$processor = new \WP_HTML_Tag_Processor( $html );
			while ( $processor->next_tag( array( 'tag_name' => 'SCRIPT' ) ) ) {
				if ( null === $processor->get_attribute( 'nonce' ) ) {
					$processor->set_attribute( 'nonce', $nonce );
				}
			}
			return $processor->get_updated_html();
		} catch ( \Throwable $e ) {
			return $html;
		}
	}
}
