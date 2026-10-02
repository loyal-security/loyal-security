<?php
/**
 * HTTP client for submitting an approved auto-drafted virtual-patch rule to LicenseKit.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\LicenseKit;

/**
 * Ships a site-derived {@see PatchSuggester} rule — never a file hash — to LicenseKit so it
 * can be reviewed and, if approved, redistributed through the existing `patches` feed to every
 * other site running the same plugin slug/version. Fail-open throughout: any transport error,
 * or the endpoint simply not existing yet, is swallowed and reported back as `ok => false`.
 *
 * Server-side confirmed live 2026-07-04 (see docs/licensekit-patch-suggestions.md) — matches
 * this exact request shape.
 */
class PatchSubmissionClient {

	/**
	 * @param array<string, mixed> $rule        The approved virtual-patch rule (VirtualPatch shape).
	 * @param string               $category    TaintAnalyzer rule category (e.g. 'tainted-rce').
	 * @param string               $license_key Raw license key (hashed before sending; may be empty).
	 * @return array{ok: bool, error?: string, response?: array<string, mixed>}
	 */
	public function submit( array $rule, string $category, string $license_key = '' ): array {
		$endpoint = LicenseKit::patch_suggestion_endpoint();
		if ( '' === $endpoint ) {
			return array( 'ok' => false, 'error' => 'not_configured' );
		}

		$body = array(
			'plugin_version' => defined( 'TOTALSECWP_VERSION' ) ? TOTALSECWP_VERSION : '',
			'timestamp'      => time(),
			'suggestion'     => array(
				'rule'     => $rule,
				'category' => $category,
			),
		);
		$json = (string) wp_json_encode( $body );

		$response = wp_remote_post(
			$endpoint,
			array(
				'timeout'    => 10,
				'user-agent' => \TotalSecurityWP\Support\Http::user_agent(),
				'headers'    => LicenseKit::auth_headers( $json, $license_key ),
				'body'       => $json,
			)
		);

		if ( is_wp_error( $response ) ) {
			// Was a silent black box before — same class of mistake already fixed once for
			// telemetry registration. Log so a persistently-failing submission is diagnosable.
			\TotalSecurityWP\Support\Debug::log( 'patch submission failed: ' . $response->get_error_message() );
			return array( 'ok' => false, 'error' => $response->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$raw_body = (string) wp_remote_retrieve_body( $response );
		if ( $code < 200 || $code >= 300 ) {
			\TotalSecurityWP\Support\Debug::log( 'patch submission failed: HTTP ' . $code . ' — ' . substr( $raw_body, 0, 500 ) );
			return array( 'ok' => false, 'error' => 'http_' . $code, 'body' => substr( $raw_body, 0, 500 ) );
		}

		$data = json_decode( $raw_body, true );
		return array( 'ok' => true, 'response' => is_array( $data ) ? $data : array() );
	}
}
