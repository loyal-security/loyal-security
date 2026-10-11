<?php
/**
 * HTTP client for the ThreatIntel feed server.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\ThreatIntel;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\ProStatus;
use LoyalSecurity\Core\LicenseKit;
use LoyalSecurity\Core\Settings;
use LoyalSecurity\Support\Http;

/**
 * Fetches a signed dataset bundle from the remote feed server.
 * The actual feed backend is out of scope; this is the plugin-side client.
 *
 * The server contract: POST the request body, receive:
 *   { "payload": "<base64-json>", "signature": "<base64-sig>", "version": "<string>" }
 * or a 304-equivalent { "up_to_date": true } when current_version already matches.
 */
class FeedClient {

	private ProStatus $pro;
	private Settings $settings;

	public function __construct( ProStatus $pro, Settings $settings ) {
		$this->pro      = $pro;
		$this->settings = $settings;
	}

	/** Feed server confirmed a bundle payload is included in the result. */
	public const STATUS_OK = 'ok';

	/** Feed server confirmed this site's cached version is already current — no bundle, but the
	 * server was reached and responded meaningfully. Distinct from STATUS_ERROR so a healthy
	 * "nothing new" outcome can still count as a successful contact for staleness tracking. */
	public const STATUS_UP_TO_DATE = 'up_to_date';

	/** No API configured, transport failure, or an unrecognized response shape. */
	public const STATUS_ERROR = 'error';

	/**
	 * Fetch a signed bundle for one dataset from the feed server.
	 *
	 * @param string $dataset waf | malware | patches | cve
	 * @return array{status:string, bundle:?array<string, mixed>} `status` is one of the
	 *   STATUS_* constants; `bundle` is populated only when `status` is STATUS_OK.
	 */
	public function fetch( string $dataset ): array {
		// Default to the configured LicenseKit deployment ({base}/api/v1/sync); the
		// loyalsec_feed_url filter can still point sync at a staging/self-hosted feed.
		$url = (string) apply_filters( 'loyalsec_feed_url', LicenseKit::feed_url() );
		if ( '' === $url ) {
			return array( 'status' => self::STATUS_ERROR, 'bundle' => null ); // No API base configured.
		}

		$channel       = $this->pro->tier();
		$license_key   = (string) $this->settings->get( 'threatintel', 'license_key', '' );
		$feed_versions = (array) $this->settings->get( 'threatintel', 'feed_versions', array() );

		// Only what the feed needs to answer: which dataset, which version this site already has,
		// and the feed subscription key when one is configured. No site URL or personal data is sent.
		$fields = array(
			'license_key'     => $license_key,
			'channel'         => $channel,
			'dataset'         => $dataset,
			'current_version' => isset( $feed_versions[ $dataset ] ) ? (string) $feed_versions[ $dataset ] : '0',
		);

		// The CVE advisory set spans the whole plugin/theme ecosystem (50k+ entries) but a
		// given site only ever matches the handful it has installed. Scope the request so the
		// server can return just the relevant subset instead of the full dataset. A server that
		// doesn't yet support this field simply ignores it and keeps returning everything —
		// VulnerabilityScanner already filters to installed slugs locally either way.
		if ( 'cve' === $dataset ) {
			$fields['installed'] = $this->installed_slugs();
		}

		$bundle = Http::post_json_body( $url, $fields );

		// Server responded { up_to_date: true } when this site's cached version is already
		// current — a healthy, successful contact with nothing new to write, not an error.
		if ( is_array( $bundle ) && ! empty( $bundle['up_to_date'] ) ) {
			return array( 'status' => self::STATUS_UP_TO_DATE, 'bundle' => null );
		}

		if ( is_array( $bundle ) && isset( $bundle['payload'], $bundle['signature'] ) ) {
			return array( 'status' => self::STATUS_OK, 'bundle' => $bundle );
		}

		return array( 'status' => self::STATUS_ERROR, 'bundle' => null );
	}

	/**
	 * Installed plugin/theme slugs, for scoping the CVE dataset request.
	 *
	 * @return array{ plugin: string[], theme: string[] }
	 */
	private function installed_slugs(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug      = dirname( $file );
			$slug      = ( '.' === $slug ) ? basename( $file, '.php' ) : $slug;
			$plugins[] = $slug;
		}

		$themes = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$themes[] = (string) $slug;
		}

		return array(
			'plugin' => array_values( array_unique( $plugins ) ),
			'theme'  => array_values( array_unique( $themes ) ),
		);
	}
}
