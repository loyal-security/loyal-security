<?php
/**
 * Database content scanner (posts, options, users).
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Scans high-risk database content for injected spam/scripts and audits administrator
 * accounts for rogue/unexpected admins.
 */
class DatabaseScanner {

	/** Patterns indicating injected content in posts/options. */
	private const PATTERNS = array(
		array( 'rule' => 'db-script', 'score' => 20, 'regex' => '/<script[\s>][\s\S]{0,200}?(document\.|eval\(|fromCharCode|\.src\s*=)/i', 'desc' => 'Injected script in content' ),
		array( 'rule' => 'db-iframe', 'score' => 18, 'regex' => '/<iframe[^>]+(src\s*=\s*[\'"]https?:\/\/(?!.*' . 'youtube|vimeo' . '))/i', 'desc' => 'Suspicious external iframe' ),
		array( 'rule' => 'db-base64', 'score' => 16, 'regex' => '/(eval|atob|unescape)\s*\(\s*[\'"][A-Za-z0-9+\/=]{40,}/i', 'desc' => 'Encoded payload in content' ),
		array( 'rule' => 'db-spamlinks', 'score' => 12, 'regex' => '/<a[^>]+href[^>]+(viagra|cialis|casino|payday-loan|replica-watch|cheap-pills|buy-pills|payday-loans|essay-writing|weight-loss|forex-signals)/i', 'desc' => 'SEO spam link injection' ),
		array( 'rule' => 'db-hidden', 'score' => 10, 'regex' => '/style\s*=\s*[\'"][^\'"]*(display\s*:\s*none|position\s*:\s*absolute;\s*left\s*:\s*-?\d{3,})/i', 'desc' => 'Hidden injected element' ),
	);

	/**
	 * Run the database scan and return findings.
	 *
	 * @return Finding[]
	 */
	public function scan(): array {
		$findings = array_merge(
			$this->scan_posts(),
			$this->scan_options(),
			$this->scan_comments(),
			$this->scan_usermeta(),
			$this->audit_admins()
		);
		return $findings;
	}

	/**
	 * @return Finding[]
	 */
	private function scan_posts(): array {
		global $wpdb;
		$findings = array();

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT ID, post_content FROM %i WHERE post_status IN ('publish','draft','private') AND post_content != '' ORDER BY ID DESC LIMIT 5000", $wpdb->posts ),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			foreach ( self::PATTERNS as $p ) {
				if ( @preg_match( $p['regex'], (string) $row['post_content'] ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$findings[] = new Finding(
						'post:' . $row['ID'],
						$p['rule'],
						'injection',
						(int) $p['score'],
						0,
						$p['desc']
					);
				}
			}
		}
		return $findings;
	}

	/**
	 * @return Finding[]
	 */
	private function scan_options(): array {
		global $wpdb;
		$findings = array();

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
			$wpdb->prepare(
				'SELECT option_name, option_value FROM %i WHERE option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s LIMIT 2000',
				$wpdb->options,
				'%' . $wpdb->esc_like( '<script' ) . '%',
				'%' . $wpdb->esc_like( 'eval(' ) . '%',
				'%' . $wpdb->esc_like( 'base64_decode' ) . '%'
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			foreach ( self::PATTERNS as $p ) {
				if ( @preg_match( $p['regex'], (string) $row['option_value'] ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$findings[] = new Finding(
						'option:' . $row['option_name'],
						$p['rule'],
						'injection',
						(int) $p['score'],
						0,
						$p['desc']
					);
				}
			}
		}
		return $findings;
	}

	/**
	 * Scan comment bodies for injected scripts and SEO spam. Comment injection is one of the
	 * most common vectors, so this covers approved and pending comments; bounded to the most
	 * recent rows to keep the inline scan within time limits.
	 *
	 * @return Finding[]
	 */
	private function scan_comments(): array {
		global $wpdb;
		$findings = array();

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT comment_ID, comment_content FROM %i WHERE comment_approved IN ('0','1') AND comment_content != '' ORDER BY comment_ID DESC LIMIT 5000", $wpdb->comments ),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			foreach ( self::PATTERNS as $p ) {
				if ( @preg_match( $p['regex'], (string) $row['comment_content'] ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$findings[] = new Finding(
						'comment:' . $row['comment_ID'],
						$p['rule'],
						'injection',
						(int) $p['score'],
						0,
						$p['desc']
					);
				}
			}
		}
		return $findings;
	}

	/**
	 * Scan user meta for encoded payloads or injected scripts. Pre-filtered with LIKE (as with
	 * options) so only candidate rows are pulled — malware occasionally hides configuration or
	 * a staged payload in usermeta to survive plugin/theme cleanups.
	 *
	 * @return Finding[]
	 */
	private function scan_usermeta(): array {
		global $wpdb;
		$findings = array();

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
			$wpdb->prepare(
				'SELECT umeta_id, user_id, meta_key, meta_value FROM %i WHERE meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s LIMIT 2000',
				$wpdb->usermeta,
				'%' . $wpdb->esc_like( '<script' ) . '%',
				'%' . $wpdb->esc_like( 'eval(' ) . '%',
				'%' . $wpdb->esc_like( 'base64_decode' ) . '%'
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			foreach ( self::PATTERNS as $p ) {
				if ( @preg_match( $p['regex'], (string) $row['meta_value'] ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$findings[] = new Finding(
						'usermeta:' . $row['user_id'] . ':' . $row['meta_key'],
						$p['rule'],
						'injection',
						(int) $p['score'],
						0,
						$p['desc']
					);
				}
			}
		}
		return $findings;
	}

	/**
	 * Flag administrator accounts (so an operator can confirm none are rogue) and detect
	 * users created very recently with admin privileges.
	 *
	 * @return Finding[]
	 */
	private function audit_admins(): array {
		$findings = array();
		$admins   = get_users( array( 'role' => 'administrator' ) );

		foreach ( $admins as $user ) {
			$registered  = strtotime( $user->user_registered . ' UTC' );
			$age         = time() - $registered;
			$very_recent = $age < HOUR_IN_SECONDS;

			// Only genuinely suspicious admins are flagged: one created within the last hour (the
			// create-then-use window of a live attack) OR one whose login matches a known
			// attacker-created pattern. The previous "created in the last 7 days" trigger flagged
			// every legitimately-provisioned admin on agency/multi-author sites — pure noise —
			// so it was dropped in favour of these two high-signal conditions.
			$suspicious_slug = (bool) preg_match( '/^(admin\d+|wp[-_]?admin|root|support\d+|backup)$/i', (string) $user->user_login );

			if ( $very_recent || $suspicious_slug ) {
				$score      = $very_recent ? 30 : 18;
				$findings[] = new Finding(
					'user:' . $user->ID,
					'db-admin-audit',
					'suspicious',
					$score,
					0,
					sprintf(
						'Administrator "%s" (registered %s)%s',
						$user->user_login,
						$user->user_registered,
						$very_recent ? ' — created within the last hour' : ' — unusual admin login name'
					)
				);
			}
		}
		return $findings;
	}
}
