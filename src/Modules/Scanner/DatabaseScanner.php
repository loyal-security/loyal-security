<?php
/**
 * Database content scanner (posts, meta, terms, options, comments, users, code snippets).
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Scans high-risk database content for injected spam and scripts, PHP stored by code-snippet
 * plugins, and a hijacked site address, and audits administrator accounts for rogue admins.
 *
 * Content rows are pre-filtered in SQL by tokens every pattern below needs, so the whole table
 * is searched (not just recent rows) while only candidate rows reach PHP.
 */
class DatabaseScanner {

	/**
	 * Location prefixes of database findings (`post:12`, `option:name`, ...). A finding whose
	 * path starts with one of these has no file on disk.
	 */
	public const LOCATION_PREFIXES = array( 'post:', 'postmeta:', 'term:', 'termmeta:', 'option:', 'user:', 'theme:', 'comment:', 'usermeta:', 'snippet:', 'mu:', 'dropin:', 'plugin:', 'core:', 'db:' );

	/** Rows read per query while walking a table. */
	private const CHUNK = 500;

	/** Upper bound on candidate rows read per source, to keep one scan step bounded. */
	private const MAX_ROWS = 20000;

	/** Patterns indicating injected content. */
	private const PATTERNS = array(
		array( 'rule' => 'db-script', 'score' => 20, 'regex' => '/<script[\s>][\s\S]{0,200}?(document\.|eval\(|fromCharCode|\.src\s*=)/i', 'desc' => 'Injected script in content' ),
		array( 'rule' => 'db-base64', 'score' => 16, 'regex' => '/(eval|atob|unescape)\s*\(\s*[\'"][A-Za-z0-9+\/=]{40,}/i', 'desc' => 'Encoded payload in content' ),
		array( 'rule' => 'db-spamlinks', 'score' => 12, 'regex' => '/<a[^>]+href[^>]+(viagra|cialis|casino|payday-loan|replica-watch|cheap-pills|buy-pills|payday-loans|essay-writing|weight-loss|forex-signals)/i', 'desc' => 'SEO spam link injection' ),
		array( 'rule' => 'db-hidden', 'score' => 10, 'regex' => '/style\s*=\s*[\'"][^\'"]*(display\s*:\s*none|position\s*:\s*absolute;\s*left\s*:\s*-?\d{3,})/i', 'desc' => 'Hidden injected element' ),
	);

	/**
	 * Hosts commonly embedded on purpose in content (video, maps, social, payments, forms,
	 * analytics). A <script src> or <iframe src> on any other host, other than this site's own,
	 * is reported for review. Public code CDNs are deliberately not listed: attackers host
	 * payloads on them too, so a script from one stored in content is worth a look. Site owners
	 * can add hosts with the `loyalsec_db_scan_allowed_hosts` filter.
	 */
	private const KNOWN_HOSTS = array(
		'youtube.com', 'youtube-nocookie.com', 'youtu.be', 'vimeo.com', 'dailymotion.com', 'twitch.tv', 'wistia.com', 'wistia.net',
		'google.com', 'googletagmanager.com', 'google-analytics.com', 'googlesyndication.com', 'doubleclick.net', 'recaptcha.net',
		'twitter.com', 'x.com', 'twimg.com', 'facebook.com', 'facebook.net', 'instagram.com', 'linkedin.com', 'licdn.com', 'pinterest.com', 'tiktok.com', 'reddit.com', 'redditmedia.com',
		'spotify.com', 'soundcloud.com', 'apple.com', 'mixcloud.com',
		'github.com', 'codepen.io', 'jsfiddle.net',
		'cloudflareinsights.com', 'hcaptcha.com',
		'stripe.com', 'stripe.network', 'paypal.com', 'paypalobjects.com', 'squareup.com',
		'calendly.com', 'typeform.com', 'hubspot.com', 'hsforms.net', 'hs-scripts.com', 'mailchimp.com', 'list-manage.com', 'klaviyo.com',
		'gravatar.com', 'wp.com', 'wordpress.com', 'wordpress.org', 'jetpack.com',
		'openstreetmap.org', 'bing.com', 'microsoft.com', 'clarity.ms', 'hotjar.com',
	);

	/** @var array<int, array<string, mixed>> Signature rules that target database content (`target` db or any). */
	private array $content_rules;

	/** @var array<int, array<string, mixed>> Signature rules for PHP code (the file scanner's set). */
	private array $code_rules;

	private string $rules_version;

	/** @var string[] Hosts allowed in <script src> / <iframe src> (this site plus KNOWN_HOSTS plus the filter). */
	private array $allowed_hosts;

	/**
	 * @param array<int, array<string, mixed>> $rules   Malware signature rules (bundled + feed). A
	 *                                                  rule applies to database content when its
	 *                                                  `target` is `db` or `any`; every rule not
	 *                                                  limited to `db` also applies to PHP code
	 *                                                  stored by snippet plugins.
	 * @param string                           $version Rules version (for findings).
	 */
	public function __construct( array $rules = array(), string $version = '' ) {
		$this->content_rules = array_values( array_filter( $rules, static fn( $r ) => is_array( $r ) && array_intersect( self::targets( $r ), array( 'db', 'any' ) ) ) );
		$this->code_rules    = array_values( array_filter( $rules, static fn( $r ) => is_array( $r ) && array_intersect( self::targets( $r ), array( 'file', 'any' ) ) ) );
		$this->rules_version = $version;

		$hosts = self::KNOWN_HOSTS;
		foreach ( array( home_url(), site_url(), content_url(), includes_url() ) as $url ) {
			$host = wp_parse_url( $url, PHP_URL_HOST );
			if ( is_string( $host ) && '' !== $host ) {
				$hosts[] = strtolower( $host );
			}
		}
		/**
		 * Filters the hosts the database scan accepts in a stored <script src> or <iframe src>.
		 * A host also covers its subdomains.
		 *
		 * @since 1.5.0
		 *
		 * @param string[] $hosts Host names.
		 */
		$this->allowed_hosts = array_values( array_unique( array_map( 'strtolower', array_map( 'strval', (array) apply_filters( 'loyalsec_db_scan_allowed_hosts', $hosts ) ) ) ) );
	}

	/**
	 * Where a signature rule applies: its `target` as a list ('file' when absent).
	 *
	 * @param array<string, mixed> $rule Signature rule.
	 * @return string[]
	 */
	private static function targets( array $rule ): array {
		$target = $rule['target'] ?? 'file';
		$list   = array_filter( array_map( 'strtolower', array_map( 'strval', is_array( $target ) ? $target : array( $target ) ) ) );
		return $list ? $list : array( 'file' );
	}

	/**
	 * Whether a finding path is a database location rather than a file.
	 */
	public static function is_location( string $path ): bool {
		foreach ( self::LOCATION_PREFIXES as $prefix ) {
			if ( 0 === strpos( $path, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Run the database scan and return findings.
	 *
	 * @return Finding[]
	 */
	public function scan(): array {
		return array_merge(
			$this->scan_posts(),
			$this->scan_postmeta(),
			$this->scan_terms(),
			$this->scan_termmeta(),
			$this->scan_options(),
			$this->scan_comments(),
			$this->scan_usermeta(),
			$this->scan_snippets(),
			$this->check_site_address(),
			$this->audit_admins()
		);
	}

	/* ------------------------------ Content checks ------------------------------ */

	/**
	 * Every content check for one stored value.
	 *
	 * @param string $location Finding path (e.g. `post:12`).
	 * @param string $content  Stored value.
	 * @return Finding[]
	 */
	private function check_content( string $location, string $content ): array {
		if ( '' === $content ) {
			return array();
		}
		// Page builders and JSON settings store HTML with escaped slashes and quotes
		// (<script src=\"https:\/\/...), so undo that before matching.
		$content  = str_replace( array( '\\/', '\\"', "\\'" ), array( '/', '"', "'" ), $content );
		$findings = array();
		foreach ( self::PATTERNS as $p ) {
			if ( 1 === @preg_match( $p['regex'], $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a failed match on odd bytes is just "no match".
				$findings[] = new Finding( $location, $p['rule'], 'injection', (int) $p['score'], 0, $p['desc'] );
			}
		}
		$findings = array_merge( $findings, $this->check_external_sources( $location, $content ) );
		if ( $this->content_rules ) {
			$findings = array_merge( $findings, ( new SignatureDb( $this->content_rules, $this->rules_version ) )->scan( $location, $content ) );
		}
		return $findings;
	}

	/**
	 * <script src> and <iframe src> pointing at a host that is neither this site nor a commonly
	 * embedded service. The most common modern injection is a single external script tag, which
	 * has no inline code for the other patterns to catch.
	 *
	 * @return Finding[]
	 */
	private function check_external_sources( string $location, string $content ): array {
		if ( false === stripos( $content, '<script' ) && false === stripos( $content, '<iframe' ) ) {
			return array();
		}
		$findings = array();
		if ( preg_match_all( '/<(script|iframe)\b[^>]*?\ssrc\s*=\s*["\']?\s*((?:https?:)?\/\/[^\s"\'>]+)/i', $content, $m, PREG_SET_ORDER ) ) {
			$seen = array();
			foreach ( $m as $match ) {
				$tag  = strtolower( $match[1] );
				$url  = $match[2];
				$host = wp_parse_url( 0 === strpos( $url, '//' ) ? 'https:' . $url : $url, PHP_URL_HOST );
				if ( ! is_string( $host ) || '' === $host || $this->host_allowed( $host ) || isset( $seen[ $tag . $host ] ) ) {
					continue;
				}
				$seen[ $tag . $host ] = true;
				$findings[]           = 'script' === $tag
					? new Finding( $location, 'db-external-script', 'injection', 20, 0, sprintf( 'Script loaded from an outside host: %s', $host ) )
					: new Finding( $location, 'db-external-iframe', 'injection', 12, 0, sprintf( 'Frame loaded from an outside host: %s', $host ) );
			}
		}
		return $findings;
	}

	private function host_allowed( string $host ): bool {
		$host = strtolower( rtrim( $host, '.' ) );
		foreach ( $this->allowed_hosts as $allowed ) {
			if ( $host === $allowed || substr( $host, -strlen( '.' . $allowed ) ) === '.' . $allowed ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * PHP stored in the database by a code-snippet plugin runs on every request, so it gets the
	 * same signatures as PHP files.
	 *
	 * @return Finding[]
	 */
	private function check_code( string $location, string $code ): array {
		if ( '' === $code || ! $this->code_rules ) {
			return array();
		}
		return ( new SignatureDb( $this->code_rules, $this->rules_version ) )->scan( $location, $code );
	}

	/* --------------------------------- Sources --------------------------------- */

	/**
	 * Every post of every type and status except revisions, auto-drafts and trash.
	 *
	 * @return Finding[]
	 */
	private function scan_posts(): array {
		global $wpdb;
		$findings = array();
		$last     = 0;
		$read     = 0;
		do {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
				$wpdb->prepare(
					"SELECT ID, post_type, post_content FROM %i WHERE ID > %d AND post_type <> 'revision' AND post_status NOT IN ('auto-draft','trash') AND (post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s) ORDER BY ID ASC LIMIT %d",
					$wpdb->posts,
					$last,
					'%' . $wpdb->esc_like( '<script' ) . '%',
					'%' . $wpdb->esc_like( '<iframe' ) . '%',
					'%' . $wpdb->esc_like( 'eval(' ) . '%',
					'%' . $wpdb->esc_like( 'atob(' ) . '%',
					'%' . $wpdb->esc_like( 'unescape(' ) . '%',
					'%' . $wpdb->esc_like( 'display:none' ) . '%',
					'%' . $wpdb->esc_like( 'display: none' ) . '%',
					'%' . $wpdb->esc_like( 'position:absolute' ) . '%',
					'%' . $wpdb->esc_like( 'viagra' ) . '%',
					'%' . $wpdb->esc_like( 'cialis' ) . '%',
					'%' . $wpdb->esc_like( 'casino' ) . '%',
					'%' . $wpdb->esc_like( 'payday' ) . '%',
					'%' . $wpdb->esc_like( 'pills' ) . '%',
					self::CHUNK
				),
				ARRAY_A
			);
			foreach ( (array) $rows as $row ) {
				$last = (int) $row['ID'];
				$read++;
				$content = (string) $row['post_content'];
				// WPCode keeps its snippets as posts: PHP and HTML, so both kinds of check.
				if ( 'wpcode' === $row['post_type'] ) {
					$findings = array_merge( $findings, $this->check_code( 'post:' . $row['ID'], $content ) );
				}
				$findings = array_merge( $findings, $this->check_content( 'post:' . $row['ID'], $content ) );
			}
		} while ( is_array( $rows ) && count( $rows ) === self::CHUNK && $read < self::MAX_ROWS );

		// WPCode snippets without any of the HTML tokens above still hold PHP.
		$snippets = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
			$wpdb->prepare( "SELECT ID, post_content FROM %i WHERE post_type = 'wpcode' AND post_status NOT IN ('auto-draft','trash') LIMIT %d", $wpdb->posts, self::MAX_ROWS ),
			ARRAY_A
		);
		$flagged = array();
		foreach ( $findings as $f ) {
			$flagged[ $f->path ] = true;
		}
		foreach ( (array) $snippets as $row ) {
			if ( ! isset( $flagged[ 'post:' . $row['ID'] ] ) ) {
				$findings = array_merge( $findings, $this->check_code( 'post:' . $row['ID'], (string) $row['post_content'] ) );
			}
		}
		return $findings;
	}

	/**
	 * Post meta: page builders (Elementor, Divi, Beaver Builder...) keep page content here.
	 *
	 * @return Finding[]
	 */
	private function scan_postmeta(): array {
		global $wpdb;
		$findings = array();
		$last     = 0;
		$read     = 0;
		do {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
				$wpdb->prepare(
					'SELECT meta_id, post_id, meta_key, meta_value FROM %i WHERE meta_id > %d AND (meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s) ORDER BY meta_id ASC LIMIT %d',
					$wpdb->postmeta,
					$last,
					'%' . $wpdb->esc_like( '<script' ) . '%',
					'%' . $wpdb->esc_like( '<iframe' ) . '%',
					'%' . $wpdb->esc_like( 'eval(' ) . '%',
					'%' . $wpdb->esc_like( 'atob(' ) . '%',
					'%' . $wpdb->esc_like( 'base64_decode' ) . '%',
					self::CHUNK
				),
				ARRAY_A
			);
			foreach ( (array) $rows as $row ) {
				$last = (int) $row['meta_id'];
				$read++;
				$findings = array_merge( $findings, $this->check_content( 'postmeta:' . $row['post_id'] . ':' . $row['meta_key'], (string) $row['meta_value'] ) );
			}
		} while ( is_array( $rows ) && count( $rows ) === self::CHUNK && $read < self::MAX_ROWS );
		return $findings;
	}

	/**
	 * Category, tag and other term descriptions (shown on archive pages).
	 *
	 * @return Finding[]
	 */
	private function scan_terms(): array {
		global $wpdb;
		$findings = array();
		$rows     = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
			$wpdb->prepare(
				'SELECT term_id, description FROM %i WHERE description LIKE %s OR description LIKE %s OR description LIKE %s OR description LIKE %s LIMIT %d',
				$wpdb->term_taxonomy,
				'%' . $wpdb->esc_like( '<script' ) . '%',
				'%' . $wpdb->esc_like( '<iframe' ) . '%',
				'%' . $wpdb->esc_like( 'eval(' ) . '%',
				'%' . $wpdb->esc_like( '<a ' ) . '%',
				self::MAX_ROWS
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$findings = array_merge( $findings, $this->check_content( 'term:' . $row['term_id'], (string) $row['description'] ) );
		}
		return $findings;
	}

	/**
	 * @return Finding[]
	 */
	private function scan_termmeta(): array {
		global $wpdb;
		$findings = array();
		$rows     = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
			$wpdb->prepare(
				'SELECT term_id, meta_key, meta_value FROM %i WHERE meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s LIMIT %d',
				$wpdb->termmeta,
				'%' . $wpdb->esc_like( '<script' ) . '%',
				'%' . $wpdb->esc_like( '<iframe' ) . '%',
				'%' . $wpdb->esc_like( 'eval(' ) . '%',
				'%' . $wpdb->esc_like( 'base64_decode' ) . '%',
				self::MAX_ROWS
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$findings = array_merge( $findings, $this->check_content( 'termmeta:' . $row['term_id'] . ':' . $row['meta_key'], (string) $row['meta_value'] ) );
		}
		return $findings;
	}

	/**
	 * Options, including widget content and header/footer-injection plugin settings.
	 *
	 * @return Finding[]
	 */
	private function scan_options(): array {
		global $wpdb;
		$findings = array();

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
			$wpdb->prepare(
				'SELECT option_name, option_value FROM %i WHERE option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s LIMIT %d',
				$wpdb->options,
				'%' . $wpdb->esc_like( '<script' ) . '%',
				'%' . $wpdb->esc_like( '<iframe' ) . '%',
				'%' . $wpdb->esc_like( 'eval(' ) . '%',
				'%' . $wpdb->esc_like( 'base64_decode' ) . '%',
				self::MAX_ROWS
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$name = (string) $row['option_name'];
			// Transients are caches of remote responses and rendered output, not configuration.
			if ( 0 === strpos( $name, '_transient_' ) || 0 === strpos( $name, '_site_transient_' ) ) {
				continue;
			}
			$findings = array_merge( $findings, $this->check_content( 'option:' . $name, (string) $row['option_value'] ) );
		}
		return $findings;
	}

	/**
	 * Comment bodies (approved and pending): comment injection is a common vector.
	 *
	 * @return Finding[]
	 */
	private function scan_comments(): array {
		global $wpdb;
		$findings = array();
		$last     = 0;
		$read     = 0;
		do {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
				$wpdb->prepare(
					"SELECT comment_ID, comment_content FROM %i WHERE comment_ID > %d AND comment_approved IN ('0','1') AND (comment_content LIKE %s OR comment_content LIKE %s OR comment_content LIKE %s OR comment_content LIKE %s OR comment_content LIKE %s OR comment_content LIKE %s) ORDER BY comment_ID ASC LIMIT %d",
					$wpdb->comments,
					$last,
					'%' . $wpdb->esc_like( '<script' ) . '%',
					'%' . $wpdb->esc_like( '<iframe' ) . '%',
					'%' . $wpdb->esc_like( 'eval(' ) . '%',
					'%' . $wpdb->esc_like( '<a ' ) . '%',
					'%' . $wpdb->esc_like( 'display:none' ) . '%',
					'%' . $wpdb->esc_like( 'display: none' ) . '%',
					self::CHUNK
				),
				ARRAY_A
			);
			foreach ( (array) $rows as $row ) {
				$last = (int) $row['comment_ID'];
				$read++;
				$findings = array_merge( $findings, $this->check_content( 'comment:' . $row['comment_ID'], (string) $row['comment_content'] ) );
			}
		} while ( is_array( $rows ) && count( $rows ) === self::CHUNK && $read < self::MAX_ROWS );
		return $findings;
	}

	/**
	 * User meta: malware sometimes stages payloads here to survive plugin and theme cleanups.
	 *
	 * @return Finding[]
	 */
	private function scan_usermeta(): array {
		global $wpdb;
		$findings = array();

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
			$wpdb->prepare(
				'SELECT umeta_id, user_id, meta_key, meta_value FROM %i WHERE meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s LIMIT %d',
				$wpdb->usermeta,
				'%' . $wpdb->esc_like( '<script' ) . '%',
				'%' . $wpdb->esc_like( '<iframe' ) . '%',
				'%' . $wpdb->esc_like( 'eval(' ) . '%',
				'%' . $wpdb->esc_like( 'base64_decode' ) . '%',
				self::MAX_ROWS
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$findings = array_merge( $findings, $this->check_content( 'usermeta:' . $row['user_id'] . ':' . $row['meta_key'], (string) $row['meta_value'] ) );
		}
		return $findings;
	}

	/**
	 * The Code Snippets plugin's table: PHP that runs on every request.
	 *
	 * @return Finding[]
	 */
	private function scan_snippets(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'snippets';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- existence check for another plugin's table.
		if ( $table !== $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) ) {
			return array();
		}
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off scan read.
			$wpdb->prepare( 'SELECT id, code FROM %i LIMIT %d', $table, self::MAX_ROWS ),
			ARRAY_A
		);
		$findings = array();
		foreach ( (array) $rows as $row ) {
			$code     = (string) ( $row['code'] ?? '' );
			$findings = array_merge( $findings, $this->check_code( 'snippet:' . $row['id'], $code ), $this->check_content( 'snippet:' . $row['id'], $code ) );
		}
		return $findings;
	}

	/**
	 * A changed `home` or `siteurl` sends every visitor (or the admin area) to another site. The
	 * addresses seen on the first scan are remembered; a later difference is reported until the
	 * owner changes the address in WordPress or marks the finding resolved. Skipped when
	 * WP_HOME / WP_SITEURL fix the addresses in wp-config.php (the database values are then unused).
	 *
	 * @return Finding[]
	 */
	private function check_site_address(): array {
		$current = self::site_address_hosts();
		$known   = get_option( self::SITE_ADDRESS_OPTION );
		if ( ! is_array( $known ) ) {
			update_option( self::SITE_ADDRESS_OPTION, $current, false );
			return array();
		}
		$findings = array();
		foreach ( $current as $name => $host ) {
			if ( '' === $host || ! isset( $known[ $name ] ) || $known[ $name ] === $host ) {
				continue;
			}
			$findings[] = new Finding(
				'option:' . $name,
				'db-site-address',
				'injection',
				30,
				0,
				sprintf( 'The site address "%1$s" now points to %2$s (it was %3$s). If you did not move the site, it has been hijacked.', $name, $host, $known[ $name ] )
			);
		}
		return $findings;
	}

	/** Option remembering the host of `home` and `siteurl` from the first scan. */
	public const SITE_ADDRESS_OPTION = 'loyalsec_known_site_address';

	/**
	 * Hosts of `home` and `siteurl` as stored in the database (constants excluded).
	 *
	 * @return array<string, string>
	 */
	public static function site_address_hosts(): array {
		global $wpdb;
		$out = array();
		foreach ( array( 'home' => 'WP_HOME', 'siteurl' => 'WP_SITEURL' ) as $name => $constant ) {
			if ( defined( $constant ) ) {
				continue;
			}
			// Read the stored value directly: get_option() can be filtered by other code.
			$value        = (string) $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, $name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the raw stored value is the point.
			$host         = wp_parse_url( $value, PHP_URL_HOST );
			$out[ $name ] = is_string( $host ) ? strtolower( $host ) : '';
		}
		return $out;
	}

	/**
	 * Remember the current addresses as the expected ones (after the owner changed them in
	 * WordPress, or confirmed a reported change).
	 */
	public static function remember_site_address(): void {
		update_option( self::SITE_ADDRESS_OPTION, self::site_address_hosts(), false );
	}

	/* ---------------------------------- Users ---------------------------------- */

	/**
	 * Flag administrator accounts (so an operator can confirm none are rogue) and detect
	 * users created very recently with admin privileges.
	 *
	 * @return Finding[]
	 */
	private function audit_admins(): array {
		global $wpdb;
		$findings = array();
		$admins   = get_users( array( 'role' => 'administrator' ) );

		// The account created when WordPress was installed is the owner, not an intruder: on a
		// site set up today it is also "created within the last hour", which flagged every new
		// install's own admin as critical. Accounts made within ten minutes of the site's first
		// user count as that installer.
		$first_user = strtotime( (string) $wpdb->get_var( "SELECT MIN(user_registered) FROM {$wpdb->users}" ) . ' UTC' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- core users table, no input.

		foreach ( $admins as $user ) {
			$registered  = strtotime( $user->user_registered . ' UTC' );
			$age         = time() - $registered;
			$installer   = $first_user && abs( $registered - $first_user ) < 10 * MINUTE_IN_SECONDS;
			$very_recent = $age < HOUR_IN_SECONDS && ! $installer;

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
