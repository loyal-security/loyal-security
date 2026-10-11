<?php
/**
 * Threat Intelligence module — feed sync and CVE scanning.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\ThreatIntel;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Core\AbstractModule;
use LoyalSecurity\Core\Cron;
use LoyalSecurity\Core\ProStatus;
use LoyalSecurity\Modules\Audit\EventCatalog;

/**
 * Coordinates the feed client, signature verifier, on-disk store, and CVE scanner.
 *
 * Every site receives every dataset (firewall rules, malware signatures, virtual patches, CVE
 * advisories) and runs the vulnerability scanner. Sites with a Loyal Security Pro subscription to
 * the feed service are updated hourly instead of twice a day.
 */
class ThreatIntelModule extends AbstractModule {

	public function id(): string {
		return 'threatintel';
	}

	public function title(): string {
		return __( 'Threat Intelligence', 'loyal-security' );
	}

	public function default_settings(): array {
		return array(
			'enabled'     => true,
			'license_key' => '',
			'auto_sync'   => true,
			'channel'     => 'free', // Derived; rendered read-only in the Settings UI.
		);
	}

	public function register_hooks(): void {
		add_action( Cron::THREATINTEL_SYNC, array( $this, 'run_scheduled_sync' ) );

		// Re-apply the sync schedule whenever settings are saved (auto-sync on/off).
		add_action( 'update_option_' . LOYALSEC_OPTION_SETTINGS, array( $this, 'maybe_reschedule' ) );

		// Surface known vulnerabilities inline on the Plugins / Themes / Updates screens.
		if ( is_admin() ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_row_style' ) );
			add_filter( 'plugin_row_meta', array( $this, 'plugin_row_vuln_notice' ), 10, 4 );
			add_action( 'after_plugin_row', array( $this, 'after_plugin_row_warning' ), 10, 3 );
			add_filter( 'theme_row_meta', array( $this, 'theme_row_vuln_notice' ), 10, 4 );

			// Invalidate the per-slug vulnerability cache when the CVE feed changes.
			add_action( 'loyalsec_feed_updated', array( $this, 'flush_vuln_cache' ) );
		}
	}

	/* --------------------- Vulnerability row notices ------------------------- */

	/**
	 * Find a known-vulnerability advisory for an installed plugin/theme slug at a given
	 * version. Cached per (type, slug) in a transient to avoid scanning the whole CVE
	 * dataset on every admin page render.
	 *
	 * @param string $type    plugin | theme.
	 * @param string $slug    Directory slug.
	 * @param string $version Installed version.
	 * @return array<string, mixed>|null The matching advisory, or null when none applies.
	 */
	private function lookup_vulnerability( string $type, string $slug, string $version ): ?array {
		if ( '' === $slug ) {
			return null;
		}

		$cache_key = 'loyalsec_vuln_index_' . $type . '_' . md5( $slug );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			$hit = $cached['hit'] ?? null;
			// Re-evaluate the cached advisory against the *current* installed version so an
			// upgrade clears the notice without waiting for the cache to expire. Uses the full
			// version logic (fixed_in/affected/max_version), not max_version alone.
			if ( is_array( $hit ) ) {
				return VulnerabilityScanner::version_affected( $hit, $version ) ? $hit : null;
			}
			return null;
		}

		$hit = null;
		try {
			$cve_db = ( new FeedStore() )->get_rules( 'cve' );
		} catch ( \Throwable $e ) {
			$cve_db = null;
		}

		if ( is_array( $cve_db ) ) {
			foreach ( $cve_db as $cve ) {
				if ( ! is_array( $cve ) ) {
					continue;
				}
				if ( (string) ( $cve['type'] ?? '' ) !== $type ) {
					continue;
				}
				if ( (string) ( $cve['slug'] ?? '' ) !== $slug ) {
					continue;
				}
				if ( ! VulnerabilityScanner::version_affected( $cve, $version ) ) {
					continue; // Already patched in the installed version, or unverifiable.
				}
				$hit = $cve;
				break;
			}
		}

		set_transient( $cache_key, array( 'hit' => $hit ), HOUR_IN_SECONDS * 6 );
		return $hit;
	}

	/**
	 * Drop all cached per-slug vulnerability lookups (called when the CVE feed updates).
	 */
	public function flush_vuln_cache(): void {
		global $wpdb;
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- bulk transient purge by prefix.
			$wpdb->prepare(
				'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s',
				$wpdb->options,
				$wpdb->esc_like( '_transient_loyalsec_vuln_index_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_loyalsec_vuln_index_' ) . '%'
			)
		);
	}

	/**
	 * Append a vulnerability warning link to a plugin's row-meta on the Plugins screen.
	 *
	 * @param string[]             $plugin_meta Row meta links.
	 * @param string               $plugin_file Plugin file (e.g. "akismet/akismet.php").
	 * @param array<string, mixed> $plugin_data Plugin header data.
	 * @param string               $status      Plugin status context.
	 * @return string[]
	 */
	public function plugin_row_vuln_notice( $plugin_meta, $plugin_file, $plugin_data, $status ) {
		$slug    = dirname( (string) $plugin_file );
		$slug    = ( '.' === $slug ) ? basename( (string) $plugin_file, '.php' ) : $slug;
		$version = (string) ( $plugin_data['Version'] ?? '' );

		$vuln = $this->lookup_vulnerability( 'plugin', $slug, $version );
		if ( null !== $vuln ) {
			$plugin_meta[] = $this->vuln_meta_link( $vuln );
		}
		return $plugin_meta;
	}

	/**
	 * Append a vulnerability warning link to a theme's row-meta on the Themes screen.
	 *
	 * @param string[]             $theme_meta Row meta links.
	 * @param string               $stylesheet Theme slug.
	 * @param array<string, mixed> $theme_data Theme header data.
	 * @param string               $status     Theme status context.
	 * @return string[]
	 */
	public function theme_row_vuln_notice( $theme_meta, $stylesheet, $theme_data, $status ) {
		$slug    = (string) $stylesheet;
		$version = (string) ( $theme_data['Version'] ?? '' );

		$vuln = $this->lookup_vulnerability( 'theme', $slug, $version );
		if ( null !== $vuln ) {
			$theme_meta[] = $this->vuln_meta_link( $vuln );
		}
		return $theme_meta;
	}

	/**
	 * Output a full-width warning row beneath a vulnerable plugin (Plugins/Updates screen).
	 *
	 * @param string               $plugin_file Plugin file.
	 * @param array<string, mixed> $plugin_data Plugin header data.
	 * @param string               $status      Status context.
	 */
	public function after_plugin_row_warning( $plugin_file, $plugin_data, $status ): void {
		$slug    = dirname( (string) $plugin_file );
		$slug    = ( '.' === $slug ) ? basename( (string) $plugin_file, '.php' ) : $slug;
		$version = (string) ( $plugin_data['Version'] ?? '' );

		$vuln = $this->lookup_vulnerability( 'plugin', $slug, $version );
		if ( null === $vuln ) {
			return;
		}

		$cve_id = (string) ( $vuln['cve_id'] ?? $vuln['id'] ?? '' );
		$title  = (string) ( $vuln['title'] ?? $cve_id );
		$cols   = 4; // Plugins list table column count.

		printf(
			'<tr class="plugin-update-tr active"><td colspan="%1$d" class="plugin-update colspanchange">'
				. '<div class="update-message notice inline notice-error notice-alt"><p>'
				. '<span class="dashicons dashicons-warning" aria-hidden="true"></span> %2$s</p></div></td></tr>',
			(int) $cols,
			wp_kses(
				sprintf(
					/* translators: 1: vulnerability title, 2: CVE id. */
					__( '<strong>Loyal Security:</strong> A known security vulnerability affects this version — %1$s %2$s. Update or remove the plugin.', 'loyal-security' ),
					esc_html( $title ),
					'' !== $cve_id ? '(' . esc_html( $cve_id ) . ')' : ''
				),
				array( 'strong' => array() )
			)
		);
	}

	/**
	 * Style the row-meta vulnerability link on the Plugins and Themes screens.
	 *
	 * @param string $hook_suffix Current admin screen.
	 */
	public function enqueue_row_style( $hook_suffix ): void {
		if ( ! in_array( $hook_suffix, array( 'plugins.php', 'themes.php', 'update-core.php' ), true ) ) {
			return;
		}
		wp_register_style( 'loyalsec-row-meta', false, array(), LOYALSEC_VERSION );
		wp_enqueue_style( 'loyalsec-row-meta' );
		wp_add_inline_style(
			'loyalsec-row-meta',
			'.loyalsec-vuln-link{color:#dc3232;font-weight:600}'
			. '.loyalsec-vuln-link .dashicons{font-size:14px;height:14px;width:14px;vertical-align:text-top}'
		);
	}

	/**
	 * Build the short row-meta vulnerability link.
	 *
	 * @param array<string, mixed> $vuln Advisory.
	 */
	private function vuln_meta_link( array $vuln ): string {
		$cve_id = (string) ( $vuln['cve_id'] ?? $vuln['id'] ?? '' );
		$label  = '' !== $cve_id
			? sprintf(
				/* translators: %s: CVE id. */
				__( 'Security vulnerability (%s)', 'loyal-security' ),
				$cve_id
			)
			: __( 'Known security vulnerability', 'loyal-security' );

		return sprintf(
			'<a href="%1$s" class="loyalsec-vuln-link"><span class="dashicons dashicons-warning" aria-hidden="true"></span> %2$s</a>',
			esc_url( admin_url( 'admin.php?page=loyal-security#/threatintel' ) ),
			esc_html( $label )
		);
	}

	public function boot(): void {
		// Ensure the sync event is scheduled if activation ran before this module existed.
		if ( $this->setting( 'auto_sync', true ) && ! wp_next_scheduled( Cron::THREATINTEL_SYNC ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, Cron::threatintel_recurrence(), Cron::THREATINTEL_SYNC );
		}
	}

	/* ----------------------------- Public API -------------------------------- */

	/**
	 * Full sync cycle: fetch → verify → cache → optional vuln scan.
	 * Called by the cron hook (return value ignored — WP discards action-callback returns)
	 * and the manual-sync REST endpoint, which uses the return value so the "Sync now" button
	 * can report what actually happened instead of a blanket "success" regardless of outcome.
	 *
	 * @return array{synced:bool,errors:array<string,string>} Whether any dataset was newly
	 *   written this run, and any per-dataset failure reasons (sig_invalid|write_failed).
	 *   `synced:false, errors:[]` can mean either every dataset already matched the server's
	 *   latest (a healthy, fully-current site) or nothing is published for this channel yet —
	 *   both count as a successful contact for staleness-tracking purposes; see `$reached` below.
	 */
	public function run_sync(): array {
		if ( ! $this->is_enabled() ) {
			return array( 'synced' => false, 'errors' => array() );
		}

		$client = new FeedClient( $this->pro_status(), $this->settings() );
		$store  = new FeedStore();

		// Every dataset is fetched on every site; a feed subscription only changes how often.
		$datasets = array( 'waf', 'malware', 'patches', 'cve' );

		$versions = (array) $this->setting( 'feed_versions', array() );
		$synced   = false;
		// Did the feed server respond meaningfully for at least one dataset this run — either
		// with new data (STATUS_OK) or a confirmed "you're already current" (STATUS_UP_TO_DATE)?
		// This, not $synced, is what should drive the staleness/health signal: a site whose feed
		// has nothing new for days in a row (common once a dataset is fully synced — see
		// FeedClient::STATUS_UP_TO_DATE's docblock) is NOT the same as a site that can't reach
		// the server at all, and conflating the two produced a permanent false "feed is out of
		// date" admin notice on a site that was actually syncing successfully every time.
		$reached = false;
		$errors  = array(); // dataset => reason, for the sync-health record.

		foreach ( $datasets as $dataset ) {
			$result = $client->fetch( $dataset );
			if ( FeedClient::STATUS_ERROR === $result['status'] ) {
				// Genuine failure for this dataset — not recorded as a per-dataset error (a
				// persistent outage still surfaces via a stale last_success timestamp once EVERY
				// dataset keeps failing), but does not count toward $reached either.
				continue;
			}
			$reached = true;

			if ( FeedClient::STATUS_UP_TO_DATE === $result['status'] ) {
				continue; // Confirmed current — nothing new to verify/write for this dataset.
			}

			$bundle  = $result['bundle'];
			$payload = SignatureVerifier::verify( $bundle );
			if ( null === $payload ) {
				$errors[ $dataset ] = 'sig_invalid';
				$this->logger()->log(
					EventCatalog::THREATINTEL_SYNC_FAILED,
					array( 'dataset' => $dataset, 'reason' => 'sig_invalid' )
				);
				continue;
			}

			if ( $store->write( $dataset, $payload ) ) {
				$versions[ $dataset ] = isset( $payload['version'] ) ? (string) $payload['version'] : '';
				$synced = true;
				$this->logger()->log(
					EventCatalog::THREATINTEL_SYNCED,
					array( 'dataset' => $dataset, 'version' => $versions[ $dataset ] )
				);
			} else {
				$errors[ $dataset ] = 'write_failed';
			}
		}

		// Always record sync health (in a dedicated option, so it does NOT trigger the
		// settings-save cascade — write_waf_config / cron reschedule — on every sync). This is
		// what makes a silently-dark feed visible: a site that never reaches the server records
		// attempts but no success, and feed_is_stale() flags it. Keyed on $reached (contact),
		// not $synced (new data) — see $reached's docblock above for why that distinction matters.
		$this->record_feed_health( $reached, $errors );

		// Batch the status update to avoid triggering write_waf_config multiple times.
		if ( $synced ) {
			$update = array(
				'feed_versions' => $versions,
				'last_sync'     => gmdate( 'Y-m-d H:i:s' ),
			);

			// Patch-gap intelligence: notify once per newly-shielding rule for an installed
			// plugin, and fold the updated "already announced" list into the same settings write.
			$announced = $this->announce_new_patch_gaps();
			if ( null !== $announced ) {
				$update['patch_gap_notified'] = $announced;
			}

			$this->settings()->update_module( $this->id(), $update );
		}

		// Run the vulnerability scanner for all tiers now that CVE data is always fetched.
		( new VulnerabilityScanner( $store ) )->scan();

		return array( 'synced' => $synced, 'errors' => $errors );
	}

	/**
	 * Reschedule the sync cron when the license tier may have changed.
	 * Hooked on update_option_loyalsec_settings.
	 */
	public function maybe_reschedule(): void {
		if ( ! $this->is_enabled() || ! $this->setting( 'auto_sync', true ) ) {
			// Automatic updates switched off: no scheduled contact with the feed service.
			wp_clear_scheduled_hook( Cron::THREATINTEL_SYNC );
			return;
		}
		Cron::reschedule_threatintel();
	}

	/**
	 * Cron entry point: sync only while automatic updates are on (the manual "Sync now" button
	 * calls run_sync() directly).
	 */
	public function run_scheduled_sync(): void {
		if ( ! $this->is_enabled() || ! $this->setting( 'auto_sync', true ) ) {
			return;
		}
		$this->run_sync();
	}

	/** Option holding feed sync health (kept out of the settings option to avoid its save cascade). */
	private const HEALTH_OPTION = 'loyalsec_feed_health';

	/**
	 * Record the outcome of a sync run for the "is my threat feed actually updating?" health
	 * signal. Stored in a dedicated option (NOT the settings option) so writing it every sync
	 * does not fire update_option_loyalsec_settings (write_waf_config + cron reschedule).
	 *
	 * @param bool                  $reached Whether the feed server responded meaningfully for at
	 *   least one dataset this run (new data OR a confirmed "already current" — see
	 *   FeedClient::STATUS_UP_TO_DATE). NOT the same as "wrote new data": a fully-synced site can
	 *   legitimately hear "nothing new" from the server on every run for days at a stretch.
	 * @param array<string, string> $errors Per-dataset failure reasons (sig_invalid|write_failed).
	 */
	private function record_feed_health( bool $reached, array $errors ): void {
		$health = get_option( self::HEALTH_OPTION, array() );
		if ( ! is_array( $health ) ) {
			$health = array();
		}
		$now                    = gmdate( 'Y-m-d H:i:s' );
		$health['last_attempt'] = $now;
		if ( $reached ) {
			$health['last_success'] = $now;
		}
		$health['last_errors'] = $errors;
		update_option( self::HEALTH_OPTION, $health, false );
	}

	/**
	 * Whether the threat feed has gone stale: sync is enabled and auto, at least one attempt has
	 * been made, and the last SUCCESSFUL sync is missing or older than the threshold (default 3
	 * days — comfortably beyond both the twice-daily and hourly cadences). A brand-new
	 * install that hasn't attempted a sync yet is never reported stale.
	 */
	public function feed_is_stale(): bool {
		if ( ! $this->is_enabled() || ! $this->setting( 'auto_sync', true ) ) {
			return false;
		}
		$health = get_option( self::HEALTH_OPTION, array() );
		if ( ! is_array( $health ) || empty( $health['last_attempt'] ) ) {
			return false; // Never attempted (fresh install) — don't nag.
		}
		$last_ok   = isset( $health['last_success'] ) ? (int) strtotime( (string) $health['last_success'] . ' UTC' ) : 0;
		$threshold = (int) apply_filters( 'loyalsec_feed_stale_seconds', 3 * DAY_IN_SECONDS );
		return $last_ok <= 0 || ( time() - $last_ok ) > $threshold;
	}

	/**
	 * Status payload consumed by the REST endpoint and the dashboard panel.
	 *
	 * @return array<string, mixed>
	 */
	public function get_status(): array {
		$pro    = $this->pro_status();
		$health = get_option( self::HEALTH_OPTION, array() );
		return array(
			'enabled'       => $this->is_enabled(),
			'tier'          => $pro->tier(),
			'channel'       => $pro->tier(),
			'last_sync'     => (string) $this->setting( 'last_sync', '' ),
			'feed_versions' => (array) $this->setting( 'feed_versions', array() ),
			'auto_sync'     => (bool) $this->setting( 'auto_sync', true ),
			'patch_gap'     => ( new PatchGap() )->summary(),
			'sync_health'   => is_array( $health ) ? $health : array(),
			'feed_stale'    => $this->feed_is_stale(),
		);
	}

	/**
	 * Emit a one-time "you are protected, update when you can" event for each patch-gap rule
	 * that newly covers an installed plugin. The audit Logger fires `loyalsec_event_logged`,
	 * which the Notifications module turns into email/webhook alerts per the operator's channel
	 * settings — so this stays fully decoupled from that module.
	 *
	 * Returns the pruned list of announced rule ids to persist (so a plugin that is later
	 * updated and then regresses would re-notify), or null when nothing changed.
	 *
	 * @return string[]|null
	 */
	private function announce_new_patch_gaps(): ?array {
		$items   = ( new PatchGap() )->active_for_installed();
		$already = array_map( 'strval', (array) $this->setting( 'patch_gap_notified', array() ) );
		$known   = array_fill_keys( $already, true );
		$changed = false;

		foreach ( $items as $item ) {
			$id = (string) $item['rule_id'];
			if ( '' === $id || isset( $known[ $id ] ) ) {
				continue;
			}
			$known[ $id ] = true;
			$changed      = true;

			$this->logger()->log(
				EventCatalog::PATCH_GAP_PROTECTED,
				array(
					'plugin'       => $item['name'],
					'slug'         => $item['slug'],
					'installed'    => $item['installed_version'],
					'version_from' => $item['version_from'],
					'version_to'   => $item['version_to'],
					'confidence'   => $item['confidence'],
					'category'     => $item['vulnerability_type'],
					'rule'         => $id,
					'note'         => $item['summary'],
				),
				EventCatalog::SEV_WARNING
			);
		}

		// Keep only ids that still correspond to an active rule, so coverage that lapses and
		// later reappears (e.g. a downgrade) is announced again.
		$active = array();
		foreach ( $items as $item ) {
			$active[ (string) $item['rule_id'] ] = true;
		}
		$pruned = array();
		foreach ( array_keys( $known ) as $id ) {
			if ( isset( $active[ $id ] ) ) {
				$pruned[] = $id;
			}
		}
		if ( count( $pruned ) !== count( $already ) ) {
			$changed = true;
		}

		return $changed ? $pruned : null;
	}

	/**
	 * Whether the separate Pro plugin is active (selects the feed channel only).
	 */
	public function pro_status(): ProStatus {
		return new ProStatus();
	}
}
