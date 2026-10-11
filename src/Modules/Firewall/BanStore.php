<?php
/**
 * IP ban storage (database) with sync to the pre-WordPress flat-file store.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Support\Ip;
use LoyalSecurity\Waf\FileStore;

/**
 * Authoritative ban list. Writes are mirrored into the WAF prepend's `bans.json` so the
 * Optimized-Mode firewall can enforce bans before WordPress loads.
 */
class BanStore {

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'loyalsec_bans';
	}

	/**
	 * Add or update a ban.
	 *
	 * @param string   $ip       IP address (or use $cidr for ranges).
	 * @param string   $reason   Human reason.
	 * @param string   $type     'temporary' | 'permanent'.
	 * @param int|null $ttl      Seconds until expiry (temporary only).
	 * @param string   $source   Origin (manual|bruteforce|waf|ratelimit|geo|bot).
	 * @param string   $cidr     Optional CIDR range.
	 * @return bool False when the address is invalid or is a proxy in front of the site.
	 */
	public function add( string $ip, string $reason = '', string $type = 'temporary', ?int $ttl = null, string $source = 'manual', string $cidr = '' ): bool {
		$ban = compact( 'ip', 'reason', 'type', 'ttl', 'source', 'cidr' );
		if ( ! $this->write_row( $ban ) ) {
			return false;
		}
		$this->sync_to_file();
		$this->announce( $ban );
		return true;
	}

	/**
	 * Add or update many bans and rewrite the prepend's ban file once, instead of once per ban.
	 * For bulk imports such as IP-reputation lists.
	 *
	 * @param array<int, array<string, mixed>> $bans Each: ip, and optionally reason, type, ttl, source, cidr (as for {@see add()}).
	 * @return int Number of bans written.
	 */
	public function add_many( array $bans ): int {
		$written = array();
		foreach ( $bans as $ban ) {
			if ( ! is_array( $ban ) ) {
				continue;
			}
			$ban = array(
				'ip'     => (string) ( $ban['ip'] ?? '' ),
				'reason' => (string) ( $ban['reason'] ?? '' ),
				'type'   => (string) ( $ban['type'] ?? 'temporary' ),
				'ttl'    => isset( $ban['ttl'] ) ? (int) $ban['ttl'] : null,
				'source' => (string) ( $ban['source'] ?? 'manual' ),
				'cidr'   => (string) ( $ban['cidr'] ?? '' ),
			);
			if ( $this->write_row( $ban ) ) {
				$written[] = $ban;
			}
		}
		if ( $written ) {
			$this->sync_to_file();
			foreach ( $written as $ban ) {
				$this->announce( $ban );
			}
		}
		return count( $written );
	}

	/**
	 * Whether an address or range belongs to a proxy in front of the site (Cloudflare's edge or a
	 * configured trusted proxy). Those addresses carry many visitors' traffic, so banning one
	 * would block real visitors instead of the attacker.
	 */
	public static function is_proxy_address( string $ip, string $cidr = '' ): bool {
		$proxies = Ip::CLOUDFLARE_RANGES;
		try {
			$settings = \LoyalSecurity\Plugin::instance()->container()->make( 'settings' );
			$proxies  = array_merge( $proxies, array_filter( array_map( 'trim', array_map( 'strval', (array) $settings->get( 'firewall', 'trusted_proxies', array() ) ) ) ) );
		} catch ( \Throwable $e ) {
			// Settings not available (very early or during uninstall): Cloudflare's ranges still apply.
			unset( $e );
		}
		if ( '' === $cidr ) {
			return Ip::is_valid( $ip ) && Ip::in_ranges( $ip, $proxies );
		}
		// Two ranges overlap when either one's network address lies inside the other.
		$base = explode( '/', $cidr, 2 )[0];
		if ( Ip::is_valid( $base ) && Ip::in_ranges( $base, $proxies ) ) {
			return true;
		}
		foreach ( $proxies as $proxy ) {
			$proxy_base = explode( '/', $proxy, 2 )[0];
			if ( Ip::is_valid( $proxy_base ) && Ip::cidr_match( $proxy_base, $cidr ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Insert or update one ban row (no file sync, no action).
	 *
	 * @param array<string, mixed> $ban ip, reason, type, ttl, source, cidr.
	 */
	private function write_row( array $ban ): bool {
		global $wpdb;

		$ip     = (string) $ban['ip'];
		$cidr   = (string) $ban['cidr'];
		$type   = (string) $ban['type'];
		$reason = (string) $ban['reason'];
		$ttl    = $ban['ttl'];

		if ( '' === $cidr && ! Ip::is_valid( $ip ) ) {
			return false;
		}
		if ( self::is_proxy_address( $ip, $cidr ) ) {
			return false;
		}

		$expires = null;
		if ( 'permanent' !== $type && $ttl ) {
			$expires = gmdate( 'Y-m-d H:i:s', time() + (int) $ttl );
		}

		$existing = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT id FROM %i WHERE ip = %s", $this->table(), $ip )
		);

		if ( $existing ) {
			$wpdb->update( // phpcs:ignore WordPress.DB
				$this->table(),
				array(
					'reason'     => mb_substr( $reason, 0, 191 ),
					'type'       => $type,
					'source'     => (string) $ban['source'],
					'cidr'       => '' !== $cidr ? $cidr : null,
					'expires_at' => $expires,
					'hits'       => 0,
				),
				array( 'id' => $existing )
			);
		} else {
			$wpdb->insert( // phpcs:ignore WordPress.DB
				$this->table(),
				array(
					'ip'         => $ip,
					'cidr'       => '' !== $cidr ? $cidr : null,
					'reason'     => mb_substr( $reason, 0, 191 ),
					'type'       => $type,
					'source'     => (string) $ban['source'],
					'created_at' => gmdate( 'Y-m-d H:i:s' ),
					'expires_at' => $expires,
				)
			);
		}
		return true;
	}

	/**
	 * Fire the ban-added action for one written ban.
	 *
	 * @param array<string, mixed> $ban ip, reason, type, source, cidr.
	 */
	private function announce( array $ban ): void {
		/**
		 * Fires after a ban is added or updated. Used by integrations (e.g. Cloudflare sync)
		 * to mirror the ban to an external edge firewall.
		 *
		 * @since 1.0.0
		 *
		 * @param string $ip     Banned IP address (the subnet base for CIDR bans).
		 * @param array  $context { reason, type, source, cidr } describing the ban.
		 */
		do_action(
			'loyalsec_ban_added',
			(string) $ban['ip'],
			array(
				'reason' => (string) $ban['reason'],
				'type'   => (string) $ban['type'],
				'source' => (string) $ban['source'],
				'cidr'   => (string) $ban['cidr'],
			)
		);
	}

	/**
	 * Remove a ban by IP.
	 */
	public function remove( string $ip ): bool {
		global $wpdb;
		$deleted = $wpdb->delete( $this->table(), array( 'ip' => $ip ) ); // phpcs:ignore WordPress.DB
		$this->sync_to_file();
		return (bool) $deleted;
	}

	/**
	 * Remove every ban that originated from a given source (e.g. 'ip_reputation').
	 *
	 * Used to prune bulk-imported bans without touching manual or engine-issued ones.
	 *
	 * @param string $source Source tag stored in the `source` column.
	 * @return int Number of rows removed.
	 */
	public function remove_by_source( string $source ): int {
		global $wpdb;
		$deleted = $wpdb->delete( $this->table(), array( 'source' => $source ) ); // phpcs:ignore WordPress.DB
		$this->sync_to_file();
		return (int) $deleted;
	}

	/**
	 * Count bans that originated from a given source.
	 *
	 * @param string $source Source tag stored in the `source` column.
	 */
	public function count_by_source( string $source ): int {
		global $wpdb;
		return (int) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE source = %s", $this->table(), $source )
		);
	}

	/**
	 * Is an IP currently banned?
	 */
	public function is_banned( string $ip ): bool {
		global $wpdb;
		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT type, expires_at FROM %i WHERE ip = %s", $this->table(), $ip ),
			ARRAY_A
		);
		if ( $row ) {
			// NULL expiry is treated as permanent regardless of type — this matches the
			// prepend exactly (sync_to_file() maps it to expiry 0, which FileStore::is_banned()
			// reads as permanent), so both modes agree.
			if ( 'permanent' === $row['type'] || null === $row['expires_at'] ) {
				return true;
			}
			if ( strtotime( $row['expires_at'] . ' UTC' ) > time() ) {
				return true;
			}
			// An EXPIRED exact match must not short-circuit the range check below: the IP can
			// still sit inside a permanently banned CIDR block (a lapsed 1-hour ban on one
			// address was un-banning it from its whole banned /24 — while the prepend's
			// FileStore, which does fall through to ranges, kept blocking it: mode drift).
		}

		// CIDR ranges: the ban file mirrors every range with a sorted index (sync_to_file()), so
		// use its binary search rather than matching each range in turn on every request.
		$dir = self::storage_dir();
		if ( '' !== $dir && is_file( $dir . '/bans.json' ) ) {
			return ( new FileStore( $dir ) )->in_banned_range( $ip );
		}
		$ranges = $wpdb->get_col( $wpdb->prepare( "SELECT cidr FROM %i WHERE cidr IS NOT NULL", $this->table() ) ); // phpcs:ignore WordPress.DB
		return $ranges && Ip::in_ranges( $ip, $ranges );
	}

	/**
	 * Paginated list for the dashboard.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function list( int $limit = 100, int $offset = 0 ): array {
		global $wpdb;
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT * FROM %i ORDER BY created_at DESC LIMIT %d OFFSET %d", $this->table(), $limit, $offset ),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : array();
	}

	public function count(): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i", $this->table() ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Mirror the active ban list into the WAF prepend's flat file.
	 */
	public function sync_to_file(): void {
		global $wpdb;

		$ips    = array();
		$ranges = array();

		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT ip, cidr, type, expires_at FROM %i", $this->table() ), ARRAY_A ); // phpcs:ignore WordPress.DB
		foreach ( (array) $rows as $row ) {
			if ( ! empty( $row['cidr'] ) ) {
				$ranges[] = $row['cidr'];
				continue;
			}
			$expiry = 0;
			if ( 'permanent' !== $row['type'] && ! empty( $row['expires_at'] ) ) {
				$expiry = (int) strtotime( $row['expires_at'] . ' UTC' );
			}
			$ips[ $row['ip'] ] = $expiry;
		}

		$dir = self::storage_dir();
		if ( $dir ) {
			( new FileStore( $dir ) )->write_bans( $ips, $ranges );
		}
	}

	/**
	 * Resolve the private storage directory shared with the prepend.
	 */
	public static function storage_dir(): string {
		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['error'] ) ) {
			return '';
		}
		return trailingslashit( $uploads['basedir'] ) . 'loyal-security';
	}
}
