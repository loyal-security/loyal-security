<?php
/**
 * IP ban storage (database) with sync to the pre-WordPress flat-file store.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Firewall;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Support\Ip;
use TotalSecurityWP\Waf\FileStore;

/**
 * Authoritative ban list. Writes are mirrored into the WAF prepend's `bans.json` so the
 * Optimized-Mode firewall can enforce bans before WordPress loads.
 */
class BanStore {

	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'totalsecwp_bans';
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
	 */
	public function add( string $ip, string $reason = '', string $type = 'temporary', ?int $ttl = null, string $source = 'manual', string $cidr = '' ): bool {
		global $wpdb;

		if ( '' === $cidr && ! Ip::is_valid( $ip ) ) {
			return false;
		}

		$expires = null;
		if ( 'permanent' !== $type && $ttl ) {
			$expires = gmdate( 'Y-m-d H:i:s', time() + $ttl );
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
					'source'     => $source,
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
					'source'     => $source,
					'created_at' => gmdate( 'Y-m-d H:i:s' ),
					'expires_at' => $expires,
				)
			);
		}

		$this->sync_to_file();

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
			'totalsecwp_ban_added',
			$ip,
			array(
				'reason' => $reason,
				'type'   => $type,
				'source' => $source,
				'cidr'   => $cidr,
			)
		);

		return true;
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

		// CIDR ranges.
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
