<?php
/**
 * Pending-domain store for the CSP learning system.
 *
 * Accumulates external domains seen in CSP violation reports (both report-only and enforce
 * modes). Admins review the list, approve domains (which writes them into the active policy)
 * or dismiss them (hide forever). After enforcement is on, newly blocked domains feed the
 * same queue so admins can whitelist without toggling modes.
 *
 * Storage: a single non-autoloaded WP option so it never bloats every page load.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Csp;

defined( 'ABSPATH' ) || exit;

class CspPendingStore {

	/** Option key for the pending domain store. */
	public const OPTION_KEY = 'totalsecwp_csp_pending';

	/** Hard cap on stored entries to prevent unbounded growth. */
	private const MAX_ENTRIES = 500;

	/* ------------------------------------------------------------------ */
	/* Public API                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Record a domain/directive observation from a CSP violation report.
	 *
	 * Returns true if this is a genuinely new domain or a new directive on a
	 * previously seen domain (i.e. something the admin hasn't reviewed yet).
	 *
	 * @param string $domain    Hostname (e.g. 'secure.gravatar.com').
	 * @param string $directive CSP directive name (e.g. 'img-src').
	 */
	public function record( string $domain, string $directive ): bool {
		$data    = $this->load();
		$domains = $data['domains'] ?? array();

		$is_new = false;

		if ( ! isset( $domains[ $domain ] ) ) {
			if ( count( $domains ) >= self::MAX_ENTRIES ) {
				return false; // cap reached
			}
			$domains[ $domain ] = array(
				'directives' => array( $directive ),
				'first_seen' => time(),
				'last_seen'  => time(),
				'count'      => 1,
				'preset'     => $this->find_preset( $domain ),
				'status'     => 'pending',
			);
			$is_new = true;
		} else {
			$entry = $domains[ $domain ];
			// Don't re-add dismissed entries; approved ones can accumulate counts.
			if ( 'dismissed' === ( $entry['status'] ?? 'pending' ) ) {
				return false;
			}
			$directives = (array) ( $entry['directives'] ?? array() );
			if ( ! in_array( $directive, $directives, true ) ) {
				$directives[]         = $directive;
				$entry['directives']  = $directives;
				$is_new               = true; // new directive = actionable new info
			}
			$entry['last_seen']   = time();
			$entry['count']       = (int) ( $entry['count'] ?? 0 ) + 1;
			$domains[ $domain ]   = $entry;
		}

		$data['domains'] = $domains;
		if ( $is_new ) {
			$data['last_new_ts'] = time();
			$data['new_flag']    = true;
		}

		$this->save( $data );
		return $is_new;
	}

	/**
	 * Override the preset hint for an entry (used for scheme-based synthetic keys like "blob: (worker-src)").
	 *
	 * @param string $domain Hostname or synthetic key.
	 * @param string $preset Preset slug to suggest.
	 */
	public function set_preset_hint( string $domain, string $preset ): void {
		$data = $this->load();
		if ( isset( $data['domains'][ $domain ] ) ) {
			$data['domains'][ $domain ]['preset'] = $preset;
			$this->save( $data );
		}
	}

	/**
	 * Mark a domain as approved (admin reviewed and accepted it).
	 * The caller is responsible for writing the domain into the actual policy.
	 *
	 * @param string $domain Hostname to approve.
	 */
	public function approve( string $domain ): void {
		$data = $this->load();
		if ( isset( $data['domains'][ $domain ] ) ) {
			$data['domains'][ $domain ]['status'] = 'approved';
			$this->save( $data );
		}
	}

	/**
	 * Mark a domain as dismissed (admin decided not to allow it).
	 *
	 * @param string $domain Hostname to dismiss.
	 */
	public function dismiss( string $domain ): void {
		$data = $this->load();
		if ( isset( $data['domains'][ $domain ] ) ) {
			$data['domains'][ $domain ]['status'] = 'dismissed';
			$this->save( $data );
		}
	}

	/**
	 * Retrieve a single domain entry, or null if not found.
	 *
	 * @param string $domain Hostname.
	 * @return array<string, mixed>|null
	 */
	public function get_entry( string $domain ): ?array {
		$data = $this->load();
		if ( ! isset( $data['domains'][ $domain ] ) ) {
			return null;
		}
		return array_merge( array( 'domain' => $domain ), (array) $data['domains'][ $domain ] );
	}

	/**
	 * Return all pending (not dismissed, not approved) domain entries, newest first.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function get_pending(): array {
		$data    = $this->load();
		$domains = $data['domains'] ?? array();
		$out     = array();

		foreach ( $domains as $domain => $entry ) {
			if ( 'pending' === ( $entry['status'] ?? 'pending' ) ) {
				$out[] = array_merge( array( 'domain' => $domain ), (array) $entry );
			}
		}

		usort( $out, static fn( $a, $b ) => (int) $b['last_seen'] - (int) $a['last_seen'] );
		return $out;
	}

	/**
	 * Count of pending (unreviewed) domains.
	 */
	public function count_pending(): int {
		$data    = $this->load();
		$domains = $data['domains'] ?? array();
		$count   = 0;
		foreach ( $domains as $entry ) {
			if ( 'pending' === ( $entry['status'] ?? 'pending' ) ) {
				$count++;
			}
		}
		return $count;
	}

	/**
	 * Whether there are newly added domains since the last notification.
	 */
	public function has_new_flag(): bool {
		$data = $this->load();
		return ! empty( $data['new_flag'] );
	}

	/**
	 * Clear the new-domains flag and record the notification timestamp.
	 */
	public function clear_new_flag(): void {
		$data                = $this->load();
		$data['new_flag']    = false;
		$data['notified_ts'] = time();
		$this->save( $data );
	}

	/**
	 * Timestamp of the last new domain/directive added.
	 */
	public function last_new_ts(): int {
		$data = $this->load();
		return (int) ( $data['last_new_ts'] ?? 0 );
	}

	/**
	 * Timestamp of the last notification email sent.
	 */
	public function last_notified_ts(): int {
		$data = $this->load();
		return (int) ( $data['notified_ts'] ?? 0 );
	}

	/**
	 * Delete the entire pending store (reset).
	 */
	public function clear(): void {
		delete_option( self::OPTION_KEY );
	}

	/* ------------------------------------------------------------------ */
	/* Preset lookup                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Find the CspPolicy preset slug that covers a given domain, or null.
	 *
	 * @param string $domain Hostname to look up.
	 */
	public function find_preset( string $domain ): ?string {
		foreach ( CspScanner::domain_map() as $pattern => $slug ) {
			if ( $domain === $pattern || str_ends_with( $domain, '.' . $pattern ) ) {
				return $slug;
			}
		}
		return null;
	}

	/* ------------------------------------------------------------------ */
	/* Storage helpers                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * @return array<string, mixed>
	 */
	private function load(): array {
		$data = get_option( self::OPTION_KEY, array() );
		return is_array( $data ) ? $data : array();
	}

	/**
	 * @param array<string, mixed> $data
	 */
	private function save( array $data ): void {
		update_option( self::OPTION_KEY, $data, false ); // non-autoloaded
	}
}
