<?php
/**
 * File Integrity Monitoring module.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Integrity;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Core\AbstractModule;
use TotalSecurityWP\Core\Cron;
use TotalSecurityWP\Modules\Audit\EventCatalog;
use TotalSecurityWP\Modules\Scanner\Finding;

/**
 * Coordinates core/plugin/theme integrity verification and records drift as findings so it
 * appears alongside malware results in the dashboard and incident workflow.
 */
class IntegrityModule extends AbstractModule {

	public function id(): string {
		return 'integrity';
	}

	public function title(): string {
		return __( 'File Integrity Monitoring', 'loyal-security' );
	}

	public function default_settings(): array {
		return array(
			'enabled'         => true,
			'verify_core'     => true,
			'verify_plugins'  => true,
			'verify_themes'   => true,
			'verify_mu'       => true,
			'scheduled'       => true,
		);
	}

	public function register_hooks(): void {
		add_action( Cron::REFRESH_SUMS, array( $this, 'run_scheduled' ) );
	}

	private function findings_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'totalsecwp_scan_findings';
	}

	/**
	 * Run a full integrity check and store findings.
	 *
	 * @return array<string, mixed>
	 */
	public function run(): array {
		$scan_id = 'fim_' . gmdate( 'YmdHis' );
		$summary = array( 'scan_id' => $scan_id, 'core' => null, 'plugins' => null, 'themes' => null, 'mu' => null );
		$changed = 0;

		if ( $this->setting( 'verify_core', true ) ) {
			$core              = ( new CoreChecksums() )->verify();
			$summary['core']   = $core;
			foreach ( $core['modified'] as $file ) {
				$this->record( $scan_id, $file, 'integrity-core-modified', 32, 'Core file modified vs WordPress.org checksum' );
				$changed++;
			}
			foreach ( $core['missing'] as $file ) {
				$this->record( $scan_id, $file, 'integrity-core-missing', 24, 'Core file missing' );
				$changed++;
			}
			foreach ( $core['unknown'] as $file ) {
				$this->record( $scan_id, $file, 'integrity-core-unknown', 30, 'Unexpected file in a WordPress core location (not part of the official distribution)' );
				$changed++;
			}
			// A modified or unexpected core file is no longer trusted, so deep-scan its
			// content for malware signatures (the heuristic scanner skips core locations by
			// default). This surfaces *what* the tampering is — e.g. an injected webshell or
			// the EICAR test string — alongside the bare "modified/unknown" signal.
			$changed += $this->deep_scan_core( $scan_id, array_merge( $core['modified'], $core['unknown'] ) );
		}

		if ( $this->setting( 'verify_plugins', true ) ) {
			$plugins            = ( new PluginChecksums() )->verify_all();
			$summary['plugins'] = $plugins;
			foreach ( $plugins['modified'] as $m ) {
				$this->record( $scan_id, $m['slug'] . '/' . $m['file'], 'integrity-plugin-modified', 28, 'Plugin file modified vs WordPress.org checksum' );
				$changed++;
			}
			// Plugins not on WordPress.org (premium/custom) can't be checksum-verified, but
			// they're still watched via the same custom-baseline drift detection themes use —
			// see PluginChecksums::baseline_diff(). Only meaningful once a baseline exists;
			// "no baseline yet" itself is surfaced to the operator by the dashboard, not as a
			// finding (it isn't evidence of tampering, just an unsnapshotted plugin).
			foreach ( $plugins['unverifiable'] as $u ) {
				if ( empty( $u['has_baseline'] ) ) {
					continue;
				}
				foreach ( array_merge( $u['modified'], $u['added'] ) as $rel ) {
					$this->record( $scan_id, $u['slug'] . '/' . $rel, 'integrity-plugin-unverifiable-drift', 26, 'Unverifiable (non-WordPress.org) plugin file changed vs baseline' );
					$changed++;
				}
			}
		}

		if ( $this->setting( 'verify_themes', true ) ) {
			$themes            = ( new ThemeChecksums() )->verify_all();
			$summary['themes'] = $themes;
			foreach ( $themes as $t ) {
				if ( empty( $t['has_baseline'] ) ) {
					continue;
				}
				foreach ( array_merge( $t['modified'], $t['added'] ) as $rel ) {
					$this->record( $scan_id, $t['source'] . '/' . $rel, 'integrity-theme-drift', 20, 'Theme file changed vs baseline' );
					$changed++;
				}
			}
		}

		if ( $this->setting( 'verify_mu', true ) ) {
			$mu            = ( new MuPluginChecksums() )->verify_all();
			$summary['mu'] = $mu;
			foreach ( $mu as $m ) {
				if ( empty( $m['has_baseline'] ) ) {
					continue;
				}
				$is_dropin = 'dropins' === ( $m['source'] ?? '' );
				// A newly-appeared executing drop-in is a strong backdoor signal, so it scores
				// higher than an mu-plugin edit and higher for "added" than "modified".
				foreach ( $m['added'] as $rel ) {
					$rule  = $is_dropin ? 'integrity-dropin-added' : 'integrity-mu-added';
					$score = $is_dropin ? 34 : 26;
					$desc  = $is_dropin
						? 'New auto-executing drop-in appeared (not present at baseline) — verify it is legitimate'
						: 'New must-use plugin file appeared vs baseline';
					$this->record( $scan_id, $this->mu_finding_path( $m['source'], $rel ), $rule, $score, $desc );
					$changed++;
				}
				foreach ( $m['modified'] as $rel ) {
					$rule  = $is_dropin ? 'integrity-dropin-modified' : 'integrity-mu-modified';
					$score = $is_dropin ? 30 : 24;
					$desc  = $is_dropin ? 'Drop-in file changed vs baseline' : 'Must-use plugin file changed vs baseline';
					$this->record( $scan_id, $this->mu_finding_path( $m['source'], $rel ), $rule, $score, $desc );
					$changed++;
				}
			}
		}

		if ( $changed > 0 ) {
			$this->logger()->log( EventCatalog::INTEGRITY_CHANGED, array( 'scan_id' => $scan_id, 'changed' => $changed ) );
		}

		$summary['changed'] = $changed;
		return $summary;
	}

	/**
	 * Build a stable, human-readable finding path for an mu-plugin / drop-in drift, prefixed so
	 * the dashboard treats it as a logical (non-disk) location rather than probing file_exists()
	 * on a relative path. See the `$db_prefixes` list in ScannerModule::findings().
	 */
	private function mu_finding_path( string $source, string $rel ): string {
		return ( 'dropins' === $source ? 'dropin:' : 'mu:' ) . $rel;
	}

	private function record( string $scan_id, string $path, string $rule, int $score, string $desc ): void {
		global $wpdb;
		$finding = new Finding( $path, $rule, 'integrity', $score, 0, $desc );
		$wpdb->insert( $this->findings_table(), $finding->to_row( $scan_id ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Force a malware content scan of untrusted core files (modified or unexpected) and
	 * record any signature hits as malware findings, preserving the line + snippet so the
	 * code inspector can show exactly what was found.
	 *
	 * @param string   $scan_id   Owning scan id.
	 * @param string[] $rel_paths Paths relative to ABSPATH.
	 * @return int Findings recorded.
	 */
	private function deep_scan_core( string $scan_id, array $rel_paths ): int {
		if ( empty( $rel_paths ) ) {
			return 0;
		}
		global $wpdb;
		$scanner = new \TotalSecurityWP\Modules\Scanner\HeuristicScanner();
		$abspath = untrailingslashit( \TotalSecurityWP\Support\Paths::root() );
		$n       = 0;
		$table = $this->findings_table();
		foreach ( array_unique( $rel_paths ) as $rel ) {
			$abs = $abspath . '/' . ltrim( $rel, '/\\' );
			foreach ( $scanner->scan_file( $abs, 3145728, false ) as $f ) {
				// Re-home the finding on the relative path and tag it as core malware.
				$rule = 'malware-core/' . $f->rule;
				// Skip if an identical open finding already exists (repeat integrity runs).
				$exists = $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name built from $wpdb->prefix, not user input.
					$wpdb->prepare(
						"SELECT id FROM %i WHERE status = 'open' AND path = %s AND rule = %s AND line = %d LIMIT 1", $table,
						$rel,
						$rule,
						(int) $f->line
					)
				);
				if ( $exists ) {
					continue;
				}
				$finding = new Finding( $rel, $rule, 'malware', max( 35, $f->score ), $f->line, $f->snippet );
				$wpdb->insert( $table, $finding->to_row( $scan_id ) ); // phpcs:ignore WordPress.DB
				$n++;
			}
		}
		return $n;
	}

	/**
	 * Snapshot baselines for themes/custom code (operator-initiated).
	 */
	public function snapshot_baselines(): int {
		return ( new ThemeChecksums() )->snapshot_all()
			+ ( new MuPluginChecksums() )->snapshot_all()
			+ ( new PluginChecksums() )->snapshot_unverifiable();
	}

	public function run_scheduled(): void {
		if ( $this->setting( 'scheduled', true ) ) {
			$this->run();
		}
	}
}
