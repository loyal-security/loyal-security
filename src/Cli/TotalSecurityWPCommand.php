<?php
/**
 * WP-CLI commands for Loyal Security.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Cli;

defined( 'ABSPATH' ) || exit;

// Loaded only under WP-CLI; bail otherwise so the file is inert in normal requests.
if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

use WP_CLI;
use WP_CLI_Command;
use TotalSecurityWP\Plugin;
use TotalSecurityWP\Core\HealthScore;
use TotalSecurityWP\Modules\Scanner\ScannerModule;
use TotalSecurityWP\Modules\Backup\BackupModule;
use TotalSecurityWP\Modules\Auth\AuthModule;
use TotalSecurityWP\Modules\Audit\EventCatalog;

/**
 * Manage the Loyal Security plugin from the command line.
 *
 * ## EXAMPLES
 *
 *     wp loyal-security status
 *     wp loyal-security scan --quick
 *     wp loyal-security firewall list
 *     wp loyal-security backup create
 *     wp loyal-security twofa reset admin
 */
class TotalSecurityWPCommand extends WP_CLI_Command {

	/**
	 * Show the health score, enabled modules, and last scan date.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output as table, json, csv, or yaml.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp loyal-security status
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional args.
	 * @param array<string,string> $assoc_args Associative args.
	 */
	public function status( $args, $assoc_args ): void {
		$health = ( new HealthScore() )->compute();

		$enabled = array();
		foreach ( Plugin::instance()->modules() as $id => $module ) {
			if ( $module->is_enabled() ) {
				$enabled[] = $id;
			}
		}

		$last_scan = '—';
		$history   = get_option( 'totalsecwp_scan_history', array() );
		if ( is_array( $history ) && ! empty( $history[0]['completed_at'] ) ) {
			$last_scan = (string) $history[0]['completed_at'] . ' UTC';
		}

		$rows = array(
			array( 'field' => 'Health score', 'value' => $health['score'] . '/100 (' . $health['grade'] . ')' ),
			array( 'field' => 'Enabled modules', 'value' => $enabled ? implode( ', ', $enabled ) : 'none' ),
			array( 'field' => 'Last scan', 'value' => $last_scan ),
		);

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		WP_CLI\Utils\format_items( $format, $rows, array( 'field', 'value' ) );
	}

	/**
	 * Run a full malware scan to completion.
	 *
	 * ## OPTIONS
	 *
	 * [--quick]
	 * : Scan files only — skip the database scan portion.
	 *
	 * ## EXAMPLES
	 *
	 *     wp loyal-security scan
	 *     wp loyal-security scan --quick
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional args.
	 * @param array<string,string> $assoc_args Associative args.
	 */
	public function scan( $args, $assoc_args ): void {
		$module = Plugin::instance()->module( 'scanner' );
		if ( ! $module instanceof ScannerModule ) {
			WP_CLI::error( 'Scanner module is not available.' );
		}

		$type  = WP_CLI\Utils\get_flag_value( $assoc_args, 'quick', false ) ? 'content' : 'full';
		$start = $module->start( $type );
		$scan_id = (string) ( $start['scan_id'] ?? '' );
		if ( '' === $scan_id ) {
			WP_CLI::error( 'Could not start a scan.' );
		}

		$total    = (int) ( $start['total'] ?? 0 );
		$progress = WP_CLI\Utils\make_progress_bar( 'Scanning', max( 1, $total ) );

		$last_scanned = 0;
		do {
			$result  = $module->run_batch( $scan_id );
			$scanned = (int) ( $result['scanned_files'] ?? 0 );
			$progress->tick( max( 0, $scanned - $last_scanned ) );
			$last_scanned = $scanned;
		} while ( 'running' === (string) ( $result['status'] ?? '' ) );

		$progress->finish();

		WP_CLI::success(
			sprintf(
				'Scan complete. Files scanned: %d. Findings: %d.',
				$last_scanned,
				(int) ( $result['findings'] ?? 0 )
			)
		);
	}

	/**
	 * List the most recent firewall blocks.
	 *
	 * ## OPTIONS
	 *
	 * [<subcommand>]
	 * : The firewall action. Only "list" is supported.
	 * ---
	 * default: list
	 * options:
	 *   - list
	 * ---
	 *
	 * [--limit=<n>]
	 * : How many recent blocks to show.
	 * ---
	 * default: 50
	 * ---
	 *
	 * [--format=<format>]
	 * : Render output as table, json, csv, or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp loyal-security firewall list
	 *     wp loyal-security firewall list --limit=20
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional args.
	 * @param array<string,string> $assoc_args Associative args.
	 */
	public function firewall( $args, $assoc_args ): void {
		$sub = $args[0] ?? 'list';
		if ( 'list' !== $sub ) {
			WP_CLI::error( "Unknown subcommand '{$sub}'. Try: wp loyal-security firewall list" );
		}

		$limit = max( 1, min( 500, (int) ( $assoc_args['limit'] ?? 50 ) ) );

		global $wpdb;
		$table = $wpdb->prefix . 'totalsecwp_events';

		$types = array(
			EventCatalog::WAF_BLOCK,
			EventCatalog::WAF_RATE_LIMIT,
			EventCatalog::WAF_BRUTEFORCE,
			EventCatalog::WAF_DDOS,
			EventCatalog::WAF_VIRTUAL_PATCH,
			EventCatalog::WAF_BOT_BLOCK,
			EventCatalog::WAF_GEO_BLOCK,
		);
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- live CLI report.
			$wpdb->prepare(
				'SELECT created_at, event_type, ip, request_uri FROM %i WHERE INSTR( CONCAT( \',\', %s, \',\' ), CONCAT( \',\', event_type, \',\' ) ) > 0 ORDER BY id DESC LIMIT %d',
				$table,
				implode( ',', $types ),
				$limit
			),
			ARRAY_A
		);

		if ( empty( $rows ) ) {
			WP_CLI::log( 'No firewall blocks recorded.' );
			return;
		}

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		WP_CLI\Utils\format_items( $format, $rows, array( 'created_at', 'event_type', 'ip', 'request_uri' ) );
	}

	/**
	 * Create a backup.
	 *
	 * ## OPTIONS
	 *
	 * [<subcommand>]
	 * : The backup action. Only "create" is supported.
	 * ---
	 * default: create
	 * options:
	 *   - create
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp loyal-security backup create
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional args.
	 * @param array<string,string> $assoc_args Associative args.
	 */
	public function backup( $args, $assoc_args ): void {
		$sub = $args[0] ?? 'create';
		if ( 'create' !== $sub ) {
			WP_CLI::error( "Unknown subcommand '{$sub}'. Try: wp loyal-security backup create" );
		}

		$module = Plugin::instance()->module( 'backup' );
		if ( ! $module instanceof BackupModule ) {
			WP_CLI::error( 'Backup module is not available.' );
		}

		WP_CLI::log( 'Creating backup…' );
		$res = $module->create();

		if ( empty( $res['ok'] ) ) {
			WP_CLI::error( 'Backup failed: ' . (string) ( $res['message'] ?? 'unknown error' ) );
		}

		$manifest = (array) ( $res['manifest'] ?? array() );
		WP_CLI::success(
			sprintf(
				'Backup created (id: %s, files: %d).',
				(string) ( $manifest['id'] ?? '?' ),
				(int) ( $manifest['files'] ?? 0 )
			)
		);
	}

	/**
	 * Clear a user's two-factor enrollment.
	 *
	 * ## OPTIONS
	 *
	 * <subcommand>
	 * : The 2FA action. Only "reset" is supported.
	 *
	 * <user>
	 * : The user login, email, or ID whose 2FA should be cleared.
	 *
	 * ## EXAMPLES
	 *
	 *     wp loyal-security twofa reset admin
	 *     wp loyal-security twofa reset 1
	 *
	 * @subcommand twofa
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional args.
	 * @param array<string,string> $assoc_args Associative args.
	 */
	public function twofa( $args, $assoc_args ): void {
		$sub = $args[0] ?? '';
		if ( 'reset' !== $sub ) {
			WP_CLI::error( "Unknown subcommand '{$sub}'. Try: wp loyal-security twofa reset <user>" );
		}

		$identifier = (string) ( $args[1] ?? '' );
		if ( '' === $identifier ) {
			WP_CLI::error( 'Specify a user: wp loyal-security twofa reset <user>' );
		}

		$user = $this->resolve_user( $identifier );
		if ( ! $user ) {
			WP_CLI::error( "No user found matching '{$identifier}'." );
		}

		$module = Plugin::instance()->module( 'auth' );
		if ( ! $module instanceof AuthModule ) {
			WP_CLI::error( 'Auth module is not available.' );
		}

		$module->twofa()->disable( (int) $user->ID );

		Plugin::instance()->container()->make( 'logger' )->log(
			EventCatalog::SETTING_CHANGED,
			array( 'action' => '2fa_reset_cli', 'user_id' => (int) $user->ID )
		);

		WP_CLI::success( sprintf( 'Two-factor authentication cleared for %s (ID %d).', $user->user_login, (int) $user->ID ) );
	}

	/**
	 * Resolve a user from an ID, login, or e-mail.
	 */
	private function resolve_user( string $identifier ): ?\WP_User {
		if ( ctype_digit( $identifier ) ) {
			$user = get_user_by( 'id', (int) $identifier );
			if ( $user ) {
				return $user;
			}
		}
		$user = get_user_by( 'login', $identifier );
		if ( ! $user ) {
			$user = get_user_by( 'email', $identifier );
		}
		return $user ?: null;
	}
}
