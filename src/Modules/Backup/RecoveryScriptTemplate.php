<?php
/**
 * Source template for the standalone recovery endpoint.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Modules\Backup;

defined( 'ABSPATH' ) || exit;

/**
 * Holds the source of the standalone recovery tool — a zero-WordPress-dependency script that
 * restores a backup even when WordPress itself won't boot. The plugin never writes it to the
 * server: an administrator downloads it from the dashboard (`GET /backups/recovery/download`,
 * see {@see RecoveryAuth}) and uploads it themselves, wherever they choose. {@see render()}
 * builds this site's paths into the downloaded copy (the recovery state file, the WordPress
 * root, wp-config.php and the tool's stylesheet), so the copy works from any location and keeps
 * working across plugin updates.
 */
class RecoveryScriptTemplate {

	/**
	 * Render the recovery tool's source with this site's paths built in.
	 *
	 * @param array{state_file?:string,wp_root?:string,wp_config?:string} $vars
	 */
	public static function render( array $vars = array() ): string {
		$quote = static function ( $value ): string {
			return "'" . addcslashes( (string) $value, "'\\" ) . "'";
		};
		return strtr(
			self::source(),
			array(
				"'{{STATE_FILE}}'" => $quote( $vars['state_file'] ?? '' ),
				"'{{WP_ROOT}}'"    => $quote( $vars['wp_root'] ?? '' ),
				"'{{WP_CONFIG}}'"  => $quote( $vars['wp_config'] ?? '' ),
			)
		);
	}

	/**
	 * The tool's source, with quoted `{{PLACEHOLDER}}` literals for {@see render()} to fill.
	 */
	private static function source(): string {
		return <<<'LOYALSEC_RECOVERY_SCRIPT'
<?php
/**
 * Loyal Security — standalone recovery tool.
 *
 * Restores a backup created by the plugin **without booting WordPress**, so it works even when
 * the site is fataling. Upload this file to your server (for example to your site's root
 * folder) under any name you like, then open its address in a browser. Access is gated by the
 * secret token generated in the dashboard; only a bcrypt hash of that token is stored on disk
 * (in the plugin's private recovery-state.php, whose location is built into this copy).
 *
 * Security model:
 *   - Disabled unless the operator has explicitly enabled recovery and minted a token.
 *   - Token verified with password_verify() (constant-time); never compared as plaintext.
 *   - Brute-force lockout: after 5 failures the endpoint locks for 15 minutes.
 *   - Backups are only ever read from the configured private storage dir; ids are slug-safe.
 *   - Archive extraction validates every entry stays within the site root (no traversal).
 *   - Generic responses; no information leak about whether recovery is configured.
 *
 * This file intentionally has NO external dependencies and does not include the plugin
 * autoloader, so it remains usable when the rest of the site is broken. It cannot use
 * ABSPATH-gating, WordPress nonces, $wpdb, or WP_Filesystem for that same reason — WordPress
 * is never booted here. Its own token+lockout auth (see loyalsec_authenticate()) is the
 * access-control layer that would normally be a capability check + nonce.
 *
 * This file was generated for one specific site by the Loyal Security dashboard (Backup &
 * Recovery → Download recovery tool). Download a fresh copy after moving the site.
 *
 * @package LoyalSecurity
 */

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors, WordPress.Security.EscapeOutput, WordPress.DB.RestrictedFunctions, Squiz.PHP.DiscouragedFunctions -- standalone, zero-WordPress-dependency script by design (see file header); direct filesystem/mysqli calls and set_time_limit() are the only tools available pre-boot.

define( 'LOYALSEC_RECOVERY', true );

// Built in by the dashboard when this copy was downloaded.
const LOYALSEC_STATE_FILE   = '{{STATE_FILE}}';
const LOYALSEC_WP_ROOT      = '{{WP_ROOT}}';
const LOYALSEC_WP_CONFIG    = '{{WP_CONFIG}}';

const LOYALSEC_MAX_ATTEMPTS = 5;
const LOYALSEC_LOCK_SECONDS = 900;
const LOYALSEC_DB_DELIM     = "\n-- LOYALSEC-STATEMENT --\n";

header( 'Content-Type: text/html; charset=utf-8' );
header( 'X-Robots-Tag: noindex, nofollow', true );
header( 'Cache-Control: no-store, no-cache, must-revalidate' );

$loyalsec_state_file = LOYALSEC_STATE_FILE;

/**
 * Read a $_POST value as a length-capped, slash-stripped string. Standalone equivalent of
 * wp_unslash()+sanitize_text_field() — WordPress isn't loaded here, and PHP itself has not
 * added magic-quotes slashes to superglobals since 5.4, so stripslashes() is a defensive
 * no-op; it exists so this never silently regresses if that ever changes.
 */
function loyalsec_post_string( $key, $max = 512 ) {
	if ( ! isset( $_POST[ $key ] ) || ! is_scalar( $_POST[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- this standalone endpoint has its own token+lockout auth (see loyalsec_authenticate()) in place of a WordPress nonce, which requires a logged-in session that doesn't exist pre-boot.
		return '';
	}
	return substr( stripslashes( (string) $_POST[ $key ] ), 0, $max ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- wp_unslash()/sanitize_text_field() are unavailable pre-boot; stripslashes() + the length cap are this file's equivalent (see the docblock above), and the nonce justification is the same as the isset() check above.
}

/**
 * Render a minimal page and stop.
 */
function loyalsec_page( $title, $body, $status = 200 ) {
	http_response_code( $status );
	echo '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">';
	echo '<title>' . htmlspecialchars( $title, ENT_QUOTES ) . '</title>';
	// Plain, unstyled page: this tool runs without WordPress, so nothing can be enqueued.
	echo '</head><body>' . $body . '</body></html>';
	exit;
}

/**
 * Load shared recovery state.
 */
function loyalsec_load_state( $file ) {
	if ( ! is_file( $file ) ) {
		return array();
	}
	$data = include $file;
	return is_array( $data ) ? $data : array();
}

/**
 * Persist recovery state back to disk (preserving the guard).
 */
function loyalsec_save_state( $file, $state ) {
	$php = "<?php\n"
		. "// Auto-generated by Loyal Security. Holds a bcrypt token hash only — no plaintext secret.\n"
		. "defined( 'LOYALSEC_RECOVERY' ) || exit;\n"
		. 'return ' . var_export( $state, true ) . ";\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- serializes the state array as valid PHP source for a fast native include; not debug output.
	@file_put_contents( $file, $php, LOCK_EX );
	@chmod( $file, 0600 );
}

/**
 * Locate wp-config.php by walking up from this endpoint.
 */
function loyalsec_find_wp_config() {
	return ( '' !== LOYALSEC_WP_CONFIG && is_file( LOYALSEC_WP_CONFIG ) ) ? LOYALSEC_WP_CONFIG : '';
}

/**
 * Extract a constant's value from wp-config.php source.
 */
function loyalsec_wpconf_const( $src, $name ) {
	if ( preg_match( '/define\(\s*[\'"]' . preg_quote( $name, '/' ) . '[\'"]\s*,\s*[\'"](.*?)[\'"]\s*\)/s', $src, $m ) ) {
		return $m[1];
	}
	return null;
}

/**
 * The WordPress root directory this tool was generated for.
 */
function loyalsec_abspath() {
	return rtrim( str_replace( '\\', '/', LOYALSEC_WP_ROOT ), '/' );
}

/**
 * List restorable backups from the private storage directory.
 */
function loyalsec_list_backups( $storage ) {
	$out = array();
	if ( ! $storage || ! is_dir( $storage ) ) {
		return $out;
	}
	foreach ( (array) glob( rtrim( $storage, '/' ) . '/*', GLOB_ONLYDIR ) as $dir ) {
		$mf = $dir . '/manifest.json';
		if ( is_file( $mf ) ) {
			$data = json_decode( (string) file_get_contents( $mf ), true );
			if ( is_array( $data ) && isset( $data['id'] ) ) {
				$out[ $data['id'] ] = $data;
			}
		}
	}
	krsort( $out );
	return $out;
}

/**
 * Reject zip entries that would escape the destination.
 */
function loyalsec_unsafe_entry( $name ) {
	$norm = str_replace( '\\', '/', $name );
	if ( '' === $norm || '/' === $norm[0] || preg_match( '#^[A-Za-z]:#', $norm ) ) {
		return true;
	}
	foreach ( explode( '/', $norm ) as $seg ) {
		if ( '..' === $seg ) {
			return true;
		}
	}
	return false;
}

/**
 * Path-safe zip extraction into $dest.
 */
function loyalsec_extract_zip( $zip_path, $dest ) {
	if ( ! class_exists( 'ZipArchive' ) || ! is_file( $zip_path ) ) {
		return -1;
	}
	$zip = new ZipArchive();
	if ( true !== $zip->open( $zip_path ) ) {
		return -1;
	}
	$dest = rtrim( str_replace( '\\', '/', $dest ), '/' );
	$n    = 0;
	for ( $i = 0; $i < $zip->numFiles; $i++ ) {
		$name = $zip->getNameIndex( $i );
		if ( loyalsec_unsafe_entry( $name ) ) {
			continue;
		}
		$target = $dest . '/' . ltrim( str_replace( '\\', '/', $name ), '/' );
		$parent = dirname( $target );
		if ( 0 !== strpos( $parent . '/', $dest . '/' ) ) {
			continue;
		}
		if ( '/' === substr( $name, -1 ) ) {
			if ( ! is_dir( $target ) ) {
				@mkdir( $target, 0755, true );
			}
			continue;
		}
		if ( ! is_dir( $parent ) ) {
			@mkdir( $parent, 0755, true );
		}
		$content = $zip->getFromIndex( $i );
		if ( false !== $content && false !== @file_put_contents( $target, $content ) ) {
			$n++;
		}
	}
	$zip->close();
	return $n;
}

/**
 * Verify a TOTP (RFC 6238) one-time code against a Base32 secret. Self-contained so the
 * standalone endpoint never depends on the plugin autoloader. Mirrors Modules\Auth\Totp.
 */
function loyalsec_totp_verify( $secret, $code, $window = 1 ) {
	$code = preg_replace( '/\s+/', '', (string) $code );
	if ( ! preg_match( '/^\d{6}$/', $code ) ) {
		return false;
	}
	$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	$secret   = strtoupper( preg_replace( '/[^A-Z2-7]/', '', strtoupper( (string) $secret ) ) );
	if ( '' === $secret ) {
		return false;
	}
	// Base32-decode the secret to raw key bytes.
	$bits = '';
	$len  = strlen( $secret );
	for ( $i = 0; $i < $len; $i++ ) {
		$pos = strpos( $alphabet, $secret[ $i ] );
		if ( false === $pos ) {
			continue;
		}
		$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
	}
	$key = '';
	foreach ( str_split( $bits, 8 ) as $byte ) {
		if ( 8 === strlen( $byte ) ) {
			$key .= chr( bindec( $byte ) );
		}
	}
	if ( '' === $key ) {
		return false;
	}
	$counter = (int) floor( time() / 30 );
	for ( $i = -$window; $i <= $window; $i++ ) {
		$c      = $counter + $i;
		$binary = pack( 'N*', 0 ) . pack( 'N*', $c );
		$hash   = hash_hmac( 'sha1', $binary, $key, true );
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;
		$value  = ( unpack( 'N', substr( $hash, $offset, 4 ) )[1] ) & 0x7fffffff;
		$otp    = str_pad( (string) ( $value % 1000000 ), 6, '0', STR_PAD_LEFT );
		if ( hash_equals( $otp, $code ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Import a SQL dump using a direct mysqli connection parsed from wp-config.php.
 *
 * NOTE: DB credentials are read by regex from wp-config.php source. This handles the standard
 * `define( 'DB_HOST', 'host[:port|:socket]' )` form (including a TCP port or a unix-socket path
 * after the colon), but NOT credentials assembled from environment variables, heredocs, or
 * included files — those hosts must restore the database from the dashboard once the site boots.
 * A clear message is returned in that case rather than a generic connection error.
 *
 * Uses mysqli directly (not $wpdb) because WordPress is never bootstrapped in this file.
 */
function loyalsec_import_db( $sql_path, $wpconfig, $expected_sha256 = '' ) {
	if ( function_exists( 'set_time_limit' ) ) {
		@set_time_limit( 0 );
	}
	if ( ! is_file( $sql_path ) ) {
		return array( 'ok' => false, 'msg' => 'Backup contains no database dump.' );
	}
	// Never replay a dump whose bytes differ from what the backup recorded — and never replay one
	// with nothing to compare against.
	//
	// This is the control that matters here. Every statement executed below is recorded SQL, and
	// while the shape check confines it to this site's own table prefix, a shape-valid CREATE
	// TABLE is still arbitrary DDL; binding the INSERT values would not change that. What makes
	// the replay safe is that the bytes are the bytes this plugin wrote. Treating a missing
	// checksum as "proceed anyway" quietly removed that guarantee for exactly the file an
	// attacker would have tampered with, so a dump that cannot be verified is now refused.
	if ( '' === (string) $expected_sha256 ) {
		return array( 'ok' => false, 'msg' => 'This backup has no recorded database checksum, so the dump could not be verified and was not restored. Restore the files below, then import the database from the dashboard once the site loads.' );
	}
	if ( ! hash_equals( (string) $expected_sha256, (string) hash_file( 'sha256', $sql_path ) ) ) {
		return array( 'ok' => false, 'msg' => 'The database dump does not match the checksum recorded when this backup was made, so it was not restored.' );
	}
	if ( ! function_exists( 'mysqli_connect' ) || '' === $wpconfig ) {
		return array( 'ok' => false, 'msg' => 'Database restore unavailable here (mysqli extension or wp-config.php missing). Restore files below, then import the database from the dashboard once the site loads.' );
	}
	$src  = (string) file_get_contents( $wpconfig );
	$name = loyalsec_wpconf_const( $src, 'DB_NAME' );
	$user = loyalsec_wpconf_const( $src, 'DB_USER' );
	$pass = loyalsec_wpconf_const( $src, 'DB_PASSWORD' );
	$host = loyalsec_wpconf_const( $src, 'DB_HOST' );
	if ( null === $name || null === $host ) {
		return array( 'ok' => false, 'msg' => 'Could not read the database credentials from wp-config.php (they may be set via environment variables). Restore the database from the dashboard once the site is reachable.' );
	}

	// Split host into host + TCP port OR host + unix socket (a non-numeric part after the colon).
	$port   = 3306;
	$socket = null;
	if ( false !== strpos( (string) $host, ':' ) ) {
		list( $host, $suffix ) = explode( ':', (string) $host, 2 );
		if ( ctype_digit( $suffix ) ) {
			$port = (int) $suffix;
		} elseif ( '' !== $suffix ) {
			$socket = $suffix; // unix socket path.
		}
	}

	$mysqli = @mysqli_connect( $host, (string) $user, (string) $pass, $name, $port, $socket );
	if ( ! $mysqli ) {
		$err = function_exists( 'mysqli_connect_error' ) ? (string) mysqli_connect_error() : '';
		return array( 'ok' => false, 'msg' => 'Database connection failed' . ( '' !== $err ? ' (' . $err . ')' : '' ) . '.' );
	}

	// Stream the dump statement-by-statement so a large file is never fully held in memory.
	$fh = @fopen( $sql_path, 'rb' );
	if ( ! $fh ) {
		mysqli_close( $mysqli );
		return array( 'ok' => false, 'msg' => 'Could not read the database dump file.' );
	}
	$ok = 0; $err = 0; $buffer = ''; $dlen = strlen( LOYALSEC_DB_DELIM );
	// Only the statement shapes the plugin's own dump writes are executed, and only on tables
	// with this site's prefix — mirrors DatabaseDump::is_dump_statement().
	$prefix = loyalsec_wpconf_var( $src, 'table_prefix' );
	$table  = '`' . preg_quote( null === $prefix ? 'wp_' : $prefix, '/' ) . '[A-Za-z0-9_]+`';
	$shape  = '/^(?:SET FOREIGN_KEY_CHECKS=[01];?|DROP TABLE IF EXISTS ' . $table . ';?|CREATE TABLE ' . $table . '\s*\(|INSERT INTO ' . $table . '\s*\()/';
	$run = function ( $stmt ) use ( $mysqli, &$ok, &$err, $shape ) {
		$stmt = trim( $stmt );
		if ( '' === $stmt || 0 === strpos( $stmt, '--' ) ) {
			return;
		}
		if ( 1 !== preg_match( $shape, $stmt ) ) {
			$err++;
			return;
		}
		if ( @mysqli_query( $mysqli, $stmt ) ) {
			$ok++;
		} else {
			$err++;
		}
	};
	while ( ! feof( $fh ) ) {
		$buffer .= (string) fread( $fh, 1 << 20 );
		while ( false !== ( $pos = strpos( $buffer, LOYALSEC_DB_DELIM ) ) ) {
			$run( substr( $buffer, 0, $pos ) );
			$buffer = substr( $buffer, $pos + $dlen );
		}
	}
	$run( $buffer );
	fclose( $fh );
	mysqli_close( $mysqli );
	return array( 'ok' => 0 === $err, 'msg' => "Imported {$ok} statement(s), {$err} error(s)." );
}

/* ------------------------------------------------------------------ *
 * Request handling.
 * ------------------------------------------------------------------ */

$loyalsec_state = loyalsec_load_state( $loyalsec_state_file );

// Disabled / not configured → indistinguishable generic response.
if ( empty( $loyalsec_state['enabled'] ) || empty( $loyalsec_state['token_hash'] ) ) {
	loyalsec_page( 'Not found', '<h1>404</h1><p class="muted">Nothing to see here.</p>', 404 );
}

// Lockout check.
$loyalsec_now = time();
if ( ! empty( $loyalsec_state['lock_until'] ) && $loyalsec_now < (int) $loyalsec_state['lock_until'] ) {
	$loyalsec_wait = (int) ceil( ( (int) $loyalsec_state['lock_until'] - $loyalsec_now ) / 60 );
	loyalsec_page( 'Locked', '<h1>Temporarily locked</h1><p class="err">Too many attempts. Try again in about ' . (int) $loyalsec_wait . ' minute(s).</p>', 429 );
}

$loyalsec_storage     = isset( $loyalsec_state['storage'] ) ? (string) $loyalsec_state['storage'] : '';
$loyalsec_otp_enabled = ! empty( $loyalsec_state['otp_enabled'] ) && ! empty( $loyalsec_state['otp_secret'] );

/**
 * Verify the submitted credentials (token + optional OTP) with brute-force accounting.
 * Returns true on success; renders a generic failure page and exits on any failure so the
 * caller can assume an authenticated context afterward. Token and OTP are validated together
 * and reported with a single generic message so neither can be probed independently.
 */
function loyalsec_authenticate( $state_file, &$state, $now, $otp_enabled ) {
	$token = loyalsec_post_string( 'token' );
	$otp   = loyalsec_post_string( 'otp', 16 );

	$token_ok = password_verify( $token, (string) $state['token_hash'] );
	$otp_ok   = ! $otp_enabled || loyalsec_totp_verify( (string) ( $state['otp_secret'] ?? '' ), $otp );

	if ( ! $token_ok || ! $otp_ok ) {
		$state['attempts'] = (int) ( $state['attempts'] ?? 0 ) + 1;
		if ( $state['attempts'] >= LOYALSEC_MAX_ATTEMPTS ) {
			$state['lock_until'] = $now + LOYALSEC_LOCK_SECONDS;
			$state['attempts']   = 0;
		}
		loyalsec_save_state( $state_file, $state );
		loyalsec_page( 'Recovery', '<h1>Loyal Security — Recovery</h1><p class="err">Invalid credentials.</p><p class="muted"><a class="link" href="">Back</a></p>', 403 );
	}

	// Success — reset the counter.
	$state['attempts']   = 0;
	$state['lock_until'] = 0;
	loyalsec_save_state( $state_file, $state );
	return true;
}

/**
 * Render the authenticated restore form (backup picker + options). Credentials are carried
 * forward as hidden fields so the operator authenticates once. NOTHING about the site, its
 * version, or its backups is shown until this point.
 */
function loyalsec_authed_form( $backups, $token, $otp ) {
	$options = '';
	foreach ( $backups as $bid => $m ) {
		$label    = htmlspecialchars( $bid . ' · ' . ( $m['scope'] ?? '' ) . ( ! empty( $m['db_included'] ) ? ' +DB' : '' ) . ' · ' . ( $m['created'] ?? '' ), ENT_QUOTES );
		$options .= '<option value="' . htmlspecialchars( $bid, ENT_QUOTES ) . '">' . $label . '</option>';
	}
	if ( '' === $options ) {
		$options = '<option value="">No backups found</option>';
	}

	loyalsec_page(
		'Loyal Security — Recovery',
		'<h1>Loyal Security — Recovery</h1>'
		. '<p class="ok">Authenticated.</p>'
		. '<form method="post">'
		. '<input type="hidden" name="token" value="' . htmlspecialchars( $token, ENT_QUOTES ) . '">'
		. '<input type="hidden" name="otp" value="' . htmlspecialchars( $otp, ENT_QUOTES ) . '">'
		. '<label>Backup</label><select name="backup">' . $options . '</select>'
		. '<label class="opt"><input type="checkbox" name="restore_db" value="1">Also restore the database</label>'
		. '<button type="submit" name="do_restore" value="1">Restore now</button>'
		. '</form>'
	);
}

/**
 * Extract a `$table_prefix = '...';` assignment from wp-config.php source.
 */
function loyalsec_wpconf_var( $src, $name ) {
	if ( preg_match( '/\$' . preg_quote( $name, '/' ) . '\s*=\s*[\'"](.*?)[\'"]\s*;/s', $src, $m ) ) {
		return $m[1];
	}
	return null;
}

$loyalsec_request_method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- wp_unslash() is unavailable pre-boot; stripslashes() + the 10-char cap + strtoupper() below are this file's equivalent.
	? strtoupper( substr( stripslashes( $_SERVER['REQUEST_METHOD'] ), 0, 10 ) ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as above.
	: 'GET';

if ( 'POST' === $loyalsec_request_method ) {
	// Always authenticate first — no backup data is read or revealed before this passes.
	loyalsec_authenticate( $loyalsec_state_file, $loyalsec_state, $loyalsec_now, $loyalsec_otp_enabled );

	$loyalsec_backups = loyalsec_list_backups( $loyalsec_storage );
	$loyalsec_token    = loyalsec_post_string( 'token' );
	$loyalsec_otp      = loyalsec_post_string( 'otp', 16 );

	// First authenticated POST (no restore action yet) → show the restore form.
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- see loyalsec_post_string()'s docblock; this endpoint's token+lockout auth replaces a WordPress nonce.
	if ( empty( $_POST['do_restore'] ) ) {
		loyalsec_authed_form( $loyalsec_backups, $loyalsec_token, $loyalsec_otp );
	}

	$loyalsec_id     = preg_replace( '/[^A-Za-z0-9_-]/', '', loyalsec_post_string( 'backup', 128 ) );
	$loyalsec_do_db  = ! empty( $_POST['restore_db'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- see loyalsec_post_string()'s docblock.

	if ( ! isset( $loyalsec_backups[ $loyalsec_id ] ) ) {
		loyalsec_page( 'Recovery', '<h1>Recovery</h1><p class="err">Unknown backup selected.</p>', 422 );
	}

	$loyalsec_dir = rtrim( $loyalsec_storage, '/' ) . '/' . $loyalsec_id;
	// Prefer the ABSPATH recorded in the manifest at backup time; fall back to deriving it
	// from this endpoint's location.
	$loyalsec_abspath_dir = ( ! empty( $loyalsec_backups[ $loyalsec_id ]['abspath'] ) && is_dir( $loyalsec_backups[ $loyalsec_id ]['abspath'] ) )
		? rtrim( str_replace( '\\', '/', (string) $loyalsec_backups[ $loyalsec_id ]['abspath'] ), '/' )
		: loyalsec_abspath();
	$loyalsec_report = array();

	// Extracting a large archive can exceed the default execution limit; lift it best-effort.
	if ( function_exists( 'set_time_limit' ) ) {
		@set_time_limit( 0 );
	}

	$loyalsec_files    = loyalsec_extract_zip( $loyalsec_dir . '/files.zip', $loyalsec_abspath_dir );
	$loyalsec_report[] = $loyalsec_files >= 0 ? "<span class=\"ok\">Files restored: {$loyalsec_files}</span>" : '<span class="err">File restore failed.</span>';

	if ( $loyalsec_do_db && ! empty( $loyalsec_backups[ $loyalsec_id ]['db_included'] ) ) {
		$loyalsec_db       = loyalsec_import_db( $loyalsec_dir . '/database.sql', loyalsec_find_wp_config(), (string) ( $loyalsec_backups[ $loyalsec_id ]['db_sha256'] ?? '' ) );
		$loyalsec_report[] = ( $loyalsec_db['ok'] ? '<span class="ok">' : '<span class="err">' ) . 'Database: ' . htmlspecialchars( $loyalsec_db['msg'], ENT_QUOTES ) . '</span>';
	}

	loyalsec_page( 'Recovery complete', '<h1>Recovery complete</h1><p>' . implode( '</p><p>', $loyalsec_report ) . '</p><p class="muted">Delete this file from your server once the site is healthy (you can download a fresh copy from the dashboard any time).</p>' );
}

/* GET — pre-auth screen. Reveals NOTHING about the site, its version, or its backups: only a
 * generic heading + token field (+ OTP field when OTP is enabled). */
$loyalsec_otp_field = $loyalsec_otp_enabled
	? '<label>One-time code</label><input type="text" name="otp" inputmode="numeric" pattern="[0-9]*" autocomplete="off" required>'
	: '';

loyalsec_page(
	'Loyal Security — Recovery',
	'<h1>Loyal Security — Recovery</h1>'
	. '<p class="muted">Enter your recovery token to continue.</p>'
	. '<form method="post">'
	. '<label>Recovery token</label><input type="password" name="token" autocomplete="off" required>'
	. $loyalsec_otp_field
	. '<button type="submit">Continue</button>'
	. '</form>'
);

LOYALSEC_RECOVERY_SCRIPT;
	}
}
