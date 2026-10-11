<?php
/**
 * Uninstall routine — full teardown when the plugin is deleted.
 *
 * Always reverts the server-level changes the plugin made (.user.ini / php.ini prepend
 * directive, marked .htaccess blocks, marked wp-config.php blocks) and clears its scheduled
 * events. Tables, options, user meta, the management capability and the private storage
 * folders are removed only when the admin enabled "Delete all data on uninstall".
 *
 * Loads only the two dependency-free helpers it needs (Support\Paths, Support\Markers) instead
 * of the plugin's autoloader — fewer moving parts during teardown means less that can fatal
 * mid-uninstall and leave wp-config.php/.htaccess/.user.ini half-reverted. Direct filesystem
 * calls below are intentional for that reason.
 *
 * @package LoyalSecurity
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

require_once __DIR__ . '/src/Support/Paths.php';
require_once __DIR__ . '/src/Support/Markers.php';

loyalsec_run_uninstall();

/**
 * Runs the full teardown. Wrapped in a single prefixed function (rather than running loose at
 * file scope) so every local of this routine is function-scoped instead of a global variable.
 */
function loyalsec_run_uninstall() {
	global $wpdb;

	$paths   = '\LoyalSecurity\Support\Paths';
	$markers = '\LoyalSecurity\Support\Markers';
	$root    = $paths::root();

	/* ---------------------------------------------------------------------
	 * Safety net: revert all server-level changes unconditionally.
	 *
	 * Deactivation should already have done this, but WP-CLI and force-delete paths bypass the
	 * deactivation hook. Doing it again is harmless (every step is idempotent); NOT doing it
	 * leaves the site broken (500 errors) if auto_prepend_file still points at deleted files.
	 * ------------------------------------------------------------------ */

	// 1. Remove this plugin's auto_prepend_file directive (and only this plugin's) from the
	// .user.ini / php.ini in the WordPress root.
	foreach ( array( '.user.ini', 'php.ini' ) as $ini_name ) {
		$ini_file = $root . $ini_name;
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check; see the file header note.
		if ( ! is_file( $ini_file ) || ! is_writable( $ini_file ) ) {
			continue;
		}
		$lines   = preg_split( '/\R/', (string) file_get_contents( $ini_file ) ) ?: array(); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see the file header note.
		$kept    = array();
		$changed = false;
		foreach ( $lines as $line ) {
			if ( preg_match( '/^\s*auto_prepend_file\s*=/i', $line ) && preg_match( '/loyalsec|loyal-security/i', $line ) ) {
				$changed = true;
				continue;
			}
			$kept[] = $line;
		}
		if ( $changed ) {
			$out = implode( "\n", array_filter( $kept, static fn( $l ) => '' !== trim( $l ) ) );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- must revert the directive in the server-root .user.ini/php.ini itself.
			file_put_contents( $ini_file, '' !== $out ? $out . "\n" : '', LOCK_EX );
		}
	}

	// 2. Remove every marked block the plugin wrote to .htaccess files.
	$htaccess_markers = array(
		array( '# BEGIN Loyal Security WAF', '# END Loyal Security WAF' ),
		array( '# BEGIN Loyal Security Login URL', '# END Loyal Security Login URL' ),
		array( '# BEGIN Loyal Security', '# END Loyal Security' ),
	);
	$htaccess_targets = array( $root . '.htaccess', $paths::includes() . '/.htaccess' );
	$uploads_dir      = $paths::uploads();
	if ( '' !== $uploads_dir ) {
		$htaccess_targets[] = trailingslashit( $uploads_dir ) . '.htaccess';
	}
	foreach ( $htaccess_targets as $ht ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check; see the file header note.
		if ( ! is_file( $ht ) || ! is_writable( $ht ) ) {
			continue;
		}
		$content = (string) file_get_contents( $ht ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see the file header note.
		$cleaned = $markers::strip( $content, $htaccess_markers );
		if ( $cleaned !== $content ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- must revert the rules in the .htaccess file itself.
			file_put_contents( $ht, $cleaned, LOCK_EX );
		}
	}

	// 3. Remove the marked constants and debug.log blocks from wp-config.php.
	$wp_config = $paths::wp_config();
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check; see the file header note.
	if ( '' !== $wp_config && is_file( $wp_config ) && is_writable( $wp_config ) ) {
		$content = (string) file_get_contents( $wp_config ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see the file header note.
		$cleaned = $markers::strip(
			$content,
			array(
				array( '/* BEGIN Loyal Security */', '/* END Loyal Security */' ),
				array( '/* BEGIN Loyal Security debug.log */', '/* END Loyal Security debug.log */' ),
			)
		);
		if ( $cleaned !== $content ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- must revert the block in wp-config.php itself.
			file_put_contents( $wp_config, $cleaned, LOCK_EX );
		}
	}

	// The delete-data preference is the main site's (on multisite the plugin is managed by
	// super admins from there).
	$delete_data = (bool) get_option( 'loyalsec_delete_on_uninstall', false );

	// Per-site cleanup: scheduled events always, data when asked. On a network every site has
	// its own tables, options, roles and uploads folder.
	if ( is_multisite() ) {
		foreach ( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) as $site_id ) {
			switch_to_blog( (int) $site_id );
			loyalsec_uninstall_site( $delete_data );
			restore_current_blog();
		}
	} else {
		loyalsec_uninstall_site( $delete_data );
	}

	// 3. Per-user data (2FA secrets, passkeys, notice dismissals — all prefixed `loyalsec_`).
	// The usermeta table is shared by the whole network, so once.
	if ( $delete_data ) {
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall.
			$wpdb->prepare( 'DELETE FROM %i WHERE meta_key LIKE %s', $wpdb->usermeta, $wpdb->esc_like( 'loyalsec_' ) . '%' )
		);
	}
}

/**
 * Remove one site's scheduled events, and its data when the owner asked for that.
 *
 * @param bool $delete_data Whether to delete tables, options, the capability and stored files.
 */
function loyalsec_uninstall_site( bool $delete_data ) {
	global $wpdb;

	// 4. Clear every scheduled event the plugin owns. All plugin hooks share the `loyalsec_`
	// prefix; force-delete paths can skip the deactivation hook that normally does this.
	$crons = _get_cron_array();
	if ( is_array( $crons ) ) {
		$cron_hooks = array();
		foreach ( $crons as $bucket ) {
			if ( ! is_array( $bucket ) ) {
				continue;
			}
			foreach ( array_keys( $bucket ) as $hook ) {
				if ( is_string( $hook ) && 0 === strpos( $hook, 'loyalsec_' ) ) {
					$cron_hooks[ $hook ] = true;
				}
			}
		}
		foreach ( array_keys( $cron_hooks ) as $hook ) {
			wp_unschedule_hook( $hook );
		}
	}

	/* ---------------------------------------------------------------------
	 * Data teardown (only when the admin enabled "Delete all data on uninstall").
	 * ------------------------------------------------------------------ */

	// The preference flag itself has no value once the plugin is gone.
	delete_option( 'loyalsec_delete_on_uninstall' );
	delete_option( 'loyalsec_onboarding_dismissed' );

	if ( ! $delete_data ) {
		return; // Keep security data so it survives a re-install.
	}

	// 1. Drop every plugin table.
	$tables = $wpdb->get_col( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall.
		$wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->prefix . 'loyalsec_' ) . '%' )
	);
	foreach ( (array) $tables as $table ) {
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', (string) $table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- uninstall.
	}

	// 2. Options and transients (all prefixed `loyalsec_`).
	$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall.
		$wpdb->prepare(
			'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s',
			$wpdb->options,
			$wpdb->esc_like( 'loyalsec_' ) . '%',
			$wpdb->esc_like( '_transient_loyalsec_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_loyalsec_' ) . '%'
		)
	);
	wp_cache_flush();

	// 4. Remove the management capability from all roles.
	if ( function_exists( 'wp_roles' ) ) {
		foreach ( array_keys( wp_roles()->roles ) as $slug ) {
			$role = get_role( $slug );
			if ( $role && $role->has_cap( 'manage_loyal_security' ) ) {
				$role->remove_cap( 'manage_loyal_security' );
			}
		}
	}

	// 5. Private storage folders in uploads (current, plus the ones earlier versions used). On a
	// network this is the current site's own uploads folder.
	$paths       = '\LoyalSecurity\Support\Paths';
	$uploads_dir = $paths::uploads();
	if ( '' !== $uploads_dir ) {
		foreach ( array( 'loyal-security' ) as $folder ) {
			$dir = trailingslashit( $uploads_dir ) . $folder;
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $it as $file ) {
				// phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir, WordPress.WP.AlternativeFunctions.unlink_unlink -- see the file header note.
				$file->isDir() ? @rmdir( $file->getPathname() ) : @unlink( $file->getPathname() );
			}
			@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- see the file header note.
		}
	}
}
