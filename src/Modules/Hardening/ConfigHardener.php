<?php
/**
 * wp-config.php hardening (constant injection).
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Safely injects/removes hardening constants in wp-config.php inside a marked block placed
 * before the "stop editing" line. Always backs up before modifying.
 */
class ConfigHardener {

	private const MARK_BEGIN = '/* BEGIN Loyal Security */';
	private const MARK_END   = '/* END Loyal Security */';

	private const MARK_DEBUG_LOG_BEGIN = '/* BEGIN Loyal Security debug.log */';
	private const MARK_DEBUG_LOG_END   = '/* END Loyal Security debug.log */';

	/** Constants block: current markers plus the ones earlier versions wrote. */
	private const MARKERS = array(
		array( self::MARK_BEGIN, self::MARK_END ),
		array( '/* BEGIN Total Security WP */', '/* END Total Security WP */' ),
	);

	/** debug.log block: current markers plus the ones earlier versions wrote. */
	private const DEBUG_LOG_MARKERS = array(
		array( self::MARK_DEBUG_LOG_BEGIN, self::MARK_DEBUG_LOG_END ),
		array( '/* BEGIN Total Security WP debug.log */', '/* END Total Security WP debug.log */' ),
	);

	/** Constants this hardener manages. */
	private const MANAGED = array( 'DISALLOW_FILE_EDIT', 'DISALLOW_FILE_MODS', 'WP_AUTO_UPDATE_CORE', 'FORCE_SSL_ADMIN' );

	private function config_path(): string {
		// wp-config.php may live one level above the WordPress root.
		return \TotalSecurityWP\Support\Paths::wp_config();
	}

	/**
	 * Current state of managed constants.
	 *
	 * @return array<string, mixed>
	 */
	public function status(): array {
		return array(
			'writable'           => $this->config_path() && is_writable( $this->config_path() ), // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check, not a write.
			'DISALLOW_FILE_EDIT' => defined( 'DISALLOW_FILE_EDIT' ) ? DISALLOW_FILE_EDIT : false,
			'DISALLOW_FILE_MODS' => defined( 'DISALLOW_FILE_MODS' ) ? DISALLOW_FILE_MODS : false,
			'FORCE_SSL_ADMIN'    => defined( 'FORCE_SSL_ADMIN' ) ? FORCE_SSL_ADMIN : false,
			'block_present'      => $this->has_block(),
		);
	}

	/**
	 * Apply a set of constants.
	 *
	 * @param array<string, bool> $constants e.g. [ 'DISALLOW_FILE_EDIT' => true ].
	 * @return array{ok:bool,message:string}
	 */
	public function apply( array $constants ): array {
		$path = $this->config_path();
		if ( '' === $path || ! is_writable( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check, not a write.
			return array( 'ok' => false, 'message' => __( 'wp-config.php is not writable.', 'loyal-security' ) );
		}

		$lines = array( self::MARK_BEGIN );
		foreach ( $constants as $name => $value ) {
			if ( ! in_array( $name, self::MANAGED, true ) ) {
				continue;
			}
			if ( 'WP_AUTO_UPDATE_CORE' === $name ) {
				$lines[] = "if ( ! defined( '{$name}' ) ) define( '{$name}', " . ( $value ? 'true' : "'minor'" ) . ' );';
			} else {
				$lines[] = "if ( ! defined( '{$name}' ) ) define( '{$name}', " . ( $value ? 'true' : 'false' ) . ' );';
			}
		}
		$lines[] = self::MARK_END;
		$block   = implode( "\n", $lines ) . "\n";

		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$this->backup( $path, $content );
		$content = $this->strip( $content );

		// Insert before the "stop editing" marker, else after the opening <?php.
		$anchor = "/* That's all, stop editing! Happy publishing. */";
		if ( false !== strpos( $content, $anchor ) ) {
			$content = str_replace( $anchor, $block . "\n" . $anchor, $content );
		} elseif ( preg_match( '/^<\?php\s*/', $content ) ) {
			$content = preg_replace( '/^<\?php\s*/', "<?php\n" . $block . "\n", $content, 1 );
		} else {
			$content = "<?php\n" . $block . "\n" . $content;
		}

		if ( false === file_put_contents( $path, $content, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			return array( 'ok' => false, 'message' => __( 'Could not write wp-config.php.', 'loyal-security' ) );
		}
		return array( 'ok' => true, 'message' => __( 'wp-config.php hardened.', 'loyal-security' ) );
	}

	/**
	 * Remove the managed block.
	 */
	public function revert(): array {
		$path = $this->config_path();
		if ( '' === $path || ! is_writable( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check, not a write.
			return array( 'ok' => false, 'message' => __( 'wp-config.php is not writable.', 'loyal-security' ) );
		}
		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$this->backup( $path, $content );
		file_put_contents( $path, $this->strip( $content ), LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		return array( 'ok' => true, 'message' => __( 'wp-config.php hardening removed.', 'loyal-security' ) );
	}

	private function has_block(): bool {
		$path = $this->config_path();
		return '' !== $path && \TotalSecurityWP\Support\Markers::present( (string) file_get_contents( $path ), self::MARKERS ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	private function backup( string $path, string $content ): void {
		// Stored under wp-content/uploads, never alongside wp-config.php itself — a same-
		// directory backup of it is a predictable-filename plaintext leak of the live DB
		// password and secret keys on any web server that doesn't specifically deny it. See
		// Filesystem::backup_config_file()'s own docblock for the full reasoning.
		\TotalSecurityWP\Support\Filesystem::backup_config_file( $path, $content );
	}

	private function strip( string $content ): string {
		return \TotalSecurityWP\Support\Markers::strip( $content, self::MARKERS );
	}

	/* ------------------------------------------------------------------ *
	 * debug.log relocation (separate managed block: a file path, not a bool constant).
	 * ------------------------------------------------------------------ */

	/**
	 * Point WP_DEBUG_LOG at an absolute path via a dedicated marked block, so it doesn't
	 * interfere with the boolean-constant block managed by apply()/revert().
	 *
	 * @return array{ok:bool,message:string}
	 */
	public function set_debug_log_path( string $target ): array {
		$path = $this->config_path();
		if ( '' === $path || ! is_writable( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- read-only pre-flight check, not a write.
			return array( 'ok' => false, 'message' => __( 'wp-config.php is not writable.', 'loyal-security' ) );
		}

		$block = self::MARK_DEBUG_LOG_BEGIN . "\n"
			. "if ( ! defined( 'WP_DEBUG_LOG' ) || true === WP_DEBUG_LOG ) define( 'WP_DEBUG_LOG', " . var_export( $target, true ) . " );\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- deliberate PHP-literal serialization for the generated wp-config.php snippet, not debug output.
			. self::MARK_DEBUG_LOG_END . "\n";

		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$this->backup( $path, $content );
		$content = \TotalSecurityWP\Support\Markers::strip( $content, self::DEBUG_LOG_MARKERS );

		$anchor = "/* That's all, stop editing! Happy publishing. */";
		if ( false !== strpos( $content, $anchor ) ) {
			$content = str_replace( $anchor, $block . "\n" . $anchor, $content );
		} elseif ( preg_match( '/^<\?php\s*/', $content ) ) {
			$content = preg_replace( '/^<\?php\s*/', "<?php\n" . $block . "\n", $content, 1 );
		} else {
			$content = "<?php\n" . $block . "\n" . $content;
		}

		if ( false === file_put_contents( $path, $content, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			return array( 'ok' => false, 'message' => __( 'Could not write wp-config.php.', 'loyal-security' ) );
		}
		return array( 'ok' => true, 'message' => __( 'debug.log relocated to private storage.', 'loyal-security' ) );
	}
}
