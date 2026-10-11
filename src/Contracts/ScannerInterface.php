<?php
/**
 * Scanner contract.
 *
 * @package LoyalSecurity
 */

namespace LoyalSecurity\Contracts;

defined( 'ABSPATH' ) || exit;

use LoyalSecurity\Modules\Scanner\Finding;

/**
 * Implemented by file/content analysers that produce {@see Finding} objects.
 */
interface ScannerInterface {

	/**
	 * Analyse a single unit (file path or content blob) and return findings.
	 *
	 * @param string $path    Absolute path being analysed (for reporting).
	 * @param string $content Raw content to inspect.
	 * @return Finding[]
	 */
	public function analyse( string $path, string $content ): array;
}
