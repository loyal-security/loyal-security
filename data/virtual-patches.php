<?php
/**
 * Virtual patch ruleset.
 *
 * Each rule intercepts requests targeting a known vulnerability in a third-party plugin or
 * theme, so sites stay protected even before the vendor patch is applied. Rules are matched
 * only when the affected plugin is installed at (or below) the affected version.
 *
 *   id          Stable rule id.
 *   slug        Plugin folder slug (basename) the rule applies to; '' = applies always.
 *   max_version Apply only when the installed plugin version is <= this (''= any).
 *   methods     HTTP methods to inspect (empty = all).
 *   path_regex  Optional regex the REQUEST_URI path must match.
 *   param       Optional request parameter to inspect (in GET/POST).
 *   value_regex Regex the param/path/body must match to trigger a block.
 *   score       Anomaly score contributed.
 *   desc        Description.
 *
 * Patch-gap intelligence (delivered via the signed `patches` feed, not this file) adds these
 * optional fields to a rule so the plugin can attribute and surface it (see
 * TotalSecurityWP\Modules\ThreatIntel\PatchGap). Enforcement still uses slug + max_version above:
 *
 *   source              'patch_gap' — marks the rule as early-virtual-patching intelligence.
 *   plugin_version_from  Version the vulnerability was introduced in / analysed from (display).
 *   plugin_version_to    Version that contains the fix; installs below it are still in the gap.
 *   confidence           0.0–1.0 triage confidence from the diff analysis (display only).
 *   vulnerability_type   e.g. 'sql_injection', 'xss', 'auth_bypass' (display only).
 *   summary              One-line human explanation of what the update fixed.
 *   detected_at          ISO-8601 timestamp the rule was generated (display only).
 *   cve_id               CVE id if one was later assigned (optional).
 *
 * @package TotalSecurityWP
 */

// Also loaded by the pre-WordPress WAF prepend (Optimized Mode), which defines
// TOTALSECWP_WAF_PREPEND instead of ABSPATH — see data/waf-signatures.php for the same pattern.
defined( 'ABSPATH' ) || exit;

return array(
	'version' => '2024.06.1',
	'rules'   => array(

		// Generic: block direct access to common backup/debug artefacts.
		array(
			'id'          => 'vp-generic-backup',
			'slug'        => '',
			'max_version' => '',
			'methods'     => array( 'GET' ),
			'path_regex'  => '/\.(sql|bak|old|swp|save|orig)(\?|$)/i',
			'param'       => '',
			'value_regex' => '',
			'score'       => 12,
			'desc'        => 'Direct access to a backup/database artefact',
		),

		// Generic: arbitrary option update via admin-ajax with suspicious action names.
		array(
			'id'          => 'vp-generic-optionupdate',
			'slug'        => '',
			'max_version' => '',
			'methods'     => array( 'POST' ),
			'path_regex'  => '#/wp-admin/admin-ajax\.php#i',
			'param'       => 'action',
			'value_regex' => '/^(update_option|set_option|.*_set_admin|grant_admin)$/i',
			'score'       => 12,
			'desc'        => 'Suspicious privileged AJAX action',
		),

		// Example targeted rule (illustrative): unauthenticated arbitrary file upload
		// pattern historically seen in vulnerable form plugins.
		array(
			'id'          => 'vp-fileupload-php',
			'slug'        => '',
			'max_version' => '',
			'methods'     => array( 'POST' ),
			'path_regex'  => '',
			'param'       => '',
			'value_regex' => '/filename\s*=\s*["\'][^"\']+\.(php|phtml|php5|phar)\b/i',
			'score'       => 14,
			'desc'        => 'Upload of a PHP-executable file extension',
		),
	),
);
