<?php
/**
 * Malware scan finding model.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Modules\Scanner;

defined( 'ABSPATH' ) || exit;

use TotalSecurityWP\Modules\Audit\EventCatalog;

/**
 * One detection within a scanned file or database row.
 */
class Finding {

	/** Database id once persisted to the scan_findings table (0 until then). */
	public int $id = 0;

	public string $path;
	public string $rule;
	public string $category;
	public int $severity;
	public int $line;
	public string $snippet;
	public int $score;

	/** Literal request-param key the tainted sink was traced to (e.g. 'cmd'), when resolvable.
	 *  Transient — set by TaintAnalyzer, consumed by PatchSuggester, never persisted itself. */
	public string $param = '';

	/** Auto-drafted virtual-patch rule (see PatchSuggester), persisted as JSON in to_row(). */
	public ?array $suggested_patch = null;

	public function __construct(
		string $path,
		string $rule,
		string $category,
		int $score,
		int $line = 0,
		string $snippet = '',
		?int $severity = null,
		string $param = ''
	) {
		$this->path     = $path;
		$this->rule     = $rule;
		$this->category = $category;
		$this->score    = $score;
		$this->line     = $line;
		$this->snippet  = mb_substr( $snippet, 0, 300 );
		$this->severity = $severity ?? $this->severity_from_score( $score );
		$this->param    = $param;
	}

	private function severity_from_score( int $score ): int {
		if ( $score >= 30 ) {
			return EventCatalog::SEV_CRITICAL;
		}
		if ( $score >= 15 ) {
			return EventCatalog::SEV_WARNING;
		}
		return EventCatalog::SEV_NOTICE;
	}

	/**
	 * Row for the scan_findings table.
	 *
	 * @param string $scan_id Owning scan id.
	 * @return array<string, mixed>
	 */
	public function to_row( string $scan_id ): array {
		return array(
			'scan_id'         => $scan_id,
			'path'            => $this->path,
			'rule'            => $this->rule,
			'category'        => $this->category,
			'severity'        => $this->severity,
			'line'            => $this->line,
			'snippet'         => $this->snippet,
			'score'           => $this->score,
			'status'          => 'open',
			'suggested_patch' => null === $this->suggested_patch ? '' : (string) wp_json_encode( $this->suggested_patch ),
			'patch_status'    => '',
			'created_at'      => gmdate( 'Y-m-d H:i:s' ),
		);
	}
}
