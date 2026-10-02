<?php
/**
 * Result of a WAF inspection.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP\Waf;

defined( 'ABSPATH' ) || exit;

/**
 * Immutable-ish value object describing whether a request should be blocked, the anomaly
 * score, and which rules contributed.
 */
class Decision {

	public bool $blocked = false;
	public int $score = 0;
	public string $action = 'allow'; // allow | block | log
	public string $category = '';
	public string $top_rule = '';
	public string $message = '';

	/** @var array<int, array{source:string,param:string,rule:string,category:string,score:int,desc:string}> */
	public array $matches = array();

	/**
	 * Build a structured context array for logging.
	 *
	 * @return array<string, mixed>
	 */
	public function to_context(): array {
		return array(
			'score'    => $this->score,
			'action'   => $this->action,
			'category' => $this->category,
			'rule'     => $this->top_rule,
			'matches'  => array_slice( $this->matches, 0, 10 ),
		);
	}
}
