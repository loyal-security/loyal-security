<?php
/**
 * WAF signature ruleset.
 *
 * Returns a versioned array of detection rules grouped by attack category. Each rule:
 *   id       Unique stable identifier.
 *   category One of: sqli, xss, lfi, rfi, traversal, rce, php, scanner, proto.
 *   score    Anomaly score contributed on match.
 *   regex    PCRE pattern (the `i` modifier is applied by the engine; patterns are matched
 *            against URL/HTML/base64-decoded candidate strings).
 *   desc     Human description.
 *
 * Patterns are written to favour decoded input and to limit catastrophic backtracking.
 *
 * @package LoyalSecurity
 */

defined( 'ABSPATH' ) || exit;

return array(
	'version' => '2026.10.1',
	'rules'   => array(

		/* ---------------------------- SQL Injection ---------------------------- */
		array( 'id' => 'sqli-union', 'category' => 'sqli', 'score' => 12, 'regex' => '/union[\s\/\*]+(all[\s\/\*]+)?select/i', 'desc' => 'SQL UNION SELECT' ),
		array( 'id' => 'sqli-bool', 'category' => 'sqli', 'score' => 7, 'regex' => '/(\bor\b|\band\b)\s+[\'"`]?\d+[\'"`]?\s*=\s*[\'"`]?\d+/i', 'desc' => 'Boolean-based SQLi (e.g. OR 1=1)' ),
		// SQL comments as attackers use them: right after a closing quote or bracket, after a
		// number at the end of the value, or as inline whitespace next to a keyword. A "#" or
		// "--" in ordinary text ("Apt #5 and 6", "back door -- or call me") does not count.
		array( 'id' => 'sqli-comment', 'category' => 'sqli', 'score' => 5, 'regex' => '/[\'"`)]\s*(?:--[\s-]|--$|#)|\d\s*--[\s-]*$|\/\*[\s\S]{0,40}?\*\/\s*(?:union|select|and|or|from|where|having|order)\b|\b(?:union|select|and|or|from|where)\s*\/\*/i', 'desc' => 'SQL comment with keyword' ),
		// Real statement shapes (SELECT cols FROM t, INSERT INTO t (, UPDATE t SET c=, DELETE FROM t,
		// DROP TABLE t), not English that happens to use the same verbs ("please delete my data
		// from your systems", "drop it from the porch", "update the address where we live").
		array( 'id' => 'sqli-stmt', 'category' => 'sqli', 'score' => 8, 'regex' => '/\bselect\s+(?:distinct\s+|all\s+)?(?:\*|[\w`"@.()]+(?:\s*,\s*[\w`"@.()]+)*)\s+from\s+[\w`".]+|\binsert\s+into\s+[\w`".]+\s*(?:\(|\bvalues\b|\bselect\b)|\bupdate\s+[\w`".]+\s+set\s+[\w`".]+\s*=|\bdelete\s+from\s+[\w`".]+\s*(?:\bwhere\b|;|$)|\bdrop\s+(?:table|database|schema)\s+(?:if\s+exists\s+)?[\w`".]+|\btruncate\s+table\s+[\w`".]+|\balter\s+table\s+[\w`".]+\s+(?:add|drop|modify|change|rename)\b|\bcreate\s+(?:table\s+[\w`".]+\s*\(|database\s+[\w`".]+\s*(?:;|$)|user\s+[\'"`]?\w+[\'"`]?@)/i', 'desc' => 'SQL statement structure' ),
		array( 'id' => 'sqli-func', 'category' => 'sqli', 'score' => 12, 'regex' => '/\b(sleep|benchmark|pg_sleep|waitfor\s+delay|extractvalue|updatexml|load_file|group_concat|information_schema)\b|@@(?:version|datadir|hostname|basedir)\b|\b(?:xp_cmdshell|sp_executesql|sp_oacreate)\b/i', 'desc' => 'SQLi function / time-based / error-based' ),
		// Stacked / chained queries via ; separator — often used to append DROP/DELETE after a
		// SELECT. Requires the statement's shape after the verb, so "; update me when shipped" or
		// "; select one size up" in an order note is not a stacked query.
		array( 'id' => 'sqli-stacked', 'category' => 'sqli', 'score' => 8, 'regex' => '/;\s*(?:select\b[\s\S]{0,120}?\bfrom\s+[\w`".]+|insert\s+into\s+[\w`".]+|update\s+[\w`".]+\s+set\b|delete\s+from\s+[\w`".]+|drop\s+(?:table|database|schema)\b|truncate\s+(?:table\s+)?[\w`".]+\s*(?:;|$)|create\s+(?:table|database|user)\b|alter\s+table\b|exec(?:ute)?\s*(?:\(|\s+(?:xp_|sp_|master\.))|shutdown\s*(?:;|--|$)|declare\s+@)/i', 'desc' => 'Stacked SQL query (semicolon separator)' ),
		array( 'id' => 'sqli-quote', 'category' => 'sqli', 'score' => 4, 'regex' => '/[\'"`]\s*(or|and)\s*[\'"`]?\s*[\'"`0-9]/i', 'desc' => 'Quote breakout' ),
		// Column-count probing after a quote: ' ORDER BY 3-- -
		array( 'id' => 'sqli-orderby', 'category' => 'sqli', 'score' => 8, 'regex' => '/[\'"`)]\s*(?:order|group)\s+by\s+\d+/i', 'desc' => 'ORDER BY / GROUP BY column probing' ),
		// A quote broken out into a comparison: ' OR '1'='1, " AND 1=CONVERT(...
		array( 'id' => 'sqli-taut', 'category' => 'sqli', 'score' => 6, 'regex' => '/[\'"`]\s*\)?\s*(?:or|and|xor|\|\||&&)\s+\(?\s*[\'"`]?[\w@]+[\'"`]?\s*(?:=|<>|!=|<=?|>=?|\blike\b|\bis\b)/i', 'desc' => 'Quote breakout into a comparison' ),

		/* ------------------------------- XSS ----------------------------------- */
		array( 'id' => 'xss-script', 'category' => 'xss', 'score' => 12, 'regex' => '/<\s*scr[\s\S]{0,5}?ipt[\s\S]{0,80}?>/i', 'desc' => '<script> tag (handles newline-split evasion)' ),
		array( 'id' => 'xss-event', 'category' => 'xss', 'score' => 7, 'regex' => '/\bon(?:error|load|click|dblclick|auxclick|contextmenu|mouse\w{2,5}|pointer\w{2,6}|touch\w{3,6}|key(?:down|up|press)|focus(?:in|out)?|blur|input|change|submit|reset|select|toggle|begin|end|repeat|animation\w{3,9}|transition\w{3,6}|scroll|wheel|drag\w{0,5}|drop|copy|cut|paste|play|pause|ended|resize|unload|beforeunload|hashchange|popstate|message|pageshow)\s*=/i', 'desc' => 'Inline event handler' ),
		array( 'id' => 'xss-js-href', 'category' => 'xss', 'score' => 6, 'regex' => '/<[^>]{0,60}\b(?:href|src|action|formaction|xlink:href)\s*=\s*[\'"]?\s*(?:javascript|vbscript|data)\s*:/i', 'desc' => 'Script URL in a link or form attribute' ),
		array( 'id' => 'xss-js-uri', 'category' => 'xss', 'score' => 8, 'regex' => '/javascript\s*:/i', 'desc' => 'javascript: URI' ),
		array( 'id' => 'xss-tags', 'category' => 'xss', 'score' => 6, 'regex' => '/<\s*(iframe|svg|img|body|object|embed|video|audio|details|marquee)[\s\S]{0,40}?(on\w+|src|data)\s*=/i', 'desc' => 'Dangerous tag with handler/src' ),
		array( 'id' => 'xss-eval', 'category' => 'xss', 'score' => 7, 'regex' => '/(document\.cookie|window\.location|eval\s*\(|String\.fromCharCode|atob\s*\()/i', 'desc' => 'Suspicious JS sink' ),
		array( 'id' => 'xss-expr', 'category' => 'xss', 'score' => 5, 'regex' => '/expression\s*\(|vbscript\s*:|data\s*:\s*text\/html/i', 'desc' => 'CSS expression / vbscript / data URI' ),

		/* --------------------------- Path Traversal ---------------------------- */
		array( 'id' => 'lfi-traversal', 'category' => 'traversal', 'score' => 9, 'regex' => '/(\.\.[\/\\\\]){2,}/', 'desc' => 'Directory traversal sequence' ),
		array( 'id' => 'lfi-etcpasswd', 'category' => 'lfi', 'score' => 12, 'regex' => '/(\/etc\/(passwd|shadow|hosts)|\/proc\/self\/environ|boot\.ini|win\.ini)/i', 'desc' => 'Sensitive file access' ),
		array( 'id' => 'lfi-wrapper', 'category' => 'lfi', 'score' => 9, 'regex' => '/php:\/\/(filter|input|data)|phar:\/\/|expect:\/\/|zip:\/\//i', 'desc' => 'PHP stream wrapper' ),
		array( 'id' => 'lfi-wpfiles', 'category' => 'lfi', 'score' => 8, 'regex' => '/\bwp-config\.php\b|\.htaccess\b/i', 'desc' => 'WordPress sensitive file' ),

		/* ----------------------------- RFI ------------------------------------- */
		// Off-site payloads (remote .txt served as code) and the classic RFI techniques of a
		// trailing "?" (neutralises the remote query) or a remote PHP stream. Deliberately does
		// NOT match a bare "=http://host/file.php" or image URL: WordPress legitimately passes
		// same-site .php/.jpg URLs in params like redirect_to / _wp_http_referer / the Referer
		// header, which previously caused every wp-login.php POST to be blocked (false positive).
		// Score raised to 12 so a single hit is sufficient to block (was 9, below threshold).
		array( 'id' => 'rfi-remote', 'category' => 'rfi', 'score' => 12, 'regex' => '/=\s*(?:https?|ftps?):\/\/[^\s&"\'<>]+?(?:\.txt\b|\?+(?:[\s&#]|$))/i', 'desc' => 'Remote file include URL (off-site .txt payload or RFI trailing-? technique)' ),
		// Catches remote script payloads passed as bare values (e.g. value candidate = "http://evil.com/shell.php")
		// after the Decoder strips the leading "=" from the URI candidate. Anchored to start-of-string
		// so it only fires on standalone values, not embedded hrefs in legitimate HTML content.
		// HEADER is excluded: the browser Referer header legitimately contains same-site admin.php
		// URLs, which would otherwise trigger a block on every WordPress admin request.
		// same_host_exempt: wp-login.php's redirect_to (and similar params) legitimately carry a
		// same-site admin.php/index.php URL as a bare value — that's a WordPress redirect
		// destination, not an attacker pointing the server at remote code. Only skipped when the
		// matched URL's host is this site's own configured hostname (see RuleEngine::is_own_host()).
		array( 'id' => 'rfi-value', 'category' => 'rfi', 'score' => 12, 'regex' => '/^(?:https?|ftps?):\/\/[^\s&"\'<>]{4,200}\.php\b/i', 'sources' => array( 'GET', 'POST', 'COOKIE', 'BODY' ), 'same_host_exempt' => true, 'desc' => 'Remote PHP script as standalone parameter value (RFI)' ),

		/* ----------------------------- SSRF ------------------------------------ */
		// Cloud instance-metadata endpoints (AWS IMDSv1/v2, GCP, Azure, Ali Cloud, Oracle Cloud).
		array( 'id' => 'ssrf-metadata', 'category' => 'proto', 'score' => 12, 'regex' => '/(?:169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|100\.100\.100\.200|192\.0\.0\.192)/i', 'desc' => 'Cloud instance-metadata SSRF target' ),
		// Internal / loopback addresses in a parameter value (private RFC-1918 + loopback + link-local).
		// HEADER source excluded: same-site Referer/Origin headers legitimately contain https://hostname.
		// Score raised to 12 so a single JSON-body hit blocks without needing multi-source accumulation.
		// same_host_exempt: a huge share of local/staging/intranet WordPress installs run on
		// localhost or an RFC-1918 address by design — WP's own redirect_to /
		// _wp_http_referer params then legitimately contain that exact host, and every login
		// would otherwise self-block. Only skipped when the matched URL's host equals this
		// site's own configured hostname (baked in from home_url(), never the client-controlled
		// Host header — see RuleEngine::is_own_host()), so a genuinely different internal/loopback
		// target is still caught.
		array( 'id' => 'ssrf-internal', 'category' => 'proto', 'score' => 12,
			'sources' => array( 'GET', 'POST', 'COOKIE', 'QUERY_STRING', 'BODY', 'URI' ),
			'regex'   => '/(?:https?|ftps?):\/\/(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|::1|\[::1\]|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/i',
			'same_host_exempt' => true,
			'desc'    => 'SSRF to loopback or RFC-1918 private address' ),
		// Dangerous URL schemes used in SSRF / XXE / gopher-bounce attacks.
		// No (?:^|=) anchor so the rule fires on raw JSON bodies (e.g. {"url":"gopher://..."}).
		// Score 12 means a single BODY or HEADER hit blocks without accumulation.
		array( 'id' => 'ssrf-scheme', 'category' => 'proto', 'score' => 12, 'regex' => '/(?:gopher|dict|ldap|ldaps|sftp|tftp|ftp):\/\//i', 'desc' => 'Dangerous URL scheme (SSRF / XXE / gopher-bounce)' ),

		/* -------------------------- RCE / Command ------------------------------ */
		// Shell injection comes from URL params and POST bodies, not from cookies or UA headers.
		// WordPress auth cookies use "|" as a field separator (username|expiry|token|hmac), so
		// inspecting COOKIE/HEADER sources causes false positives when the token/hmac fragment
		// happens to start with one of the short command words (sh, nc, ls, id).  The same value
		// is inspected twice (once parsed under COOKIE, once as the raw "cookie" HEADER), which
		// doubles the score and crosses the 12-point threshold even without any other rule firing.
		array( 'id' => 'rce-shell', 'category' => 'rce', 'score' => 10,
			'sources' => array( 'GET', 'POST', 'BODY', 'QUERY_STRING', 'URI' ),
			'regex'   => '/(;|\||&&|`|\$\()\s*(cat|wget|curl|nc|bash|sh|chmod|chown|rm|ls|id|uname|whoami|ping|nslookup|powershell|cmd\.exe)\b/i',
			'desc'    => 'Shell command injection' ),
		array( 'id' => 'rce-phpfuncs', 'category' => 'php', 'score' => 10, 'regex' => '/\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(/i', 'desc' => 'PHP command-exec function' ),
		array( 'id' => 'rce-eval', 'category' => 'php', 'score' => 10, 'regex' => '/\b(eval|assert|create_function|call_user_func(_array)?)\s*\(/i', 'desc' => 'PHP code-eval function' ),
		array( 'id' => 'rce-decode', 'category' => 'php', 'score' => 6, 'regex' => '/\b(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(/i', 'desc' => 'PHP decode/unpack function' ),
		array( 'id' => 'rce-super', 'category' => 'php', 'score' => 7, 'regex' => '/\$\{?(_GET|_POST|_REQUEST|_COOKIE|_SERVER|GLOBALS)\b/i', 'desc' => 'PHP superglobal injection' ),

		/* --------------------------- Protocol abuse ---------------------------- */
		array( 'id' => 'proto-nullbyte', 'category' => 'proto', 'score' => 8, 'regex' => '/(%00|\x00)/', 'desc' => 'Null byte injection' ),
		// CRLF injection: catches %0d%0a (or bare %0d / %0a) followed by any HTTP header-like sequence.
		// PHP 8 strips CRLF inside header(), but detection + logging is still valuable.
		// Score 8 means two sources (GET + QUERY_STRING) accumulate to 16 → block.
		array( 'id' => 'proto-crlf', 'category' => 'proto', 'score' => 8, 'regex' => '/(?:%0[dD](?:%0[aA])?|%0[aA]|\r\n)[A-Za-z][\w-]{1,30}\s*:/i', 'desc' => 'CRLF / HTTP response splitting' ),
		// PHP object injection via unserialize() — serialized object syntax in any request param.
		// Score 12: single-source block (covers base64-encoded payloads inside JSON bodies via Decoder).
		array( 'id' => 'php-deserial', 'category' => 'php', 'score' => 12, 'regex' => '/O:\d+:"[^"]{1,50}":\d+:\{/', 'desc' => 'PHP serialized object (potential object injection)' ),

		/* ----------------------- PHP obfuscation in requests ------------------- */
		// chr(115).chr(121).chr(115).chr(116).chr(101).chr(109) → 'system' — used in eval payloads.
		array( 'id' => 'rce-chr-chain', 'category' => 'php', 'score' => 10, 'regex' => '/(chr\s*\(\s*\d+\s*\)\s*[.\s]*){4,}/i', 'desc' => 'PHP chr() chain obfuscation' ),
		// 'sys'.'tem'('id') — PHP string-concat to hide function names from literal match.
		array( 'id' => 'rce-str-concat', 'category' => 'php', 'score' => 8, 'regex' => '/[\'"][a-z]{2,8}[\'"]\s*\.\s*[\'"][a-z]{2,8}[\'"]\s*\(/i', 'desc' => 'PHP concat function call (obfuscated name)' ),

		/* ---------------------- Overlong / malformed UTF-8 ------------------- */
		// Matches both the percent-encoded form (QUERY_STRING raw source) and the decoded raw bytes
		// (GET/URI sources after PHP/rawurldecode strips the % notation). Score 12 = single-source block.
		array( 'id' => 'lfi-overlong', 'category' => 'lfi', 'score' => 12,
			'regex' => '/(%c0%af|%c1%1c|%c0%ae|%e0%80%af|%f0%80%80%af|\xC0\xAF|\xC1\x1C|\xC0\xAE|\xE0\x80\xAF|\xF0\x80\x80\xAF)/i',
			'desc' => 'Overlong UTF-8 encoding of / or . (LFI evasion — both encoded and decoded forms)' ),

		/* ---------------------- Injection / protocol abuse -------------------- */
		// Log4Shell (CVE-2021-44228) and generic JNDI injection in any input source.
		// PHP sites themselves are not vulnerable, but JNDI payloads in headers/params can reach
		// Java-based log aggregators, reverse proxies, or middleware in the stack.
		array( 'id' => 'rce-jndi', 'category' => 'rce', 'score' => 12,
			'regex' => '/\$\{jndi\s*:/i',
			'desc' => 'Log4Shell / JNDI injection (CVE-2021-44228)' ),

		/* ------------------------- Scanner / bad tools ------------------------- */
		array( 'id' => 'scan-tools', 'category' => 'scanner', 'score' => 5, 'regex' => '/(sqlmap|nikto|acunetix|nessus|nmap|masscan|wpscan|fimap|havij|dirbuster|gobuster)/i', 'desc' => 'Known scanning tool signature' ),
	),
);
