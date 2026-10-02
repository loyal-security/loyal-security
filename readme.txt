=== Loyal Security - Firewall & Malware Scanner ===
Contributors: totalsecuritywp
Tags: security, firewall, malware scanner, waf, two factor authentication
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 1.4.11
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, malware scanner, file integrity monitoring, hardening, 2FA, backups, and audit logging — one self-contained plugin.

== Description ==

Loyal Security - Firewall & Malware Scanner is an all-in-one WordPress security suite: a dual-mode web application
firewall, malware scanner with file integrity monitoring, server hardening, two-factor
authentication, backups, and audit logging — in a single self-contained plugin.

Every protection runs on your own server with the rules bundled in the plugin. No Node.js, no
build step: the admin dashboard is a React app powered by WordPress core's own bundled
`wp-element`, and every PHP class is loaded by a built-in autoloader. Install it, activate it,
and it works. A small number of features use outside services; each one is listed under
"External services" below, with what it sends and how to switch it off.

**Everything in this plugin is free and fully functional — nothing is locked, limited or
time-restricted.** Loyal Security Pro is a separate plugin, sold and downloaded from our
website, that adds automation and agency tools on top.

= Features =

* **Web Application Firewall** — Optimized Mode (runs before WordPress even loads, via a
  lightweight prepend) or Standard Mode (runs inside WordPress). Blocks SQL injection, XSS,
  LFI/RFI, path traversal, and RCE.
* **Rate limiting, brute-force protection & DDoS shielding** — plus a bad-bot blocker and
  country-level geo-blocking.
* **Virtual patching** — shields known-vulnerable third-party plugins/themes until you're
  able to update them.
* **Deep system hardening** — .htaccess/Nginx rule generation, wp-config hardening,
  directory-browsing lockdown, REST API & XML-RPC restriction, version obfuscation.
* **Malware scanner** — heuristic regex + token-based detection engine, on-demand full-site
  scans, and a weekly automatic scan.
* **File integrity monitoring** — WordPress.org checksum verification for core and plugins,
  plus baseline diffing for everything else, including themes, mu-plugins and drop-ins.
* **Database scanner** — checks posts, comments, options, and user meta for spam injections
  and rogue admin accounts.
* **Incident response** — safe quarantine, one-click clean-file recovery, and file-permission
  reset.
* **Backup & restore** — on-demand and scheduled full-site backups (files + database), plus a
  downloadable recovery tool you can upload to restore a backup even if WordPress itself won't
  load.
* **Two-factor authentication** — TOTP with QR enrollment and backup codes, passkeys, login
  CAPTCHA, password policy, breached-password checking, and active-session management.
* **Audit log** — full event trail with IP/user/proxy tracking, configurable retention
  (90 days by default), and CSV export.
* **Email notifications** — alerts with human-readable event guidance, throttling, quiet
  hours and per-event muting.
* **Live Traffic monitor** — real-time request feed with user-agent classification, filters,
  and one-click block/unblock.
* **Content Security Policy manager** — builds a policy from the resources your site
  actually loads, with a report-only mode.
* **Admin-bar Security Score** — an at-a-glance A–F health grade.
* **Inline vulnerability notices** — flags installed plugins/themes with known CVEs directly
  on the Plugins, Themes, and Updates screens.
* **WP-CLI support** — `wp loyal-security status | scan | firewall | backup | twofa`.

= Loyal Security Pro =

Loyal Security Pro is a separate plugin for people running security across many sites. It is
not needed for anything listed above. It adds:

* **Hourly threat-intelligence updates** — the same feed, delivered every hour instead of twice
  a day.
* **Under Attack Mode** — a one-click emergency shield with automatic expiry.
* **Faster scheduled scans & auto-quarantine** — daily or twice-daily scans, and infected files
  isolated the moment they are found.
* **Sentinel AI** — AI-assisted review of suspicious activity with reversible responses.
* **Threat hunting, uptime monitoring and compliance reports.**
* **Webhook, PagerDuty and OpsGenie alerts, and Cloudflare edge sync.**
* **WooCommerce-aware backups and staging restores.**
* **Agency tooling** — white-label dashboard, role management, and multi-site hub.

== External services ==

Loyal Security connects to the services below. Nothing else is contacted, and no request
carries your site's URL, your visitors' personal data, or your content unless stated here.
Requests the plugin makes identify themselves as `LoyalSecurity/<version>` instead of
WordPress's default user agent (which includes the site's URL).

= Loyal Security threat-intelligence service (licensekit.loyalsecuritywp.com) =

Our own service, used for:

* **Threat-intelligence feed (on by default).** Keeps the firewall rules, malware signatures,
  virtual patches and the vulnerability (CVE) database up to date. Twice a day, and when you
  click "Sync now", the plugin requests each dataset and sends: the dataset name, the version
  it already has, the feed channel ("free", or "pro" with the separate Pro plugin), the
  subscription key if Pro stored one, and — for the vulnerability dataset only — the slugs (folder names) of the
  installed plugins and themes, so only advisories that concern them are returned. Switch
  automatic updates off with Settings → Threat Intelligence → "Auto Sync", or turn the module
  off with "Enabled"; the plugin then keeps using the rules it already has.
* **Pricing on the "About Pro" screen.** Opening that screen fetches the public plan list. No
  site data is sent.
* **Connection test.** Only when you click "Test connection" on the Threat Intelligence
  screen: sends a timestamp, an anonymous install ID and, if present, a hash of the
  subscription key.
* **Firewall-bypass reports and virtual-patch suggestions (off by default).** Only after an
  administrator gives explicit consent (Loyal Security → Bypass Telemetry in the Advanced view,
  where it can be withdrawn at any time): when an attack appears to have got past the firewall, the plugin
  sends the attacker's request (method, path, parameters, IP address and country), the matching
  rule names, the plugin/WordPress/PHP versions (major.minor) and an anonymous install ID —
  with cookies, authorization headers and nonces removed. With the same consent, a virtual
  patch you approve can be shared as a rule suggestion.

Terms of use: https://loyalsecuritywp.com/terms.html — Privacy policy: https://loyalsecuritywp.com/privacy.html

= Have I Been Pwned — Pwned Passwords (api.pwnedpasswords.com) =

**On by default.** When a user logs in, the plugin checks whether the password appears in known
data breaches, using k-anonymity: only the first five characters of the password's SHA-1 hash
are sent — never the password, the username or the email address. It never blocks a login; the
user sees a warning. Switch it off with Settings → Identity & Access → "Breach Check".

Terms of use: https://haveibeenpwned.com/TermsOfUse — Privacy policy: https://haveibeenpwned.com/Privacy

= Cloudflare Turnstile (challenges.cloudflare.com) =

Only if you choose Turnstile as the login CAPTCHA and enter your keys. The Turnstile script
loads on the login form, and on submission the visitor's CAPTCHA token and IP address are sent
to Cloudflare to verify it.

Terms of use: https://www.cloudflare.com/website-terms/ — Privacy policy: https://www.cloudflare.com/privacypolicy/ — Turnstile privacy addendum: https://www.cloudflare.com/turnstile-privacy-policy/

= Google reCAPTCHA (www.google.com) =

Only if you choose reCAPTCHA v3 as the login CAPTCHA and enter your keys. The reCAPTCHA script
loads on the login form, and on submission the visitor's CAPTCHA token and IP address are sent
to Google to verify it.

Terms of service: https://policies.google.com/terms — Privacy policy: https://policies.google.com/privacy

= Google Safe Browsing (safebrowsing.googleapis.com) =

Only if you enter your own Safe Browsing API key (Settings → Hardening). The plugin then sends
your site's home URL to check whether Google has flagged it. Nothing is sent without a key.

Terms of service: https://developers.google.com/terms — Privacy policy: https://policies.google.com/privacy

= WordPress.org (api.wordpress.org, downloads.wordpress.org, core.svn.wordpress.org) =

File integrity checks download the official checksums of WordPress core and of the installed
WordPress.org plugins (plugin slug and version). When you choose to repair or reinstall, the
official WordPress core or plugin package, or a single core file, is downloaded. These are the
same public services WordPress uses for updates.

Privacy policy: https://wordpress.org/about/privacy/

= Stylesheets your pages already load (CSP scanner) =

Only when an administrator clicks "Scan" on the Content Security Policy screen. To suggest
which domains your policy should allow, the scanner loads a few of your own pages and the
external stylesheets those pages already use (for example a Google Fonts or CDN stylesheet),
with a plain request that carries no site data. Those providers' own terms apply to those
files, exactly as when a visitor loads your site.

= DNS (your server's resolver) =

To confirm that a visitor claiming to be a search-engine crawler (Googlebot, Bingbot…) really
is one, the plugin performs a reverse and forward DNS lookup of that visitor's IP address
through your server's normal DNS resolver. The result is cached.

== Installation ==

1. Upload the `loyal-security` folder to `/wp-content/plugins/`, or install it directly from
   **Plugins → Add New**.
2. Activate the plugin through the **Plugins** screen.
3. Open **Loyal Security** in the admin menu and run the Setup Wizard — it deploys the
   firewall in the best mode for your hosting environment automatically.
4. Review the defaults under **Loyal Security → Settings**, and enable two-factor
   authentication for every admin account.

**Server requirements:** PHP 8.0 or later. Optimized Mode (recommended) needs either
`auto_prepend_file` support (mod_php/CGI) or a writable `.user.ini` (PHP-FPM). Where neither
is available, the firewall automatically falls back to Standard Mode — no manual
configuration required.

== Frequently Asked Questions ==

= Does this require Node.js or a build step? =

No. The dashboard uses WordPress's bundled React via ES modules, so there's nothing to
compile — and no Composer install either, since the plugin ships its own lightweight
autoloader.

= Does it work with both block and classic themes? =

Yes. The dashboard lives entirely in wp-admin, so it's completely independent of your active
theme.

= Will this slow down my site? =

Optimized Mode runs the firewall before WordPress even loads, so malicious requests are
blocked before the WordPress bootstrap, database connection, or plugin/theme loading happen.
Standard Mode, used automatically when the prepend can't be deployed, still runs as early as
possible inside WordPress.

= What happens if the firewall itself breaks? =

The Optimized Mode prepend is written to fail open: if its configuration or any of its files
are missing or unreadable, it does nothing rather than breaking the site. The Setup Wizard
also self-tests the deployment and automatically rolls back if the test fails.

= Is anything in this plugin limited or locked? =

No. Every feature in this plugin is complete and has no time, usage or licence limits.
Loyal Security Pro is a separate plugin that adds its own features (listed above); installing
it unlocks nothing in this one.

= Which outside services does the plugin contact? =

By default, two: our threat-intelligence feed (twice a day, to keep the firewall and scanner
rules current) and Have I Been Pwned's Pwned Passwords range API (at login, k-anonymous). Both
can be switched off in Settings. Everything else — CAPTCHA, Safe Browsing, bypass reports — is
off until you enable it. See "External services" above for exactly what each one sends.

= Can I use this alongside another security plugin? =

You can, but running two firewalls or two file scanners at once is generally redundant and
can occasionally conflict (for example, both plugins trying to write competing rules to
.htaccess). We recommend deactivating other firewall plugins before activating Loyal
Security's.

= Where do I report a security vulnerability in the plugin itself? =

Please report it privately rather than in the public support forum so it can be fixed before
details become public.

= What happens to my data if I delete the plugin? =

By default, deleting Loyal Security keeps your security data (logs, scan history, settings)
in the database in case you reinstall it. Any deployed server-level changes — the firewall
prepend, .htaccess rules, wp-config markers — are always reverted on delete regardless. If you
want a full data wipe instead, enable "Delete all data on uninstall" under Settings before
removing the plugin.

== Screenshots ==

1. Dashboard overview with the admin-bar Security Score and at-a-glance module status.
2. Firewall panel — live rule matches, virtual patches, and suggested patches.
3. Malware scanner — findings list with one-click quarantine and repair.
4. Live Traffic monitor — real-time request feed with user-agent classification.

== Changelog ==

= 1.4.11 =
* Fix: Backups — any `%` character in the database (e.g. in posts or options) was written to the backup incorrectly and came back as a long placeholder code after a restore. Backups taken with 1.4.11 or later restore it correctly; restoring a backup taken with an earlier version does not repair values that were already stored incorrectly in that backup.
* Fix: Restoring a database backup now verifies the backup's checksum and only runs the statements a Loyal Security backup contains.
* Fix: CSV export of the audit log no longer stops at 200 rows.
* Fix: Removing the hardening .htaccess rules could damage the firewall's own .htaccess block.
* Fix: The weekly automatic malware scan runs again.
* Fix: With a custom login URL set, "Lost your password?" returned a "page not found" error and the lost-password form could not be submitted.
* Fix: The audit log and notification history showed events without their details, and the CSV export printed PHP warnings.
* Fix: The audit log no longer records the values of WordPress's secret keys and salts, and no longer raises an alert when WordPress creates them.
* Fix: Outbound-request protection no longer blocks the site's requests to itself (such as WP-Cron) when its address resolves to a private IP.
* Fix: Host-header protection no longer redirects WP-CLI and cron runs, accepts the site's home address, and keeps the port when redirecting.
* Fix: The audit log, Live Traffic and vulnerability matching now also work on SQLite databases, such as WordPress Playground.
* Fix: A "translation loading was triggered too early" notice when WP_DEBUG is on.
* Change: No feature is limited any more — full scan history, audit-log retention as configured, backup retention as configured, and the complete Live Traffic monitor with filters and payload details.
* Change: Passkey sign-in now goes through the standard WordPress login form.
* Change: The standalone recovery tool is now downloaded from Backup & Recovery and uploaded by you, instead of being written into the plugin folder.
* Change: The breached-password check has an on/off setting (Settings → Identity & Access).
* Change: Features of the separate Loyal Security Pro plugin are described, not included.
* Change: Requires WordPress 6.6 or later.
* Security: Hardened input handling, output escaping and database queries throughout.

= 1.4.10 =
* Improvement: General maintenance and internal code quality improvements.

= 1.4.9 =
* Improvement: General maintenance and internal code quality improvements.

= 1.4.8 =
* Fix: WordPress.org Plugin Check compliance pass — resolved several code-quality and internationalization warnings ahead of the official directory listing. No user-facing behavior changes.
* Fix: `Tested up to` bumped to the current WordPress release.

== Upgrade Notice ==

= 1.4.11 =
Fixes backups of data containing the % character, restores the weekly automatic scan, and removes every feature limit. Requires WordPress 6.6. Recommended for all users.
