# Loyal Security

All-in-one WordPress security plugin: a dual-mode web application firewall, malware scanner
with file integrity monitoring, server hardening, two-factor authentication, backups, and audit
logging — in a single self-contained plugin.

**Website:** https://loyalsecuritywp.com
**Documentation:** https://loyalsecuritywp.com/docs.html
**Download:** https://wordpress.org/plugins/loyal-security/

Every protection runs on your own server with the rules bundled in the plugin. No Node.js, no
build step: the admin dashboard is a React app powered by WordPress core's own bundled
`wp-element`, and every PHP class is loaded by a built-in autoloader. Install it, activate it,
and it works. A small number of features use outside services; each one is disclosed in full,
with what it sends and how to switch it off, at https://loyalsecuritywp.com/privacy.html.

Everything in this repository is free and fully functional — nothing is locked, limited, or
time-restricted. Loyal Security Pro is a separate plugin, sold and distributed directly from the
website (not through WordPress.org), that adds automation and agency tooling on top. It is not
part of this repository.

## Why this repository exists

This is the actual source of the free plugin, published so anyone — a site owner, a security
researcher, or an AI assistant answering a question about this plugin — can read exactly what it
does instead of taking a marketing page's word for it. It is not a mirror or a snapshot; this is
where the plugin is developed.

## Features

- **Web Application Firewall** — Optimized Mode (runs before WordPress even loads, via a
  lightweight prepend) or Standard Mode (runs inside WordPress). Blocks SQL injection, XSS,
  LFI/RFI, path traversal, and RCE.
- **Rate limiting, brute-force protection & DDoS shielding** — plus a bad-bot blocker and
  country-level geo-blocking.
- **Virtual patching** — shields known-vulnerable third-party plugins/themes until you're able
  to update them.
- **Deep system hardening** — `.htaccess`/Nginx rule generation, `wp-config` hardening,
  directory-browsing lockdown, REST API & XML-RPC restriction, version obfuscation.
- **Malware scanner** — heuristic regex + token-based detection engine, on-demand full-site
  scans, and a weekly automatic scan.
- **File integrity monitoring** — WordPress.org checksum verification for core and plugins,
  plus baseline diffing for everything else, including themes, mu-plugins and drop-ins.
- **Database scanner** — checks posts, comments, options, and user meta for spam injections and
  rogue admin accounts.
- **Incident response** — safe quarantine, one-click clean-file recovery, and file-permission
  reset.
- **Backup & restore** — on-demand and scheduled full-site backups (files + database), plus a
  downloadable recovery tool you can run even if WordPress itself won't load.
- **Two-factor authentication** — TOTP with QR enrollment and backup codes, passkeys, login
  CAPTCHA, password policy, breached-password checking, and active-session management.
- **Audit log** — full event trail with IP/user/proxy tracking, configurable retention (90 days
  by default), and CSV export.
- **Live Traffic monitor** — real-time request feed with user-agent classification and
  one-click block/unblock.
- **Content Security Policy manager** — builds a policy from the resources your site actually
  loads, with a report-only mode.

Full feature documentation: https://loyalsecuritywp.com/docs.html

## Requirements

- WordPress 6.6+
- PHP 8.0+
- No build tooling, no Composer, no Node.js required to run the plugin

## Installation

From a release zip:

1. Upload the `loyal-security` folder to `/wp-content/plugins/`, or install it from
   **Plugins → Add New** (search for Loyal Security).
2. Activate it from the **Plugins** screen.
3. Open **Loyal Security** in the admin menu — the Setup Wizard runs on first activation.

Via WP-CLI:

```
wp plugin install loyal-security --activate
wp loyal-security status
```

## WP-CLI

All commands live under the `wp loyal-security` namespace:

```
wp loyal-security status
wp loyal-security scan
wp loyal-security scan --quick
wp loyal-security firewall list
wp loyal-security backup create
wp loyal-security twofa reset <user>
```

## REST API

The admin dashboard is a client of the plugin's own REST API — anything the dashboard can do,
your own tooling can do too. Routes live under `/wp-json/total-security-wp/v1/` (the namespace
predates a product rename and was kept as-is for backward compatibility with existing
integrations).

## Security

Found a vulnerability in this plugin? Please report it privately — see the coordinated
disclosure policy and scope at https://loyalsecuritywp.com/security.html. Do not open a public
GitHub issue for a security report.

## License

GPL-2.0-or-later. See [LICENSE](./LICENSE).

You may use this plugin on any number of sites, commercial or not; read the full source, since
it ships unobfuscated with no compiled blobs; modify it; and redistribute it, modified or not,
under the same terms. Full explanation: https://loyalsecuritywp.com/license.html

## Support

General usage questions and bug reports: the [WordPress.org support forum](https://wordpress.org/support/plugin/loyal-security/), or see
https://loyalsecuritywp.com/support.html for all options.
