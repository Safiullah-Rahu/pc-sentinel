# Security policy

PC Sentinel is a security tool, so its own attack surface matters. This page describes the threat model, the
protections built in, and how to report a vulnerability.

## Reporting a vulnerability
Please **do not open a public issue**. Use GitHub's private reporting instead: **Security → Report a vulnerability**
on this repository. You'll get an acknowledgement within a few days. Fixes are released as a new version, with
credit if you want it.

## Supported versions
Only the latest release receives security fixes.

## Threat model
PC Sentinel runs as your normal user. A local engine serves the dashboard on `127.0.0.1`, and the desktop app
shows it. The engine can kill processes and add network blocks, so it is protected against:

| Threat | Protection |
|---|---|
| Other computers on the network | The engine binds to `127.0.0.1` only. |
| Web pages you visit calling the local API (CSRF, DNS rebinding) | Every `/api` call needs a per-install random token, sent in a custom header (browsers block this cross-origin without CORS, and PC Sentinel sends no CORS headers). The `Host` header must be `127.0.0.1:<port>` or `localhost:<port>`. |
| Other local apps reading the token | It sits in your per-user data folder (`0600` file in a `0700` folder on macOS/Linux; your profile ACL on Windows). |
| Malicious data on screen (process names, command lines, reverse-DNS names, task names) | The dashboard escapes all data. A strict CSP is set: `default-src 'self'`, no inline scripts, `object-src 'none'`, `frame-ancestors 'none'`. There are no external resources. |
| Command injection through actions | PIDs are integers and IPs are parsed with `ipaddress`. Privileged commands are argument lists, never shell strings built from data, and file lists reach PowerShell through private files, not the command line. |
| SQL injection | Every query uses bound parameters. |
| Oversized or unexpected requests | Request bodies are limited to 64 KB. `/api` accepts only GET and POST. |
| Supply chain | Dependencies are pinned exactly. CI runs `pip-audit` (known vulnerabilities), `bandit`, `ruff` security rules and CodeQL (Python + JavaScript) on every push. |
| Personal data leaking into the repo | Runtime data (token, database, logs, your own threat intel in `iocs.json`) lives outside the repository and is git-ignored. |

### Out of scope / limitations
- Malware already running **with administrator/root rights** can stop or blind any user-space monitor, including
  this one. Keep your OS antivirus on; PC Sentinel complements it.
- Release builds are **not code-signed** yet, so Windows SmartScreen and macOS Gatekeeper will warn on first launch.
  Verify downloads against the published `.sha256` checksums.
- Reverse-DNS lookups of the remote addresses your apps contact go to your normal DNS resolver. Nothing else
  leaves your machine, and there is no telemetry.
