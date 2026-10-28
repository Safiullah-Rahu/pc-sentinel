# PC Sentinel — dashboard ↔ engine API contract

The engine (Python, FastAPI) listens on `http://127.0.0.1:8777` only. It serves the dashboard
from `/` (files in `dashboard/`) and JSON under `/api/*`.

## Auth
Every `/api/*` call needs header `X-Sentinel-Token: <token>`. The engine injects the token into
`index.html` by replacing the literal `__SENTINEL_TOKEN__` (put it in a `<meta name="sentinel-token">`).
The SSE stream takes it as a query param: `/api/stream?token=<token>`.
If the meta value is still the literal `__SENTINEL_TOKEN__` (file opened directly), or `?mock=1`
is in the URL, the dashboard runs on built-in mock data (`dashboard/mock.js`).

## Shared shapes
```jsonc
// Trust levels used everywhere (drive the badge colour)
"trust": "trusted" | "known" | "unsigned" | "suspicious" | "malicious"
// severity
"severity": "critical" | "high" | "medium" | "low" | "info"
// ProcessRef
{ "pid": 18736, "name": "updsvc.exe", "exe": "C:\\ProgramData\\{8C2E…}\\updsvc.exe",
  "signer": "Contoso Software Ltd.", "sig_status": "HashMismatch", "trust": "malicious" }
```
`sig_status`: `Valid | NotSigned | HashMismatch | NotTrusted | UnknownError | Unknown` (Unknown = not checked yet).
`flags` arrays contain short machine tags, e.g. `"user_writable_path"`, `"unsigned"`, `"sig_mismatch"`,
`"blocklisted_ip"`, `"odd_port"`, `"lolbin"`, `"padded_binary"`, `"hidden_dir"`, `"new_app"`,
`"exposed"`, `"first_seen"`. Show them as small chips (map tag → human label in the UI).

## Endpoints

## Cross-platform fields (v1.1)
PC Sentinel runs on Windows, macOS and Linux. Some monitors only exist on some systems:
- `summary.engine.platform` = `"windows" | "macos" | "linux"`, plus `summary.engine.os` (e.g. `"Windows 11 (26200)"`,
  `"macOS 15.1"`, `"Ubuntu 24.04"`).
- `summary.coverage_supported` has the same keys as `coverage`; `false` means "not available on this OS".
  The UI must show such monitors as **n/a** (not as a problem and not as "needs admin setup").
- `settings.autostart` = `{ "supported": true, "enabled": false, "detail": "Startup folder shortcut" }`;
  toggle with POST `/api/actions/autostart` `{ "enabled": true }` → `{ ok, message }`.
- Labels that were Windows-only should read naturally on every OS (e.g. "Run keys / Startup folder" on Windows,
  "LaunchAgents / Login items" on macOS, "systemd units / XDG autostart / cron" on Linux; persistence `kind` values
  add `launch_agent`, `launch_daemon`, `login_item`, `systemd_unit`, `xdg_autostart`, `cron`, `shell_rc`).

### GET /api/summary
```json
{
  "engine": { "version": "1.0.0", "started": "2026-10-28T20:01:02", "uptime_s": 3600, "host": "WORKSTATION-01",
              "user": "alex", "elevated": false },
  "coverage": { "processes": true, "network": true, "privacy": true, "persistence": true,
                "defender_log": true, "security_log": false, "dns_log": false, "file_audit": false,
                "canaries": 0 },
  "defender": { "realtime": true, "tamper": true, "signatures": "1.463.9.0", "signatures_age_h": 3,
                "exclusions_known": 0, "last_detection": null },
  "kpis": { "alerts_open": { "critical": 1, "high": 2, "medium": 5, "low": 9 },
            "processes": 312, "connections": 214, "listening_exposed": 6, "remote_hosts_24h": 188,
            "apps_online": 23, "camera_in_use": false, "mic_in_use": false },
  "throughput": { "rx_bps": 152000, "tx_bps": 23000 },
  "risk": { "score": 72, "label": "Elevated" }   // 0-100, higher = worse; labels: Low/Guarded/Elevated/High/Severe
}
```

### GET /api/metrics?minutes=60
`{ "points": [ { "t": "2026-10-28T20:01:00", "rx_bps": 12000, "tx_bps": 3000, "cpu": 12.5, "conns": 210 } ] }`
(one point per 5 s; the stream also pushes live points.)

### GET /api/alerts?status=open|all&severity=&category=&q=&limit=200
```json
{ "items": [ {
  "id": 41, "ts": "2026-10-28T20:03:11", "first_ts": "…", "last_ts": "…", "count": 3,
  "severity": "critical", "category": "network",
  "title": "Connection to blocklisted IP 203.0.113.66:224",
  "summary": "updsvc.exe (HashMismatch signature) tried to reach a known malware server.",
  "process": { /* ProcessRef */ },
  "remote": { "ip": "203.0.113.66", "port": 4444, "host": null },
  "details": { "rule": "blocklisted_ip", "state": "SYN_SENT" },
  "status": "open"          // open | acknowledged | allowed
} ] }
```
`category`: `network | process | privacy | persistence | file | defender | account | system`.

POST `/api/alerts/{id}/ack` → `{ "ok": true }` · POST `/api/alerts/ack_all` (body `{ "severity": "low" }` optional) → `{ "ok": true, "count": 9 }`

### GET /api/network/connections
```json
{ "items": [ { "pid": 2280, "process": "msedge.exe", "exe": "C:\\…\\msedge.exe", "signer": "Microsoft Corporation",
  "trust": "trusted", "proto": "TCP", "laddr": "192.168.1.20", "lport": 51343, "raddr": "13.107.42.14",
  "rport": 443, "rhost": "edge.microsoft.com", "status": "ESTABLISHED", "direction": "out",
  "first_seen": "…", "flags": [] } ] }
```
`direction`: `out | in` (in = remote peer connected to one of our listening ports).

### GET /api/network/apps
`{ "items": [ { "process": "Slack.exe", "exe": "…", "signer": null, "trust": "unsigned", "conns": 37,
  "remote_hosts": 9, "ports": [443], "first_seen": "…", "last_seen": "…", "flags": ["unsigned"] } ] }`

### GET /api/network/destinations?hours=24
`{ "items": [ { "ip": "203.0.113.66", "host": null, "ports": [4444], "apps": ["updsvc.exe"], "hits": 14,
  "first_seen": "…", "last_seen": "…", "blocklisted": true, "private": false } ] }`

### GET /api/network/listening
`{ "items": [ { "proto": "TCP", "laddr": "0.0.0.0", "lport": 3000, "pid": 5512, "process": "node.exe",
  "exe": "…", "trust": "unsigned", "exposed": true, "first_seen": "…" } ] }`
(`exposed` = bound to all interfaces, not loopback.)

### GET /api/dns?limit=300
`{ "enabled": false, "items": [ { "ts": "…", "pid": 1234, "process": "opera.exe", "query": "example.com",
  "type": "A", "result": "93.184.215.14" } ] }`

### GET /api/processes?filter=all|flagged|unsigned
`{ "items": [ { "pid": 18736, "ppid": 5212, "parent": "explorer.exe", "name": "updsvc.exe", "exe": "…",
  "cmdline": "\"…updsvc.exe\" /auto", "user": "alex", "started": "…", "signer": "…", "sig_status": "HashMismatch",
  "trust": "malicious", "cpu": 0.1, "mem_mb": 23, "net_conns": 1, "flags": ["sig_mismatch","padded_binary"] } ] }`

### GET /api/privacy
```json
{ "devices": {
    "webcam":     { "in_use": false, "by": [] },
    "microphone": { "in_use": true,  "by": ["msedge.exe"] },
    "location":   { "in_use": false, "by": [] } },
  "history": [ { "device": "webcam", "app": "camhelper.exe", "path": "C:\\Users\\alex\\.cache\\…\\camhelper.exe",
                 "start": "2025-03-28T07:16:40", "stop": "2025-03-28T07:17:02", "in_use": false,
                 "trust": "malicious", "allowed": false } ] }
```

### GET /api/persistence
`{ "items": [ { "kind": "run_key" | "startup_folder" | "scheduled_task" | "service",
  "location": "HKCU\\…\\Run", "name": "Opera Stable", "command": "\"C:\\…\\opera.exe\" --autostart",
  "exe": "…", "signer": "Opera Norway AS", "sig_status": "Valid", "trust": "trusted",
  "status": "baseline" | "new" | "changed" | "removed", "first_seen": "…", "flags": [] } ] }`

### GET /api/files
```json
{ "audit_enabled": false,
  "watched": [ { "path": "C:\\Users\\alex\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
                 "label": "Chrome saved passwords", "kind": "credential" | "wallet" | "ssh" | "messenger" | "canary",
                 "audited": true, "exists": true } ],
  "access": [ { "ts": "…", "path": "…", "label": "Chrome saved passwords", "process": "python.exe", "pid": 4321,
                "exe": "…", "access": "ReadData", "expected": false } ] }
```

### GET /api/events?category=&limit=300
Timeline of everything (alerts plus info-level observations):
`{ "items": [ { "id": 1, "ts": "…", "severity": "info", "category": "process", "title": "Process started: node.exe", "summary": "…" } ] }`

### GET /api/settings
```json
{ "allowlist": [ { "id": 1, "kind": "process" | "destination" | "privacy" | "persistence", "value": "…", "note": "…", "ts": "…" } ],
  "blocklist": [ { "id": 1, "ip": "203.0.113.66", "note": "example C2", "ts": "…" } ],
  "notify": { "enabled": false, "min_severity": "high" } }
```

### GET /api/graph   (Live Map)
```jsonc
{ "generated": "2026-10-28T20:30:00",
  "nodes": [
    { "id": "host", "type": "host", "label": "WORKSTATION-01" },
    { "id": "p:c:\\program files\\…\\msedge.exe", "type": "process", "label": "msedge.exe",
      "exe": "C:\\Program Files (x86)\\…\\msedge.exe", "pids": [2280, 5120], "trust": "trusted",
      "signer": "Microsoft Corporation", "sig_status": "Valid", "conns": 29, "cpu": 3.1, "mem_mb": 812,
      "flags": [], "parent": "explorer.exe" },
    { "id": "r:203.0.113.66", "type": "remote", "label": "203.0.113.66", "ip": "203.0.113.66",
      "host": null, "ports": [4444], "blocklisted": true, "private": false }
  ],
  "edges": [
    { "source": "host", "target": "p:…msedge.exe", "kind": "host" },
    { "source": "p:…updsvc.exe", "target": "r:203.0.113.66", "kind": "net", "count": 1, "ports": [4444],
      "direction": "out", "states": ["SYN_SENT"], "danger": true },
    { "source": "p:…explorer.exe", "target": "p:…updsvc.exe", "kind": "spawn" }
  ] }
```
Process nodes are grouped per executable (all PIDs of one exe = one node). Only processes with at least one
remote (non-loopback) connection or a listening port are included, plus their parents for `spawn` edges.
`danger` = blocklisted remote or malicious/suspicious process. `direction` "in" means the remote side connected to us.
```

### Actions (POST, JSON body, all return `{ "ok": bool, "message": "…" }`)
- `/api/actions/kill` `{ "pid": 18736 }`
- `/api/actions/block_ip` `{ "ip": "203.0.113.66" }` — engine raises a Windows admin prompt to add a firewall rule.
- `/api/actions/allow` `{ "kind": "process", "value": "C:\\…\\node.exe", "note": "dev tool" }`
- `/api/actions/blocklist` `{ "ip": "1.2.3.4", "note": "…" }`
- `/api/actions/unallow` `{ "id": 3 }` · `/api/actions/unblocklist` `{ "id": 2 }`
- `/api/actions/notify` `{ "enabled": true, "min_severity": "high" }` — desktop pop-ups are OFF by default; when
  enabled, alerts at or above `min_severity` also show a Windows notification.

### GET /api/stream?token=…  (Server-Sent Events)
- `event: metric` → `{ "t": "…", "rx_bps": …, "tx_bps": …, "cpu": …, "conns": … }` every 2–5 s
- `event: alert`  → an Alert object (new or count-updated)
- `event: summary` → the `/api/summary` object every 10 s
