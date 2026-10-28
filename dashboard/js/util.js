/* PC Sentinel dashboard: shared helpers (escaping, formatting, vocabulary, small HTML builders, event bus). */
(function () {
  'use strict';
  const PCS = (window.PCS = window.PCS || {});

  /* API.md names the throughput fields *_bps. The engine fills them from psutil byte counters
     (bytes per second), so they are shown as B/s, KB/s, MB/s. Flip to true if they ever become bits. */
  const RATE_IN_BITS = false;

  /* ------------------------------------------------------------------ escaping / DOM
     SECURITY: everything shown here (process names, command lines, paths, reverse-DNS names, task names, DNS
     queries…) is attacker-influenced. Every dynamic value that goes into an HTML string must pass through esc(),
     which is safe in text AND in double- or single-quoted attribute values. Never build href/src/on* from data. */
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
  function esc(v) {
    return v === null || v === undefined ? '' : String(v).replace(/[&<>"'`]/g, (c) => ESC[c]);
  }
  /** Own-property lookup: own(MAP, key) never returns Object.prototype members for keys like "constructor". */
  const own = (obj, key) => (obj && typeof key === 'string' && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined);
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  /* ------------------------------------------------------------------ vocabulary */
  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
  const sevRank = (s) => {
    const i = SEVERITIES.indexOf(s);
    return i < 0 ? SEVERITIES.length : i;
  };

  const TRUSTS = ['malicious', 'suspicious', 'unsigned', 'known', 'trusted'];
  const TRUST_LABEL = { trusted: 'Trusted', known: 'Known', unsigned: 'Unsigned', suspicious: 'Suspicious', malicious: 'Malicious' };
  const TRUST_ICON = { trusted: 'shieldCheck', known: 'shield', unsigned: 'shieldOff', suspicious: 'shieldAlert', malicious: 'shieldX' };
  const trustRank = (t) => {
    const i = TRUSTS.indexOf(t);
    return i < 0 ? TRUSTS.length : i;
  };

  const SIG = {
    Valid: ['Valid signature', 'ok'],
    NotSigned: ['Not signed', 'warn'],
    HashMismatch: ['Hash mismatch', 'danger'],
    NotTrusted: ['Untrusted signer', 'danger'],
    UnknownError: ['Check failed', 'muted'],
    Unknown: ['Not checked yet', 'muted'],
  };

  const FLAGS = {
    user_writable_path: ['User-writable path', 'warn'],
    unsigned: ['Unsigned', 'warn'],
    sig_mismatch: ['Signature mismatch', 'danger'],
    blocklisted_ip: ['Blocklisted IP', 'danger'],
    odd_port: ['Unusual port', 'warn'],
    lolbin: ['LOLBin', 'warn'],
    padded_binary: ['Padded binary', 'danger'],
    hidden_dir: ['Hidden folder', 'danger'],
    new_app: ['New app', 'info'],
    exposed: ['Exposed', 'warn'],
    first_seen: ['First seen', 'info'],
    missing_file: ['File missing', 'warn'],
  };
  function humanize(s) {
    s = String(s === null || s === undefined ? '' : s).replace(/[_-]+/g, ' ').trim();
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
  }
  const flagInfo = (tag) => own(FLAGS, tag) || [humanize(tag), 'neutral'];
  const catLabel = (c) => own(CAT_LABEL, c) || humanize(c);
  const catIcon = (c) => own(CAT_ICON, c) || 'info';

  const CATEGORIES = ['network', 'process', 'privacy', 'persistence', 'file', 'defender', 'account', 'system'];
  const CAT_LABEL = {
    network: 'Network', process: 'Process', privacy: 'Privacy', persistence: 'Persistence',
    file: 'Files', defender: 'Defender', account: 'Account', system: 'System',
  };
  const CAT_ICON = {
    network: 'globe', process: 'cpu', privacy: 'eye', persistence: 'power',
    file: 'fileLock', defender: 'shield', account: 'user', system: 'monitor',
  };

  const COVERAGE = [
    { key: 'processes', label: 'Processes', icon: 'cpu' },
    { key: 'network', label: 'Network', icon: 'globe' },
    { key: 'privacy', label: 'Privacy', icon: 'eye' },
    { key: 'persistence', label: 'Persistence', icon: 'power' },
    { key: 'defender_log', label: 'Defender log', icon: 'shield' },
    { key: 'security_log', label: 'Security log', icon: 'user', admin: true },
    { key: 'dns_log', label: 'DNS log', icon: 'list', admin: true },
    { key: 'file_audit', label: 'File audit', icon: 'fileLock', admin: true },
    { key: 'canaries', label: 'Canaries', icon: 'flag', admin: true },
  ];
  function coverageOn(cov, key) {
    const v = own(cov, key);
    return typeof v === 'number' ? v > 0 : v === true || (typeof v === 'string' && v !== '' && v !== '0' && v !== 'false');
  }

  /* ------------------------------------------------------------------ platform (API.md v1.1) */
  const PLATFORMS = { windows: 'Windows', macos: 'macOS', linux: 'Linux' };
  /** "windows" | "macos" | "linux" from the latest summary, or null while unknown. */
  function platform(summary) {
    const s = summary || (PCS.state && PCS.state.summary);
    const p = s && s.engine && s.engine.platform;
    return own(PLATFORMS, p) ? p : null;
  }
  const osName = (p) => own(PLATFORMS, p === undefined ? platform() : p) || 'this system';
  /** Short OS label for the UI: engine.os ("macOS 15.1") when sent, else the platform name. */
  function osLabel(summary) {
    const s = summary || (PCS.state && PCS.state.summary);
    const e = (s && s.engine) || {};
    return typeof e.os === 'string' && e.os.trim() ? e.os.trim() : own(PLATFORMS, e.platform) || '';
  }
  /** false only when the engine says this monitor does not exist on this OS (coverage_supported[key] === false). */
  function coverageSupported(summary, key) {
    const s = summary || (PCS.state && PCS.state.summary);
    return !(s && s.coverage_supported && own(s.coverage_supported, key) === false);
  }
  /** 'on' | 'off' | 'na' for one monitor. */
  function coverageState(summary, key) {
    const s = summary || (PCS.state && PCS.state.summary) || {};
    if (!coverageSupported(s, key)) return 'na';
    return coverageOn(s.coverage, key) ? 'on' : 'off';
  }
  /** Monitors that exist on this OS (the denominator of "x/y active"). */
  const coverageList = (summary) => COVERAGE.filter((c) => coverageSupported(summary, c.key));

  /* Friendly names for every persistence kind the engine reports, on any OS. Groups only render when present. */
  const PERSIST_KINDS = [
    { key: 'run_key', label: 'Run keys', icon: 'key', os: 'windows' },
    { key: 'startup_folder', label: 'Startup folder', icon: 'folder', os: 'windows' },
    { key: 'scheduled_task', label: 'Scheduled tasks', icon: 'clock', os: 'windows' },
    { key: 'service', label: 'Services', icon: 'server', os: 'windows' },
    { key: 'hijack', label: 'System hooks (Winlogon / IFEO / AppInit)', icon: 'shieldAlert', os: 'windows' },
    { key: 'launch_agent', label: 'Launch agents', icon: 'power', os: 'macos' },
    { key: 'launch_daemon', label: 'Launch daemons', icon: 'server', os: 'macos' },
    { key: 'login_item', label: 'Login items', icon: 'user', os: 'macos' },
    { key: 'systemd_unit', label: 'systemd units', icon: 'server', os: 'linux' },
    { key: 'xdg_autostart', label: 'XDG autostart entries', icon: 'folder', os: 'linux' },
    { key: 'cron', label: 'Cron jobs', icon: 'clock' },
    { key: 'shell_rc', label: 'Shell startup files', icon: 'terminal' },
  ];
  const persistKind = (k) => PERSIST_KINDS.find((x) => x.key === k) || { key: k, label: humanize(k) || 'Other', icon: 'power' };
  /** What "autostart" means on each OS (Persistence view subtitle). */
  const PERSIST_SCOPE = {
    windows: 'Run keys, Startup folder, scheduled tasks, services and system hooks',
    macos: 'LaunchAgents, LaunchDaemons, login items, cron and shell startup files',
    linux: 'systemd units, XDG autostart, cron and shell startup files',
  };

  /* ------------------------------------------------------------------ time */
  const DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const pad2 = (n) => String(n).padStart(2, '0');

  /** Engine timestamps are naive local ISO strings ("2026-10-28T20:01:02"); Date() reads those as local time. */
  function parseTs(ts) {
    if (ts === null || ts === undefined || ts === '') return null;
    if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts;
    if (typeof ts === 'number') return new Date(ts < 1e11 ? ts * 1000 : ts);
    if (/^\d+$/.test(ts)) return parseTs(Number(ts));
    const d = new Date(ts);
    return isNaN(d.getTime()) ? null : d;
  }
  const ms = (ts) => {
    const d = parseTs(ts);
    return d ? d.getTime() : NaN;
  };
  function sameDay(a, b) {
    return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  }
  function hms(ts) {
    const d = parseTs(ts);
    return d ? `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}` : '—';
  }
  function hm(ts) {
    const d = parseTs(ts);
    return d ? `${pad2(d.getHours())}:${pad2(d.getMinutes())}` : '—';
  }
  function fmtDate(ts, withYear) {
    const d = parseTs(ts);
    if (!d) return '—';
    const y = withYear || d.getFullYear() !== new Date().getFullYear() ? ` ${d.getFullYear()}` : '';
    return `${d.getDate()} ${MON[d.getMonth()]}${y}`;
  }
  function abs(ts) {
    const d = parseTs(ts);
    return d ? `${DOW[d.getDay()]} ${d.getDate()} ${MON[d.getMonth()]} ${d.getFullYear()}, ${hms(d)}` : '';
  }
  /** Compact absolute: "20:03:11" today, "27 Oct 20:03" this year, "28 Mar 2025 07:16" otherwise. */
  function shortTs(ts) {
    const d = parseTs(ts);
    if (!d) return '—';
    if (sameDay(d, new Date())) return hms(d);
    return `${fmtDate(d)} ${hm(d)}`;
  }
  function rel(ts, now) {
    const d = parseTs(ts);
    if (!d) return '—';
    let s = Math.round(((now || Date.now()) - d.getTime()) / 1000);
    const future = s < -5;
    s = Math.abs(s);
    if (s < 10) return 'just now';
    let out;
    if (s < 60) out = `${s}s`;
    else if (s < 3600) out = `${Math.floor(s / 60)}m`;
    else if (s < 86400) out = `${Math.floor(s / 3600)}h`;
    else if (s < 86400 * 30) out = `${Math.floor(s / 86400)}d`;
    else return fmtDate(d, true);
    return future ? `in ${out}` : `${out} ago`;
  }
  function dayKey(ts) {
    const d = parseTs(ts);
    return d ? `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}` : 'unknown';
  }
  function dayLabel(ts) {
    const d = parseTs(ts);
    if (!d) return 'Unknown date';
    const today = new Date();
    const yest = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
    const base = `${DOW[d.getDay()]} ${fmtDate(d)}`;
    if (sameDay(d, today)) return `Today · ${base}`;
    if (sameDay(d, yest)) return `Yesterday · ${base}`;
    return base;
  }
  function duration(sec) {
    if (sec === null || sec === undefined || isNaN(sec)) return '—';
    sec = Math.max(0, Math.round(sec));
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${pad2(sec % 60)}s`;
    if (sec < 86400) return `${Math.floor(sec / 3600)}h ${pad2(Math.floor((sec % 3600) / 60))}m`;
    return `${Math.floor(sec / 86400)}d ${Math.floor((sec % 86400) / 3600)}h`;
  }
  const uptime = (sec) => (sec < 60 ? `${Math.max(0, Math.round(sec || 0))}s` : duration(sec).replace(/ 0?0s$/, ''));

  /* ------------------------------------------------------------------ numbers */
  const NF = new Intl.NumberFormat('en-US');
  const fmtInt = (n) => (n === null || n === undefined || isNaN(n) ? '—' : NF.format(Math.round(Number(n))));
  function rateParts(v) {
    if (v === null || v === undefined || isNaN(v)) return { value: '—', unit: '' };
    v = Math.max(0, Number(v));
    const units = RATE_IN_BITS ? ['bps', 'kbps', 'Mbps', 'Gbps'] : ['B/s', 'KB/s', 'MB/s', 'GB/s'];
    const base = RATE_IN_BITS ? 1000 : 1024;
    let i = 0;
    while (v >= base && i < units.length - 1) { v /= base; i++; }
    const value = i === 0 ? String(Math.round(v)) : v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
    return { value, unit: units[i] };
  }
  const fmtRate = (v) => {
    const p = rateParts(v);
    return p.unit ? `${p.value} ${p.unit}` : p.value;
  };
  function fmtMem(mb) {
    if (mb === null || mb === undefined || isNaN(mb)) return '—';
    if (mb >= 1024) return `${(mb / 1024).toFixed(mb >= 10240 ? 0 : 1)} GB`;
    if (mb < 1) return `${Math.round(mb * 1024)} KB`;
    return `${Math.round(mb)} MB`;
  }
  function fmtPct(v) {
    if (v === null || v === undefined || isNaN(v)) return '—';
    v = Number(v);
    return `${v < 10 ? v.toFixed(1) : Math.round(v)}%`;
  }

  /* ------------------------------------------------------------------ strings / net */
  /** Middle ellipsis that keeps the file name: "C:\ProgramData\{8C2E…}\updsvc.exe". */
  function middle(str, max) {
    const s = String(str === null || str === undefined ? '' : str);
    max = max || 52;
    if (s.length <= max) return s;
    const cut = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/'));
    let tail = cut > 0 ? s.slice(cut) : '';
    if (!tail || tail.length > max * 0.7) tail = s.slice(-Math.ceil(max * 0.55));
    const head = Math.max(4, max - tail.length - 1);
    return `${s.slice(0, head)}…${tail}`;
  }
  function ipKind(ip) {
    if (!ip || typeof ip !== 'string') return null;
    if (ip.includes(':')) {
      const v = ip.toLowerCase();
      if (v === '::1') return 'loopback';
      if (v === '::') return 'any';
      if (v.startsWith('fe80')) return 'link-local';
      if (/^f[cd]/.test(v)) return 'lan';
      if (v.startsWith('::ffff:')) return ipKind(v.slice(7));
      return 'public';
    }
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some((n) => isNaN(n) || n < 0 || n > 255)) return null;
    if (p[0] === 0 && p[1] === 0 && p[2] === 0 && p[3] === 0) return 'any';
    if (p[0] === 127) return 'loopback';
    if (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168)) return 'lan';
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return 'tailnet';
    if (p[0] === 169 && p[1] === 254) return 'link-local';
    if (p[0] === 0 || p[0] >= 224) return 'special';
    return 'public';
  }
  const isPublicIp = (ip) => ipKind(ip) === 'public';
  function isValidIp(s) {
    s = String(s || '').trim();
    if (/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s)) return true;
    return s.includes(':') && /^[0-9a-f:.]+$/i.test(s) && s.split(':').length <= 8 && s.length >= 2;
  }
  const NET_TAG = { lan: 'LAN', tailnet: 'Tailnet', loopback: 'Loopback', 'link-local': 'Link-local', special: 'Multicast', any: 'All interfaces' };

  /* ------------------------------------------------------------------ HTML builders */
  const ic = (name, opts) => (PCS.icon ? PCS.icon(name, opts) : '');

  /** Severity / trust values that are safe to use as CSS class suffixes (anything else maps to a fallback). */
  const sevKey = (sev) => (own(SEV_LABEL, sev) ? sev : 'info');
  const trustKey = (t, fallback) => (own(TRUST_LABEL, t) ? t : fallback === undefined ? 'known' : fallback);
  function sevBadge(sev) {
    const s = sevKey(sev);
    return `<span class="badge sev-${s}"><span class="badge-dot" aria-hidden="true"></span>${SEV_LABEL[s]}</span>`;
  }
  function trustBadge(trust) {
    if (trust === null || trust === undefined || trust === '') return '';
    if (!own(TRUST_LABEL, trust)) {
      return `<span class="badge trust-other" title="Trust: ${esc(trust)}">${ic('shield', { size: 12, stroke: 2.2 })}${esc(humanize(trust))}</span>`;
    }
    return `<span class="badge trust-${trust}" title="Trust: ${TRUST_LABEL[trust]}">${ic(TRUST_ICON[trust], { size: 12, stroke: 2.2 })}${TRUST_LABEL[trust]}</span>`;
  }
  function sigText(sig) {
    const s = own(SIG, sig) || (sig ? [humanize(sig), 'muted'] : SIG.Unknown);
    return `<span class="sig tone-${s[1]}">${esc(s[0])}</span>`;
  }
  function flagChips(flags, max) {
    if (!Array.isArray(flags) || !flags.length) return '';
    flags = flags.map((f) => (typeof f === 'string' ? f : JSON.stringify(f)));
    const list = max ? flags.slice(0, max) : flags;
    let html = list.map((f) => {
      const [label, tone] = flagInfo(f);
      return `<span class="chip tone-${tone}" title="${esc(f)}">${esc(label)}</span>`;
    }).join('');
    if (max && flags.length > max) {
      const rest = flags.slice(max).map((f) => flagInfo(f)[0]).join(', ');
      html += `<span class="chip tone-neutral" title="${esc(rest)}">+${flags.length - max}</span>`;
    }
    return `<span class="chips">${html}</span>`;
  }
  function copyBtn(value, display, cls) {
    if (value === null || value === undefined || value === '') return '<span class="muted">—</span>';
    const shown = display === undefined || display === null ? value : display;
    return `<button type="button" class="copy ${cls || ''}" data-copy="${esc(value)}" title="${esc(value)}&#10;Click to copy">${esc(shown)}</button>`;
  }
  function pathHtml(p, max, cls) {
    return p ? copyBtn(p, middle(p, max || 56), `mono path ${cls || ''}`) : '<span class="muted">—</span>';
  }
  function relTime(ts, cls) {
    const d = parseTs(ts);
    if (!d) return '<span class="muted">—</span>';
    return `<time class="rel ${cls || ''}" datetime="${esc(d.toISOString())}" data-ts="${d.getTime()}" title="${esc(abs(d))}">${esc(rel(d))}</time>`;
  }
  function endpoint(ip, port) {
    if (!ip) return '';
    const h = String(ip).includes(':') ? `[${ip}]` : ip;
    return port || port === 0 ? `${h}:${port}` : h;
  }
  function netTag(ip) {
    const t = own(NET_TAG, ipKind(ip));
    return t ? `<span class="chip tone-neutral">${esc(t)}</span>` : '';
  }
  function emptyState(o) {
    const tone = o.tone ? ` tone-${o.tone}` : '';
    return `<div class="empty${tone}${o.compact ? ' is-compact' : ''}">
      <div class="empty-icon">${ic(o.icon || 'info', { size: 22 })}</div>
      <div class="empty-title">${esc(o.title)}</div>
      ${o.body ? `<div class="empty-body">${o.body}</div>` : ''}
    </div>`;
  }
  function skeleton(rows) {
    const row = '<div class="sk-row"><span></span><span></span><span></span><span></span></div>';
    return `<div class="skeleton" aria-busy="true" aria-label="Loading">${row.repeat(rows || 6)}</div>`;
  }
  /** Where extra coverage comes from on each OS (no setup script exists: README › Admin mode on Windows,
      running with administrator/root rights on macOS and Linux). Returns safe HTML. */
  function adminHintText(p) {
    const plat = p === undefined ? platform() : p;
    if (plat === 'windows') return 'Admin mode adds these (see README › Admin mode).';
    if (plat === 'macos' || plat === 'linux') return 'Run PC Sentinel with administrator/root rights for more coverage.';
    return 'Admin mode adds these (see README › Admin mode).';
  }
  /** "<b>Security log, DNS log</b> are off. Admin mode adds these …" for monitors that exist here but are off. */
  function setupHint(what, p) {
    const many = /,| and /.test(what) || /s$/.test(what);
    return `<b>${esc(what)}</b> ${many ? 'are' : 'is'} off. ${esc(adminHintText(p))}`;
  }
  /** Muted "n/a on macOS" pill for monitors that do not exist on this OS. */
  const naPill = (p) => `<span class="pill tone-muted is-na" title="Not available on ${esc(osName(p))}">n/a on ${esc(osName(p))}</span>`;

  /* ------------------------------------------------------------------ misc */
  const store = {
    get(key, fallback) {
      try {
        const v = localStorage.getItem(key);
        return v === null ? fallback : JSON.parse(v);
      } catch (e) { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* ignore */ }
    },
    getRaw(key) {
      try { return localStorage.getItem(key); } catch (e) { return null; }
    },
    setRaw(key, value) {
      try { localStorage.setItem(key, value); } catch (e) { /* ignore */ }
    },
  };

  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* fall through */ }
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch (e) { return false; }
  }

  function debounce(fn, wait) {
    let t = null;
    const d = function (...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), wait);
    };
    d.cancel = () => clearTimeout(t);
    return d;
  }
  const reducedMotion = () => !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

  /** Eased animation driven by rAF, with a timer that forces the final frame if rAF is throttled
      (occluded windows / hidden panes). step(e) gets the eased progress 0..1; returns a cancel function. */
  function tween(dur, step) {
    let raf = 0;
    let done = false;
    const t0 = performance.now();
    const finish = () => {
      if (done) return;
      done = true;
      cancelAnimationFrame(raf);
      clearTimeout(timer);
      step(1);
    };
    const frame = (now) => {
      if (done) return;
      const k = Math.min(1, (now - t0) / dur);
      if (k >= 1) { finish(); return; }
      step(1 - Math.pow(1 - k, 3));
      raf = requestAnimationFrame(frame);
    };
    const timer = setTimeout(finish, dur + 160);
    raf = requestAnimationFrame(frame);
    return () => {
      done = true;
      cancelAnimationFrame(raf);
      clearTimeout(timer);
    };
  }

  /** Free-text filter: every whitespace-separated term must appear somewhere in the haystack. */
  function makeMatcher(q) {
    const terms = String(q || '').toLowerCase().trim().split(/\s+/).filter(Boolean);
    if (!terms.length) return null;
    return (hay) => {
      const h = String(hay || '').toLowerCase();
      return terms.every((t) => h.includes(t));
    };
  }
  function filterRows(rows, q, hayFn) {
    const m = makeMatcher(q);
    return m ? rows.filter((r) => m(hayFn(r))) : rows;
  }
  const hay = (...parts) => parts.flat().filter((p) => p !== null && p !== undefined).join(' ');
  const uniq = (arr) => Array.from(new Set(arr.filter((x) => x !== null && x !== undefined && x !== '')));
  const plural = (n, one, many) => `${fmtInt(n)} ${n === 1 ? one : many || `${one}s`}`;

  PCS.util = {
    RATE_IN_BITS, esc, own, $, $$,
    SEVERITIES, SEV_LABEL, sevRank, sevKey, TRUSTS, TRUST_LABEL, trustRank, trustKey, SIG, FLAGS, flagInfo, humanize,
    CATEGORIES, CAT_LABEL, CAT_ICON, catLabel, catIcon, COVERAGE, coverageOn, PERSIST_KINDS, persistKind, PERSIST_SCOPE,
    PLATFORMS, platform, osName, osLabel, coverageSupported, coverageState, coverageList,
    parseTs, ms, hms, hm, fmtDate, abs, shortTs, rel, dayKey, dayLabel, duration, uptime,
    fmtInt, rateParts, fmtRate, fmtMem, fmtPct,
    middle, ipKind, isPublicIp, isValidIp,
    sevBadge, trustBadge, sigText, flagChips, copyBtn, pathHtml, relTime, endpoint, netTag, emptyState, skeleton,
    adminHintText, setupHint, naPill,
    store, copyText, debounce, reducedMotion, tween, makeMatcher, filterRows, hay, uniq, plural,
  };

  /* ------------------------------------------------------------------ tiny event bus */
  const topics = {};
  PCS.bus = {
    on(topic, fn) {
      (topics[topic] = topics[topic] || new Set()).add(fn);
      return () => topics[topic].delete(fn);
    },
    off(topic, fn) {
      if (topics[topic]) topics[topic].delete(fn);
    },
    emit(topic, data) {
      if (!topics[topic]) return;
      Array.from(topics[topic]).forEach((fn) => {
        try { fn(data); } catch (e) { console.error(`[bus:${topic}]`, e); }
      });
    },
  };
})();
