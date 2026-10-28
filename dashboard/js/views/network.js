/* PC Sentinel view: Network — tabs for live connections, per-app aggregates, 24 h destinations, listening ports, DNS. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;

  const TABS = [
    { id: 'connections', label: 'Connections', icon: 'link', path: '/api/network/connections' },
    { id: 'apps', label: 'Apps', icon: 'grid', path: '/api/network/apps' },
    { id: 'destinations', label: 'Destinations · 24h', icon: 'target', path: '/api/network/destinations?hours=24' },
    { id: 'listening', label: 'Listening ports', icon: 'plug', path: '/api/network/listening' },
    { id: 'dns', label: 'DNS', icon: 'list', path: '/api/dns?limit=300' },
  ];
  const STATE_TONE = { ESTABLISHED: 'ok', SYN_SENT: 'warn', SYN_RECV: 'warn', LISTEN: 'info', TIME_WAIT: 'muted', CLOSE_WAIT: 'muted', FIN_WAIT1: 'muted', FIN_WAIT2: 'muted', NONE: 'muted' };

  const procCell = (name, trust, pid, exe) => `<div class="cell-proc"><span class="mono" ${exe ? `title="${esc(exe)}"` : ''}>${esc(name || '—')}</span>${U.trustBadge(trust)}</div>${pid ? `<div class="cell-sub mono">PID ${esc(pid)}</div>` : ''}`;
  const portsText = (ports) => {
    const p = [].concat(ports === null || ports === undefined ? [] : ports);
    return p.length ? `<span class="mono">${esc(p.slice(0, 6).join(', '))}${p.length > 6 ? ` +${p.length - 6}` : ''}</span>` : '<span class="muted">—</span>';
  };
  const list = (v) => [].concat(v === null || v === undefined ? [] : v);

  const view = {
    id: 'network',
    title: 'Network',
    search: 'Filter rows (process, IP, host, port)…',

    mount(root, tab) {
      this.root = root;
      this.tab = TABS.some((t) => t.id === tab) ? tab : 'connections';
      this.data = {};
      this.errors = {};
      this.opts = Object.assign({ dir: 'all', flaggedOnly: false, hidePrivate: false, exposedOnly: false, blocklistedOnly: false }, this.opts || {});
      root.innerHTML = `
        <div class="tabs" role="tablist" aria-label="Network views">
          ${TABS.map((t) => `<a role="tab" class="tab" href="#/network/${t.id}" data-tab="${t.id}" aria-selected="${t.id === this.tab}">${icon(t.icon, { size: 15 })}${esc(t.label)}<span class="tab-count num" data-count="${t.id}"></span></a>`).join('')}
        </div>
        <div class="toolbar panel" data-r="toolbar"></div>
        <div class="panel table-panel" role="tabpanel"><div class="table-wrap" data-r="table">${U.skeleton(8)}</div></div>
        <div class="table-foot" data-r="foot"></div>`;
      this.onClick = (e) => {
        const o = e.target.closest('[data-opt]');
        if (o) {
          const k = o.dataset.opt;
          if (k === 'dir') this.opts.dir = o.dataset.val;
          else this.opts[k] = !this.opts[k];
          this.renderToolbar();
          this.render();
        }
      };
      root.addEventListener('click', this.onClick);
      this.renderToolbar();
    },
    unmount() {
      this.root.removeEventListener('click', this.onClick);
    },
    onRoute(tab) {
      this.tab = TABS.some((t) => t.id === tab) ? tab : 'connections';
      this.root.querySelectorAll('[data-tab]').forEach((a) => a.setAttribute('aria-selected', String(a.dataset.tab === this.tab)));
      this.renderToolbar();
      this.render();
      this.load();
    },

    async load() {
      const t = TABS.find((x) => x.id === this.tab);
      const tabAtStart = this.tab;
      try {
        this.data[t.id] = await PCS.api.get(t.path);
        this.errors[t.id] = null;
      } catch (e) {
        this.errors[t.id] = e;
      }
      if (tabAtStart === this.tab) this.render();
    },

    renderToolbar() {
      const tb = this.root.querySelector('[data-r=toolbar]');
      const toggle = (key, label, ic) => `<button type="button" class="hud-toggle" data-opt="${key}" aria-pressed="${!!this.opts[key]}">${icon(ic, { size: 14 })}${esc(label)}</button>`;
      let html = '';
      if (this.tab === 'connections') {
        html = `<div class="seg" role="group" aria-label="Direction">
            ${[['all', 'All'], ['out', 'Outbound'], ['in', 'Inbound']].map(([v, l]) => `<button type="button" data-opt="dir" data-val="${v}" aria-pressed="${this.opts.dir === v}">${l}</button>`).join('')}
          </div>${toggle('flaggedOnly', 'Flagged only', 'alert')}${toggle('hidePrivate', 'Hide LAN & loopback', 'server')}`;
      } else if (this.tab === 'apps') {
        html = toggle('flaggedOnly', 'Not trusted / flagged only', 'alert');
      } else if (this.tab === 'destinations') {
        html = `${toggle('blocklistedOnly', 'Blocklisted only', 'ban')}${toggle('hidePrivate', 'Hide private', 'server')}`;
      } else if (this.tab === 'listening') {
        html = toggle('exposedOnly', 'Exposed only', 'plug');
      } else {
        const plat = U.platform();
        html = !U.coverageSupported(null, 'dns_log')
          ? `<span class="muted small">Per-process DNS lookups are n/a on ${esc(U.osName(plat))}.</span>`
          : `<span class="muted small">Per-process DNS lookups${plat === 'windows' || !plat ? ' from the Windows DNS-Client log' : ''}.</span>`;
      }
      tb.innerHTML = `${html}<span class="spacer"></span><span class="hud-sub" data-r="tb-count"></span>`;
    },

    setCount(id, n) {
      const el = this.root.querySelector(`[data-count="${id}"]`);
      if (el) el.textContent = n === null || n === undefined ? '' : U.fmtInt(n);
    },

    render() {
      const el = this.root.querySelector('[data-r=table]');
      const d = this.data[this.tab];
      Object.keys(this.data).forEach((k) => {
        const x = this.data[k];
        this.setCount(k, x && x.items && x.enabled !== false ? x.items.length : null);
      });
      if (!d) {
        el.innerHTML = ui.loading({ error: this.errors[this.tab] });
        return;
      }
      const fn = U.own(view, `render_${this.tab}`);
      const out = fn.call(this, d);
      el.innerHTML = out.html;
      this.root.querySelector('[data-r=tb-count]').textContent = out.count || '';
      this.root.querySelector('[data-r=foot]').innerHTML = out.foot || '';
    },

    /* ---------------- connections */
    render_connections(d) {
      const all = d.items || [];
      const o = this.opts;
      let rows = all.filter((c) => (o.dir === 'all' || c.direction === o.dir)
        && (!o.flaggedOnly || (c.flags && c.flags.length) || ['unsigned', 'suspicious', 'malicious'].includes(c.trust))
        && (!o.hidePrivate || U.isPublicIp(c.raddr)));
      rows = U.filterRows(rows, PCS.state.search, (c) => U.hay(c.process, c.exe, c.pid, c.raddr, c.rport, c.rhost, c.laddr, c.lport, c.status, c.proto, c.trust, c.flags));
      const key = (c) => `${c.pid}|${c.proto}|${c.laddr}:${c.lport}|${c.raddr}:${c.rport}`;
      const html = ui.table('net-conns', {
        rows, allKeys: all.map(key), key,
        defaultSort: { col: 'risk', dir: 'asc' },
        rowClass: (c) => `trust-row-${U.trustKey(c.trust)}${list(c.flags).includes('blocklisted_ip') ? ' is-danger' : ''}`,
        empty: U.emptyState({ icon: 'link', title: 'No connections match', body: 'Change the filters or the search text.', compact: true }),
        columns: [
          { id: 'risk', label: 'Process', sort: (c) => `${U.trustRank(c.trust)}${list(c.flags).length ? 0 : 1}${String(c.process || '').toLowerCase()}`, render: (c) => procCell(c.process, c.trust, c.pid, c.exe) },
          { id: 'remote', label: 'Remote', sort: (c) => c.rhost || c.raddr, cls: 'col-main', render: (c) => `<div class="cell-title mono">${esc(c.rhost || U.endpoint(c.raddr, c.rport))}</div>${c.rhost ? `<div class="cell-sub mono">${esc(U.endpoint(c.raddr, c.rport))}</div>` : ''}${U.netTag(c.raddr)}` },
          { id: 'local', label: 'Local', sort: (c) => c.lport, cls: 'hide-lg', render: (c) => `<span class="mono muted">${esc(U.endpoint(c.laddr, c.lport))}</span><div class="cell-sub">${esc(c.proto || '')}</div>` },
          { id: 'state', label: 'State', sort: (c) => c.status, cls: 'hide-sm', render: (c) => `<span class="state tone-${U.own(STATE_TONE, c.status) || 'muted'}">${esc(c.status && c.status !== 'NONE' ? c.status : '—')}</span>` },
          { id: 'dir', label: 'Dir', sort: (c) => c.direction, render: (c) => `<span class="dir dir-${c.direction === 'in' ? 'in' : 'out'}" title="${c.direction === 'in' ? 'Inbound: the remote side connected to us' : 'Outbound'}">${icon(c.direction === 'in' ? 'arrowIn' : 'arrowOut', { size: 14 })}${c.direction === 'in' ? 'In' : 'Out'}</span>` },
          { id: 'seen', label: 'Since', sort: (c) => U.ms(c.first_seen), cls: 'hide-md', render: (c) => U.relTime(c.first_seen) },
          { id: 'flags', label: 'Flags', render: (c) => U.flagChips(c.flags, 2) || '<span class="muted">—</span>' },
          { id: 'act', sr: 'Actions', render: (c) => ui.rowActions({ ip: c.raddr, pid: c.pid, name: c.process, exe: c.exe, allow: c.exe ? { kind: 'process', value: c.exe, label: c.process } : null }) },
        ],
      });
      const apps = new Set(all.map((c) => c.exe || c.process)).size;
      return { html, count: `${U.plural(rows.length, 'connection')} · ${U.plural(apps, 'app')}`, foot: '<span class="muted">Live sockets, refreshed every 5 s. Inbound = a remote peer connected to one of your listening ports.</span>' };
    },

    /* ---------------- apps */
    render_apps(d) {
      const all = d.items || [];
      let rows = all.filter((a) => !this.opts.flaggedOnly || a.trust !== 'trusted' || (a.flags && a.flags.length));
      rows = U.filterRows(rows, PCS.state.search, (a) => U.hay(a.process, a.exe, a.signer, a.trust, a.flags, a.ports));
      const max = Math.max(1, ...all.map((a) => a.conns || 0));
      const html = ui.table('net-apps', {
        rows, allKeys: all.map((a) => a.exe || a.process), key: (a) => a.exe || a.process,
        defaultSort: { col: 'conns', dir: 'desc' },
        rowClass: (a) => `trust-row-${U.trustKey(a.trust)}`,
        columns: [
          { id: 'app', label: 'App', sort: (a) => a.process, cls: 'col-main', render: (a) => `${procCell(a.process, a.trust)}<div class="cell-sub">${U.pathHtml(a.exe, 60)}</div>` },
          { id: 'signer', label: 'Signer', sort: (a) => a.signer, cls: 'hide-md', render: (a) => (a.signer ? esc(a.signer) : '<span class="tone-warn">Unsigned</span>') },
          { id: 'conns', label: 'Conns', sort: (a) => a.conns, render: (a) => `<div class="bar-cell"><span class="num">${U.fmtInt(a.conns)}</span><span class="mini-bar"><i style="width:${Math.max(4, Math.round(((Number(a.conns) || 0) / max) * 100))}%"></i></span></div>` },
          { id: 'hosts', label: 'Hosts', sort: (a) => a.remote_hosts, cls: 'num-col', render: (a) => `<span class="num">${U.fmtInt(a.remote_hosts)}</span>` },
          { id: 'ports', label: 'Ports', sort: (a) => (a.ports || []).length, cls: 'hide-lg', render: (a) => portsText(a.ports) },
          { id: 'first', label: 'First seen', sort: (a) => U.ms(a.first_seen), cls: 'hide-md', render: (a) => U.relTime(a.first_seen) },
          { id: 'flags', label: 'Flags', render: (a) => U.flagChips(a.flags, 2) || '<span class="muted">—</span>' },
          { id: 'act', sr: 'Actions', render: (a) => ui.rowActions({ allow: a.exe ? { kind: 'process', value: a.exe, label: a.process } : null }) },
        ],
      });
      return { html, count: U.plural(rows.length, 'app'), foot: '<span class="muted">One row per executable with live connections.</span>' };
    },

    /* ---------------- destinations */
    render_destinations(d) {
      const all = d.items || [];
      let rows = all.filter((x) => (!this.opts.blocklistedOnly || x.blocklisted) && (!this.opts.hidePrivate || !x.private));
      rows = U.filterRows(rows, PCS.state.search, (x) => U.hay(x.ip, x.host, x.ports, x.apps, x.blocklisted ? 'blocklisted' : '', x.private ? 'private lan' : ''));
      const max = Math.max(1, ...all.map((x) => x.hits || 0));
      const html = ui.table('net-dest', {
        rows, allKeys: all.map((x) => x.ip), key: (x) => x.ip,
        defaultSort: { col: 'hits', dir: 'desc' },
        pin: (x) => !!x.blocklisted,
        rowClass: (x) => (x.blocklisted ? 'is-danger sev-row sev-critical' : x.private ? 'is-dim' : ''),
        columns: [
          { id: 'ip', label: 'Address', sort: (x) => `${x.blocklisted ? 0 : 1}${x.ip}`, render: (x) => `<div class="cell-title mono">${U.copyBtn(x.ip, x.ip, 'mono')}</div>${x.blocklisted ? '<span class="chip tone-danger">Blocklisted</span>' : U.netTag(x.ip)}` },
          { id: 'host', label: 'Host', sort: (x) => x.host, cls: 'col-main', render: (x) => (x.host ? `<span class="mono">${esc(x.host)}</span>` : '<span class="muted">No hostname</span>') },
          { id: 'ports', label: 'Ports', sort: (x) => (x.ports || [])[0], render: (x) => portsText(x.ports) },
          { id: 'apps', label: 'Apps', sort: (x) => list(x.apps).join(','), render: (x) => `<span class="mono">${esc(list(x.apps).slice(0, 3).join(', '))}${list(x.apps).length > 3 ? ` +${list(x.apps).length - 3}` : ''}</span>` },
          { id: 'hits', label: 'Hits', sort: (x) => x.hits, render: (x) => `<div class="bar-cell"><span class="num">${U.fmtInt(x.hits)}</span><span class="mini-bar"><i style="width:${Math.max(4, Math.round(((Number(x.hits) || 0) / max) * 100))}%"></i></span></div>` },
          { id: 'first', label: 'First seen', sort: (x) => U.ms(x.first_seen), cls: 'hide-lg', render: (x) => U.relTime(x.first_seen) },
          { id: 'last', label: 'Last seen', sort: (x) => U.ms(x.last_seen), cls: 'hide-md', render: (x) => U.relTime(x.last_seen) },
          { id: 'act', sr: 'Actions', render: (x) => ui.rowActions({ ip: x.blocklisted ? null : x.ip, allow: { kind: 'destination', value: x.ip, label: x.host || x.ip } }) },
        ],
      });
      const bl = all.filter((x) => x.blocklisted).length;
      return { html, count: `${U.plural(rows.length, 'address', 'addresses')}${bl ? ` · ${U.fmtInt(bl)} blocklisted` : ''}`, foot: '<span class="muted">Every remote address contacted in the last 24 hours. Blocklisted rows are pinned in red.</span>' };
    },

    /* ---------------- listening */
    render_listening(d) {
      const all = d.items || [];
      let rows = all.filter((l) => !this.opts.exposedOnly || l.exposed);
      rows = U.filterRows(rows, PCS.state.search, (l) => U.hay(l.process, l.exe, l.pid, l.laddr, l.lport, l.proto, l.trust, l.exposed ? 'exposed' : 'local'));
      const key = (l) => `${l.proto}|${l.laddr}|${l.lport}|${l.pid}`;
      const html = ui.table('net-listen', {
        rows, allKeys: all.map(key), key,
        defaultSort: { col: 'exposure', dir: 'asc' },
        rowClass: (l) => (l.exposed && l.trust !== 'trusted' ? 'is-warn' : l.exposed ? '' : 'is-dim'),
        columns: [
          { id: 'port', label: 'Port', sort: (l) => l.lport, render: (l) => `<span class="port mono">${esc(l.lport)}</span> <span class="proto-tag">${esc(l.proto)}</span>` },
          { id: 'addr', label: 'Bound to', sort: (l) => l.laddr, render: (l) => `<span class="mono">${esc(U.endpoint(l.laddr, l.lport))}</span>` },
          { id: 'exposure', label: 'Exposure', sort: (l) => `${l.exposed ? 0 : 1}${U.trustRank(l.trust)}${String(l.lport).padStart(5, '0')}`, render: (l) => (l.exposed ? `<span class="chip tone-${l.trust === 'trusted' ? 'warn' : 'danger'}">${icon('alert', { size: 12 })}Exposed</span>` : `<span class="chip tone-neutral">${U.ipKind(l.laddr) === 'loopback' ? 'Loopback only' : 'One interface'}</span>`) },
          { id: 'proc', label: 'Process', sort: (l) => l.process, cls: 'col-main', render: (l) => procCell(l.process, l.trust, l.pid, l.exe) },
          { id: 'first', label: 'Since', sort: (l) => U.ms(l.first_seen), cls: 'hide-md', render: (l) => U.relTime(l.first_seen) },
          { id: 'act', sr: 'Actions', render: (l) => ui.rowActions({ pid: l.pid, name: l.process, exe: l.exe, allow: l.exe ? { kind: 'process', value: l.exe, label: l.process } : null }) },
        ],
      });
      const exposed = new Set(all.filter((l) => l.exposed).map((l) => `${l.lport}/${l.proto}`)).size;
      return { html, count: `${U.plural(rows.length, 'socket')} · ${exposed} exposed`, foot: '<span class="muted">Exposed = bound to all interfaces, so other machines on your networks can reach it.</span>' };
    },

    /* ---------------- dns */
    render_dns(d) {
      const plat = U.platform();
      if (!U.coverageSupported(null, 'dns_log')) {
        return {
          html: U.emptyState({
            icon: 'list', title: `Per-app DNS log: n/a on ${U.osName(plat)}`,
            body: `<p class="muted">${esc(U.osName(plat))} has no system log that records which program looked up which name, so this tab stays empty here. Connections and their reverse-DNS names are still listed under Connections and Destinations.</p>`,
          }),
          count: '',
          foot: '',
        };
      }
      if (d.enabled === false) {
        return {
          html: U.emptyState({
            icon: 'list', title: 'DNS logging is off',
            body: `<p>Windows can record every DNS lookup and which process made it (the <span class="mono">Microsoft-Windows-DNS-Client/Operational</span> log). It is disabled by default.</p>
              <p>${U.setupHint('Per-app DNS', plat || 'windows')}</p>`,
          }),
          count: '',
          foot: '',
        };
      }
      const all = d.items || [];
      const rows = U.filterRows(all, PCS.state.search, (x) => U.hay(x.process, x.pid, x.query, x.type, x.result));
      const key = (x) => `${x.ts}|${x.pid}|${x.query}|${x.type}`;
      const html = ui.table('net-dns', {
        rows, allKeys: all.map(key), key,
        defaultSort: { col: 'ts', dir: 'desc' },
        empty: U.emptyState({ icon: 'list', title: 'No lookups recorded yet', compact: true }),
        columns: [
          { id: 'ts', label: 'Time', sort: (x) => U.ms(x.ts), render: (x) => `<span class="mono" title="${esc(U.abs(x.ts))}">${esc(U.shortTs(x.ts))}</span>` },
          { id: 'proc', label: 'Process', sort: (x) => x.process, render: (x) => `<span class="mono">${esc(x.process || '—')}</span><div class="cell-sub mono">PID ${esc(x.pid)}</div>` },
          { id: 'query', label: 'Query', sort: (x) => x.query, cls: 'col-main', render: (x) => `<span class="mono">${esc(x.query)}</span>` },
          { id: 'type', label: 'Type', sort: (x) => x.type, render: (x) => `<span class="chip tone-neutral">${esc(x.type || '—')}</span>` },
          { id: 'result', label: 'Answer', sort: (x) => x.result, render: (x) => `<span class="mono">${esc(x.result || '—')}</span>` },
        ],
      });
      return { html, count: U.plural(rows.length, 'lookup'), foot: '' };
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.network = view;
})();
