/* PC Sentinel view: Alerts — filterable table + the shared alert detail drawer (PCS.openAlert). */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;
  const STATUS_LABEL = { open: 'Open', acknowledged: 'Acknowledged', allowed: 'Allowed' };

  /* ================================================================== alert drawer (used everywhere) */
  function valueHtml(k, v) {
    if (v === null || v === undefined || v === '') return '';
    if (typeof v === 'boolean') return v ? 'Yes' : 'No';
    if (typeof v === 'number') return `<span class="num mono">${esc(v)}</span>`;
    if (Array.isArray(v)) return v.every((x) => typeof x !== 'object') ? `<span class="mono">${esc(v.join(', '))}</span>` : `<pre class="code-block">${esc(JSON.stringify(v, null, 2))}</pre>`;
    if (typeof v === 'object') return `<pre class="code-block">${esc(JSON.stringify(v, null, 2))}</pre>`;
    const s = String(v);
    if (/^[a-z]:\\|^\\\\|^hk(lm|cu)\\|^%|^"|^~?\//i.test(s) || s.length > 48) return U.copyBtn(s, s, 'mono path wrap');
    if (U.isValidIp(s)) return U.copyBtn(s, s, 'mono');
    if (/^\d{4}-\d\d-\d\dT/.test(s)) return `<span title="${esc(U.abs(s))}">${esc(U.shortTs(s))}</span>`;
    return `<span class="${/^[\w.:-]+$/.test(s) ? 'mono' : ''}">${esc(s)}</span>`;
  }
  const DETAIL_LABEL = { rule: 'Rule', state: 'Socket state', event_id: 'Event ID', cmdline: 'Command line', blocklist_note: 'Blocklist note' };

  function allowChoices(a) {
    const p = a.process || {};
    const d = a.details || {};
    const out = [];
    if (a.category === 'privacy' && p.exe) out.push({ kind: 'privacy', value: p.exe });
    if (a.category === 'persistence' && (p.exe || d.exe)) out.push({ kind: 'persistence', value: p.exe || d.exe });
    if (p.exe) out.push({ kind: 'process', value: p.exe });
    if (a.remote && a.remote.ip) out.push({ kind: 'destination', value: a.remote.ip });
    return out;
  }

  function drawerHtml(a) {
    const p = a.process || null;
    const r = a.remote || null;
    const d = a.details || {};
    const flags = U.uniq([].concat(a.flags || [], Array.isArray(d.flags) ? d.flags : []));
    const status = a.status || 'open';
    const canKill = p && Number(p.pid) > 4;
    const canBlock = r && U.isPublicIp(r.ip);
    const allow = allowChoices(a);

    const procSec = p ? ui.section('Process', `
      <div class="proc-head"><b class="mono">${esc(p.name || '—')}</b>${U.trustBadge(p.trust)}${p.pid ? `<span class="muted mono">PID ${esc(p.pid)}</span>` : '<span class="muted">not running</span>'}</div>
      ${ui.kv([
        ['Path', p.exe ? U.copyBtn(p.exe, p.exe, 'mono path wrap') : ''],
        ['Signer', esc(p.signer || '')],
        ['Signature', U.sigText(p.sig_status)],
      ])}`, 'cpu') : '';
    const remoteSec = r ? ui.section('Remote', ui.kv([
      ['Address', U.copyBtn(U.endpoint(r.ip, r.port), U.endpoint(r.ip, r.port), 'mono')],
      ['Host', r.host ? `<span class="mono">${esc(r.host)}</span>` : '<span class="muted">No reverse hostname</span>'],
      ['Network', `${esc({ public: 'Internet', lan: 'Local network', tailnet: 'Tailscale', loopback: 'Loopback' }[U.ipKind(r.ip)] || '—')}`],
    ]), 'globe') : '';
    const detailRows = Object.keys(d).filter((k) => k !== 'flags').map((k) => [U.own(DETAIL_LABEL, k) || U.humanize(k), valueHtml(k, d[k])]);
    const detailSec = detailRows.length ? ui.section('Details', ui.kv(detailRows), 'list') : '';
    const flagSec = flags.length ? ui.section('Flags', U.flagChips(flags), 'flag') : '';

    return ui.drawerFrame({
      eyebrow: `${U.sevBadge(a.severity)}<span class="cat-tag">${icon(U.catIcon(a.category), { size: 13 })}${esc(U.catLabel(a.category))}</span><span class="pill status-${esc(status)}">${esc(U.own(STATUS_LABEL, status) || status)}</span>`,
      title: esc(a.title),
      sub: esc(a.summary || ''),
      meta: `<span>${a.count > 1 ? `Seen <b class="num">${U.fmtInt(a.count)}</b> times` : 'Seen once'}</span>
        <span>First ${U.relTime(a.first_ts || a.ts)}</span><span>Last ${U.relTime(a.last_ts || a.ts)}</span><span class="mono muted">#${esc(a.id)}</span>`,
      body: procSec + remoteSec + flagSec + detailSec,
      foot: [
        ui.dbtn('ack', status === 'open' ? 'Acknowledge' : 'Acknowledged', 'check', { cls: 'btn-primary', disabled: status !== 'open', why: 'Already handled' }),
        ui.dbtn('kill', 'Kill process', 'kill', { cls: 'btn-danger-soft', disabled: !canKill, why: p ? 'The process is not running' : 'No process involved' }),
        ui.dbtn('block', 'Block IP', 'ban', { cls: 'btn-danger-soft', disabled: !canBlock, why: r ? 'Local and private addresses can’t be blocked here' : 'No remote address' }),
        ui.dbtn('allow', 'Allow…', 'allow', { disabled: !allow.length, why: 'Nothing to allow' }),
        ui.dbtn('copy', 'Copy as JSON', 'braces', { cls: 'btn-ghost' }),
      ].join(''),
    });
  }

  function current(id) {
    return PCS.state.alerts.get(String(id)) || null;
  }

  PCS.openAlert = function (alertOrId) {
    const a = typeof alertOrId === 'object' ? alertOrId : current(alertOrId);
    if (!a) return;
    PCS.app.markSeen(a.id);
    ui.drawer.open(drawerHtml(a), {
      key: `alert:${a.id}`,
      onAction: async (act) => {
        const x = current(a.id) || a;
        if (act === 'ack') await PCS.actions.ack(x.id);
        else if (act === 'kill') PCS.actions.kill(x.process);
        else if (act === 'block') PCS.actions.blockIp(x.remote && x.remote.ip);
        else if (act === 'allow') PCS.actions.allow({ choices: allowChoices(x) });
        else if (act === 'copy') {
          const ok = await U.copyText(JSON.stringify(x, null, 2));
          ui.toast({ kind: ok ? 'success' : 'error', title: ok ? 'Alert copied as JSON' : 'Copy failed' });
        }
      },
    });
  };
  PCS.openAlert.refresh = function (id) {
    if (!ui.drawer.isOpen(`alert:${id}`)) return;
    const a = current(id);
    if (a) ui.drawer.update(drawerHtml(a));
  };

  /* ================================================================== view */
  const view = {
    id: 'alerts',
    title: 'Alerts',
    search: 'Filter alerts on screen…',

    mount(root) {
      this.root = root;
      this.items = null;
      this.f = Object.assign({ status: 'open', sev: [], category: '', q: '' }, this.f || {});
      root.innerHTML = `
        <div class="toolbar panel">
          <div class="seg" role="group" aria-label="Status">
            <button type="button" data-status="open" aria-pressed="${this.f.status === 'open'}">Open</button>
            <button type="button" data-status="all" aria-pressed="${this.f.status === 'all'}">All</button>
          </div>
          <div class="sev-chips" role="group" aria-label="Severity" data-r="sev"></div>
          <label class="select-wrap"><span class="sr-only">Category</span>
            <select class="input input-sm" data-f="category">
              <option value="">All categories</option>
              ${U.CATEGORIES.map((c) => `<option value="${c}" ${this.f.category === c ? 'selected' : ''}>${U.CAT_LABEL[c]}</option>`).join('')}
            </select>
          </label>
          <label class="input-icon"><span class="sr-only">Search alerts on the engine</span>${icon('search', { size: 15 })}
            <input class="input input-sm" type="search" data-f="q" placeholder="Search title, process, IP…" value="${esc(this.f.q)}" autocomplete="off" spellcheck="false"></label>
          <span class="spacer"></span>
          <button type="button" class="btn btn-sm" data-act-local="ack-low">${icon('checkCheck', { size: 15 })}<span data-r="ack-low-label">Acknowledge all low</span></button>
        </div>
        <div class="panel table-panel"><div class="table-wrap" data-r="table">${U.skeleton(8)}</div></div>
        <div class="table-foot" data-r="foot"></div>`;
      this.onClick = (e) => {
        const s = e.target.closest('[data-status]');
        if (s) {
          this.f.status = s.dataset.status;
          root.querySelectorAll('[data-status]').forEach((b) => b.setAttribute('aria-pressed', String(b === s)));
          ui.resetTrack('alerts');
          this.load();
          return;
        }
        const c = e.target.closest('[data-sev]');
        if (c) {
          const sev = c.dataset.sev;
          this.f.sev = this.f.sev.includes(sev) ? this.f.sev.filter((x) => x !== sev) : this.f.sev.concat(sev);
          ui.resetTrack('alerts');
          this.load();
          return;
        }
        if (e.target.closest('[data-act-local="ack-low"]')) {
          const n = (this.items || []).filter((a) => a.severity === 'low' && a.status === 'open').length;
          PCS.actions.ackAll('low', n || this.lowOpenTotal() || 0);
        }
      };
      this.onChange = (e) => {
        if (e.target.matches('[data-f=category]')) {
          this.f.category = e.target.value;
          ui.resetTrack('alerts');
          this.load();
        }
      };
      this.onInput = U.debounce((e) => {
        if (e.target.matches('[data-f=q]')) {
          this.f.q = e.target.value.trim();
          ui.resetTrack('alerts');
          this.load();
        }
      }, 300);
      root.addEventListener('click', this.onClick);
      root.addEventListener('change', this.onChange);
      root.addEventListener('input', this.onInput);
      this.renderChips();
    },
    unmount() {
      this.root.removeEventListener('click', this.onClick);
      this.root.removeEventListener('change', this.onChange);
      this.root.removeEventListener('input', this.onInput);
    },

    async load() {
      const p = new URLSearchParams({ status: this.f.status, limit: '500' });
      if (this.f.sev.length) p.set('severity', this.f.sev.join(','));
      if (this.f.category) p.set('category', this.f.category);
      if (this.f.q) p.set('q', this.f.q);
      try {
        const r = await PCS.api.get(`/api/alerts?${p.toString()}`);
        this.items = r.items || [];
        this.error = null;
        PCS.app.mergeAlerts(this.items, this.f.status === 'open' && !this.f.sev.length && !this.f.category && !this.f.q);
      } catch (e) {
        this.error = e;
      }
      this.render();
    },

    lowOpenTotal() {
      const s = PCS.state.summary;
      const n = s && s.kpis && s.kpis.alerts_open ? Number(s.kpis.alerts_open.low) : 0;
      return n > 0 ? Math.round(n) : 0;
    },

    renderChips() {
      const counts = (PCS.state.summary && PCS.state.summary.kpis && PCS.state.summary.kpis.alerts_open) || {};
      this.root.querySelector('[data-r=sev]').innerHTML = ['critical', 'high', 'medium', 'low', 'info'].map((s) => `
        <button type="button" class="sev-chip sev-${s}" data-sev="${s}" aria-pressed="${this.f.sev.includes(s)}">
          <i class="sev-dot sev-${s}"></i>${U.SEV_LABEL[s]}${U.own(counts, s) !== undefined ? `<b class="num">${esc(U.fmtInt(counts[s]))}</b>` : ''}</button>`).join('');
    },

    render() {
      this.renderChips();
      const el = this.root.querySelector('[data-r=table]');
      if (!this.items) {
        el.innerHTML = ui.loading(this);
        return;
      }
      const all = this.items;
      const rows = U.filterRows(all, PCS.state.search, (a) => U.hay(a.title, a.summary, a.category, a.severity, a.status,
        a.process && [a.process.name, a.process.exe, a.process.signer], a.remote && [a.remote.ip, a.remote.host, a.remote.port]));
      const lowOpen = all.filter((a) => a.severity === 'low' && a.status === 'open').length;
      const btn = this.root.querySelector('[data-act-local="ack-low"]');
      const lowTotal = this.lowOpenTotal() || lowOpen;
      btn.disabled = !lowTotal;
      this.root.querySelector('[data-r=ack-low-label]').textContent = `Acknowledge all low${lowTotal ? ` (${lowTotal})` : ''}`;

      el.innerHTML = ui.table('alerts', {
        rows,
        allKeys: all.map((a) => `${a.id}:${a.count}`),
        key: (a) => `${a.id}:${a.count}`,
        defaultSort: { col: 'severity', dir: 'asc' },
        rowClass: (a) => `clickable sev-row sev-${U.sevKey(a.severity)}${a.status !== 'open' ? ' is-muted' : ''}${PCS.state.seen.has(String(a.id)) ? '' : ' is-unread'}`,
        rowAttrs: (a) => `data-alert-id="${esc(a.id)}" tabindex="0" aria-label="${esc(`${U.SEV_LABEL[U.sevKey(a.severity)]} alert: ${a.title}`)}"`,
        empty: U.emptyState({ icon: 'shieldCheck', tone: 'ok', title: this.f.status === 'open' ? 'No open alerts match' : 'No alerts match', body: 'Try another severity, category or search.' }),
        columns: [
          { id: 'severity', label: 'Severity', sort: (a) => U.sevRank(a.severity) * 1e13 - U.ms(a.last_ts || a.ts), render: (a) => U.sevBadge(a.severity), cls: 'col-sev' },
          { id: 'title', label: 'Alert', sort: (a) => a.title, cls: 'col-main', render: (a) => `<div class="cell-title">${esc(a.title)}</div><div class="cell-sub">${esc(a.summary || '')}</div>` },
          { id: 'category', label: 'Category', sort: (a) => a.category, cls: 'hide-md', render: (a) => `<span class="cat-tag">${icon(U.catIcon(a.category), { size: 13 })}${esc(U.catLabel(a.category))}</span>` },
          { id: 'process', label: 'Process', sort: (a) => (a.process ? a.process.name : null), render: (a) => (a.process ? `<div class="cell-proc"><span class="mono">${esc(a.process.name)}</span>${U.trustBadge(a.process.trust)}</div>` : '<span class="muted">—</span>') },
          { id: 'remote', label: 'Remote', sort: (a) => (a.remote ? a.remote.ip : null), cls: 'hide-lg', render: (a) => (a.remote ? `<span class="mono">${esc(U.endpoint(a.remote.ip, a.remote.port))}</span>${a.remote.host ? `<div class="cell-sub mono">${esc(a.remote.host)}</div>` : ''}` : '<span class="muted">—</span>') },
          { id: 'count', label: 'Seen', sort: (a) => a.count || 1, cls: 'num-col hide-sm', render: (a) => (a.count > 1 ? `<span class="count-badge">×${U.fmtInt(a.count)}</span>` : '<span class="muted">1</span>') },
          { id: 'last', label: 'Last seen', sort: (a) => U.ms(a.last_ts || a.ts), render: (a) => U.relTime(a.last_ts || a.ts) },
          { id: 'status', label: 'Status', sort: (a) => a.status, cls: 'hide-sm', render: (a) => `<span class="pill status-${esc(a.status)}">${esc(U.own(STATUS_LABEL, a.status) || a.status)}</span>` },
          { id: 'act', sr: 'Actions', render: (a) => (a.status === 'open' ? `<div class="row-actions"><button type="button" class="icon-btn sm act act-ok" data-act="ack" data-id="${esc(a.id)}" aria-label="Acknowledge alert" title="Acknowledge">${icon('check', { size: 15 })}</button></div>` : '') },
        ],
      });
      const shown = rows.length;
      this.root.querySelector('[data-r=foot]').innerHTML = `<span>${U.plural(shown, 'alert')}${shown !== all.length ? ` of ${U.fmtInt(all.length)}` : ''}</span>
        <span class="muted">Click a row for details · relative times show the exact time on hover</span>`;
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.alerts = view;
})();
