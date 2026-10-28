/* PC Sentinel view: Processes — all / flagged / unsigned, sortable, command lines expandable. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;

  const view = {
    id: 'processes',
    title: 'Processes',
    search: 'Filter by name, PID, path, signer, command line…',

    mount(root) {
      this.root = root;
      this.items = null;
      this.filter = this.filter || 'all';
      this.expanded = this.expanded || new Set();
      root.innerHTML = `
        <div class="toolbar panel">
          <div class="seg" role="group" aria-label="Which processes">
            ${[['all', 'All'], ['flagged', 'Flagged'], ['unsigned', 'Unsigned']].map(([v, l]) => `<button type="button" data-filter="${v}" aria-pressed="${this.filter === v}">${l}</button>`).join('')}
          </div>
          <div class="stat-strip" data-r="strip"></div>
          <span class="spacer"></span>
          <button type="button" class="btn btn-sm btn-ghost" data-r="collapse">${icon('collapse', { size: 15 })}Collapse command lines</button>
        </div>
        <div class="panel table-panel"><div class="table-wrap" data-r="table">${U.skeleton(10)}</div></div>
        <div class="table-foot" data-r="foot"></div>`;
      this.onClick = (e) => {
        const f = e.target.closest('[data-filter]');
        if (f) {
          this.filter = f.dataset.filter;
          root.querySelectorAll('[data-filter]').forEach((b) => b.setAttribute('aria-pressed', String(b === f)));
          ui.resetTrack('procs');
          this.items = null;
          this.render();
          this.load();
          return;
        }
        const x = e.target.closest('[data-expand]');
        if (x) {
          const pid = x.dataset.expand;
          if (this.expanded.has(pid)) this.expanded.delete(pid);
          else this.expanded.add(pid);
          this.render();
          return;
        }
        if (e.target.closest('[data-r=collapse]')) {
          this.expanded.clear();
          this.render();
        }
      };
      root.addEventListener('click', this.onClick);
    },
    unmount() {
      this.root.removeEventListener('click', this.onClick);
    },

    async load() {
      try {
        const r = await PCS.api.get(`/api/processes?filter=${encodeURIComponent(this.filter)}`);
        this.items = r.items || [];
        this.error = null;
      } catch (e) {
        this.error = e;
      }
      this.render();
    },

    render() {
      const el = this.root.querySelector('[data-r=table]');
      if (!this.items) {
        el.innerHTML = ui.loading(this);
        return;
      }
      const all = this.items;
      const rows = U.filterRows(all, PCS.state.search, (p) => U.hay(p.name, p.pid, p.ppid, p.parent, p.exe, p.cmdline, p.user, p.signer, p.trust, p.flags));
      const cpu = all.reduce((a, p) => a + (Number(p.cpu) || 0), 0);
      const mem = all.reduce((a, p) => a + (Number(p.mem_mb) || 0), 0);
      const flagged = all.filter((p) => (p.flags && p.flags.length) || ['suspicious', 'malicious'].includes(p.trust)).length;
      const unsigned = all.filter((p) => ['unsigned', 'suspicious', 'malicious'].includes(p.trust)).length;
      this.root.querySelector('[data-r=strip]').innerHTML = `
        <span><b class="num">${U.fmtInt(all.length)}</b> shown</span>
        <span><b class="num">${U.fmtInt(flagged)}</b> flagged</span>
        <span><b class="num">${U.fmtInt(unsigned)}</b> unsigned</span>
        <span>CPU <b class="num">${U.fmtPct(cpu)}</b></span>
        <span>RAM <b class="num">${U.fmtMem(mem)}</b></span>`;
      this.root.querySelector('[data-r=collapse]').hidden = !this.expanded.size;

      el.innerHTML = ui.table('procs', {
        rows,
        allKeys: all.map((p) => String(p.pid)),
        key: (p) => String(p.pid),
        defaultSort: { col: 'trust', dir: 'asc' },
        rowClass: (p) => `trust-row-${U.trustKey(p.trust)}${this.expanded.has(String(p.pid)) ? ' is-expanded' : ''}`,
        empty: U.emptyState({ icon: 'cpu', title: this.filter === 'all' ? 'No processes match' : `No ${this.filter} processes`, body: this.filter === 'flagged' ? 'Nothing running looks unusual right now.' : '', tone: this.filter === 'all' ? '' : 'ok', compact: true }),
        columns: [
          {
            id: 'name', label: 'Process', sort: (p) => String(p.name || '').toLowerCase(), cls: 'col-main',
            render: (p) => {
              const open = this.expanded.has(String(p.pid));
              const cmd = p.cmdline === null || p.cmdline === undefined ? '' : String(p.cmdline);
              return `<div class="cell-proc"><b class="mono">${esc(p.name)}</b>${U.trustBadge(p.trust)}${U.flagChips(p.flags, 3)}</div>
                <div class="cell-sub">${U.pathHtml(p.exe, 70)}</div>
                ${cmd ? `<div class="cmdline ${open ? 'is-open' : ''}">
                  <button type="button" class="cmd-toggle" data-expand="${esc(p.pid)}" aria-expanded="${open}" aria-label="${open ? 'Collapse' : 'Expand'} command line">${icon(open ? 'chevronDown' : 'chevronRight', { size: 13 })}</button>
                  <code class="mono">${esc(cmd)}</code>
                  ${open ? U.copyBtn(cmd, 'Copy', 'btn btn-xs btn-ghost') : ''}
                </div>` : ''}`;
            },
          },
          { id: 'pid', label: 'PID', sort: (p) => Number(p.pid), cls: 'num-col', render: (p) => `<span class="mono">${esc(p.pid)}</span>${p.parent ? `<div class="cell-sub mono" title="Parent PID ${esc(p.ppid)}">↳ ${esc(p.parent)}</div>` : ''}` },
          { id: 'trust', label: 'Signer / trust', sort: (p) => `${U.trustRank(p.trust)}${String(1000 - Math.min(999, Math.round((Number(p.cpu) || 0) * 10))).padStart(4, '0')}`, cls: 'hide-md', render: (p) => `<div>${p.signer ? esc(p.signer) : '<span class="muted">No signer</span>'}</div><div class="cell-sub">${U.sigText(p.sig_status)}</div>` },
          { id: 'cpu', label: 'CPU', sort: (p) => Number(p.cpu) || 0, cls: 'num-col', render: (p) => `<div class="bar-cell"><span class="num">${U.fmtPct(p.cpu)}</span><span class="mini-bar"><i style="width:${Math.min(100, Math.max(2, (Number(p.cpu) || 0) * 4))}%"></i></span></div>` },
          { id: 'mem', label: 'Memory', sort: (p) => Number(p.mem_mb) || 0, cls: 'num-col hide-sm', render: (p) => `<span class="num">${U.fmtMem(p.mem_mb)}</span>` },
          { id: 'net', label: 'Net', sort: (p) => Number(p.net_conns) || 0, cls: 'num-col', render: (p) => (p.net_conns ? `<a class="num link" href="#/network/connections" title="Open connections">${U.fmtInt(p.net_conns)}</a>` : '<span class="muted">0</span>') },
          { id: 'started', label: 'Started', sort: (p) => U.ms(p.started), cls: 'hide-lg', render: (p) => `${U.relTime(p.started)}<div class="cell-sub">${esc(p.user || '')}</div>` },
          { id: 'act', sr: 'Actions', render: (p) => ui.rowActions({ pid: p.pid, name: p.name, exe: p.exe, allow: p.exe && p.trust !== 'trusted' ? { kind: 'process', value: p.exe, label: p.name } : null }) },
        ],
      });
      this.root.querySelector('[data-r=foot]').innerHTML = `<span>${U.plural(rows.length, 'process', 'processes')}${rows.length !== all.length ? ` of ${U.fmtInt(all.length)}` : ''}</span><span class="muted">Click a column header to sort · chevron expands the command line</span>`;
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.processes = view;
})();
