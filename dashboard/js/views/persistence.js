/* PC Sentinel view: Persistence — autostart entries grouped by kind, new/changed first. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;
  const STATUS = {
    new: ['NEW', 'danger', 0], changed: ['Changed', 'warn', 1], removed: ['Removed', 'muted', 3], baseline: ['Baseline', 'neutral', 2],
  };
  const statusPill = (s) => {
    const x = U.own(STATUS, s) || [U.humanize(s), 'neutral'];
    return `<span class="pill status-pill tone-${x[1]}">${esc(x[0])}</span>`;
  };

  const view = {
    id: 'persistence',
    title: 'Persistence',
    search: 'Filter autostart entries…',

    mount(root) {
      this.root = root;
      this.items = null;
      this.showBaseline = this.showBaseline !== false;
      root.innerHTML = `
        <div class="toolbar panel">
          <div class="status-summary" data-r="summary"></div>
          <span class="spacer"></span>
          <span class="muted small hide-md" data-r="scope"></span>
          <button type="button" class="hud-toggle" data-r="baseline" aria-pressed="${this.showBaseline}">${icon('eye', { size: 14 })}Show baseline entries</button>
        </div>
        <div class="persist-groups" data-r="groups">${U.skeleton(8)}</div>`;
      this.onClick = (e) => {
        if (e.target.closest('[data-r=baseline]')) {
          this.showBaseline = !this.showBaseline;
          e.target.closest('[data-r=baseline]').setAttribute('aria-pressed', String(this.showBaseline));
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
        const r = await PCS.api.get('/api/persistence');
        this.items = r.items || [];
        this.error = null;
      } catch (e) {
        this.error = e;
      }
      this.render();
    },

    render() {
      const box = this.root.querySelector('[data-r=groups]');
      if (!this.items) {
        box.innerHTML = ui.loading(this);
        return;
      }
      const all = this.items;
      const counts = { new: 0, changed: 0, removed: 0, baseline: 0 };
      all.forEach((i) => { if (U.own(counts, i.status) !== undefined) counts[i.status] += 1; });
      this.root.querySelector('[data-r=summary]').innerHTML = ['new', 'changed', 'removed', 'baseline'].map((s) => `
        <span class="status-count ${counts[s] && s !== 'baseline' ? `tone-${STATUS[s][1]}` : ''}">${statusPill(s)}<b class="num">${counts[s]}</b></span>`).join('');
      const plat = U.platform();
      this.root.querySelector('[data-r=scope]').textContent = U.own(U.PERSIST_SCOPE, plat) ? `Watching ${U.PERSIST_SCOPE[plat]}` : '';

      let rows = all.filter((i) => this.showBaseline || i.status !== 'baseline');
      rows = U.filterRows(rows, PCS.state.search, (i) => U.hay(i.name, i.command, i.exe, i.location, i.signer, i.trust, i.status, i.kind, U.persistKind(i.kind).label, i.flags));
      // this OS's kinds first, then the cross-platform ones, then anything unknown the engine sends
      const kinds = U.PERSIST_KINDS.filter((k) => !plat || !k.os || k.os === plat).concat(U.PERSIST_KINDS.filter((k) => plat && k.os && k.os !== plat));
      all.forEach((i) => { if (!kinds.some((k) => k.key === i.kind)) kinds.push(U.persistKind(i.kind)); });

      const html = kinds.map((k) => {
        const group = rows.filter((i) => i.kind === k.key);
        const total = all.filter((i) => i.kind === k.key);
        const attention = total.filter((i) => i.status === 'new' || i.status === 'changed').length;
        if (!total.length) return '';
        const key = (i) => `${i.kind}|${i.location}|${i.name}`;
        const table = ui.table(`persist-${k.key}`, {
          rows: group, allKeys: total.map(key), key,
          defaultSort: { col: 'status', dir: 'asc' },
          rowClass: (i) => `${i.status === 'new' ? 'sev-row sev-high is-new-entry' : i.status === 'changed' ? 'sev-row sev-medium' : ''}${i.status === 'removed' ? ' is-removed' : ''} trust-row-${U.trustKey(i.trust)}`,
          empty: U.emptyState({ icon: 'check', title: this.showBaseline ? 'No entries match' : 'Only baseline entries here', compact: true }),
          columns: [
            { id: 'status', label: 'Status', sort: (i) => `${(U.own(STATUS, i.status) || [0, 0, 9])[2]}${String(i.name || '').toLowerCase()}`, render: (i) => statusPill(i.status) },
            { id: 'name', label: 'Name', sort: (i) => String(i.name || '').toLowerCase(), render: (i) => `<b class="mono name-cell" title="${esc(i.name)}">${esc(U.middle(i.name, 44))}</b>${U.flagChips(i.flags, 3)}` },
            { id: 'command', label: 'Command', sort: (i) => i.command, cls: 'col-main', render: (i) => `${U.copyBtn(i.command, U.middle(i.command, 90), 'mono path')}<div class="cell-sub">${U.copyBtn(i.location, U.middle(i.location, 70), 'mono path muted')}</div>` },
            { id: 'signer', label: 'Publisher', sort: (i) => `${U.trustRank(i.trust)}${i.signer || ''}`, cls: 'hide-md', render: (i) => `<div>${i.signer ? esc(i.signer) : '<span class="muted">No signer</span>'}</div><div class="cell-sub">${U.trustBadge(i.trust)} ${U.sigText(i.sig_status)}</div>` },
            { id: 'first', label: 'First seen', sort: (i) => U.ms(i.first_seen), cls: 'hide-lg', render: (i) => U.relTime(i.first_seen) },
            { id: 'act', sr: 'Actions', render: (i) => (i.status !== 'removed' && i.exe && i.trust !== 'trusted' ? ui.rowActions({ allow: { kind: 'persistence', value: i.exe, label: i.name } }) : '') },
          ],
        });
        return `<section class="panel brackets persist-group" aria-label="${esc(k.label)}">
          <div class="panel-head"><h2 class="hud-label">${icon(k.icon, { size: 13 })}${esc(k.label)}</h2>
            <span class="hud-sub">${U.plural(total.length, 'entry', 'entries')}${attention ? ` · <span class="tone-warn">${U.fmtInt(attention)} need${attention === 1 ? 's' : ''} review</span>` : ''}</span></div>
          <div class="table-wrap">${table}</div>
        </section>`;
      }).join('');
      box.innerHTML = html || U.emptyState({ icon: 'power', title: 'No autostart entries reported', body: 'The persistence monitor has not finished its first scan.' });
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.persistence = view;
})();
