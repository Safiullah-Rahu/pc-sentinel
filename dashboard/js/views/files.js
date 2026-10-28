/* PC Sentinel view: Sensitive files — watched credential / wallet / SSH / messenger / canary files and who touched them. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;
  const KIND = {
    credential: ['Credential', 'key'], wallet: ['Wallet', 'wallet'], ssh: ['SSH', 'terminal'],
    messenger: ['Messenger', 'message'], canary: ['Canary', 'flag'],
  };
  const kindTag = (k) => {
    const x = U.own(KIND, k) || [U.humanize(k), 'file'];
    return `<span class="kind-tag kind-${U.own(KIND, k) ? k : 'other'}">${icon(x[1], { size: 14 })}${esc(x[0])}</span>`;
  };

  const view = {
    id: 'files',
    title: 'Sensitive files',
    search: 'Filter watched files and access log…',

    mount(root) {
      this.root = root;
      this.data = null;
      root.innerHTML = `
        <div data-r="callout"></div>
        <div class="files-grid">
          <section class="panel brackets" aria-label="Access log">
            <div class="panel-head"><h2 class="hud-label">${icon('history', { size: 13 })}Access log</h2><span class="hud-sub" data-r="acc-count"></span></div>
            <div class="table-wrap" data-r="access">${U.skeleton(6)}</div>
          </section>
          <section class="panel brackets" aria-label="Watched files">
            <div class="panel-head"><h2 class="hud-label">${icon('fileLock', { size: 13 })}Watched files</h2><span class="hud-sub" data-r="w-count"></span></div>
            <div class="table-wrap" data-r="watched">${U.skeleton(6)}</div>
          </section>
        </div>`;
    },
    unmount() {},

    async load() {
      try {
        this.data = await PCS.api.get('/api/files');
        this.error = null;
      } catch (e) {
        this.error = e;
      }
      this.render();
    },

    render() {
      if (!this.data) {
        this.root.querySelector('[data-r=access]').innerHTML = ui.loading(this);
        return;
      }
      const d = this.data;
      const audit = d.audit_enabled !== false;
      const plat = U.platform();
      const auditNa = !U.coverageSupported(null, 'file_audit');
      // n/a on this OS = muted note; supported but off = warning with the admin hint
      this.root.querySelector('[data-r=callout]').innerHTML = audit ? '' : auditNa ? `
        <div class="callout-panel panel brackets tone-info" role="note">
          <span class="callout-icon">${icon('fileLock', { size: 22 })}</span>
          <div><h2>Per-file access log: n/a on ${esc(U.osName(plat))}</h2>
            <p>Recording which program opened a file is a Windows auditing feature. Here the list below is checked for existence only, so the access log stays empty.</p></div>
        </div>` : `
        <div class="callout-panel panel brackets tone-warn" role="note">
          <span class="callout-icon">${icon('lock', { size: 22 })}</span>
          <div><h2>File access auditing is off</h2>
            <p>Windows only records which program opens these files after object-access auditing is turned on for them and the canary (decoy) files are placed. Until then the list below is watched for existence only.</p>
            <p>${U.setupHint('File auditing and canaries', plat)}</p></div>
        </div>`;

      // watched
      const watched = U.filterRows(d.watched || [], PCS.state.search, (w) => U.hay(w.label, w.path, w.kind));
      const korder = ['canary', 'credential', 'wallet', 'ssh', 'messenger'];
      this.root.querySelector('[data-r=w-count]').textContent = `${U.plural((d.watched || []).length, 'file')} · ${(d.watched || []).filter((w) => w.exists).length} present`;
      this.root.querySelector('[data-r=watched]').innerHTML = ui.table('files-watched', {
        rows: watched, key: (w) => w.path,
        defaultSort: { col: 'kind', dir: 'asc' },
        rowClass: (w) => (w.exists ? '' : 'is-dim'),
        empty: U.emptyState({ icon: 'fileLock', title: 'No watched files', compact: true }),
        columns: [
          { id: 'kind', label: 'Kind', sort: (w) => `${korder.indexOf(w.kind) < 0 ? 9 : korder.indexOf(w.kind)}${w.label}`, render: (w) => kindTag(w.kind) },
          { id: 'label', label: 'File', sort: (w) => w.label, cls: 'col-main', render: (w) => `<div class="cell-title">${esc(w.label)}</div><div class="cell-sub">${U.pathHtml(w.path, 64)}</div>` },
          { id: 'audited', label: 'Audited', sort: (w) => (w.audited ? 1 : 0), render: (w) => (w.audited ? `<span class="pill tone-ok">${icon('check', { size: 12 })}Yes</span>` : `<span class="pill tone-muted">${auditNa ? 'n/a' : 'No'}</span>`) },
          { id: 'exists', label: 'Present', sort: (w) => (w.exists ? 1 : 0), render: (w) => (w.exists ? '<span class="pill">Yes</span>' : '<span class="pill tone-muted">Missing</span>') },
        ],
      });

      // access log
      const accEl = this.root.querySelector('[data-r=access]');
      const accAll = Array.isArray(d.access) ? d.access : [];
      const unexpected = accAll.filter((a) => !a.expected).length;
      this.root.querySelector('[data-r=acc-count]').innerHTML = `${U.plural(accAll.length, 'event')}${unexpected ? ` · <span class="tone-critical">${U.fmtInt(unexpected)} unexpected</span>` : ''}`;
      if (!audit && !accAll.length) {
        accEl.innerHTML = auditNa
          ? U.emptyState({ icon: 'fileLock', title: 'No access data', body: `File-access auditing is n/a on ${esc(U.osName(plat))}.` })
          : U.emptyState({ icon: 'lock', title: 'No access data', body: 'Auditing is off, so Windows is not recording reads of these files yet.' });
        return;
      }
      const rows = U.filterRows(accAll, PCS.state.search, (a) => U.hay(a.label, a.path, a.process, a.pid, a.exe, a.access, a.expected ? 'expected' : 'unexpected'));
      const key = (a) => `${a.ts}|${a.path}|${a.pid}|${a.access}`;
      accEl.innerHTML = ui.table('files-access', {
        rows, allKeys: accAll.map(key), key,
        defaultSort: { col: 'ts', dir: 'desc' },
        rowClass: (a) => (a.expected ? '' : 'sev-row sev-critical is-danger'),
        empty: U.emptyState({ icon: 'check', title: 'No access recorded yet', body: 'Reads of watched files will show up here.', tone: 'ok', compact: true }),
        columns: [
          { id: 'ts', label: 'Time', sort: (a) => U.ms(a.ts), render: (a) => U.relTime(a.ts) },
          { id: 'file', label: 'File', sort: (a) => a.label, cls: 'col-main', render: (a) => `<div class="cell-title">${a.kind ? kindTag(a.kind) : ''} ${esc(a.label || '')}</div><div class="cell-sub">${U.pathHtml(a.path, 60)}</div>` },
          { id: 'proc', label: 'Process', sort: (a) => a.process, render: (a) => `<b class="mono" title="${esc(a.exe || '')}">${esc(a.process || '—')}</b><div class="cell-sub mono">PID ${esc(a.pid)}</div>` },
          { id: 'access', label: 'Access', sort: (a) => a.access, render: (a) => `<span class="chip tone-neutral mono">${esc(a.access || '—')}</span>` },
          { id: 'verdict', label: 'Verdict', sort: (a) => (a.expected ? 1 : 0), render: (a) => (a.expected ? '<span class="pill tone-ok">Expected</span>' : `<span class="pill tone-danger">${icon('alert', { size: 12 })}Unexpected</span>`) },
          { id: 'act', sr: 'Actions', render: (a) => (a.expected ? '' : ui.rowActions({ pid: a.pid, name: a.process, exe: a.exe, allow: a.exe ? { kind: 'process', value: a.exe, label: a.process } : null })) },
        ],
      });
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.files = view;
})();
