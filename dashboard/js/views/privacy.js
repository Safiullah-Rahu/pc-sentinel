/* PC Sentinel view: Privacy — camera / microphone / location / screen-capture state (exactly as the OS reports it)
   + access history. Devices the engine does not report on this OS (missing key, or { supported: false }) show as n/a. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;
  const DEVICES = [
    { key: 'webcam', label: 'Camera', icon: 'webcam' },
    { key: 'microphone', label: 'Microphone', icon: 'mic' },
    { key: 'location', label: 'Location', icon: 'mapPin' },
    { key: 'screen_capture', label: 'Screen capture', icon: 'monitor' },
  ];
  const DEV = Object.fromEntries(DEVICES.map((d) => [d.key, d]));
  const devInfo = (k) => U.own(DEV, k) || { key: k, label: U.humanize(k) || 'Device', icon: 'eye' };

  /* Where the record comes from on each OS (shown in the toolbar). */
  const SOURCE = {
    windows: 'Source: Windows CapabilityAccessManager (the same record behind Settings › Privacy).',
    linux: 'Source: live checks of camera devices (/dev/video*) and audio recording streams.',
  };

  const view = {
    id: 'privacy',
    title: 'Privacy',
    search: 'Filter history by app, path or device…',

    mount(root) {
      this.root = root;
      this.data = null;
      this.device = this.device || 'all';
      root.innerHTML = `
        <div class="panel brackets callout-panel tone-info" data-r="na" hidden></div>
        <div class="device-tiles" data-r="tiles">${DEVICES.slice(0, 3).map(() => `<div class="panel brackets device-tile">${U.skeleton(2)}</div>`).join('')}</div>
        <div class="toolbar panel">
          <h2 class="hud-label">${icon('history', { size: 13 })}Access history</h2>
          <div class="seg" role="group" aria-label="Device" data-r="seg"></div>
          <span class="spacer"></span>
          <span class="muted small" data-r="source"></span>
        </div>
        <div class="panel table-panel"><div class="table-wrap" data-r="table">${U.skeleton(6)}</div></div>`;
      this.onClick = (e) => {
        const b = e.target.closest('[data-dev]');
        if (b) {
          this.device = b.dataset.dev;
          root.querySelectorAll('[data-dev]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
          this.render();
        }
      };
      root.addEventListener('click', this.onClick);
      this.offSummary = PCS.bus.on('summary', () => { if (this.data) this.renderTiles(); });
    },
    unmount() {
      this.root.removeEventListener('click', this.onClick);
      this.offSummary();
    },

    async load() {
      try {
        this.data = await PCS.api.get('/api/privacy');
        this.error = null;
      } catch (e) {
        this.error = e;
      }
      this.render();
    },

    /** Devices this engine reports: present in `devices` and not marked { supported: false }. */
    supported() {
      const devices = (this.data && this.data.devices && typeof this.data.devices === 'object') ? this.data.devices : {};
      const monitorNa = !U.coverageSupported(null, 'privacy');
      return DEVICES.filter((d) => {
        const s = U.own(devices, d.key);
        return !monitorNa && s && typeof s === 'object' && s.supported !== false;
      }).map((d) => d.key);
    },

    render() {
      if (!this.data) {
        this.root.querySelector('[data-r=table]').innerHTML = ui.loading(this);
        return;
      }
      this.renderTiles();
      this.renderSeg();
      this.renderHistory();
    },

    renderSeg() {
      const sup = this.supported();
      const hist = Array.isArray(this.data.history) ? this.data.history : [];
      // filter buttons for supported devices plus any device that appears in the history
      const keys = DEVICES.map((d) => d.key).filter((k) => sup.includes(k) || hist.some((h) => h.device === k));
      if (this.device !== 'all' && !keys.includes(this.device)) this.device = 'all';
      this.root.querySelector('[data-r=seg]').innerHTML = [['all', 'All'], ...keys.map((k) => [k, devInfo(k).label])]
        .map(([v, l]) => `<button type="button" data-dev="${esc(v)}" aria-pressed="${this.device === v}">${esc(l)}</button>`).join('');
      const plat = U.platform();
      this.root.querySelector('[data-r=source]').textContent = U.own(SOURCE, plat) || (plat ? '' : SOURCE.windows);
    },

    renderTiles() {
      const devices = (this.data.devices && typeof this.data.devices === 'object') ? this.data.devices : {};
      const hist = Array.isArray(this.data.history) ? this.data.history : [];
      const sup = this.supported();
      const plat = U.platform();
      const naBox = this.root.querySelector('[data-r=na]');
      const monitorNa = !U.coverageSupported(null, 'privacy');
      naBox.hidden = !monitorNa;
      naBox.innerHTML = monitorNa ? `<span class="callout-icon">${icon('eye', { size: 22 })}</span>
        <div><h2>Device-use monitoring is n/a on ${esc(U.osName(plat))}</h2>
          <p>${esc(U.osName(plat))} does not let other programs see which app is using the camera, microphone or screen without special system entitlements, so these tiles stay empty. Processes, network, autostart and file checks still run.</p></div>` : '';
      // on Windows all four tiles show; elsewhere only what the engine reports, plus n/a tiles for the core two
      const tiles = DEVICES.filter((d) => sup.includes(d.key) || d.key === 'webcam' || d.key === 'microphone' || (plat === 'windows' || !plat));
      this.root.querySelector('[data-r=tiles]').innerHTML = tiles.map((d) => {
        if (!sup.includes(d.key)) {
          return `<section class="panel brackets device-tile is-na" aria-label="${esc(d.label)}: not available">
            <div class="device-icon">${icon(d.icon, { size: 26 })}</div>
            <div class="device-info">
              <div class="hud-label">${esc(d.label)}</div>
              <div class="device-big">n/a</div>
              <div class="device-by"><span class="muted">Not reported on ${esc(U.osName(plat))}</span></div>
            </div>
          </section>`;
        }
        const s = U.own(devices, d.key) || {};
        const live = s.in_use === true; // shown exactly as reported
        const by = Array.isArray(s.by) ? s.by : [];
        const last = hist.filter((h) => h.device === d.key && h.stop).sort((a, b) => U.ms(b.stop) - U.ms(a.stop))[0];
        return `<section class="panel brackets device-tile ${live ? 'is-live' : ''}" aria-label="${esc(d.label)}">
          <div class="device-icon">${icon(d.icon, { size: 26 })}${live ? '<span class="live-ring" aria-hidden="true"></span>' : ''}</div>
          <div class="device-info">
            <div class="hud-label">${esc(d.label)}</div>
            <div class="device-big">${live ? '<span class="live-dot" aria-hidden="true"></span>In use' : 'Not in use'}</div>
            <div class="device-by">${live
              ? (by.length ? `by ${by.map((b) => `<span class="chip tone-danger mono">${esc(b)}</span>`).join(' ')}` : '<span class="muted">App not reported</span>')
              : last ? `Last used by <span class="mono">${esc(last.app)}</span> ${U.relTime(last.stop)}` : '<span class="muted">No recorded use</span>'}</div>
          </div>
        </section>`;
      }).join('');
    },

    renderHistory() {
      const all = (Array.isArray(this.data.history) ? this.data.history : []).map((h, i) => Object.assign({ _i: i }, h));
      let rows = all.filter((h) => this.device === 'all' || h.device === this.device);
      rows = U.filterRows(rows, PCS.state.search, (h) => U.hay(h.device, devInfo(h.device).label, h.app, h.path, h.trust, h.allowed ? 'allowed' : 'not allowed'));
      const key = (h) => `${h.device}|${h.path}|${h.start}`;
      const monitorNa = !U.coverageSupported(null, 'privacy');
      this.root.querySelector('[data-r=table]').innerHTML = ui.table('privacy', {
        rows, allKeys: all.map(key), key,
        defaultSort: { col: 'start', dir: 'desc' },
        rowClass: (h) => (['malicious', 'suspicious'].includes(h.trust) || (!h.allowed && /\\\.|\/\.|\\temp\\|\\appdata\\local\\temp|^\/tmp\//i.test(h.path || '')) ? 'is-danger sev-row sev-critical' : h.in_use ? 'is-live' : ''),
        empty: monitorNa
          ? U.emptyState({ icon: 'eye', title: `No device history on ${U.osName(U.platform())}`, body: 'Device-use monitoring is not available on this system.', compact: true })
          : U.emptyState({ icon: 'eye', title: 'No access recorded', body: 'No camera, microphone, location or screen-capture use on record for this filter.', compact: true }),
        columns: [
          { id: 'device', label: 'Device', sort: (h) => h.device, render: (h) => `<span class="dev-tag">${icon(devInfo(h.device).icon, { size: 15 })}${esc(devInfo(h.device).label)}</span>` },
          { id: 'app', label: 'App', sort: (h) => String(h.app || '').toLowerCase(), cls: 'col-main', render: (h) => `<div class="cell-proc"><b class="mono">${esc(h.app)}</b>${U.trustBadge(h.trust)}</div><div class="cell-sub">${U.pathHtml(h.path, 72)}</div>` },
          { id: 'start', label: 'Started', sort: (h) => U.ms(h.start), render: (h) => `<span title="${esc(U.abs(h.start))}">${esc(U.shortTs(h.start))}</span>` },
          { id: 'stop', label: 'Stopped', sort: (h) => (h.stop ? U.ms(h.stop) : Infinity), render: (h) => (h.in_use ? '<span class="pill tone-danger"><span class="live-dot sm"></span>In use</span>' : h.stop ? `<span title="${esc(U.abs(h.stop))}">${esc(U.shortTs(h.stop))}</span>` : '<span class="muted">—</span>') },
          { id: 'dur', label: 'Duration', sort: (h) => (h.stop ? U.ms(h.stop) - U.ms(h.start) : Date.now() - U.ms(h.start)), cls: 'num-col', render: (h) => `<span class="num">${esc(U.duration(((h.stop ? U.ms(h.stop) : Date.now()) - U.ms(h.start)) / 1000))}</span>` },
          { id: 'allowed', label: 'Allowed', sort: (h) => (h.allowed ? 1 : 0), render: (h) => (h.allowed ? '<span class="pill tone-ok">Allowed</span>' : '<span class="pill tone-warn">Not allowlisted</span>') },
          { id: 'act', sr: 'Actions', render: (h) => (h.allowed || !h.path || !/[\\/]/.test(h.path) ? '' : ui.rowActions({ allow: { kind: 'privacy', value: h.path, label: `${h.app} (${devInfo(h.device).label})` } })) },
        ],
      });
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.privacy = view;
})();
