/* PC Sentinel view: Overview — risk gauge, KPIs, live throughput, latest alerts, top talkers, Defender, coverage. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;
  const SEV_VAR = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)' };

  const view = {
    id: 'overview',
    title: 'Overview',
    search: 'Filter latest alerts and top talkers…',

    mount(root) {
      this.root = root;
      this.alerts = null;
      this.apps = null;
      const kpi = (key, label, iconName, href, extra) => `
        <a class="kpi panel brackets" href="${href}" data-kpi="${key}">
          <div class="kpi-head"><span class="hud-label">${esc(label)}</span><span class="kpi-icon">${icon(iconName, { size: 16 })}</span></div>
          <div class="kpi-value num" data-v="${key}">—</div>
          <div class="kpi-foot" data-f="${key}">${extra || ''}</div>
        </a>`;
      root.innerHTML = `
        <div class="ov-grid">
          <section class="panel brackets gauge-card" aria-label="Risk posture">
            <div class="panel-head"><h2 class="hud-label">${icon('shield', { size: 13 })}Risk posture</h2><span class="hud-sub" data-r="risk-sub"></span></div>
            <div class="gauge" data-r="gauge" role="img"></div>
            <ul class="drivers" data-r="drivers"></ul>
          </section>
          <div class="kpi-grid">
            <a class="kpi kpi-alerts panel brackets" href="#/alerts" data-kpi="alerts">
              <div class="kpi-head"><span class="hud-label">Open alerts</span><span class="kpi-icon">${icon('alert', { size: 16 })}</span></div>
              <div class="kpi-alerts-body"><div class="donut-wrap" data-r="donut"></div><ul class="sev-legend" data-r="sev-legend"></ul></div>
            </a>
            ${kpi('processes', 'Processes', 'cpu', '#/processes', '<span data-r="cpu-text"></span><span class="spark-slot" data-r="spark-cpu"></span>')}
            ${kpi('connections', 'Connections', 'link', '#/network/connections', '<span>live sockets</span><span class="spark-slot" data-r="spark-conns"></span>')}
            ${kpi('listening_exposed', 'Exposed ports', 'plug', '#/network/listening', '<span>listening on all interfaces</span>')}
            ${kpi('remote_hosts_24h', 'Remote hosts · 24h', 'target', '#/network/destinations', '<span>unique addresses contacted</span>')}
            ${kpi('apps_online', 'Apps online', 'grid', '#/network/apps', '<span>with network activity</span>')}
            <a class="kpi kpi-devices panel brackets" href="#/privacy" data-kpi="devices">
              <div class="kpi-head"><span class="hud-label">Camera · Mic</span><span class="kpi-icon">${icon('eye', { size: 16 })}</span></div>
              <div class="device-rows" data-r="devices"></div>
            </a>
          </div>

          <section class="panel brackets chart-card" aria-label="Network throughput">
            <div class="panel-head">
              <h2 class="hud-label">${icon('activity', { size: 13 })}Network throughput</h2>
              <div class="chart-legend" data-r="legend"></div>
              <span class="chip tone-neutral">Last 60 min</span>
            </div>
            <div class="chart-wrap" data-r="chart"></div>
          </section>
          <section class="panel brackets latest-card" aria-label="Latest alerts">
            <div class="panel-head"><h2 class="hud-label">${icon('alert', { size: 13 })}Latest alerts</h2><a class="link" href="#/alerts">View all${icon('chevronRight', { size: 14 })}</a></div>
            <div class="latest-list" data-r="latest">${U.skeleton(5)}</div>
          </section>

          <section class="panel brackets talkers-card" aria-label="Top talkers">
            <div class="panel-head"><h2 class="hud-label">${icon('globe', { size: 13 })}Top talkers</h2><a class="link" href="#/network/apps">All apps${icon('chevronRight', { size: 14 })}</a></div>
            <div data-r="talkers">${U.skeleton(5)}</div>
          </section>
          <section class="panel brackets defender-card" aria-label="Antivirus status">
            <div class="panel-head"><h2 class="hud-label">${icon('shield', { size: 13 })}<span data-r="def-title">Microsoft Defender</span></h2></div>
            <div data-r="defender">${U.skeleton(4)}</div>
          </section>
          <section class="panel brackets coverage-card" aria-label="Monitoring coverage">
            <div class="panel-head"><h2 class="hud-label">${icon('radar', { size: 13 })}Coverage</h2><span class="hud-sub" data-r="cov-count"></span></div>
            <div data-r="coverage">${U.skeleton(3)}</div>
          </section>
        </div>`;
      this.gauge = new PCS.charts.Gauge(root.querySelector('[data-r=gauge]'));
      this.chart = new PCS.charts.ThroughputChart(root.querySelector('[data-r=chart]'));
      if (PCS.state.metrics.length) this.chart.setPoints(PCS.state.metrics);
      this.offMetric = PCS.bus.on('metric', (m) => {
        this.chart.push(m);
        this.renderLegend();
        this.renderSparks();
      });
      this.offSummary = PCS.bus.on('summary', () => this.renderSummary());
      this.renderSummary();
      this.renderLegend();
      this.renderSparks();
    },

    unmount() {
      this.chart.destroy();
      this.offMetric();
      this.offSummary();
    },

    async load() {
      const api = PCS.api;
      const st = PCS.state;
      // fetch the 60-minute history once, and again whenever the stream is down (points would be missing)
      const needMetrics = !st.metricsLoaded || !st.streamLive;
      const [sum, alerts, apps, metrics] = await Promise.allSettled([
        api.get('/api/summary'),
        api.get('/api/alerts?status=open&limit=200'),
        api.get('/api/network/apps'),
        needMetrics ? api.get('/api/metrics?minutes=60') : Promise.resolve(null),
      ]);
      if (sum.status === 'fulfilled') PCS.app.setSummary(sum.value);
      if (alerts.status === 'fulfilled') {
        this.alerts = alerts.value.items || [];
        PCS.app.mergeAlerts(this.alerts, true);
      }
      if (apps.status === 'fulfilled') this.apps = apps.value.items || [];
      if (metrics.status === 'fulfilled' && metrics.value) {
        const hist = metrics.value.points || [];
        const lastHist = hist.length ? U.ms(hist[hist.length - 1].t) : -Infinity;
        st.metrics = hist.concat(st.metrics.filter((p) => U.ms(p.t) > lastHist)); // keep streamed points newer than the history
        st.metricsLoaded = true;
        this.chart.setPoints(st.metrics);
        this.renderSparks();
      }
      this.error = sum.status === 'rejected' ? sum.reason : null;
      this.render();
    },

    render() {
      this.renderSummary();
      this.renderLatest();
      this.renderTalkers();
      this.renderLegend();
      this.renderSparks();
    },
    onSearch() {
      this.renderLatest();
      this.renderTalkers();
    },

    renderSummary() {
      const s = PCS.state.summary;
      if (!s) return;
      const k = s.kpis || {};
      const risk = s.risk || {};
      this.gauge.set(risk.score, risk.label);
      this.root.querySelector('[data-r=risk-sub]').textContent = s.engine ? `${s.engine.host || ''}` : '';
      ['processes', 'connections', 'listening_exposed', 'remote_hosts_24h', 'apps_online'].forEach((key) => {
        ui.countUp(this.root.querySelector(`[data-v=${key}]`), k[key]);
      });
      this.root.querySelector('[data-kpi=listening_exposed]').classList.toggle('is-warn', (k.listening_exposed || 0) > 0);

      // alerts donut
      const ao = k.alerts_open || {};
      const segs = ['critical', 'high', 'medium', 'low'].map((sev) => ({ value: Math.max(0, Number(ao[sev]) || 0), color: SEV_VAR[sev], label: U.SEV_LABEL[sev] }));
      const total = segs.reduce((a, x) => a + x.value, 0);
      this.root.querySelector('[data-r=donut]').innerHTML = `${PCS.charts.donut(segs, { size: 96, thickness: 9, label: `${total} open alerts` })}
        <div class="donut-center"><b class="num" data-v="alerts-total"></b><span class="hud-label">open</span></div>`;
      const tot = this.root.querySelector('[data-v=alerts-total]');
      tot._v = this.prevTotal;
      ui.countUp(tot, total);
      this.prevTotal = total;
      this.root.querySelector('[data-r=sev-legend]').innerHTML = segs.map((x, i) => {
        const sev = ['critical', 'high', 'medium', 'low'][i];
        return `<li class="${x.value ? '' : 'is-zero'}"><i class="sev-dot sev-${sev}"></i><span>${esc(x.label)}</span><b class="num">${esc(U.fmtInt(x.value))}</b></li>`;
      }).join('');
      this.root.querySelector('[data-kpi=alerts]').classList.toggle('is-critical', (ao.critical || 0) > 0);

      // camera / mic
      const privacyNa = !U.coverageSupported(s, 'privacy');
      const dev = (on, label, ic) => `<div class="device-row ${on ? 'is-live' : ''}${privacyNa ? ' is-na' : ''}">${icon(ic, { size: 16 })}<span>${label}</span>
        <span class="device-state">${privacyNa ? `n/a on ${esc(U.osName(U.platform(s)))}` : on ? '<span class="live-dot" aria-hidden="true"></span>In use' : 'Idle'}</span></div>`;
      this.root.querySelector('[data-r=devices]').innerHTML = dev(k.camera_in_use === true, 'Camera', 'webcam') + dev(k.mic_in_use === true, 'Microphone', 'mic');
      this.root.querySelector('[data-kpi=devices]').classList.toggle('is-live', !!(k.camera_in_use || k.mic_in_use));

      this.renderDrivers(s);
      this.renderDefender(s.defender, s);
      this.renderCoverage(s.coverage, s);
    },

    renderDrivers(s) {
      const k = s.kpis || {};
      const ao = k.alerts_open || {};
      const cov = s.coverage || {};
      const items = [];
      if (ao.critical) items.push(['critical', `${U.plural(ao.critical, 'critical alert')} open`]);
      if (ao.high) items.push(['high', `${U.plural(ao.high, 'high alert')} open`]);
      if (s.defender && s.defender.realtime === false && U.coverageSupported(s, 'defender_log')) items.push(['critical', 'Defender real-time protection is off']);
      if (k.camera_in_use) items.push(['medium', 'Camera in use right now']);
      if (k.mic_in_use) items.push(['medium', 'Microphone in use right now']);
      if (k.listening_exposed) items.push(['medium', `${U.plural(k.listening_exposed, 'port')} open to the network`]);
      // monitors that do not exist on this OS are n/a, not a gap
      const gaps = U.coverageList(s).filter((c) => !U.coverageOn(cov, c.key)).length;
      if (gaps) items.push(['info', `${U.plural(gaps, 'monitor')} not active`]);
      if (!items.length) items.push(['ok', 'Nothing needs attention']);
      this.root.querySelector('[data-r=drivers]').innerHTML = items.slice(0, 4).map(([tone, text]) => `<li class="tone-${tone}"><i></i>${esc(text)}</li>`).join('');
    },

    renderDefender(d, s) {
      const el = this.root.querySelector('[data-r=defender]');
      const plat = U.platform(s);
      const title = this.root.querySelector('[data-r=def-title]');
      // Microsoft Defender only exists on Windows; elsewhere the card says so (muted, not a warning)
      if (!U.coverageSupported(s, 'defender_log') || (plat && plat !== 'windows' && !d)) {
        title.textContent = 'Antivirus';
        el.innerHTML = U.emptyState({
          icon: 'shield', compact: true, title: `Microsoft Defender: n/a on ${U.osName(plat)}`,
          body: `<span class="muted">Defender status and detections are read from Windows only. PC Sentinel's own process, network and autostart checks still run here.</span>`,
        });
        return;
      }
      title.textContent = 'Microsoft Defender';
      if (!d) {
        el.innerHTML = U.emptyState({ icon: 'shield', title: 'No Defender status yet', compact: true });
        return;
      }
      const onoff = (v) => (v === true ? '<span class="pill tone-ok">On</span>' : v === false ? '<span class="pill tone-danger">Off</span>' : '<span class="pill">Unknown</span>');
      const age = d.signatures_age_h === null || d.signatures_age_h === undefined || d.signatures_age_h === '' ? null : Number(d.signatures_age_h);
      el.innerHTML = ui.kv([
        ['Real-time protection', onoff(d.realtime)],
        ['Tamper protection', onoff(d.tamper)],
        ['Signatures', `<span class="mono">${esc(d.signatures || '—')}</span>${age !== null ? ` <span class="muted small">${age > 24 ? `<span class="tone-warn">${esc(U.fmtInt(age))} h old</span>` : `${esc(U.fmtInt(age))} h old`}</span>` : ''}`],
        ['Known exclusions', `<span class="num">${esc(U.fmtInt(d.exclusions_known))}</span>`],
        ['Last detection', d.last_detection ? `<a class="link" href="#/alerts">${U.relTime(d.last_detection)}</a>` : '<span class="muted">None recorded</span>'],
      ]);
    },

    renderCoverage(cov, s) {
      const el = this.root.querySelector('[data-r=coverage]');
      if (!cov) return;
      const plat = U.platform(s);
      const supported = U.coverageList(s);
      const on = supported.filter((c) => U.coverageOn(cov, c.key));
      const offAdmin = supported.filter((c) => c.admin && !U.coverageOn(cov, c.key));
      const na = U.COVERAGE.length - supported.length;
      this.root.querySelector('[data-r=cov-count]').textContent = `${on.length}/${supported.length} active${na ? ` · ${na} n/a` : ''}`;
      el.innerHTML = `<ul class="cov-grid">${U.COVERAGE.map((c) => {
        const st = U.coverageState(s, c.key);
        const extra = c.key === 'canaries' && st === 'on' ? ` · ${U.fmtInt(cov.canaries)}` : '';
        const why = st === 'on' ? 'active' : st === 'na' ? `not available on ${U.osName(plat)}` : 'off';
        return `<li class="cov-item is-${st}" title="${esc(`${c.label}: ${why}`)}">${icon(c.icon, { size: 15 })}<span>${esc(c.label)}${esc(extra)}</span>${st === 'na' ? '<small class="cov-na">n/a</small>' : '<i aria-hidden="true"></i>'}</li>`;
      }).join('')}</ul>
      ${offAdmin.length ? `<p class="cov-hint">${icon('info', { size: 14 })}<span>${U.setupHint(offAdmin.map((c) => c.label).join(', '), plat)}</span></p>` : ''}`;
    },

    renderLegend() {
      const last = this.chart.latest();
      const el = this.root.querySelector('[data-r=legend]');
      el.innerHTML = `<span class="lgd"><i class="sw sw-rx"></i>Down <b class="num">${esc(last ? U.fmtRate(last.rx) : '—')}</b></span>
        <span class="lgd"><i class="sw sw-tx"></i>Up <b class="num">${esc(last ? U.fmtRate(last.tx) : '—')}</b></span>`;
    },

    renderSparks() {
      const pts = PCS.state.metrics.slice(-180);
      const cpu = pts.map((p) => Number(p.cpu));
      const conns = pts.map((p) => Number(p.conns));
      const last = pts[pts.length - 1];
      const cpuText = this.root.querySelector('[data-r=cpu-text]');
      if (cpuText) cpuText.textContent = last ? `CPU ${U.fmtPct(last.cpu)}` : 'CPU —';
      const a = this.root.querySelector('[data-r=spark-cpu]');
      if (a) a.innerHTML = PCS.charts.sparkline(cpu, { w: 110, h: 30, color: 'var(--accent)' });
      const b = this.root.querySelector('[data-r=spark-conns]');
      if (b) b.innerHTML = PCS.charts.sparkline(conns, { w: 110, h: 30, color: 'var(--accent-2)' });
    },

    renderLatest() {
      const el = this.root.querySelector('[data-r=latest]');
      if (!this.alerts) {
        el.innerHTML = ui.loading(this);
        return;
      }
      let list = this.alerts.slice().sort((a, b) => U.ms(b.last_ts || b.ts) - U.ms(a.last_ts || a.ts));
      list = U.filterRows(list, PCS.state.search, (a) => U.hay(a.title, a.summary, a.category, a.process && a.process.name, a.remote && a.remote.ip));
      if (!list.length) {
        el.innerHTML = U.emptyState({ icon: 'shieldCheck', title: PCS.state.search ? 'No matching alerts' : 'No open alerts', body: PCS.state.search ? '' : 'All clear. New alerts appear here live.', tone: 'ok', compact: true });
        return;
      }
      const fresh = ui.track('ov-latest', list.map((a) => `${a.id}:${a.count}`));
      el.innerHTML = `<ul class="alert-feed">${list.slice(0, 7).map((a) => `
        <li><button type="button" class="feed-item sev-${U.sevKey(a.severity)}${fresh.has(`${a.id}:${a.count}`) ? ' is-new' : ''}" data-alert-id="${esc(a.id)}">
          <span class="feed-bar" aria-hidden="true"></span>
          <span class="feed-main">
            <span class="feed-title">${esc(a.title)}</span>
            <span class="feed-meta">${U.sevBadge(a.severity)}<span>${esc(U.catLabel(a.category))}</span>${a.process ? `<span class="mono">${esc(a.process.name)}</span>` : ''}${a.count > 1 ? `<span class="count-badge">×${U.fmtInt(a.count)}</span>` : ''}</span>
          </span>
          <span class="feed-time">${U.relTime(a.last_ts || a.ts)}</span>
        </button></li>`).join('')}</ul>`;
    },

    renderTalkers() {
      const el = this.root.querySelector('[data-r=talkers]');
      if (!this.apps) {
        el.innerHTML = ui.loading(this);
        return;
      }
      let list = this.apps.slice().sort((a, b) => (b.conns || 0) - (a.conns || 0));
      list = U.filterRows(list, PCS.state.search, (a) => U.hay(a.process, a.exe, a.signer, a.trust));
      if (!list.length) {
        el.innerHTML = U.emptyState({ icon: 'globe', title: 'No apps online', compact: true });
        return;
      }
      const max = Math.max(1, ...list.map((a) => a.conns || 0));
      el.innerHTML = `<ul class="talkers">${list.slice(0, 7).map((a) => `
        <li class="talker trust-row-${U.trustKey(a.trust)}">
          <span class="talker-name"><b class="mono">${esc(a.process)}</b>${U.trustBadge(a.trust)}</span>
          <span class="talker-bar" aria-hidden="true"><i style="width:${Math.max(3, Math.round(((Number(a.conns) || 0) / max) * 100))}%"></i></span>
          <span class="talker-num num" title="${esc(`${a.conns} connections to ${a.remote_hosts} hosts`)}">${U.fmtInt(a.conns)}<small>/${U.fmtInt(a.remote_hosts)}</small></span>
        </li>`).join('')}</ul>
        <p class="hud-foot"><span>connections / remote hosts</span></p>`;
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.overview = view;
})();
