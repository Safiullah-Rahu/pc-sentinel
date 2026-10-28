/* PC Sentinel dashboard: app shell — routing, polling of the active view, SSE, connectivity banner,
   sidebar / top bar (clock, search, bell, desktop pop-up switch) and global event delegation. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc, $, $$ } = U;

  const NAV = [
    { id: 'map', label: 'Live Map', icon: 'radar' },
    { id: 'overview', label: 'Overview', icon: 'dashboard' },
    { id: 'alerts', label: 'Alerts', icon: 'alert' },
    { id: 'network', label: 'Network', icon: 'globe' },
    { id: 'processes', label: 'Processes', icon: 'cpu' },
    { id: 'privacy', label: 'Privacy', icon: 'eye' },
    { id: 'persistence', label: 'Persistence', icon: 'power' },
    { id: 'files', label: 'Sensitive files', icon: 'fileLock' },
    { id: 'timeline', label: 'Timeline', icon: 'history' },
    { id: 'settings', label: 'Settings', icon: 'sliders', bottom: true },
  ];
  const DEFAULT_VIEW = 'map';
  const POLL_MS = 5000;
  const SEEN_KEY = 'pcs-seen';

  const state = (PCS.state = {
    route: { view: null, tab: null },
    search: '',
    summary: null,
    summaryAt: 0,
    status: null,
    streamLive: false,
    lastOk: null,
    alerts: new Map(),
    seen: new Set(((v) => (Array.isArray(v) ? v : []))(U.store.get(SEEN_KEY, [])).slice(-600).map(String)),
    metrics: [],
    notify: { enabled: false, min_severity: 'high' },
    fx: U.store.getRaw('pcs-fx') !== 'off',
  });

  const views = () => PCS.views || {};
  const current = () => U.own(views(), state.route.view) || null;

  /* ================================================================== shell */
  function buildShell() {
    $('#brand').innerHTML = `${PCS.logo(30)}<div class="brand-text"><b>PC Sentinel</b><span class="hud-label">Host defence</span></div>`;
    const item = (n) => `<a class="nav-item" href="#/${n.id}" data-nav="${n.id}" title="${esc(n.label)}">
        <span class="nav-icon">${icon(n.icon, { size: 19 })}</span><span class="nav-label">${esc(n.label)}</span><span class="nav-badge" data-badge="${n.id}" hidden></span></a>`;
    $('#nav').innerHTML = `<div class="nav-group">${NAV.filter((n) => !n.bottom).map(item).join('')}</div>
      <div class="nav-group nav-bottom">${NAV.filter((n) => n.bottom).map(item).join('')}</div>`;
    $('#btn-collapse').innerHTML = icon('panelLeft', { size: 18 });
    $('#search-icon').innerHTML = icon('search', { size: 16 });
    $('#btn-bell').insertAdjacentHTML('afterbegin', icon('bell', { size: 19 }));
    $('#mock-chip').hidden = !PCS.api.isMock;
    if (PCS.api.isMock) {
      const m = PCS.mock || {};
      const tags = [m.os && m.os !== 'windows' ? U.osName(m.os) : '', m.setup && m.setup !== 'partial' ? m.setup : '', m.xss ? 'XSS test' : ''].filter(Boolean);
      $('#mock-chip').innerHTML = `${icon('database', { size: 13 })}Mock data${tags.length ? ` · ${esc(tags.join(' · '))}` : ''}`;
    }
    renderNotifySwitch();
    renderFoot();
    applyFx();
  }

  function renderFoot() {
    const s = state.summary;
    const st = state.status;
    const running = st === 'online' && s;
    const label = st === 'unauthorized' ? 'Engine locked' : st === 'offline' ? 'Engine offline' : running ? 'Engine running' : 'Connecting…';
    const tone = st === 'unauthorized' || st === 'offline' ? 'danger' : running ? 'ok' : 'muted';
    const e = (s && s.engine) || {};
    const cov = (s && s.coverage) || null;
    const plat = U.platform(s);
    const os = U.osLabel(s);
    const supported = U.coverageList(s);
    const active = cov ? supported.filter((c) => U.coverageOn(cov, c.key)).length : 0;
    const offAdmin = cov ? supported.filter((c) => c.admin && !U.coverageOn(cov, c.key)).length : 0;
    const version = e.version ? String(e.version) : '';
    $('#sidebar-foot').innerHTML = `
      <div class="engine-pill tone-${tone}" title="${esc(`${label}${version ? ` · v${version}` : ''}${os ? ` · ${os}` : ''}`)}">
        <span class="engine-dot" aria-hidden="true"></span>
        <div class="engine-text"><b>${esc(label)}</b><span>${running ? `v${esc(version || '?')} · up <span data-uptime></span>` : st === 'offline' ? 'retrying every 5 s' : '&nbsp;'}</span>
          ${os ? `<span class="engine-os">${icon(plat === 'macos' ? 'monitor' : plat === 'linux' ? 'terminal' : 'grid', { size: 11 })}${esc(os)}</span>` : ''}</div>
      </div>
      <a class="cov-mini" href="#/settings" title="Monitoring coverage">
        <div class="cov-mini-head"><span class="hud-label">Coverage</span><span class="num">${cov ? `${active}/${supported.length}` : '—'}</span></div>
        <div class="cov-dots">${U.COVERAGE.map((c) => {
          const cs = cov ? U.coverageState(s, c.key) : 'off';
          const why = cs === 'on' ? 'active' : cs === 'na' ? `n/a on ${U.osName(plat)}` : c.admin && plat !== 'macos' ? 'off (needs admin rights)' : 'off';
          return `<span class="cov-dot is-${cs}" title="${esc(`${c.label}: ${why}`)}">${icon(c.icon, { size: 13 })}</span>`;
        }).join('')}</div>
        ${cov && offAdmin ? `<div class="cov-mini-hint">${esc(plat === 'macos' || plat === 'linux' ? `${offAdmin} off · run as admin/root for more` : `${offAdmin} off · admin mode adds ${offAdmin === 1 ? 'it' : 'them'}`)}</div>` : ''}
      </a>`;
    tickUptime();
  }

  function renderBadges() {
    const k = (state.summary && state.summary.kpis) || {};
    const ao = k.alerts_open || {};
    const total = ['critical', 'high', 'medium', 'low'].reduce((a, s) => a + (ao[s] || 0), 0);
    const top = ['critical', 'high', 'medium', 'low'].find((s) => ao[s]);
    const b = $('[data-badge="alerts"]');
    if (b) {
      b.hidden = !total;
      b.textContent = total > 99 ? '99+' : String(total);
      b.className = `nav-badge sev-${top || 'low'}`;
    }
    const p = $('[data-badge="privacy"]');
    if (p) {
      const live = k.camera_in_use || k.mic_in_use;
      p.hidden = !live;
      p.className = 'nav-badge is-dot';
      p.title = live ? 'Camera or microphone in use' : '';
      p.textContent = '';
    }
  }

  function markNav() {
    $$('[data-nav]').forEach((a) => {
      if (a.dataset.nav === state.route.view) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  }

  /* ================================================================== connectivity */
  function onStatus(s) {
    const prev = state.status;
    state.status = s;
    state.lastOk = PCS.api.lastOk;
    const banner = $('#banner');
    if (s === 'offline' || s === 'unauthorized') {
      banner.hidden = false;
      banner.className = `banner tone-${s === 'offline' ? 'warn' : 'danger'}`;
      banner.innerHTML = s === 'offline'
        ? `<span class="spinner" aria-hidden="true"></span><b>Engine offline — retrying</b><span class="muted">${state.lastOk ? `Last contact ${esc(U.hms(state.lastOk))}. Showing the last data received.` : 'Waiting for the engine on 127.0.0.1:8777.'}</span><button type="button" class="btn btn-xs" data-retry>${icon('refresh', { size: 13 })}Retry now</button>`
        : `${icon('lock', { size: 16 })}<b>Access token rejected</b><span class="muted">Close this window and reopen the dashboard from PC Sentinel so it gets a fresh token.</span>`;
    } else {
      banner.hidden = true;
      if (prev === 'offline') ui.toast({ kind: 'success', title: 'Engine back online' });
    }
    document.documentElement.dataset.conn = s || '';
    renderFoot();
    renderLive();
  }

  function renderLive() {
    const el = $('#live-ind');
    const s = state.status;
    const tone = s === 'offline' || s === 'unauthorized' ? 'danger' : state.streamLive ? 'ok' : s === 'online' ? 'warn' : 'muted';
    const text = s === 'offline' ? 'Offline' : s === 'unauthorized' ? 'Locked' : state.streamLive ? 'Live' : s === 'online' ? 'Polling' : '…';
    el.className = `live-ind tone-${tone}`;
    el.innerHTML = `<i aria-hidden="true"></i>${text}`;
    el.title = state.streamLive ? 'Receiving the live event stream' : s === 'online' ? 'Live stream reconnecting; polling every 5 s' : 'Not connected to the engine';
  }

  /* ================================================================== summary / alerts state */
  function setSummary(s) {
    if (!s || typeof s !== 'object') return;
    state.summary = s;
    state.summaryAt = Date.now();
    renderFoot();
    renderBadges();
    PCS.bus.emit('summary', s);
  }

  /** authoritative = this list is the complete set of open alerts, so anything we still think is open but is missing was handled elsewhere. */
  function mergeAlerts(items, authoritative) {
    const ids = new Set();
    (items || []).forEach((a) => {
      if (a && a.id !== undefined) {
        state.alerts.set(String(a.id), a);
        ids.add(String(a.id));
      }
    });
    if (authoritative === true) {
      state.alerts.forEach((a, id) => {
        if (!ids.has(id) && a.status === 'open') state.alerts.set(id, Object.assign({}, a, { status: 'acknowledged' }));
      });
    }
    renderBell();
  }
  function patchAlert(id, patch) {
    const k = String(id);
    const a = state.alerts.get(k);
    if (a) state.alerts.set(k, Object.assign({}, a, patch));
    renderBell();
    if (PCS.openAlert) PCS.openAlert.refresh(k);
  }
  function markSeen(id) {
    state.seen.add(String(id));
    saveSeen();
    renderBell();
  }
  function saveSeen() {
    U.store.set(SEEN_KEY, Array.from(state.seen).slice(-600));
  }

  function onStreamAlert(a) {
    if (!a || a.id === undefined) return;
    state.alerts.set(String(a.id), a);
    renderBell();
    if (PCS.openAlert) PCS.openAlert.refresh(String(a.id));
    const v = state.route.view;
    if (['alerts', 'overview', 'timeline', 'map'].includes(v)) softRefresh();
  }

  /* ================================================================== bell (unread critical/high) */
  function unreadList() {
    const out = [];
    state.alerts.forEach((a, id) => {
      if (a.status === 'open' && (a.severity === 'critical' || a.severity === 'high')) out.push(Object.assign({ _unread: !state.seen.has(id) }, a));
    });
    return out.sort((x, y) => (U.sevRank(x.severity) - U.sevRank(y.severity)) || (U.ms(y.last_ts || y.ts) - U.ms(x.last_ts || x.ts)));
  }
  function renderBell() {
    const list = unreadList();
    const unread = list.filter((a) => a._unread);
    const badge = $('#bell-badge');
    badge.hidden = !unread.length;
    badge.textContent = unread.length > 9 ? '9+' : String(unread.length);
    badge.className = `bell-badge${unread.some((a) => a.severity === 'critical') ? ' is-critical' : ''}`;
    $('#btn-bell').setAttribute('aria-label', unread.length ? `${unread.length} unread critical or high alerts` : 'Notifications: no unread critical or high alerts');
    const pop = $('#bell-pop');
    if (pop.hidden) return;
    pop.innerHTML = `<div class="pop-head"><span class="hud-label">Critical &amp; high · open</span>
        ${unread.length ? '<button type="button" class="link" data-bell="read-all">Mark all read</button>' : ''}</div>
      ${list.length ? `<ul class="pop-list">${list.slice(0, 8).map((a) => `<li><button type="button" class="pop-item sev-${U.sevKey(a.severity)}${a._unread ? ' is-unread' : ''}" data-alert-id="${esc(a.id)}">
          <span class="feed-bar" aria-hidden="true"></span>
          <span class="pop-main"><span class="pop-title">${esc(a.title)}</span><span class="pop-meta">${U.sevBadge(a.severity)}${a.count > 1 ? `<span class="count-badge">×${U.fmtInt(a.count)}</span>` : ''}${U.relTime(a.last_ts || a.ts)}</span></span>
          ${a._unread ? '<i class="unread-dot" aria-label="unread"></i>' : ''}
        </button></li>`).join('')}</ul>`
        : U.emptyState({ icon: 'shieldCheck', title: 'Nothing critical or high', body: 'You’re all caught up.', tone: 'ok', compact: true })}
      <a class="pop-foot" href="#/alerts">${icon('alert', { size: 14 })}Open the alerts view</a>`;
  }
  function toggleBell(open) {
    const pop = $('#bell-pop');
    const btn = $('#btn-bell');
    const show = open === undefined ? pop.hidden : open;
    pop.hidden = !show;
    btn.setAttribute('aria-expanded', String(show));
    if (show) {
      renderBell();
      const r = btn.getBoundingClientRect();
      pop.style.top = `${Math.round(r.bottom + 8)}px`;
      pop.style.right = `${Math.round(window.innerWidth - r.right)}px`;
    }
  }

  /* ================================================================== desktop pop-up switch (top bar) */
  function renderNotifySwitch() {
    const n = state.notify;
    const el = $('#btn-notify');
    el.setAttribute('aria-checked', String(!!n.enabled));
    el.innerHTML = `${icon(n.enabled ? 'bellRing' : 'bellOff', { size: 16 })}<span class="notify-text">Pop-ups</span><span class="switch mini" aria-hidden="true"><span class="switch-knob"></span></span>`;
    el.title = n.enabled ? `Desktop pop-ups ON for ${n.min_severity} alerts and above. Click to turn off.` : 'Desktop pop-ups OFF. Click to turn on (alerts always show here).';
  }
  function setNotifyFromSettings(s) {
    if (s && s.notify && typeof s.notify === 'object') {
      const min = s.notify.min_severity;
      state.notify = { enabled: !!s.notify.enabled, min_severity: ['critical', 'high', 'medium', 'low'].includes(min) ? min : 'high' };
      PCS.bus.emit('notify', state.notify);
    }
  }

  /* ================================================================== display effects */
  function applyFx() {
    document.documentElement.dataset.fx = state.fx ? 'on' : 'off';
  }
  function setFx(on) {
    state.fx = !!on;
    U.store.setRaw('pcs-fx', on ? 'on' : 'off');
    applyFx();
    PCS.bus.emit('fx', state.fx);
  }

  /* ================================================================== routing */
  function parseHash() {
    const h = location.hash.replace(/^#\/?/, '');
    const [v, tab] = h.split('/');
    return { view: U.own(views(), v) ? v : DEFAULT_VIEW, tab: tab || null };
  }
  function route() {
    const r = parseHash();
    const prev = state.route;
    const v0 = current();
    if (v0 && r.view === prev.view) {
      if (r.tab !== prev.tab) {
        state.route = r;
        if (v0.onRoute) v0.onRoute(r.tab);
      }
      return;
    }
    if (v0 && v0.unmount) {
      try { v0.unmount(); } catch (e) { console.error(e); }
    }
    ui.drawer.close();
    toggleBell(false);
    state.route = r;
    state.search = '';
    const input = $('#global-search');
    input.value = '';
    const v = current();
    const outer = $('#view');
    outer.className = `view view-${v.id}`;
    outer.innerHTML = '';
    // Each mount gets its own (display: contents) container. A load() that finishes after the user has already
    // navigated away then renders into the detached old container instead of into the next view's DOM.
    const root = document.createElement('div');
    root.className = 'view-mount';
    outer.appendChild(root);
    ui.resetTrack();
    try {
      v.mount(root, r.tab);
    } catch (e) {
      console.error(e);
      root.innerHTML = U.emptyState({ icon: 'alert', title: 'This view failed to load', body: esc(e.message), tone: 'danger' });
    }
    input.placeholder = v.search || 'Filter this view…';
    $('#page-title').textContent = v.title;
    document.title = `${v.title} · PC Sentinel`;
    $('#content').scrollTop = 0;
    $('#content').classList.toggle('is-map', v.id === 'map');
    markNav();
    loadCurrent();
    schedulePoll();
  }

  /* ================================================================== polling (active view only) */
  let pollTimer = null;
  let busy = false;
  function schedulePoll() {
    clearTimeout(pollTimer);
    const v = current();
    pollTimer = setTimeout(poll, (v && v.pollMs) || POLL_MS);
  }
  async function poll() {
    if (!document.hidden) await loadCurrent();
    schedulePoll();
  }
  async function loadCurrent() {
    const v = current();
    if (!v || busy) return;
    busy = true;
    const viewAtStart = v;
    try {
      await whenIdle();
      if (current() === viewAtStart) await v.load();
    } catch (e) {
      console.error(e);
    } finally {
      busy = false;
    }
    // keep the shell (sidebar, badges) fresh when the stream is quiet and the view does not fetch the summary itself
    const sumStale = Date.now() - state.summaryAt > (state.streamLive ? 15000 : POLL_MS - 500);
    if (!['overview', 'settings'].includes(v.id) && sumStale) refreshSummary();
  }
  /* don't swap rows out from under a pressed mouse button or an active text selection */
  let pointerDown = false;
  function whenIdle() {
    const sel = window.getSelection ? String(window.getSelection()) : '';
    if (!pointerDown && !sel) return Promise.resolve();
    return new Promise((resolve) => {
      const t0 = Date.now();
      const check = () => {
        const s = window.getSelection ? String(window.getSelection()) : '';
        if ((!pointerDown && !s) || Date.now() - t0 > 15000) resolve();
        else setTimeout(check, 400);
      };
      setTimeout(check, 400);
    });
  }
  async function refreshSummary() {
    try { setSummary(await PCS.api.get('/api/summary')); } catch (e) { /* banner handles it */ }
  }
  async function refreshOpenAlerts() {
    try {
      const r = await PCS.api.get('/api/alerts?status=open&limit=500');
      mergeAlerts(r.items || [], true);
    } catch (e) { /* ignore */ }
  }
  const softRefresh = U.debounce(() => loadCurrent(), 700);
  const refresh = U.debounce(() => {
    loadCurrent();
    refreshSummary();
    refreshOpenAlerts();
  }, 250);

  /* ================================================================== live stream */
  function connectStream() {
    PCS.api.stream({
      open() {
        state.streamLive = true;
        renderLive();
      },
      error() {
        state.streamLive = false;
        renderLive();
      },
      any() {
        if (!state.streamLive) {
          state.streamLive = true;
          renderLive();
        }
      },
      metric(m) {
        state.metrics.push(m);
        const cutoff = U.ms(m.t) - 62 * 60000;
        while (state.metrics.length && U.ms(state.metrics[0].t) < cutoff) state.metrics.shift();
        PCS.bus.emit('metric', m);
      },
      alert(a) { onStreamAlert(a); },
      summary(s) { setSummary(s); },
    });
  }

  /* ================================================================== clock, uptime, relative times */
  function tickClock() {
    const now = new Date();
    $('#clock-time').textContent = U.hms(now);
    $('#clock-date').textContent = `${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][now.getDay()]} ${U.fmtDate(now)}`;
    tickUptime();
  }
  function tickUptime() {
    const e = state.summary && state.summary.engine;
    if (!e) return;
    const up = (Number(e.uptime_s) || 0) + (Date.now() - state.summaryAt) / 1000;
    $$('[data-uptime]').forEach((el) => { el.textContent = U.uptime(up); });
  }
  function tickRel() {
    $$('time.rel[data-ts]').forEach((t) => { t.textContent = U.rel(Number(t.dataset.ts)); });
  }

  /* ================================================================== global events */
  function bindGlobal() {
    document.addEventListener('pointerdown', () => { pointerDown = true; }, true);
    document.addEventListener('pointerup', () => { pointerDown = false; }, true);
    document.addEventListener('pointercancel', () => { pointerDown = false; }, true);

    document.addEventListener('click', (e) => {
      const t = e.target;
      // drawer
      if (t.closest('[data-drawer-close]') || t.id === 'drawer-scrim') {
        ui.drawer.close();
        if (current() && current().graph) current().graph.select(null);
        return;
      }
      const dact = t.closest('[data-dact]');
      if (dact && !dact.disabled && ui.drawer.current && ui.drawer.current.onAction) {
        ui.drawer.current.onAction(dact.dataset.dact, dact);
        return;
      }
      // copy
      const cp = t.closest('[data-copy]');
      if (cp) {
        e.preventDefault();
        e.stopPropagation();
        U.copyText(cp.dataset.copy).then((ok) => ui.toast({ kind: ok ? 'success' : 'error', title: ok ? 'Copied to clipboard' : 'Copy failed', message: ok ? U.middle(cp.dataset.copy, 70) : '', timeout: 2200 }));
        return;
      }
      // sort
      const s = t.closest('[data-sort-table]');
      if (s) {
        ui.toggleSort(s.dataset.sortTable, s.dataset.sortCol);
        const v = current();
        if (v) v.render();
        return;
      }
      // row quick actions
      const a = t.closest('[data-act]');
      if (a) {
        const d = a.dataset;
        if (d.act === 'kill') PCS.actions.kill({ pid: Number(d.pid), name: d.name, exe: d.exe });
        else if (d.act === 'block') PCS.actions.blockIp(d.ip);
        else if (d.act === 'allow') PCS.actions.allow({ kind: d.kind, value: d.value, label: d.label });
        else if (d.act === 'ack') PCS.actions.ack(d.id);
        return;
      }
      // alerts (rows, feed items, bell items)
      const al = t.closest('[data-alert-id]');
      if (al) {
        toggleBell(false);
        const id = al.dataset.alertId;
        const v = current();
        const fromView = v && v.items && v.items.find && v.items.find((x) => String(x.id) === id);
        PCS.openAlert(fromView || id);
        return;
      }
      // top bar
      if (t.closest('#btn-bell')) {
        toggleBell();
        return;
      }
      if (t.closest('[data-bell="read-all"]')) {
        unreadList().forEach((x) => state.seen.add(String(x.id)));
        saveSeen();
        renderBell();
        return;
      }
      if (t.closest('#btn-notify')) {
        PCS.actions.setNotify(!state.notify.enabled, state.notify.min_severity);
        return;
      }
      if (t.closest('#btn-collapse')) {
        const collapsed = document.documentElement.dataset.sidebar === 'collapsed';
        document.documentElement.dataset.sidebar = collapsed ? 'expanded' : 'collapsed';
        U.store.setRaw('pcs-sidebar', collapsed ? 'expanded' : 'collapsed');
        $('#btn-collapse').setAttribute('aria-expanded', String(collapsed));
        return;
      }
      if (t.closest('[data-retry]')) {
        loadCurrent();
        refreshSummary();
        return;
      }
      // close the bell popover on outside clicks
      if (!$('#bell-pop').hidden && !t.closest('#bell-pop')) toggleBell(false);
    });

    document.addEventListener('keydown', (e) => {
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
      if ((e.key === '/' && !typing) || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')) {
        e.preventDefault();
        $('#global-search').focus();
        $('#global-search').select();
        return;
      }
      if (e.key === 'Escape') {
        if ($('#dialog').open) return;
        if (!$('#bell-pop').hidden) {
          toggleBell(false);
          $('#btn-bell').focus();
          return;
        }
        if (ui.drawer.isOpen()) {
          ui.drawer.close();
          if (current() && current().graph) current().graph.select(null);
          return;
        }
        if (e.target.id === 'global-search' && e.target.value) {
          e.target.value = '';
          onSearchInput();
        }
        return;
      }
      if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('tr[data-alert-id]')) {
        e.preventDefault();
        e.target.click();
      }
    });

    const input = $('#global-search');
    const onSearchInput = () => {
      state.search = input.value.trim();
      const v = current();
      if (!v) return;
      if (v.onSearch) v.onSearch();
      else v.render();
    };
    input.addEventListener('input', U.debounce(onSearchInput, 120));
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        onSearchInput();
        const v = current();
        if (v && v.onSearchEnter) v.onSearchEnter();
      }
    });

    PCS.bus.on('notify', renderNotifySwitch);
    window.addEventListener('hashchange', route);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        loadCurrent();
        schedulePoll();
      }
    });
    window.addEventListener('resize', () => { if (!$('#bell-pop').hidden) toggleBell(true); });
  }

  /* ================================================================== boot */
  async function boot() {
    buildShell();
    bindGlobal();
    PCS.api.onStatus(onStatus);
    renderLive();
    tickClock();
    setInterval(tickClock, 1000);
    setInterval(tickRel, 15000);
    route();
    connectStream();
    refreshSummary();
    refreshOpenAlerts();
    setInterval(() => { if (!document.hidden && !state.streamLive) refreshOpenAlerts(); }, 30000);
    try {
      setNotifyFromSettings(await PCS.api.get('/api/settings'));
    } catch (e) { /* stays at the default: off */ }
  }

  PCS.app = { refresh, setSummary, mergeAlerts, patchAlert, markSeen, setNotifyFromSettings, tickUptime, setFx, loadCurrent };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
