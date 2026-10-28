/* PC Sentinel view: Live Map — this PC, its networked processes and their remote peers as a live force graph. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;
  const FILTER_KEY = 'pcs-map-filters';
  const FILTERS = [
    { key: 'flagged', label: 'Flagged only', icon: 'alert' },
    { key: 'hideTrusted', label: 'Hide trusted', icon: 'shieldCheck' },
    { key: 'hideLan', label: 'Hide LAN', icon: 'server' },
    { key: 'spawn', label: 'Spawn links', icon: 'gitBranch' },
  ];
  const RISKY = ['unsigned', 'suspicious', 'malicious'];

  const view = {
    id: 'map',
    title: 'Live Map',
    search: 'Highlight a process, IP or host…  (Enter to fly to it)',
    pollMs: 3000,

    mount(root) {
      this.root = root;
      this.raw = null;
      this.error = null;
      // only known boolean keys are read back from storage (no prototype tricks from a tampered localStorage value)
      const saved = U.store.get(FILTER_KEY, {}) || {};
      this.filters = {};
      FILTERS.forEach((f) => { this.filters[f.key] = U.own(saved, f.key) === true; });
      const M = PCS.MAP_COLORS;
      root.innerHTML = `
        <section class="map-shell panel brackets" aria-label="Live network map">
          <div class="map-stage" data-r="stage"></div>
          <div class="map-hud map-hud-tl">
            <div class="hud-title"><span class="live-pulse" aria-hidden="true"></span><span class="hud-label">Live map</span><span class="hud-sub" data-r="updated">connecting…</span></div>
            <div class="map-filters" role="group" aria-label="Map filters">
              ${FILTERS.map((f) => `<button type="button" class="hud-toggle" data-filter="${f.key}" aria-pressed="${this.filters[f.key] ? 'true' : 'false'}">${icon(f.icon, { size: 14 })}${f.label}</button>`).join('')}
            </div>
          </div>
          <div class="map-right">
            <div class="map-hud map-hud-tr" data-r="stats" aria-live="polite"></div>
            <div class="map-hud map-hud-r" data-r="focus" hidden></div>
          </div>
          <details class="map-hud map-hud-bl map-legend" data-r="legend" ${window.innerHeight >= 820 ? 'open' : ''}>
            <summary class="hud-label">${icon('info', { size: 12 })}Legend</summary>
            <div class="legend-body">
            <div class="legend-group"><span class="hud-label">Process trust</span>
              ${['trusted', 'known', 'unsigned', 'suspicious', 'malicious'].map((t) => `<span class="lg"><i class="lg-dot" style="--c:${M.trust[t]}"></i>${U.TRUST_LABEL[t]}</span>`).join('')}
            </div>
            <div class="legend-group"><span class="hud-label">Remote</span>
              <span class="lg"><i class="lg-dot sm" style="--c:${M.C.remote}"></i>Internet</span>
              <span class="lg"><i class="lg-dot sm" style="--c:${M.C.lan}"></i>LAN / tailnet</span>
              <span class="lg"><i class="lg-dot sm ring" style="--c:${M.C.danger}"></i>Blocklisted</span>
            </div>
            <div class="legend-group"><span class="hud-label">Links</span>
              <span class="lg"><i class="lg-line" style="--c:${M.C.net}"></i>Outbound</span>
              <span class="lg"><i class="lg-line" style="--c:${M.C.inbound}"></i>Inbound</span>
              <span class="lg"><i class="lg-line" style="--c:${M.C.danger}"></i>Danger</span>
              <span class="lg"><i class="lg-line dash" style="--c:${M.C.spawn}"></i>Spawned</span>
            </div>
            </div>
          </details>
          <div class="map-hud map-hud-br map-zoom" role="group" aria-label="Zoom">
            <button type="button" class="icon-btn hud-btn" data-zoom="in" aria-label="Zoom in" title="Zoom in (+)">${icon('plus', { size: 16 })}</button>
            <button type="button" class="icon-btn hud-btn" data-zoom="out" aria-label="Zoom out" title="Zoom out (−)">${icon('minus', { size: 16 })}</button>
            <button type="button" class="icon-btn hud-btn" data-zoom="fit" aria-label="Fit everything" title="Fit everything (0)">${icon('focus', { size: 16 })}</button>
          </div>
          <div class="map-overlay" data-r="overlay" hidden></div>
        </section>`;
      this.graph = new PCS.LiveGraph(root.querySelector('[data-r=stage]'), {
        tooltip: (d) => this.tooltip(d),
        onSelect: (d) => this.select(d),
        fitPadding: () => {
          const focus = root.querySelector('[data-r=focus]');
          const legend = root.querySelector('[data-r=legend]');
          const w = root.querySelector('.map-shell').clientWidth;
          return { l: 30, r: focus && !focus.hidden && w > 720 ? 280 : 40, t: 110, b: legend && legend.open ? 150 : 60 };
        },
      });
      this.onClick = (e) => {
        const f = e.target.closest('[data-filter]');
        if (f) {
          const k = f.dataset.filter;
          this.filters[k] = !this.filters[k];
          f.setAttribute('aria-pressed', this.filters[k] ? 'true' : 'false');
          U.store.set(FILTER_KEY, this.filters);
          this.render();
          return;
        }
        const z = e.target.closest('[data-zoom]');
        if (z) {
          if (z.dataset.zoom === 'in') this.graph.zoomBy(1.3);
          else if (z.dataset.zoom === 'out') this.graph.zoomBy(1 / 1.3);
          else this.graph.fit(true);
          return;
        }
        const fo = e.target.closest('[data-focus]');
        if (fo) {
          const id = fo.dataset.focus;
          this.graph.focus(id);
          const n = this.byId(id);
          if (n) this.select(n);
        }
      };
      root.addEventListener('click', this.onClick);
      root.querySelector('[data-r=legend]').addEventListener('toggle', () => { if (!this.graph.userMoved) this.graph.fit(true); });
      this.offFx = PCS.bus.on('fx', (on) => this.graph.setMotion(on));
      this.graph.setMotion(PCS.state.fx !== false);
      this.render();
    },

    unmount() {
      this.root.removeEventListener('click', this.onClick);
      this.offFx();
      this.graph.destroy();
    },

    async load() {
      try {
        this.raw = await PCS.api.get('/api/graph');
        this.error = null;
      } catch (e) {
        this.error = e;
      }
      this.render();
    },

    byId(id) {
      return this.raw ? this.raw.nodes.find((n) => n.id === id) : null;
    },

    /* ---------- filtering */
    filtered() {
      const g = this.raw;
      const f = this.filters;
      const nodes = new Map(g.nodes.map((n) => [n.id, n]));
      const hostT = new Set();
      const netS = new Set();
      const dangerP = new Set();
      g.edges.forEach((e) => {
        if (e.kind === 'host') hostT.add(e.target);
        if (e.kind === 'net') {
          netS.add(e.source);
          if (e.danger) dangerP.add(e.source);
        }
      });
      // "context" nodes are parents that are only on the map for spawn links: no remote peers, no live
      // connections, not an exposed listener, but the source of a spawn edge (the engine still links them to the host)
      const spawnSrc = new Set(g.edges.filter((e) => e.kind === 'spawn').map((e) => e.source));
      g.nodes.forEach((n) => {
        if (n.type === 'process') {
          n.context = !netS.has(n.id) && !(n.conns > 0) && !(n.flags || []).includes('exposed') && (spawnSrc.has(n.id) || !hostT.has(n.id));
        }
      });
      const keep = new Set(['host']);
      g.nodes.forEach((n) => {
        if (n.type !== 'process' || n.context || !(hostT.has(n.id) || netS.has(n.id))) return;
        if (f.hideTrusted && n.trust === 'trusted' && !dangerP.has(n.id)) return;
        if (f.flagged && !((n.flags && n.flags.length) || RISKY.includes(n.trust) || dangerP.has(n.id))) return;
        keep.add(n.id);
      });
      g.edges.forEach((e) => {
        if (e.kind !== 'net' || !keep.has(e.source)) return;
        const r = nodes.get(e.target);
        if (!r) return;
        if (f.hideLan && r.private) return;
        if (f.flagged && !e.danger && !RISKY.includes((nodes.get(e.source) || {}).trust) && !(r.blocklisted)) {
          // flagged view keeps only the risky edges of a kept process
          const p = nodes.get(e.source);
          if (!(p && p.flags && p.flags.length)) return;
        }
        keep.add(e.target);
      });
      if (f.spawn) {
        // parents (context nodes) that lead to something on screen, several generations up
        for (let pass = 0; pass < 5; pass++) {
          let added = false;
          g.edges.forEach((e) => {
            if (e.kind === 'spawn' && keep.has(e.target) && !keep.has(e.source) && nodes.has(e.source)) {
              keep.add(e.source);
              added = true;
            }
          });
          if (!added) break;
        }
      }
      const edges = g.edges.filter((e) => keep.has(e.source) && keep.has(e.target) && (e.kind !== 'spawn' || f.spawn)
        && !(e.kind === 'net' && f.hideLan && (nodes.get(e.target) || {}).private));
      return { nodes: g.nodes.filter((n) => keep.has(n.id)), edges };
    },

    /* ---------- rendering */
    render() {
      const overlay = this.root.querySelector('[data-r=overlay]');
      if (!this.raw) {
        overlay.hidden = false;
        overlay.innerHTML = this.error
          ? U.emptyState({ icon: 'wifiOff', title: 'Can’t reach the engine', body: 'The map appears as soon as the engine answers. Retrying every few seconds.', tone: 'danger' })
          : `<div class="map-boot"><span class="boot-ring"></span><span class="hud-label">Acquiring network map…</span></div>`;
        return;
      }
      const g = this.filtered();
      this.graph.setData(g, { showSpawn: this.filters.spawn });
      const onlyHost = g.nodes.length <= 1;
      overlay.hidden = !onlyHost;
      if (onlyHost) {
        overlay.innerHTML = U.emptyState({
          icon: 'radar', title: this.raw.nodes.length > 1 ? 'Nothing matches these filters' : 'No network activity yet',
          body: this.raw.nodes.length > 1 ? 'Turn a filter off to see more of the map.' : 'Processes appear here as soon as they open a connection or a listening port.',
        });
      }
      this.renderStats(g);
      this.renderFocus(g);
      this.root.querySelector('[data-r=updated]').textContent = this.raw.generated ? `updated ${U.hms(this.raw.generated)}` : 'live';
      this.onSearch(true);
      if (ui.drawer.isOpen() && ui.drawer.current.key && ui.drawer.current.key.startsWith('node:')) {
        const id = ui.drawer.current.key.slice(5);
        const n = this.byId(id);
        if (n) {
          this.goneKey = null;
          ui.drawer.update(this.drawerHtml(n));
        } else if (this.goneKey !== id) {
          this.goneKey = id;
          ui.drawer.update(ui.drawerFrame({
            eyebrow: '<span class="hud-label">Node</span>',
            title: 'No longer on the map',
            sub: 'The process exited or all of its connections closed. It reappears here if it comes back.',
            body: U.emptyState({ icon: 'radar', title: 'Nothing to show', compact: true }),
          }));
        }
      }
    },

    renderStats(g) {
      const procs = g.nodes.filter((n) => n.type === 'process').length;
      const remotes = g.nodes.filter((n) => n.type === 'remote').length;
      const links = g.edges.filter((e) => e.kind === 'net').reduce((a, e) => a + (e.count || 1), 0);
      const danger = g.edges.filter((e) => e.kind === 'net' && e.danger).length;
      const box = this.root.querySelector('[data-r=stats]');
      box.innerHTML = `
        <div class="stat"><span class="hud-label">Processes</span><b class="num" data-n="p"></b></div>
        <div class="stat"><span class="hud-label">Remotes</span><b class="num" data-n="r"></b></div>
        <div class="stat"><span class="hud-label">Connections</span><b class="num" data-n="c"></b></div>
        <div class="stat ${danger ? 'is-danger' : ''}"><span class="hud-label">Danger links</span><b class="num" data-n="d"></b></div>
        <div class="stat match" data-r="matches" hidden><span class="hud-label">Matches</span><b class="num" data-n="m">0</b></div>`;
      const set = (k, v) => {
        const el = box.querySelector(`[data-n=${k}]`);
        el._v = this.prevStats ? this.prevStats[k] : undefined;
        ui.countUp(el, v);
      };
      set('p', procs);
      set('r', remotes);
      set('c', links);
      set('d', danger);
      this.prevStats = { p: procs, r: remotes, c: links, d: danger };
    },

    renderFocus(g) {
      const deg = {};
      g.edges.forEach((e) => {
        if (e.kind !== 'net') return;
        deg[e.source] = deg[e.source] || { count: 0, danger: false, ports: new Set() };
        deg[e.source].count += e.count || 1;
        deg[e.source].danger = deg[e.source].danger || e.danger;
      });
      const items = [];
      g.nodes.forEach((n) => {
        if (n.type === 'process') {
          const rank = { malicious: 0, suspicious: 1, unsigned: 3 }[n.trust];
          const d = deg[n.id];
          if (rank !== undefined || (d && d.danger)) {
            items.push({ id: n.id, rank: d && d.danger ? Math.min(rank === undefined ? 2 : rank, 0.5) : rank, label: n.label, tone: U.trustKey(n.trust), why: `${U.own(U.TRUST_LABEL, n.trust) || U.humanize(n.trust)} · ${U.plural(n.conns || (d ? d.count : 0), 'conn')}` });
          }
        } else if (n.type === 'remote' && n.blocklisted) {
          items.push({ id: n.id, rank: 0.2, label: n.host || n.ip, tone: 'malicious', why: `Blocklisted · ${(n.ports || []).join(', ')}` });
        }
      });
      items.sort((a, b) => a.rank - b.rank);
      const box = this.root.querySelector('[data-r=focus]');
      if (!items.length) {
        box.hidden = true;
        return;
      }
      box.hidden = false;
      box.innerHTML = `<div class="hud-label">${icon('target', { size: 12 })}Threat focus</div>
        <ul class="focus-list">${items.slice(0, 6).map((it) => `<li><button type="button" class="focus-item tone-${esc(it.tone)}" data-focus="${esc(it.id)}">
          <i class="focus-dot"></i><span class="focus-text"><b class="mono">${esc(U.middle(it.label, 26))}</b><small>${esc(it.why)}</small></span>${icon('chevronRight', { size: 14 })}</button></li>`).join('')}</ul>`;
    },

    onSearch(silent) {
      const n = this.graph.setHighlight(PCS.state.search);
      const box = this.root.querySelector('[data-r=matches]');
      if (box) {
        box.hidden = n === null;
        if (n !== null) box.querySelector('b').textContent = String(n);
      }
      if (!silent && n === 0) this.graph.dirty = true;
    },
    onSearchEnter() {
      const n = this.graph.firstMatch();
      if (n) {
        this.graph.focus(n.id);
        this.graph.select(n.id);
      }
    },

    /* ---------- tooltip + drawer */
    neighbours(id) {
      const out = [];
      if (!this.raw) return out;
      this.raw.edges.forEach((e) => {
        if (e.kind !== 'net') return;
        if (e.source === id) out.push({ edge: e, node: this.byId(e.target) });
        else if (e.target === id) out.push({ edge: e, node: this.byId(e.source) });
      });
      return out.filter((x) => x.node);
    },

    tooltip(d) {
      if (d.type === 'host') {
        const g = this.raw || { nodes: [] };
        return `<div class="tip-eyebrow hud-label">This PC</div><div class="tip-title">${esc(d.label)}</div>
          <div class="tip-meta">${U.plural(g.nodes.filter((n) => n.type === 'process').length, 'process', 'processes')} · ${U.plural(g.nodes.filter((n) => n.type === 'remote').length, 'remote')}</div>`;
      }
      if (d.type === 'process') {
        const pids = d.pids || [];
        return `<div class="tip-eyebrow hud-label">Process</div>
          <div class="tip-title mono">${esc(d.label)}</div>
          <div class="tip-meta">${U.trustBadge(d.trust)}<span>${U.plural(d.conns || 0, 'conn')}</span><span>${U.plural(pids.length, 'PID')}</span></div>
          <div class="tip-meta mono">CPU ${esc(U.fmtPct(d.cpu))} · ${esc(U.fmtMem(d.mem_mb))}</div>
          ${U.flagChips(d.flags, 3)}
          <div class="tip-hint">Click for details and actions</div>`;
      }
      const peers = this.neighbours(d.id).map((x) => x.node.label);
      return `<div class="tip-eyebrow hud-label">${d.blocklisted ? '<span class="tone-critical">Blocklisted remote</span>' : d.private ? 'Local network' : 'Remote host'}</div>
        <div class="tip-title mono">${esc(d.host || d.ip)}</div>
        <div class="tip-meta mono">${d.host ? `${esc(d.ip)} · ` : ''}port ${esc((d.ports || []).join(', '))}</div>
        ${peers.length ? `<div class="tip-meta">← ${esc(U.uniq(peers).slice(0, 3).join(', '))}${peers.length > 3 ? '…' : ''}</div>` : ''}
        <div class="tip-hint">Click for details and actions</div>`;
    },

    select(d) {
      if (!d) {
        this.graph.select(null);
        return;
      }
      this.graph.select(d.id);
      ui.drawer.open(this.drawerHtml(d), {
        key: `node:${d.id}`,
        onAction: (act, el) => this.action(act, el),
      });
    },

    drawerHtml(d) {
      if (d.type === 'host') {
        const s = PCS.state.summary || {};
        const eng = s.engine || {};
        const g = this.raw || { nodes: [], edges: [] };
        return ui.drawerFrame({
          eyebrow: `<span class="hud-label">${icon('monitor', { size: 13 })}This PC</span>`,
          title: esc(d.label),
          sub: 'The centre of the map. Every process with network activity hangs off this node.',
          body: ui.section('On the map', ui.kv([
            ['Processes', U.fmtInt(g.nodes.filter((n) => n.type === 'process').length)],
            ['Remote hosts', U.fmtInt(g.nodes.filter((n) => n.type === 'remote').length)],
            ['Connections', U.fmtInt(g.edges.filter((e) => e.kind === 'net').reduce((a, e) => a + (Number(e.count) || 1), 0))],
          ]), 'radar') + ui.section('Engine', ui.kv([
            ['System', esc(U.osLabel(s) || '—')],
            ['User', esc(eng.user || '—')],
            ['Elevated', eng.elevated ? '<span class="pill tone-ok">Yes</span>' : '<span class="pill tone-warn">No</span>'],
            ['Version', esc(eng.version || '—')],
          ]), 'server'),
          foot: '<a class="btn" href="#/overview">Open overview</a>',
        });
      }
      if (d.type === 'process') {
        const peers = this.neighbours(d.id);
        const pids = d.pids || [];
        const pidList = pids.length > 1
          ? `<ul class="pid-list">${pids.map((p) => `<li><span class="mono">PID ${esc(p)}</span><button type="button" class="btn btn-sm btn-danger-soft" data-dact="kill" data-pid="${esc(p)}">${icon('kill', { size: 14 })}Kill</button></li>`).join('')}</ul>`
          : '';
        const peerRows = peers.length ? `<ul class="peer-list">${peers.sort((a, b) => (b.edge.danger - a.edge.danger) || (b.edge.count - a.edge.count)).map(({ edge, node }) => `
            <li class="${edge.danger ? 'is-danger' : ''}">
              <span class="peer-dir" title="${edge.direction === 'in' ? 'Inbound' : 'Outbound'}">${icon(edge.direction === 'in' ? 'arrowIn' : 'arrowOut', { size: 14 })}</span>
              <span class="peer-main"><b class="mono">${esc(node.host || node.ip)}</b><small class="mono">${esc(U.endpoint(node.ip))} · ${esc([].concat(edge.ports || []).join(', '))}${Array.isArray(edge.states) && edge.states.length ? ` · ${esc(edge.states.join('/'))}` : ''}</small></span>
              <span class="peer-tags">${node.blocklisted ? '<span class="chip tone-danger">Blocklisted</span>' : ''}${U.netTag(node.ip)}<span class="count-badge">×${U.fmtInt(edge.count || 1)}</span></span>
              ${U.isPublicIp(node.ip) ? `<button type="button" class="icon-btn sm act act-danger" data-dact="block" data-ip="${esc(node.ip)}" aria-label="Block ${esc(node.ip)}" title="Block ${esc(node.ip)}">${icon('ban', { size: 15 })}</button>` : ''}
            </li>`).join('')}</ul>` : '<p class="muted small">No remote peers right now (listening only).</p>';
        return ui.drawerFrame({
          eyebrow: `${U.trustBadge(d.trust)}<span class="hud-label">Process node</span>`,
          title: `<span class="mono">${esc(d.label)}</span>`,
          sub: d.signer ? `Signed by ${esc(d.signer)}` : 'No publisher signature',
          meta: `<span>${U.plural(d.conns || 0, 'connection')}</span><span>${U.plural(pids.length, 'PID')}</span><span>CPU ${esc(U.fmtPct(d.cpu))}</span><span>${esc(U.fmtMem(d.mem_mb))}</span>`,
          body: ui.section('Identity', ui.kv([
            ['Executable', d.exe ? U.copyBtn(d.exe, d.exe, 'mono path wrap') : ''],
            ['Signer', esc(d.signer || '')],
            ['Signature', U.sigText(d.sig_status)],
            ['Trust', U.trustBadge(d.trust)],
            ['Parent', d.parent ? `<span class="mono">${esc(d.parent)}</span>` : ''],
            ['PIDs', pids.length === 1 ? `<span class="mono">${esc(pids[0])}</span>` : `<span class="mono">${esc(pids.slice(0, 12).join(', '))}${pids.length > 12 ? '…' : ''}</span>`],
          ]), 'cpu')
            + (d.flags && d.flags.length ? ui.section('Flags', U.flagChips(d.flags), 'flag') : '')
            + ui.section(`Remote peers (${peers.length})`, peerRows, 'globe')
            + (pidList ? ui.section('Instances', pidList, 'list') : ''),
          foot: [
            pids.length === 1 ? ui.dbtn('kill', 'Kill process', 'kill', { cls: 'btn-danger' }) : '',
            ui.dbtn('allow', 'Allow…', 'allow'),
            ui.dbtn('copy', 'Copy JSON', 'braces', { cls: 'btn-ghost' }),
          ].join(''),
        });
      }
      const peers = this.neighbours(d.id);
      const kind = U.ipKind(d.ip);
      return ui.drawerFrame({
        eyebrow: `${d.blocklisted ? '<span class="badge sev-critical"><span class="badge-dot"></span>Blocklisted</span>' : ''}<span class="hud-label">Remote node</span>`,
        title: `<span class="mono">${esc(d.host || d.ip)}</span>`,
        sub: d.host ? `<span class="mono">${esc(d.ip)}</span>` : 'No reverse hostname',
        body: ui.section('Address', ui.kv([
          ['IP', U.copyBtn(d.ip, d.ip, 'mono')],
          ['Hostname', d.host ? `<span class="mono">${esc(d.host)}</span>` : ''],
          ['Ports', `<span class="mono">${esc((d.ports || []).join(', '))}</span>`],
          ['Network', esc({ public: 'Internet', lan: 'Local network', tailnet: 'Tailscale (CGNAT range)', loopback: 'Loopback' }[kind] || (d.private ? 'Private' : 'Internet'))],
          ['Blocklisted', d.blocklisted ? '<span class="pill tone-danger">Yes</span>' : '<span class="pill">No</span>'],
        ]), 'target')
          + ui.section(`Talking to (${peers.length})`, peers.length ? `<ul class="peer-list">${peers.map(({ edge, node }) => `
            <li class="${edge.danger ? 'is-danger' : ''}">
              <span class="peer-dir">${icon(edge.direction === 'in' ? 'arrowIn' : 'arrowOut', { size: 14 })}</span>
              <span class="peer-main"><b class="mono">${esc(node.label)}</b><small>${U.trustBadge(node.trust)} ${esc([].concat(edge.ports || []).join(', '))}</small></span>
              <span class="peer-tags"><span class="count-badge">×${U.fmtInt(edge.count || 1)}</span></span>
            </li>`).join('')}</ul>` : '<p class="muted small">No live connections.</p>', 'cpu'),
        foot: [
          U.isPublicIp(d.ip) ? ui.dbtn('block', 'Block IP', 'ban', { cls: 'btn-danger' }) : ui.dbtn('block', 'Block IP', 'ban', { disabled: true, why: 'Local and private addresses can’t be blocked here' }),
          ui.dbtn('allow', 'Allow destination', 'allow'),
          ui.dbtn('copy', 'Copy IP', 'copy', { cls: 'btn-ghost' }),
        ].join(''),
      });
    },

    action(act, el) {
      const key = ui.drawer.current && ui.drawer.current.key;
      const d = key ? this.byId(key.slice(5)) : null;
      if (!d) return;
      if (act === 'kill') {
        const pid = el.dataset.pid ? Number(el.dataset.pid) : (d.pids || [])[0];
        PCS.actions.kill({ pid, name: d.label, exe: d.exe });
      } else if (act === 'block') {
        PCS.actions.blockIp(el.dataset.ip || d.ip);
      } else if (act === 'allow') {
        if (d.type === 'remote') PCS.actions.allow({ kind: 'destination', value: d.ip });
        else PCS.actions.allow({ kind: 'process', value: d.exe || d.label });
      } else if (act === 'copy') {
        U.copyText(d.type === 'remote' ? d.ip : JSON.stringify(d, null, 2)).then((ok) => ui.toast({ kind: ok ? 'success' : 'error', title: ok ? 'Copied' : 'Copy failed' }));
      }
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.map = view;
})();
