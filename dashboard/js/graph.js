/* PC Sentinel: Live Map engine — a small force-directed graph on <canvas>, no libraries.
   Forces: many-body repulsion, link springs, radial rings (processes inner orbit, remotes outer orbit), collision.
   Rendering: DPR-aware canvas, cached glow sprites, curved net edges with flowing "packets", radar sweep,
   pulsing halo on malicious nodes. Updates merge into the running layout (positions kept, new nodes ease in,
   removed nodes fade out). Interaction: pan (drag background), zoom (wheel/buttons/keys), drag nodes,
   hover tooltip, click to select. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;

  const TRUST_COLOR = { trusted: '#2dd4bf', known: '#7c93d8', unsigned: '#f59e0b', suspicious: '#fb923c', malicious: '#ef4444' };
  const C = {
    host: '#22d3ee', remote: '#7dd3fc', lan: '#64748b', danger: '#ef4444', net: '#38bdf8', spawn: '#94a3b8',
    packet: '#a5f3fc', inbound: '#c4b5fd', label: '#dbe7f5', labelDim: '#8ea0b8', ring: '#22d3ee', bg: 'rgba(5,8,15,0.72)',
  };
  const MONO = '"Cascadia Mono", Consolas, monospace';
  const RING_PROC = 215;
  const RING_REMOTE = 400;

  function hexA(hex, a) {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
  }
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const easeOut = (k) => 1 - Math.pow(1 - k, 3);

  /* glow sprites: one radial-gradient canvas per colour, scaled with drawImage (much cheaper than shadowBlur) */
  const sprites = {};
  function glow(color) {
    if (sprites[color]) return sprites[color];
    const s = 128;
    const cv = document.createElement('canvas');
    cv.width = s;
    cv.height = s;
    const g = cv.getContext('2d');
    const grd = g.createRadialGradient(s / 2, s / 2, 0, s / 2, s / 2, s / 2);
    grd.addColorStop(0, hexA(color, 0.55));
    grd.addColorStop(0.35, hexA(color, 0.18));
    grd.addColorStop(1, hexA(color, 0));
    g.fillStyle = grd;
    g.fillRect(0, 0, s, s);
    sprites[color] = cv;
    return cv;
  }

  class LiveGraph {
    constructor(container, opts) {
      this.el = container;
      this.opts = opts || {};
      this.canvas = document.createElement('canvas');
      this.canvas.className = 'map-canvas';
      this.canvas.tabIndex = 0;
      this.canvas.setAttribute('role', 'img');
      this.canvas.setAttribute('aria-label', 'Live network map. Drag to pan, scroll or press plus and minus to zoom, 0 to fit, click a node for details.');
      this.tip = document.createElement('div');
      this.tip.className = 'map-tip';
      this.tip.hidden = true;
      container.append(this.canvas, this.tip);
      this.ctx = this.canvas.getContext('2d');

      this.nodes = new Map();
      this.edges = new Map();
      this.posCache = new Map();
      this.t = { x: 0, y: 0, k: 0.85 };
      this.alpha = 1;
      this.alphaTarget = 0;
      this.showSpawn = false;
      this.motion = !U.reducedMotion();
      this.hover = null;
      this.selected = null;
      this.matches = null;
      this.userMoved = false;
      this.autoFit = true;
      this.w = 0;
      this.h = 0;
      this.dpr = window.devicePixelRatio || 1;
      this.last = performance.now();
      this.lastDraw = 0;
      this.dirty = true;

      this.bind();
      this.ro = new ResizeObserver(() => this.resize());
      this.ro.observe(container);
      this.resize();
      this.loop = this.loop.bind(this);
      this.lastLoop = performance.now();
      this.raf = requestAnimationFrame(this.loop);
      // watchdog: occluded windows / hidden panes can stall rAF; keep the layout and picture current anyway
      this.watch = setInterval(() => {
        if (performance.now() - this.lastLoop < 1500) return;
        for (let i = 0; i < 60 && this.alpha > 0.004; i++) this.tick();
        this.nodes.forEach((n) => {
          n.a = n.dying ? 0 : 1;
          n.r = n.tr;
        });
        this.edges.forEach((e) => { e.a = e.dying ? 0 : 1; });
        this.reap();
        if (this.tween) {
          this.t = this.tween.to;
          this.tween = null;
        }
        if (this.autoFit && !this.userMoved && !this.didAutoFit && this.alpha < 0.12 && this.nodes.size > 1) {
          this.didAutoFit = true;
          this.fit(false);
        }
        this.draw(performance.now());
      }, 1000);
    }

    /* ------------------------------------------------------------ data merge */
    setData(graph, opts) {
      const o = opts || {};
      this.showSpawn = !!o.showSpawn;
      const inNodes = (graph && graph.nodes) || [];
      const inEdges = ((graph && graph.edges) || []).filter((e) => e && e.source && e.target);
      const ids = new Set(inNodes.map((n) => n.id));
      const hostEdge = new Set();
      const netCount = {};
      inEdges.forEach((e) => {
        if (e.kind === 'host') hostEdge.add(e.target);
        if (e.kind === 'net') {
          hostEdge.add(e.source);
          netCount[e.target] = (netCount[e.target] || 0) + (e.count || 1);
          netCount[e.source] = (netCount[e.source] || 0) + (e.count || 1);
        }
      });

      let structural = false;
      // retire nodes that disappeared
      this.nodes.forEach((n, id) => {
        if (!ids.has(id) && !n.dying) {
          n.dying = true;
          structural = true;
        }
      });
      // add / update (host first, then processes, then remotes, so new nodes find placed anchors)
      const order = { host: 0, process: 1, remote: 2 };
      inNodes.slice().sort((a, b) => (order[a.type] || 3) - (order[b.type] || 3)).forEach((d) => {
        let n = this.nodes.get(d.id);
        if (!n) {
          n = this.makeNode(d, inEdges);
          this.nodes.set(d.id, n);
          structural = true;
        } else if (n.dying) {
          n.dying = false;
          structural = true;
        }
        n.d = d;
        n.type = d.type;
        n.context = d.type === 'process' && (d.context === true || !hostEdge.has(d.id));
        n.netCount = netCount[d.id] || 0;
        n.tr = this.radiusFor(n);
        n.color = this.colorFor(n);
        n.label = d.type === 'remote' ? d.host || d.label || d.ip : d.label || d.id;
        n.hay = U.hay(d.label, d.exe, d.ip, d.host, d.signer, d.trust, d.blocklisted ? 'blocklisted' : '', d.private ? 'lan private' : '', (d.pids || []).join(' '), (d.ports || []).join(' ')).toLowerCase();
      });
      // edges
      const keys = new Set();
      inEdges.forEach((d) => {
        if (d.kind === 'spawn' && !this.showSpawn) return;
        const s = this.nodes.get(d.source);
        const t = this.nodes.get(d.target);
        if (!s || !t || !ids.has(d.source) || !ids.has(d.target)) return;
        const key = `${d.source}>${d.target}:${d.kind}:${d.direction || ''}`;
        keys.add(key);
        let e = this.edges.get(key);
        if (!e) {
          e = { key, a: 0, dying: false, seed: Math.random() };
          this.edges.set(key, e);
          structural = true;
        } else if (e.dying) {
          e.dying = false;
          structural = true;
        }
        e.source = s;
        e.target = t;
        e.kind = d.kind;
        e.d = d;
      });
      this.edges.forEach((e, k) => {
        if (!keys.has(k) && !e.dying) {
          e.dying = true;
          structural = true;
        }
      });
      this.computeDegrees();
      if (structural) this.reheat(this.nodes.size > 1 && this.everLaidOut ? 0.35 : 1);
      this.everLaidOut = true;
      if (this.matches) this.setHighlight(this.query);
      this.dirty = true;
      // no animation frames while reduced-motion is on or the page is hidden: lay out to rest right away
      if (!this.motion || document.hidden) this.settle();
    }

    makeNode(d, inEdges) {
      const n = { id: d.id, type: d.type, d, x: 0, y: 0, vx: 0, vy: 0, r: 0, tr: 4, a: 0, dying: false, fx: null, fy: null, seed: Math.random() * Math.PI * 2 };
      const cached = this.posCache.get(d.id);
      if (d.type === 'host') {
        n.fx = 0;
        n.fy = 0;
      } else if (cached) {
        n.x = cached.x;
        n.y = cached.y;
      } else {
        let anchor = null;
        for (const e of inEdges) {
          const other = e.source === d.id ? e.target : e.target === d.id ? e.source : null;
          if (other && other !== 'host' && this.nodes.has(other)) { anchor = this.nodes.get(other); break; }
        }
        const ang = Math.random() * Math.PI * 2;
        if (anchor) {
          const dist = d.type === 'remote' ? 46 : 60;
          n.x = anchor.x + Math.cos(ang) * dist;
          n.y = anchor.y + Math.sin(ang) * dist;
        } else {
          const R = (d.type === 'process' ? RING_PROC : RING_REMOTE) * (this.everLaidOut ? 1 : 0.25);
          n.x = Math.cos(ang) * R;
          n.y = Math.sin(ang) * R;
        }
      }
      return n;
    }

    radiusFor(n) {
      if (n.type === 'host') return 21;
      if (n.type === 'process') return n.context ? 5 : Math.min(24, 6.5 + 2.4 * Math.sqrt(n.d.conns || n.netCount || 0));
      return Math.min(7.5, 3.2 + 0.9 * Math.sqrt(n.netCount || 1));
    }
    colorFor(n) {
      if (n.type === 'host') return C.host;
      if (n.type === 'process') return TRUST_COLOR[U.trustKey(n.d.trust)];
      if (n.d.blocklisted) return C.danger;
      if (n.d.private) return C.lan;
      return C.remote;
    }
    computeDegrees() {
      this.nodes.forEach((n) => { n.deg = 0; });
      this.edges.forEach((e) => {
        if (e.dying) return;
        e.source.deg++;
        e.target.deg++;
      });
    }
    reheat(a) {
      this.alpha = Math.max(this.alpha, a);
    }

    /* ------------------------------------------------------------ simulation */
    tick() {
      this.alpha += (this.alphaTarget - this.alpha) * 0.03;
      const alpha = this.alpha;
      const list = [];
      this.nodes.forEach((n) => { if (!n.dying) list.push(n); });
      const len = list.length;
      // many-body + collision (O(n²) is fine for a few hundred nodes)
      for (let i = 0; i < len; i++) {
        const a = list[i];
        const ca = a.type === 'host' ? -700 : a.type === 'process' ? (a.context ? -110 : -340) : -55;
        for (let j = i + 1; j < len; j++) {
          const b = list[j];
          let dx = b.x - a.x;
          let dy = b.y - a.y;
          let d2 = dx * dx + dy * dy;
          if (d2 > 360000) continue;
          if (d2 < 1) {
            dx = (Math.random() - 0.5) * 2;
            dy = (Math.random() - 0.5) * 2;
            d2 = dx * dx + dy * dy + 0.01;
          }
          const cb = b.type === 'host' ? -700 : b.type === 'process' ? (b.context ? -110 : -340) : -55;
          const w = alpha / d2;
          a.vx += dx * cb * w;
          a.vy += dy * cb * w;
          b.vx -= dx * ca * w;
          b.vy -= dy * ca * w;
          // processes keep room for their labels; remotes may pack tighter
          const pad = a.type === 'remote' && b.type === 'remote' ? 6 : a.type === 'process' && b.type === 'process' ? 38 : 14;
          const min = a.r + b.r + pad;
          if (d2 < min * min) {
            const d = Math.sqrt(d2);
            const push = ((min - d) / d) * 0.35;
            const ra = b.r * b.r / (a.r * a.r + b.r * b.r + 0.01);
            a.vx -= dx * push * ra;
            a.vy -= dy * push * ra;
            b.vx += dx * push * (1 - ra);
            b.vy += dy * push * (1 - ra);
          }
        }
      }
      // links
      this.edges.forEach((e) => {
        if (e.dying) return;
        const s = e.source;
        const t = e.target;
        let dist;
        let strength;
        if (e.kind === 'host') { dist = RING_PROC * 0.85 + t.r; strength = 0.35; }
        else if (e.kind === 'spawn') { dist = 70; strength = 0.12; }
        else { dist = 34 + s.r + t.r * 2; strength = 0.9; }
        strength /= Math.max(1, Math.min(s.deg, t.deg));
        let dx = t.x + t.vx - s.x - s.vx;
        let dy = t.y + t.vy - s.y - s.vy;
        let l = Math.sqrt(dx * dx + dy * dy) || 1;
        l = ((l - dist) / l) * alpha * strength;
        dx *= l;
        dy *= l;
        const bias = s.deg / (s.deg + t.deg || 1);
        t.vx -= dx * bias;
        t.vy -= dy * bias;
        s.vx += dx * (1 - bias);
        s.vy += dy * (1 - bias);
      });
      // radial rings around the host
      for (const n of list) {
        if (n.type === 'host') continue;
        const R = n.type === 'process' ? (n.context ? RING_PROC * 0.55 : RING_PROC) : RING_REMOTE;
        const s = n.type === 'process' ? 0.05 : 0.025;
        const r = Math.sqrt(n.x * n.x + n.y * n.y) || 1;
        const k = ((R - r) * s * alpha) / r;
        n.vx += n.x * k;
        n.vy += n.y * k;
      }
      // integrate
      for (const n of list) {
        if (n.fx !== null) {
          n.x = n.fx;
          n.y = n.fy;
          n.vx = 0;
          n.vy = 0;
          continue;
        }
        n.vx *= 0.58;
        n.vy *= 0.58;
        n.x += clamp(n.vx, -40, 40);
        n.y += clamp(n.vy, -40, 40);
      }
    }
    /** Reduced motion: run the layout to rest synchronously, then draw once. */
    settle() {
      for (let i = 0; i < 260 && this.alpha > 0.004; i++) this.tick();
      this.nodes.forEach((n) => {
        n.r = n.tr;
        n.a = n.dying ? 0 : 1;
      });
      this.edges.forEach((e) => { e.a = e.dying ? 0 : 1; });
      this.reap();
      if (this.autoFit && !this.userMoved) this.fit(false);
      this.dirty = true;
      this.draw(performance.now());
    }
    reap() {
      this.nodes.forEach((n, id) => {
        if (n.dying && n.a <= 0.01) {
          this.posCache.set(id, { x: n.x, y: n.y });
          this.nodes.delete(id);
          if (this.hover === n) this.hover = null;
        }
      });
      this.edges.forEach((e, k) => {
        if ((e.dying && e.a <= 0.01) || !this.nodes.has(e.source.id) || !this.nodes.has(e.target.id)) this.edges.delete(k);
      });
      if (this.posCache.size > 600) this.posCache.clear();
    }

    /* ------------------------------------------------------------ frame loop */
    loop(now) {
      this.raf = requestAnimationFrame(this.loop);
      this.lastLoop = performance.now();
      const dt = Math.min(64, now - this.last);
      this.last = now;
      const simActive = this.alpha > 0.004 || this.dragging;
      if (this.motion && simActive) this.tick();
      let animating = false;
      const fade = this.motion ? dt / 450 : 1;
      this.nodes.forEach((n) => {
        const ta = n.dying ? 0 : 1;
        if (n.a !== ta) {
          n.a = ta > n.a ? Math.min(ta, n.a + fade) : Math.max(ta, n.a - fade);
          animating = true;
        }
        if (Math.abs(n.r - n.tr) > 0.05) {
          n.r += (n.tr - n.r) * (this.motion ? Math.min(1, dt / 160) : 1);
          animating = true;
        } else n.r = n.tr;
      });
      this.edges.forEach((e) => {
        const ta = e.dying ? 0 : 1;
        if (e.a !== ta) {
          e.a = ta > e.a ? Math.min(ta, e.a + fade) : Math.max(ta, e.a - fade);
          animating = true;
        }
      });
      if (animating) this.reap();
      if (this.tween) {
        const k = Math.min(1, (now - this.tween.t0) / this.tween.dur);
        const e = easeOut(k);
        this.t = { x: this.tween.from.x + (this.tween.to.x - this.tween.from.x) * e, y: this.tween.from.y + (this.tween.to.y - this.tween.from.y) * e, k: this.tween.from.k + (this.tween.to.k - this.tween.from.k) * e };
        if (k >= 1) this.tween = null;
        animating = true;
      }
      if (this.autoFit && !this.userMoved && this.motion && this.alpha < 0.12 && !this.didAutoFit && this.nodes.size > 1) {
        this.didAutoFit = true;
        this.fit(true);
      }
      // continuous drawing is only needed for motion (packets/sweep/pulse); cap idle redraws at ~30 fps
      const live = this.motion && (simActive || animating || now - this.lastDraw > 32);
      if (this.dirty || animating || simActive || live) {
        this.draw(now);
        this.lastDraw = now;
        this.dirty = false;
      }
    }

    /* ------------------------------------------------------------ geometry */
    resize() {
      const r = this.el.getBoundingClientRect();
      const w = Math.round(r.width);
      const h = Math.round(r.height);
      if (!w || !h) return;
      this.w = w;
      this.h = h;
      this.dpr = window.devicePixelRatio || 1;
      this.canvas.width = Math.round(w * this.dpr);
      this.canvas.height = Math.round(h * this.dpr);
      this.canvas.style.width = `${w}px`;
      this.canvas.style.height = `${h}px`;
      this.dirty = true;
      if (!this.motion || document.hidden) this.draw(performance.now());
    }
    toWorld(sx, sy) {
      return { x: (sx - this.w / 2 - this.t.x) / this.t.k, y: (sy - this.h / 2 - this.t.y) / this.t.k };
    }
    toScreen(x, y) {
      return { x: x * this.t.k + this.w / 2 + this.t.x, y: y * this.t.k + this.h / 2 + this.t.y };
    }
    nodeAt(sx, sy) {
      const p = this.toWorld(sx, sy);
      let best = null;
      let bd = Infinity;
      this.nodes.forEach((n) => {
        if (n.dying || n.a < 0.3 || !this.visible(n)) return;
        const d = Math.hypot(n.x - p.x, n.y - p.y);
        const hit = n.r + 5 / this.t.k;
        if (d <= hit && d < bd) { bd = d; best = n; }
      });
      return best;
    }
    visible() {
      return true;
    }
    animateTo(to, dur) {
      if (!this.motion || document.hidden) {
        this.t = to;
        this.dirty = true;
        if (!this.motion) this.draw(performance.now());
        return;
      }
      this.tween = { from: Object.assign({}, this.t), to, t0: performance.now(), dur: dur || 600 };
    }
    fit(animate) {
      let minX = Infinity;
      let minY = Infinity;
      let maxX = -Infinity;
      let maxY = -Infinity;
      this.nodes.forEach((n) => {
        if (n.dying) return;
        minX = Math.min(minX, n.x - n.r);
        maxX = Math.max(maxX, n.x + n.r);
        minY = Math.min(minY, n.y - n.r);
        maxY = Math.max(maxY, n.y + n.r);
      });
      if (!isFinite(minX) || !this.w) return;
      // padding leaves room for the HUD panels laid over the canvas (labels need ~20px below nodes)
      const p = Object.assign({ l: 60, r: 60, t: 60, b: 60 }, typeof this.opts.fitPadding === 'function' ? this.opts.fitPadding() : this.opts.fitPadding);
      const aw = Math.max(120, this.w - p.l - p.r);
      const ah = Math.max(120, this.h - p.t - p.b);
      const k = clamp(Math.min(aw / Math.max(80, maxX - minX), ah / Math.max(80, maxY - minY + 30)), 0.3, 1.6);
      const cx = (minX + maxX) / 2;
      const cy = (minY + maxY + 30) / 2;
      const to = { k, x: p.l + aw / 2 - this.w / 2 - cx * k, y: p.t + ah / 2 - this.h / 2 - cy * k };
      if (animate) this.animateTo(to, 700);
      else {
        this.t = to;
        this.dirty = true;
      }
    }
    zoomBy(f, sx, sy) {
      const cx = sx === undefined ? this.w / 2 : sx;
      const cy = sy === undefined ? this.h / 2 : sy;
      const k = clamp(this.t.k * f, 0.25, 4);
      const wpt = this.toWorld(cx, cy);
      const to = { k, x: cx - this.w / 2 - wpt.x * k, y: cy - this.h / 2 - wpt.y * k };
      this.userMoved = true;
      if (sx === undefined) this.animateTo(to, 260);
      else {
        this.tween = null;
        this.t = to;
        this.dirty = true;
      }
    }
    focus(id) {
      const n = this.nodes.get(id);
      if (!n) return false;
      const k = Math.max(this.t.k, 1.15);
      this.userMoved = true;
      this.animateTo({ k, x: -n.x * k, y: -n.y * k }, 650);
      return true;
    }
    select(id) {
      this.selected = id || null;
      this.dirty = true;
    }
    setHighlight(q) {
      this.query = q;
      const m = U.makeMatcher(q);
      if (!m) {
        this.matches = null;
      } else {
        this.matches = new Set();
        this.nodes.forEach((n) => { if (!n.dying && m(n.hay)) this.matches.add(n.id); });
      }
      this.dirty = true;
      return this.matches ? this.matches.size : null;
    }
    firstMatch() {
      if (!this.matches || !this.matches.size) return null;
      let best = null;
      this.matches.forEach((id) => {
        const n = this.nodes.get(id);
        if (n && (!best || (n.type === 'process' && best.type !== 'process'))) best = n;
      });
      return best;
    }
    setMotion(on) {
      this.motion = !!on && !U.reducedMotion();
      if (!this.motion) this.settle();
      this.dirty = true;
    }

    /* ------------------------------------------------------------ input */
    bind() {
      const cv = this.canvas;
      let down = null;
      const pos = (e) => {
        const r = cv.getBoundingClientRect();
        return { x: e.clientX - r.left, y: e.clientY - r.top };
      };
      this.onDown = (e) => {
        if (e.button !== 0) return;
        const p = pos(e);
        const n = this.nodeAt(p.x, p.y);
        down = { p, n, moved: false, tx: this.t.x, ty: this.t.y };
        cv.setPointerCapture(e.pointerId);
        if (n && n.type !== 'host') {
          this.dragging = n;
          n.fx = n.x;
          n.fy = n.y;
          this.alphaTarget = 0.25;
          this.reheat(0.25);
        }
        this.hideTip();
      };
      this.onMove = (e) => {
        const p = pos(e);
        if (down) {
          const dx = p.x - down.p.x;
          const dy = p.y - down.p.y;
          if (!down.moved && Math.hypot(dx, dy) > 4) down.moved = true;
          if (!down.moved) return;
          if (this.dragging) {
            const w = this.toWorld(p.x, p.y);
            this.dragging.fx = w.x;
            this.dragging.fy = w.y;
            if (!this.motion) { this.dragging.x = w.x; this.dragging.y = w.y; this.draw(performance.now()); }
          } else {
            this.tween = null;
            this.userMoved = true;
            this.t.x = down.tx + dx;
            this.t.y = down.ty + dy;
            this.dirty = true;
            if (!this.motion) this.draw(performance.now());
          }
          cv.style.cursor = 'grabbing';
          return;
        }
        const n = this.nodeAt(p.x, p.y);
        if (n !== this.hover) {
          this.hover = n;
          this.dirty = true;
          if (!this.motion) this.draw(performance.now());
        }
        cv.style.cursor = n ? 'pointer' : 'grab';
        if (n) this.showTip(n, p);
        else this.hideTip();
      };
      this.onUp = (e) => {
        if (!down) return;
        const wasDrag = down.moved;
        const n = down.n;
        if (this.dragging) {
          if (this.dragging.type !== 'host') {
            this.dragging.fx = null;
            this.dragging.fy = null;
          }
          this.dragging = null;
          this.alphaTarget = 0;
        }
        down = null;
        try { cv.releasePointerCapture(e.pointerId); } catch (err) { /* ignore */ }
        cv.style.cursor = 'grab';
        if (!wasDrag && this.opts.onSelect) this.opts.onSelect(n ? n.d : null);
      };
      this.onLeave = () => {
        if (this.hover) {
          this.hover = null;
          this.dirty = true;
        }
        this.hideTip();
      };
      this.onWheel = (e) => {
        e.preventDefault();
        const p = pos(e);
        const f = Math.exp(-e.deltaY * (e.deltaMode === 1 ? 0.05 : 0.0016));
        this.zoomBy(f, p.x, p.y);
        if (!this.motion) this.draw(performance.now());
      };
      this.onKey = (e) => {
        const step = 60;
        const map = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] };
        if (map[e.key]) {
          e.preventDefault();
          this.userMoved = true;
          this.animateTo({ k: this.t.k, x: this.t.x + map[e.key][0], y: this.t.y + map[e.key][1] }, 180);
        } else if (e.key === '+' || e.key === '=') this.zoomBy(1.25);
        else if (e.key === '-' || e.key === '_') this.zoomBy(0.8);
        else if (e.key === '0') this.fit(true);
      };
      this.onDbl = (e) => {
        const p = pos(e);
        if (!this.nodeAt(p.x, p.y)) this.fit(true);
      };
      cv.addEventListener('pointerdown', this.onDown);
      cv.addEventListener('pointermove', this.onMove);
      cv.addEventListener('pointerup', this.onUp);
      cv.addEventListener('pointercancel', this.onUp);
      cv.addEventListener('pointerleave', this.onLeave);
      cv.addEventListener('wheel', this.onWheel, { passive: false });
      cv.addEventListener('keydown', this.onKey);
      cv.addEventListener('dblclick', this.onDbl);
    }
    showTip(n, p) {
      if (!this.opts.tooltip) return;
      this.tip.innerHTML = this.opts.tooltip(n.d, n);
      this.tip.hidden = false;
      const tw = this.tip.offsetWidth;
      const th = this.tip.offsetHeight;
      let x = p.x + 16;
      let y = p.y + 14;
      if (x + tw > this.w - 8) x = p.x - tw - 16;
      if (y + th > this.h - 8) y = this.h - th - 8;
      this.tip.style.transform = `translate(${Math.round(Math.max(8, x))}px, ${Math.round(Math.max(8, y))}px)`;
    }
    hideTip() {
      this.tip.hidden = true;
    }

    /* ------------------------------------------------------------ drawing */
    draw(now) {
      const ctx = this.ctx;
      const { w, h, dpr, t } = this;
      if (!w || !h) return;
      const time = now / 1000;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      ctx.setTransform(dpr * t.k, 0, 0, dpr * t.k, dpr * (w / 2 + t.x), dpr * (h / 2 + t.y));
      const px = 1 / t.k; // one screen pixel in world units

      this.drawBackdrop(ctx, px, time);

      // focus set: hover neighbourhood or search matches
      let focus = null;
      if (this.hover) {
        focus = new Set([this.hover.id]);
        this.edges.forEach((e) => {
          if (e.dying) return;
          if (e.source === this.hover) focus.add(e.target.id);
          if (e.target === this.hover) focus.add(e.source.id);
        });
      } else if (this.matches && this.matches.size) {
        focus = this.matches;
      }
      const dimOf = (n) => (focus && !focus.has(n.id) ? 0.18 : 1);

      // edges
      this.edges.forEach((e) => {
        const s = e.source;
        const tg = e.target;
        const a = e.a * Math.min(s.a, tg.a) * Math.min(dimOf(s), dimOf(tg));
        if (a <= 0.01) return;
        const st = this.edgeStyle(e);
        ctx.globalAlpha = a * st.a;
        ctx.strokeStyle = st.color;
        ctx.lineWidth = Math.max(st.w, 0.8 * px);
        if (st.dash) ctx.setLineDash([4 * px, 4 * px]);
        const c = this.ctrl(e);
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        if (c) ctx.quadraticCurveTo(c.x, c.y, tg.x, tg.y);
        else ctx.lineTo(tg.x, tg.y);
        ctx.stroke();
        if (st.dash) ctx.setLineDash([]);
      });

      // packets flowing along net edges (out: process → remote, in: remote → process)
      if (this.motion) {
        this.edges.forEach((e) => {
          if (e.kind !== 'net' || e.dying) return;
          const s = e.source;
          const tg = e.target;
          const a = e.a * Math.min(s.a, tg.a) * Math.min(dimOf(s), dimOf(tg));
          if (a <= 0.05) return;
          const len = Math.hypot(tg.x - s.x, tg.y - s.y) || 1;
          const count = e.d.count || 1;
          const n = Math.min(4, 1 + Math.floor(Math.log2(count + 1)));
          const speed = (e.d.states && e.d.states.includes('SYN_SENT') ? 110 : 55) / len;
          const color = e.d.danger ? C.danger : e.d.direction === 'in' ? C.inbound : C.packet;
          const c = this.ctrl(e);
          const sprite = glow(color);
          for (let i = 0; i < n; i++) {
            let f = (time * speed + i / n + e.seed) % 1;
            if (e.d.direction === 'in') f = 1 - f;
            const u = 1 - f;
            const x = c ? u * u * s.x + 2 * u * f * c.x + f * f * tg.x : s.x + (tg.x - s.x) * f;
            const y = c ? u * u * s.y + 2 * u * f * c.y + f * f * tg.y : s.y + (tg.y - s.y) * f;
            const fadeEnds = Math.min(1, f * 6, (1 - f) * 6);
            ctx.globalAlpha = a * fadeEnds;
            const gs = 9 * px;
            ctx.drawImage(sprite, x - gs, y - gs, gs * 2, gs * 2);
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(x, y, Math.max(1.6, 1.2 * px * 1.4), 0, Math.PI * 2);
            ctx.fill();
          }
        });
      }

      // nodes
      const order = [];
      this.nodes.forEach((n) => order.push(n));
      order.sort((a, b) => (a.type === 'remote' ? 0 : a.type === 'process' ? 1 : 2) - (b.type === 'remote' ? 0 : b.type === 'process' ? 1 : 2));
      for (const n of order) this.drawNode(ctx, n, n.a * dimOf(n), px, time);

      // labels in screen space (crisp, constant size)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.globalAlpha = 1;
      for (const n of order) this.drawLabel(ctx, n, n.a * dimOf(n), focus);
      ctx.globalAlpha = 1;
    }

    drawBackdrop(ctx, px, time) {
      ctx.globalAlpha = 1;
      ctx.lineWidth = px;
      // orbit rings + crosshair
      [[RING_PROC, 0.16], [RING_REMOTE, 0.12], [RING_REMOTE + 150, 0.06]].forEach(([r, a]) => {
        ctx.strokeStyle = hexA(C.ring, a);
        ctx.setLineDash([2 * px, 6 * px]);
        ctx.beginPath();
        ctx.arc(0, 0, r, 0, Math.PI * 2);
        ctx.stroke();
      });
      ctx.setLineDash([]);
      ctx.strokeStyle = hexA(C.ring, 0.05);
      ctx.beginPath();
      ctx.moveTo(-RING_REMOTE - 190, 0);
      ctx.lineTo(RING_REMOTE + 190, 0);
      ctx.moveTo(0, -RING_REMOTE - 190);
      ctx.lineTo(0, RING_REMOTE + 190);
      ctx.stroke();
      // ring captions
      ctx.fillStyle = hexA(C.ring, 0.42);
      ctx.font = `${10 * px}px ${MONO}`;
      ctx.textAlign = 'center';
      ctx.fillText('PROCESS ORBIT', 0, -RING_PROC - 6 * px);
      ctx.fillText('REMOTE ORBIT', 0, -RING_REMOTE - 6 * px);
      // radar sweep
      if (this.motion && ctx.createConicGradient) {
        const ang = (time * 0.45) % (Math.PI * 2);
        const g = ctx.createConicGradient(ang, 0, 0);
        g.addColorStop(0, 'rgba(34,211,238,0.10)');
        g.addColorStop(0.07, 'rgba(34,211,238,0.0)');
        g.addColorStop(1, 'rgba(34,211,238,0.0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(0, 0, RING_REMOTE + 150, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    ctrl(e) {
      if (e.kind !== 'net') return null;
      const s = e.source;
      const t = e.target;
      const mx = (s.x + t.x) / 2;
      const my = (s.y + t.y) / 2;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const bend = 0.12;
      return { x: mx - dy * bend, y: my + dx * bend };
    }

    edgeStyle(e) {
      if (e.kind === 'host') return { color: C.host, a: 0.2, w: 0.9 };
      if (e.kind === 'spawn') return { color: C.spawn, a: 0.45, w: 0.9, dash: true };
      const w = 0.9 + 1.1 * Math.log2(1 + (e.d.count || 1));
      if (e.d.danger) return { color: C.danger, a: 0.85, w: w + 0.4 };
      if (e.target.d && e.target.d.private) return { color: C.lan, a: 0.45, w };
      if (e.d.direction === 'in') return { color: C.inbound, a: 0.5, w };
      return { color: C.net, a: 0.42, w };
    }

    drawNode(ctx, n, a, px, time) {
      if (a <= 0.01 || n.r <= 0.1) return;
      const r = n.r;
      const col = n.color;
      const malicious = n.type === 'process' && (n.d.trust === 'malicious' || n.d.trust === 'suspicious');
      // halo
      let halo = r * (n.type === 'remote' ? 4 : 3);
      let haloA = n.type === 'remote' ? 0.75 : 0.6;
      if (n.type === 'remote' && n.d.private) haloA = 0.3;
      if (malicious || (n.type === 'remote' && n.d.blocklisted)) {
        const pulse = this.motion ? (Math.sin(time * 3.2 + n.seed) + 1) / 2 : 0.6;
        halo = r * (3.4 + pulse * 2.2);
        haloA = 0.7 + pulse * 0.3;
      }
      ctx.globalAlpha = a * haloA;
      const sp = glow(col);
      ctx.drawImage(sp, n.x - halo, n.y - halo, halo * 2, halo * 2);

      ctx.globalAlpha = a;
      if (n.type === 'host') {
        this.hex(ctx, n.x, n.y, r + 7);
        ctx.strokeStyle = hexA(col, 0.35);
        ctx.lineWidth = px;
        ctx.stroke();
        this.hex(ctx, n.x, n.y, r);
        const g = ctx.createRadialGradient(n.x, n.y - r * 0.4, 1, n.x, n.y, r);
        g.addColorStop(0, hexA(col, 0.55));
        g.addColorStop(1, 'rgba(8,20,36,0.95)');
        ctx.fillStyle = g;
        ctx.fill();
        ctx.strokeStyle = col;
        ctx.lineWidth = 1.8;
        ctx.stroke();
        // monitor glyph
        ctx.strokeStyle = '#e0fbff';
        ctx.lineWidth = 1.4;
        ctx.strokeRect(n.x - 7, n.y - 6, 14, 9.5);
        ctx.beginPath();
        ctx.moveTo(n.x - 4, n.y + 7);
        ctx.lineTo(n.x + 4, n.y + 7);
        ctx.moveTo(n.x, n.y + 3.5);
        ctx.lineTo(n.x, n.y + 7);
        ctx.stroke();
      } else if (n.type === 'process') {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(6,12,24,0.92)';
        ctx.fill();
        ctx.fillStyle = hexA(col, n.context ? 0.12 : 0.22);
        ctx.fill();
        ctx.strokeStyle = col;
        ctx.lineWidth = n.context ? 1 : 1.6;
        if (n.context) ctx.setLineDash([2.5, 2.5]);
        ctx.stroke();
        ctx.setLineDash([]);
        if (!n.context) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, Math.max(1.8, r * 0.32), 0, Math.PI * 2);
          ctx.fillStyle = col;
          ctx.fill();
          // orbit tick marks for HUD flavour
          ctx.strokeStyle = hexA(col, 0.55);
          ctx.lineWidth = 1;
          const rot = this.motion ? time * 0.6 + n.seed : n.seed;
          for (let i = 0; i < 3; i++) {
            const s = rot + (i * Math.PI * 2) / 3;
            ctx.beginPath();
            ctx.arc(n.x, n.y, r + 3.5, s, s + 0.7);
            ctx.stroke();
          }
        }
      } else {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = col;
        ctx.globalAlpha = a * (n.d.private ? 0.6 : 1);
        ctx.fill();
        ctx.globalAlpha = a;
        if (n.d.blocklisted) {
          // warning ring, rotating dashes
          ctx.strokeStyle = C.danger;
          ctx.lineWidth = 1.4;
          ctx.setLineDash([3, 3]);
          ctx.lineDashOffset = this.motion ? -time * 8 : 0;
          ctx.beginPath();
          ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
          ctx.stroke();
          ctx.setLineDash([]);
          ctx.lineDashOffset = 0;
          // warning triangle above
          const ty = n.y - r - 15;
          ctx.beginPath();
          ctx.moveTo(n.x, ty - 5);
          ctx.lineTo(n.x + 5.5, ty + 4.5);
          ctx.lineTo(n.x - 5.5, ty + 4.5);
          ctx.closePath();
          ctx.fillStyle = C.danger;
          ctx.fill();
          ctx.fillStyle = '#1a0606';
          ctx.fillRect(n.x - 0.6, ty - 1.5, 1.2, 3.2);
          ctx.fillRect(n.x - 0.6, ty + 2.4, 1.2, 1.1);
        }
      }

      // selection / search rings
      const isSel = this.selected === n.id;
      const isMatch = this.matches && this.matches.has(n.id);
      if (isSel || isMatch) {
        const rr = r + (n.type === 'host' ? 12 : 8);
        ctx.strokeStyle = isSel ? '#e0fbff' : C.host;
        ctx.lineWidth = isSel ? 1.6 : 1.2;
        ctx.globalAlpha = a;
        ctx.beginPath();
        ctx.arc(n.x, n.y, rr, 0, Math.PI * 2);
        ctx.stroke();
        // bracket ticks
        for (let i = 0; i < 4; i++) {
          const ang = (Math.PI / 2) * i + Math.PI / 4;
          ctx.beginPath();
          ctx.moveTo(n.x + Math.cos(ang) * (rr + 3), n.y + Math.sin(ang) * (rr + 3));
          ctx.lineTo(n.x + Math.cos(ang) * (rr + 8), n.y + Math.sin(ang) * (rr + 8));
          ctx.stroke();
        }
      }
      ctx.globalAlpha = 1;
    }

    hex(ctx, x, y, r) {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i - Math.PI / 2;
        const px = x + r * Math.cos(a);
        const py = y + r * Math.sin(a);
        if (i) ctx.lineTo(px, py);
        else ctx.moveTo(px, py);
      }
      ctx.closePath();
    }

    drawLabel(ctx, n, a, focus) {
      if (a <= 0.05) return;
      const k = this.t.k;
      const important = n.type !== 'remote' || n.d.blocklisted || n === this.hover || (focus && focus.has(n.id)) || this.selected === n.id;
      if (n.type === 'remote' && !important && k < 1.05) return;
      if (n.type === 'process' && n.context && k < 0.9 && n !== this.hover) return;
      const s = this.toScreen(n.x, n.y);
      if (s.x < -100 || s.x > this.w + 100 || s.y < -40 || s.y > this.h + 40) return;
      // canvas text is never parsed as HTML, but labels are still forced to plain strings
      let text = String(n.label === null || n.label === undefined ? '' : n.label);
      if (text.length > 26) text = `${text.slice(0, 24)}…`;
      const size = n.type === 'host' ? 12.5 : n.type === 'process' ? 11 : 10;
      ctx.font = `${n.type === 'host' ? '600 ' : ''}${size}px ${MONO}`;
      const tw = ctx.measureText(text).width;
      const y = s.y + n.r * k + (n.type === 'host' ? 20 : 13);
      ctx.globalAlpha = a * 0.85;
      ctx.fillStyle = C.bg;
      ctx.fillRect(Math.round(s.x - tw / 2 - 4), Math.round(y - size + 1), Math.round(tw + 8), Math.round(size + 5));
      ctx.globalAlpha = a;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'alphabetic';
      let color = n.type === 'remote' ? C.labelDim : C.label;
      if (n.type === 'remote' && n.d.blocklisted) color = '#fca5a5';
      if (n.type === 'process' && (n.d.trust === 'malicious' || n.d.trust === 'suspicious')) color = '#fca5a5';
      if (n.type === 'host') color = '#e0fbff';
      ctx.fillStyle = color;
      ctx.fillText(text, Math.round(s.x), Math.round(y + 2));
      if (n.type === 'host') {
        ctx.font = `9.5px ${MONO}`;
        ctx.fillStyle = hexA(C.host, 0.8);
        ctx.fillText('THIS PC', Math.round(s.x), Math.round(s.y - n.r * k - 14));
      }
    }

    destroy() {
      cancelAnimationFrame(this.raf);
      clearInterval(this.watch);
      this.ro.disconnect();
      const cv = this.canvas;
      cv.removeEventListener('pointerdown', this.onDown);
      cv.removeEventListener('pointermove', this.onMove);
      cv.removeEventListener('pointerup', this.onUp);
      cv.removeEventListener('pointercancel', this.onUp);
      cv.removeEventListener('pointerleave', this.onLeave);
      cv.removeEventListener('wheel', this.onWheel);
      cv.removeEventListener('keydown', this.onKey);
      cv.removeEventListener('dblclick', this.onDbl);
    }
  }

  PCS.LiveGraph = LiveGraph;
  PCS.MAP_COLORS = { trust: TRUST_COLOR, C };
})();
