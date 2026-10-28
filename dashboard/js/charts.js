/* PC Sentinel dashboard: hand-rolled charts.
   - ThroughputChart: HiDPI canvas area chart (rx/tx), eased rescale + slide, hover tooltip, gap breaks.
   - sparkline(), donut(): small SVG strings (crisp at any devicePixelRatio).
   - Gauge: SVG risk gauge that animates between scores. */
(function () {
  'use strict';
  const PCS = (window.PCS = window.PCS || {});
  const U = PCS.util;

  function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }
  function withAlpha(color, a) {
    const c = color.trim();
    if (c[0] === '#') {
      let h = c.slice(1);
      if (h.length === 3) h = h.split('').map((x) => x + x).join('');
      const n = parseInt(h.slice(0, 6), 16);
      return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
    }
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (m) {
      const p = m[1].split(',').map((s) => s.trim());
      return `rgba(${p[0]},${p[1]},${p[2]},${a})`;
    }
    return c;
  }
  /** Axis maximum that gives round labels in the unit the formatter will use (KB/s = 1024, kbps = 1000),
      split into four gridlines: e.g. 4 MB/s → 1, 2, 3, 4 MB/s instead of 977 KB/s steps. */
  function niceRate(v) {
    if (!(v > 0)) return 1024;
    const base = U.RATE_IN_BITS ? 1000 : 1024;
    const i = Math.max(0, Math.floor(Math.log(v) / Math.log(base)));
    const unit = Math.pow(base, i);
    const x = v / unit;
    const exp = Math.pow(10, Math.floor(Math.log10(x)));
    const f = x / exp;
    const n = [1, 2, 4, 6, 8, 10].find((c) => f <= c) || 10;
    return n * exp * unit;
  }

  /* ================================================================== throughput chart */
  class ThroughputChart {
    constructor(container, opts) {
      const o = opts || {};
      this.el = container;
      this.windowMs = (o.minutes || 60) * 60000;
      this.gapMs = o.gapMs || 45000;
      this.points = [];
      this.view = { tEnd: Date.now(), yMax: 1024 };
      this.hoverX = null;
      this.w = 0;
      this.h = 0;

      this.canvas = document.createElement('canvas');
      this.canvas.className = 'chart-canvas';
      this.canvas.setAttribute('role', 'img');
      this.canvas.setAttribute('aria-label', 'Network throughput over the last 60 minutes');
      this.tip = document.createElement('div');
      this.tip.className = 'chart-tip';
      this.tip.hidden = true;
      container.append(this.canvas, this.tip);
      this.ctx = this.canvas.getContext('2d');

      this.onMove = (e) => {
        const r = this.canvas.getBoundingClientRect();
        this.hoverX = e.clientX - r.left;
        this.draw();
      };
      this.onLeave = () => {
        this.hoverX = null;
        this.tip.hidden = true;
        this.draw();
      };
      this.canvas.addEventListener('pointermove', this.onMove);
      this.canvas.addEventListener('pointerleave', this.onLeave);
      this.ro = new ResizeObserver(() => this.resize());
      this.ro.observe(container);
      this.offTheme = PCS.bus.on('theme', () => this.draw());
      // re-rasterise when the window moves to a monitor with a different devicePixelRatio
      this.watchDpr();
      this.resize();
    }

    watchDpr() {
      if (!window.matchMedia) return;
      const mq = window.matchMedia(`(resolution: ${window.devicePixelRatio}dppx)`);
      const fn = () => {
        this.resize();
        this.watchDpr();
      };
      mq.addEventListener('change', fn, { once: true });
      this.dprMq = { mq, fn };
    }

    destroy() {
      this.ro.disconnect();
      this.offTheme();
      if (this.cancelTween) this.cancelTween();
      this.canvas.removeEventListener('pointermove', this.onMove);
      this.canvas.removeEventListener('pointerleave', this.onLeave);
      if (this.dprMq) this.dprMq.mq.removeEventListener('change', this.dprMq.fn);
    }

    static norm(p) {
      if (!p) return null;
      const t = U.ms(p.t);
      if (isNaN(t)) return null;
      return { t, rx: Math.max(0, Number(p.rx_bps) || 0), tx: Math.max(0, Number(p.tx_bps) || 0) };
    }

    setPoints(raw) {
      this.points = (raw || []).map(ThroughputChart.norm).filter(Boolean).sort((a, b) => a.t - b.t);
      this.trim();
      this.retarget(false);
    }

    push(raw) {
      const n = ThroughputChart.norm(raw);
      if (!n) return;
      const last = this.points[this.points.length - 1];
      if (last && n.t < last.t) return;
      if (last && n.t === last.t) this.points[this.points.length - 1] = n;
      else this.points.push(n);
      this.trim();
      this.retarget(true);
    }

    latest() {
      return this.points[this.points.length - 1] || null;
    }

    trim() {
      if (!this.points.length) return;
      const cutoff = this.points[this.points.length - 1].t - this.windowMs - 120000;
      let i = 0;
      while (i < this.points.length && this.points[i].t < cutoff) i++;
      if (i) this.points.splice(0, i);
    }

    target() {
      const tEnd = this.points.length ? this.points[this.points.length - 1].t : Date.now();
      const tStart = tEnd - this.windowMs;
      let m = 0;
      for (const p of this.points) if (p.t >= tStart) m = Math.max(m, p.rx, p.tx);
      return { tEnd, yMax: niceRate(m * 1.08) };
    }

    retarget(animate) {
      const to = this.target();
      if (this.cancelTween) this.cancelTween();
      // hidden pages don't run rAF; jump straight to the final frame there
      if (!animate || !this.w || document.hidden || U.reducedMotion()) {
        this.view = to;
        this.draw();
        return;
      }
      const from = Object.assign({}, this.view);
      this.cancelTween = U.tween(700, (e) => {
        this.view = { tEnd: from.tEnd + (to.tEnd - from.tEnd) * e, yMax: from.yMax + (to.yMax - from.yMax) * e };
        this.draw();
      });
    }

    resize() {
      const r = this.el.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      const w = Math.max(0, Math.round(r.width));
      const h = Math.max(0, Math.round(r.height));
      if (!w || !h) return;
      this.w = w;
      this.h = h;
      this.canvas.width = Math.round(w * dpr);
      this.canvas.height = Math.round(h * dpr);
      this.canvas.style.width = `${w}px`;
      this.canvas.style.height = `${h}px`;
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      this.draw();
    }

    colors() {
      return {
        rx: cssVar('--chart-rx', '#22d3ee'),
        tx: cssVar('--chart-tx', '#a78bfa'),
        grid: cssVar('--chart-grid', 'rgba(148,163,184,.1)'),
        text: cssVar('--chart-text', '#808b9e'),
        panel: cssVar('--panel', '#111827'),
        cross: cssVar('--chart-cross', 'rgba(148,163,184,.45)'),
      };
    }

    draw() {
      const { ctx, w, h } = this;
      if (!w || !h) return;
      const c = this.colors();
      const font = getComputedStyle(document.body).fontFamily;
      ctx.clearRect(0, 0, w, h);

      const pad = { l: 66, r: 12, t: 12, b: 26 };
      const pw = Math.max(10, w - pad.l - pad.r);
      const ph = Math.max(10, h - pad.t - pad.b);
      const { tEnd, yMax } = this.view;
      const tStart = tEnd - this.windowMs;
      const X = (t) => pad.l + ((t - tStart) / this.windowMs) * pw;
      const Y = (v) => pad.t + ph - (Math.min(v, yMax * 1.4) / yMax) * ph;

      // grid + y labels
      ctx.font = `11px ${font}`;
      ctx.lineWidth = 1;
      ctx.strokeStyle = c.grid;
      ctx.fillStyle = c.text;
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      for (let i = 0; i <= 4; i++) {
        const v = (yMax * i) / 4;
        const y = Math.round(Y(v)) + 0.5;
        ctx.beginPath();
        ctx.moveTo(pad.l, y);
        ctx.lineTo(w - pad.r, y);
        ctx.stroke();
        ctx.fillText(i === 0 ? '0' : U.fmtRate(v).replace(/(\.\d*?[1-9])0+(?= )/, '$1').replace(/\.0+(?= )/, ''), pad.l - 10, y);
      }
      // x labels every 10 minutes
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      const step = 10 * 60000;
      for (let t = Math.ceil(tStart / step) * step; t <= tEnd; t += step) {
        const x = X(t);
        if (x < pad.l + 18 || x > w - pad.r - 18) continue;
        ctx.fillText(U.hm(t), x, pad.t + ph + 8);
      }

      // series, clipped to the plot area
      const visible = this.points.filter((p) => p.t >= tStart - 15000);
      const segs = [];
      let cur = [];
      for (const p of visible) {
        if (cur.length && p.t - cur[cur.length - 1].t > this.gapMs) {
          segs.push(cur);
          cur = [];
        }
        cur.push(p);
      }
      if (cur.length) segs.push(cur);

      ctx.save();
      ctx.beginPath();
      ctx.rect(pad.l, pad.t - 2, pw + 1, ph + 4);
      ctx.clip();
      const base = Y(0);
      const series = (key, color, alpha, lw) => {
        const grad = ctx.createLinearGradient(0, pad.t, 0, base);
        grad.addColorStop(0, withAlpha(color, alpha));
        grad.addColorStop(1, withAlpha(color, 0));
        for (const s of segs) {
          if (s.length < 2) continue;
          ctx.beginPath();
          ctx.moveTo(X(s[0].t), base);
          for (const p of s) ctx.lineTo(X(p.t), Y(p[key]));
          ctx.lineTo(X(s[s.length - 1].t), base);
          ctx.closePath();
          ctx.fillStyle = grad;
          ctx.fill();
          ctx.beginPath();
          s.forEach((p, i) => (i ? ctx.lineTo(X(p.t), Y(p[key])) : ctx.moveTo(X(p.t), Y(p[key]))));
          ctx.strokeStyle = color;
          ctx.lineWidth = lw;
          ctx.lineJoin = 'round';
          ctx.stroke();
        }
      };
      series('tx', c.tx, 0.16, 1.4);
      series('rx', c.rx, 0.3, 1.7);

      // "now" marker at the newest point
      const last = this.latest();
      if (last && this.hoverX === null) {
        for (const [key, color] of [['tx', c.tx], ['rx', c.rx]]) {
          ctx.beginPath();
          ctx.arc(X(last.t), Y(last[key]), 3, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.fill();
          ctx.beginPath();
          ctx.arc(X(last.t), Y(last[key]), 6, 0, Math.PI * 2);
          ctx.fillStyle = withAlpha(color, 0.18);
          ctx.fill();
        }
      }
      ctx.restore();

      if (!visible.length) {
        ctx.fillStyle = c.text;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.font = `13px ${font}`;
        ctx.fillText('Waiting for throughput samples…', pad.l + pw / 2, pad.t + ph / 2);
      }

      this.drawHover(visible, { X, Y, pad, pw, ph, c });
    }

    drawHover(visible, g) {
      const { ctx } = this;
      if (this.hoverX === null || !visible.length) {
        this.tip.hidden = true;
        return;
      }
      if (this.hoverX < g.pad.l || this.hoverX > g.pad.l + g.pw) {
        this.tip.hidden = true;
        return;
      }
      let best = visible[0];
      let bd = Infinity;
      for (const p of visible) {
        const d = Math.abs(g.X(p.t) - this.hoverX);
        if (d < bd) { bd = d; best = p; }
      }
      const x = Math.round(g.X(best.t)) + 0.5;
      ctx.save();
      ctx.strokeStyle = g.c.cross;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(x, g.pad.t);
      ctx.lineTo(x, g.pad.t + g.ph);
      ctx.stroke();
      ctx.setLineDash([]);
      for (const [key, color] of [['tx', g.c.tx], ['rx', g.c.rx]]) {
        ctx.beginPath();
        ctx.arc(x, g.Y(best[key]), 4, 0, Math.PI * 2);
        ctx.fillStyle = g.c.panel;
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = color;
        ctx.stroke();
      }
      ctx.restore();

      this.tip.innerHTML = `<div class="chart-tip-time">${U.esc(U.hms(best.t))}</div>
        <div class="chart-tip-row"><i class="sw sw-rx"></i>Download<b>${U.esc(U.fmtRate(best.rx))}</b></div>
        <div class="chart-tip-row"><i class="sw sw-tx"></i>Upload<b>${U.esc(U.fmtRate(best.tx))}</b></div>`;
      this.tip.hidden = false;
      const tw = this.tip.offsetWidth;
      const left = x + 14 + tw > this.w ? x - 14 - tw : x + 14;
      this.tip.style.transform = `translate(${Math.round(left)}px, ${g.pad.t + 4}px)`;
    }
  }

  /* ================================================================== sparkline (SVG string) */
  let gid = 0;
  function sparkline(values, opts) {
    const o = opts || {};
    const w = o.w || 120;
    const h = o.h || 34;
    const color = U.esc(o.color || 'var(--accent)'); // fixed CSS token from the caller, never data
    let vals = (values || []).filter((v) => typeof v === 'number' && isFinite(v));
    if (vals.length < 2) return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"></svg>`;
    const maxPts = o.points || 48;
    if (vals.length > maxPts) {
      const out = [];
      const size = vals.length / maxPts;
      for (let i = 0; i < maxPts; i++) {
        const chunk = vals.slice(Math.floor(i * size), Math.max(Math.floor((i + 1) * size), Math.floor(i * size) + 1));
        out.push(chunk.reduce((a, b) => a + b, 0) / chunk.length);
      }
      vals = out;
    }
    const lo = o.min !== undefined ? o.min : Math.min(...vals);
    const hi = Math.max(...vals);
    const span = hi - lo || 1;
    const pts = vals.map((v, i) => [(i / (vals.length - 1)) * w, h - 2 - ((v - lo) / span) * (h - 5)]);
    const d = `M${pts.map((p) => `${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' L')}`;
    const id = `spark-g${++gid}`;
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
      <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" style="stop-color:${color};stop-opacity:.3"/><stop offset="1" style="stop-color:${color};stop-opacity:0"/></linearGradient></defs>
      <path d="${d} L${w} ${h} L0 ${h} Z" fill="url(#${id})"/>
      <path d="${d}" fill="none" style="stroke:${color}" stroke-width="1.6" vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/>
    </svg>`;
  }

  /* ================================================================== donut (SVG string) */
  function donut(segs, opts) {
    const o = opts || {};
    const size = o.size || 92;
    const th = o.thickness || 10;
    const r = (size - th) / 2;
    const C = 2 * Math.PI * r;
    const cx = size / 2;
    segs = segs.map((s) => Object.assign({}, s, { value: Math.max(0, Number(s.value) || 0) }));
    const sum = segs.reduce((a, s) => a + s.value, 0);
    const nonzero = segs.filter((s) => s.value > 0);
    const gap = nonzero.length > 1 ? 2.5 : 0;
    let offset = 0;
    const arcs = nonzero.map((s) => {
      const len = (s.value / sum) * C;
      const dash = Math.max(0.5, len - gap);
      // s.color is a fixed CSS token from the caller (var(--sev-…)), never data
      const el = `<circle cx="${cx}" cy="${cx}" r="${r}" fill="none" style="stroke:${U.esc(s.color)}" stroke-width="${th}" stroke-dasharray="${dash.toFixed(2)} ${(C - dash).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}"><title>${U.esc(s.label)}: ${U.esc(U.fmtInt(s.value))}</title></circle>`;
      offset += len;
      return el;
    }).join('');
    return `<svg class="donut" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="${U.esc(o.label || '')}">
      <circle cx="${cx}" cy="${cx}" r="${r}" fill="none" class="donut-track" stroke-width="${th}"/>
      <g transform="rotate(-90 ${cx} ${cx})">${arcs}</g>
    </svg>`;
  }

  /* ================================================================== risk gauge */
  /* Radial 270° HUD gauge: tick ring, glowing value arc coloured by the risk label, a knob riding the arc,
     and a radar sweep rotating behind the score (CSS animation, disabled for reduced motion). */
  const LABEL_TONE = { low: 'ok', guarded: 'info', elevated: 'medium', high: 'high', severe: 'critical' };
  const G = { cx: 110, cy: 110, r: 90 };
  const gpt = (deg, r) => {
    const a = (deg * Math.PI) / 180;
    return [G.cx + r * Math.cos(a), G.cy + r * Math.sin(a)];
  };
  class Gauge {
    constructor(el) {
      this.el = el;
      this.score = 0;
      this.len = G.r * Math.PI * 1.5;
      const [sx, sy] = gpt(135, G.r);
      const [ex, ey] = gpt(45, G.r);
      const arc = `M${sx.toFixed(2)} ${sy.toFixed(2)} A${G.r} ${G.r} 0 1 1 ${ex.toFixed(2)} ${ey.toFixed(2)}`;
      el.innerHTML = `
        <div class="gauge-sweep" aria-hidden="true"></div>
        <svg class="gauge-svg" viewBox="0 0 220 220" aria-hidden="true" focusable="false">
          <circle class="gauge-ring" cx="${G.cx}" cy="${G.cy}" r="66"/>
          <circle class="gauge-ring faint" cx="${G.cx}" cy="${G.cy}" r="44"/>
          ${this.ticks()}
          <path class="gauge-track" d="${arc}" fill="none" stroke-width="9" stroke-linecap="round"/>
          <path class="gauge-value" d="${arc}" fill="none" stroke-width="9" stroke-linecap="round"
                stroke-dasharray="${this.len.toFixed(2)}" stroke-dashoffset="${this.len.toFixed(2)}"/>
          <g class="gauge-needle"><circle cx="${sx.toFixed(2)}" cy="${sy.toFixed(2)}" r="7.5" class="gauge-knob"/><circle cx="${sx.toFixed(2)}" cy="${sy.toFixed(2)}" r="3" class="gauge-knob-core"/></g>
        </svg>
        <div class="gauge-center">
          <div class="hud-label">Risk index</div>
          <div class="gauge-score"><span class="gauge-num">0</span><span class="gauge-max">/100</span></div>
          <div class="gauge-label tone-ok">—</div>
        </div>`;
      this.valueEl = el.querySelector('.gauge-value');
      this.needle = el.querySelector('.gauge-needle');
      this.num = el.querySelector('.gauge-num');
      this.labelEl = el.querySelector('.gauge-label');
    }
    ticks() {
      let s = '';
      for (let i = 0; i <= 30; i++) {
        const deg = 135 + (270 * i) / 30;
        const major = i % 5 === 0;
        const [x1, y1] = gpt(deg, 78);
        const [x2, y2] = gpt(deg, major ? 70 : 74);
        s += `<line class="gauge-tick${major ? ' major' : ''}" x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"/>`;
      }
      return s;
    }
    set(score, label) {
      const s = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
      this.valueEl.setAttribute('stroke-dashoffset', (this.len * (1 - s / 100)).toFixed(2));
      this.needle.style.transform = `rotate(${(s * 2.7).toFixed(2)}deg)`;
      const tone = LABEL_TONE[String(label || '').toLowerCase()] || 'info';
      this.el.dataset.tone = tone;
      this.labelEl.className = `gauge-label tone-${tone}`;
      this.labelEl.textContent = label || '—';
      this.el.setAttribute('aria-label', `Risk score ${s} of 100, ${label || 'unknown'}`);
      this.countTo(s);
    }
    countTo(to) {
      const from = this.score;
      this.score = to;
      if (this.cancelTween) this.cancelTween();
      if (from === to || document.hidden || U.reducedMotion()) {
        this.num.textContent = String(to);
        return;
      }
      this.cancelTween = U.tween(900, (e) => { this.num.textContent = String(Math.round(from + (to - from) * e)); });
    }
  }

  PCS.charts = { ThroughputChart, sparkline, donut, Gauge, niceRate };
})();
