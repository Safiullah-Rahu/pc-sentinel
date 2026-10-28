/* PC Sentinel dashboard: shared UI pieces — toasts, modal dialog, side drawer, sortable tables with
   new-row highlighting, count-ups, and the engine actions (kill / block / allow / ack / notify). */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const icon = PCS.icon;
  const { esc, $ } = U;
  const ui = (PCS.ui = {});

  /* ================================================================== toasts (in-page, action results) */
  const TOAST_ICON = { success: 'check', error: 'xCircle', info: 'info', warn: 'alert' };
  ui.toast = function (o) {
    const host = $('#toasts');
    if (!host) return () => {};
    const kind = o.kind || 'info';
    const timeout = o.timeout || 5200;
    const el = document.createElement('div');
    el.className = `toast toast-${kind}`;
    el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    el.innerHTML = `<span class="toast-icon">${icon(TOAST_ICON[kind] || 'info', { size: 18 })}</span>
      <div class="toast-body">${o.title ? `<div class="toast-title">${esc(o.title)}</div>` : ''}${o.message ? `<div class="toast-msg">${esc(o.message)}</div>` : ''}</div>
      <button type="button" class="icon-btn sm toast-close" aria-label="Dismiss">${icon('x', { size: 14 })}</button>
      <span class="toast-timer" aria-hidden="true"></span>`;
    host.appendChild(el);
    while (host.children.length > 4) host.firstElementChild.remove();
    let timer = null;
    let left = timeout;
    let started = Date.now();
    const close = () => {
      clearTimeout(timer);
      el.classList.add('is-leaving');
      setTimeout(() => el.remove(), 240);
    };
    const arm = () => {
      started = Date.now();
      timer = setTimeout(close, left);
    };
    el.style.setProperty('--toast-ms', `${timeout}ms`);
    el.addEventListener('mouseenter', () => {
      clearTimeout(timer);
      left = Math.max(800, left - (Date.now() - started));
      el.classList.add('is-paused');
    });
    el.addEventListener('mouseleave', () => {
      el.classList.remove('is-paused');
      arm();
    });
    el.querySelector('.toast-close').addEventListener('click', close);
    arm();
    return close;
  };

  /* ================================================================== modal dialog (<dialog>) */
  function fieldHtml(f) {
    const id = `dlg-f-${esc(f.name)}`;
    if (f.type === 'radio') {
      return `<fieldset class="field radio-cards"><legend class="field-label">${esc(f.label)}</legend>
        ${f.options.map((op, i) => `<label class="radio-card">
          <input type="radio" name="${esc(f.name)}" value="${esc(op.value)}" ${op.value === f.value || (!f.value && i === 0) ? 'checked' : ''}>
          <span class="radio-card-body"><span class="radio-card-title">${esc(op.label)}</span>${op.hint ? `<span class="radio-card-hint mono">${esc(op.hint)}</span>` : ''}</span>
        </label>`).join('')}</fieldset>`;
    }
    if (f.type === 'select') {
      return `<label class="field" for="${id}"><span class="field-label">${esc(f.label)}</span>
        <select class="input" name="${esc(f.name)}" id="${id}">${f.options.map((op) => `<option value="${esc(op.value)}" ${op.value === f.value ? 'selected' : ''}>${esc(op.label)}</option>`).join('')}</select></label>`;
    }
    return `<label class="field" for="${id}"><span class="field-label">${esc(f.label)}</span>
      <input class="input${f.mono ? ' mono' : ''}" name="${esc(f.name)}" id="${id}" value="${esc(f.value || '')}" placeholder="${esc(f.placeholder || '')}"
             ${f.readonly ? 'readonly' : ''} autocomplete="off" spellcheck="false" maxlength="${Number(f.maxlength) || 400}"></label>`;
  }

  /** Resolves to the field values (or {} when there are no fields), or null when cancelled.
      o.body is trusted HTML: callers build it with esc() around every dynamic value. */
  ui.dialog = function (o) {
    return new Promise((resolve) => {
      const dlg = $('#dialog');
      if (dlg.open) dlg.close();
      const fields = o.fields || [];
      const tone = o.tone || 'primary';
      dlg.innerHTML = `<form class="dialog-form" novalidate>
        <header class="dialog-head">
          ${o.icon ? `<span class="dialog-icon tone-${tone}">${icon(o.icon, { size: 20 })}</span>` : ''}
          <h2 id="dlg-title">${esc(o.title)}</h2>
        </header>
        <div class="dialog-body">${o.body || ''}${fields.map(fieldHtml).join('')}<p class="dialog-error" role="alert" hidden></p></div>
        <footer class="dialog-foot">
          <button type="button" class="btn btn-ghost" data-dlg-cancel>${esc(o.cancelLabel || 'Cancel')}</button>
          <button type="submit" class="btn ${tone === 'danger' ? 'btn-danger' : 'btn-primary'}">${o.confirmIcon ? icon(o.confirmIcon, { size: 16 }) : ''}${esc(o.confirmLabel || 'Confirm')}</button>
        </footer>
      </form>`;
      dlg.setAttribute('aria-labelledby', 'dlg-title');
      const form = dlg.querySelector('form');
      let done = false;
      const finish = (v) => {
        if (done) return;
        done = true;
        if (dlg.open) dlg.close();
        resolve(v);
      };
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const vals = {};
        fields.forEach((f) => {
          if (f.type === 'radio') {
            const c = Array.from(form.querySelectorAll('input[type=radio]')).find((r) => r.name === f.name && r.checked);
            vals[f.name] = c ? c.value : '';
          } else {
            vals[f.name] = String(form.elements[f.name].value || '').trim();
          }
        });
        const msg = o.validate ? o.validate(vals) : null;
        if (msg) {
          const p = form.querySelector('.dialog-error');
          p.textContent = msg;
          p.hidden = false;
          return;
        }
        finish(vals);
      });
      dlg.querySelector('[data-dlg-cancel]').addEventListener('click', () => finish(null));
      dlg.onclose = () => finish(null);
      dlg.oncancel = () => finish(null);
      dlg.onclick = (e) => { if (e.target === dlg) finish(null); };
      if (o.onRender) o.onRender(form);
      dlg.showModal();
      const first = form.querySelector('input:not([readonly]):not([type=radio]), select');
      (first || form.querySelector('button[type=submit]')).focus();
    });
  };

  /* ================================================================== side drawer */
  const drawer = (ui.drawer = {
    current: null,
    lastFocus: null,
    open(html, opts) {
      const o = opts || {};
      const el = $('#drawer');
      const scrim = $('#drawer-scrim');
      if (!this.current) this.lastFocus = document.activeElement;
      el.innerHTML = html;
      this.current = { key: o.key || null, onAction: o.onAction || null };
      el.hidden = false;
      scrim.hidden = false;
      void el.offsetWidth; // commit the closed state so the slide-in transition runs (rAF is paused in hidden pages)
      el.classList.add('is-open');
      scrim.classList.add('is-open');
      el.setAttribute('aria-hidden', 'false');
      const app = $('#app');
      if (app) app.inert = true;
      const close = el.querySelector('[data-drawer-close]');
      (close || el).focus({ preventScroll: true });
    },
    update(html) {
      if (!this.current) return;
      const el = $('#drawer');
      const body = el.querySelector('.drawer-body');
      const st = body ? body.scrollTop : 0;
      const hadFocus = el.contains(document.activeElement) && document.activeElement.dataset ? document.activeElement.dataset.dact : null;
      el.innerHTML = html;
      const nb = el.querySelector('.drawer-body');
      if (nb) nb.scrollTop = st;
      const refocus = hadFocus ? Array.from(el.querySelectorAll('[data-dact]')).find((b) => b.dataset.dact === hadFocus) : null;
      (refocus || el.querySelector('[data-drawer-close]') || el).focus({ preventScroll: true });
    },
    close() {
      if (!this.current) return;
      const el = $('#drawer');
      const scrim = $('#drawer-scrim');
      el.classList.remove('is-open');
      scrim.classList.remove('is-open');
      el.setAttribute('aria-hidden', 'true');
      const app = $('#app');
      if (app) app.inert = false;
      this.current = null;
      setTimeout(() => {
        if (!this.current) {
          el.hidden = true;
          scrim.hidden = true;
          el.innerHTML = '';
        }
      }, 260);
      if (this.lastFocus && document.contains(this.lastFocus)) this.lastFocus.focus({ preventScroll: true });
      this.lastFocus = null;
    },
    isOpen(key) {
      return !!this.current && (!key || this.current.key === key);
    },
  });

  /** Drawer layout. eyebrow / title / sub / meta / body / foot are trusted HTML: every caller escapes dynamic values. */
  ui.drawerFrame = function (o) {
    return `<header class="drawer-head">
        <div class="drawer-head-row">
          <div class="drawer-eyebrow">${o.eyebrow || ''}</div>
          <button type="button" class="icon-btn" data-drawer-close aria-label="Close details">${icon('x', { size: 18 })}</button>
        </div>
        <h2 class="drawer-title" id="drawer-title">${o.title}</h2>
        ${o.sub ? `<p class="drawer-sub">${o.sub}</p>` : ''}
        ${o.meta ? `<div class="drawer-meta">${o.meta}</div>` : ''}
      </header>
      <div class="drawer-body">${o.body || ''}</div>
      ${o.foot ? `<footer class="drawer-foot">${o.foot}</footer>` : ''}`;
  };
  /** Key/value list. Keys are escaped here; values are trusted HTML built by the caller with esc(). */
  ui.kv = (rows) => `<dl class="kv">${rows.filter(Boolean).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v === '' || v === null || v === undefined ? '<span class="muted">—</span>' : v}</dd>`).join('')}</dl>`;
  ui.section = (title, body, iconName) => `<section class="dsec"><h3 class="hud-label">${iconName ? icon(iconName, { size: 13 }) : ''}<span>${esc(title)}</span></h3>${body}</section>`;
  ui.dbtn = (act, label, iconName, o) => {
    const x = o || {};
    return `<button type="button" class="btn ${esc(x.cls || '')}" data-dact="${esc(act)}" ${x.disabled ? `disabled title="${esc(x.why || '')}"` : ''}>${icon(iconName, { size: 16 })}${esc(label)}</button>`;
  };

  /* ================================================================== sortable tables + new-row tracking */
  const seenKeys = new Map();
  /** Returns the keys that were not present the last time this table rendered (empty on first render). */
  ui.track = function (id, keys) {
    const prev = seenKeys.get(id);
    seenKeys.set(id, new Set(keys));
    if (!prev) return new Set();
    const fresh = new Set();
    keys.forEach((k) => { if (!prev.has(k)) fresh.add(k); });
    return fresh;
  };
  ui.resetTrack = (prefix) => {
    Array.from(seenKeys.keys()).forEach((k) => { if (!prefix || k.startsWith(prefix)) seenKeys.delete(k); });
  };

  const sorts = {};
  ui.sortState = (id, def) => (sorts[id] = sorts[id] || Object.assign({}, def || { col: null, dir: 'desc' }));
  ui.toggleSort = (id, col) => {
    const s = sorts[id] || (sorts[id] = { col: null, dir: 'desc' });
    if (s.col === col) s.dir = s.dir === 'asc' ? 'desc' : 'asc';
    else {
      s.col = col;
      s.dir = 'desc';
    }
  };
  function cmp(a, b) {
    const an = a === null || a === undefined || a === '' || (typeof a === 'number' && isNaN(a));
    const bn = b === null || b === undefined || b === '' || (typeof b === 'number' && isNaN(b));
    if (an || bn) return an && bn ? 0 : an ? 1 : -1;
    if (typeof a === 'number' && typeof b === 'number') return a - b;
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
  }

  /**
   * table(id, { columns, rows, allKeys?, key, rowClass?, rowAttrs?, defaultSort?, empty? })
   * columns: [{ id, label, sort?: row => value, render: row => html, cls?, th?: extra th class, sr?: hidden label }]
   */
  ui.table = function (id, o) {
    const st = ui.sortState(id, o.defaultSort);
    let rows = o.rows.slice();
    const col = o.columns.find((c) => c.id === st.col && c.sort);
    if (col) {
      const dir = st.dir === 'asc' ? 1 : -1;
      rows = rows.map((r, i) => [r, i]).sort((x, y) => {
        const va = col.sort(x[0]);
        const vb = col.sort(y[0]);
        const nullA = va === null || va === undefined || va === '';
        const nullB = vb === null || vb === undefined || vb === '';
        if (nullA !== nullB) return nullA ? 1 : -1; // empty values last in both directions
        return cmp(va, vb) * dir || x[1] - y[1];
      }).map((x) => x[0]);
    }
    if (o.pin) rows = rows.filter(o.pin).concat(rows.filter((r) => !o.pin(r))); // pinned rows stay on top in any sort
    const fresh = ui.track(id, o.allKeys || o.rows.map(o.key));
    const head = o.columns.map((c) => {
      const cls = `${c.cls || ''} ${c.th || ''}`.trim();
      if (!c.sort) return `<th scope="col" class="${esc(cls)}">${c.label ? esc(c.label) : `<span class="sr-only">${esc(c.sr || '')}</span>`}</th>`;
      const active = st.col === c.id;
      const aria = active ? (st.dir === 'asc' ? 'ascending' : 'descending') : 'none';
      return `<th scope="col" class="${esc(cls)}" aria-sort="${aria}"><button type="button" class="th-sort${active ? ' is-active' : ''}" data-sort-table="${esc(id)}" data-sort-col="${esc(c.id)}">${esc(c.label)}${icon(active && st.dir === 'asc' ? 'chevronUp' : 'chevronDown', { size: 12, stroke: 2.2 })}</button></th>`;
    }).join('');
    if (!rows.length) return o.empty || U.emptyState({ icon: 'search', title: 'Nothing to show', body: 'No rows match the current filters.', compact: true });
    // rowClass may contain data (trust, severity…), so the class attribute is escaped as a whole;
    // rowAttrs and column renderers return trusted HTML built with esc().
    const body = rows.map((r) => {
      const k = o.key(r);
      const cls = `${o.rowClass ? o.rowClass(r) : ''}${fresh.has(k) ? ' is-new' : ''}`.trim();
      return `<tr data-key="${esc(k)}"${cls ? ` class="${esc(cls)}"` : ''} ${o.rowAttrs ? o.rowAttrs(r) : ''}>${o.columns.map((c) => `<td class="${esc(c.cls || '')}">${c.render(r)}</td>`).join('')}</tr>`;
    }).join('');
    return `<table class="table" data-table="${esc(id)}"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
  };

  /** Placeholder for a data region that has never loaded. */
  ui.loading = (view) => {
    const e = view && view.error;
    if (!e) return U.skeleton(6);
    if (e.kind === 'auth') return U.emptyState({ icon: 'lock', title: 'Access token rejected', body: 'Reopen the dashboard from PC Sentinel to get a fresh token.', tone: 'danger' });
    if (e.kind === 'network') return U.emptyState({ icon: 'wifiOff', title: 'Can’t reach the engine', body: 'Nothing loaded yet. Retrying every few seconds.', tone: 'danger' });
    return U.emptyState({ icon: 'alert', title: 'The engine couldn’t serve this view', body: `${esc(e.message || 'Unknown error')}. Retrying every few seconds.`, tone: 'warn' });
  };

  /* ================================================================== count-up numbers */
  ui.countUp = function (el, value, fmt) {
    if (!el) return;
    const f = fmt || U.fmtInt;
    const to = Number(value);
    if (value === null || value === undefined || isNaN(to)) {
      el.textContent = '—';
      el._v = undefined;
      return;
    }
    const from = el._v === undefined ? 0 : el._v;
    el._v = to;
    if (el._cancel) el._cancel();
    if (from === to || document.hidden || U.reducedMotion()) {
      el.textContent = f(to);
      return;
    }
    el._cancel = U.tween(900, (e) => { el.textContent = f(from + (to - from) * e); });
  };

  /* ================================================================== inline row actions */
  function actBtn(act, data, iconName, label, cls) {
    // data-* names are fixed keys from this file; values are escaped (they become dataset strings, never markup)
    const attrs = Object.entries(data).map(([k, v]) => `data-${k.replace(/[^a-z-]/g, '')}="${esc(v === null || v === undefined ? '' : v)}"`).join(' ');
    return `<button type="button" class="icon-btn sm act ${esc(cls || '')}" data-act="${esc(act)}" ${attrs} aria-label="${esc(label)}" title="${esc(label)}">${icon(iconName, { size: 15 })}</button>`;
  }
  /** Quick actions for a table row. Each part is optional; Block is only offered for public IPs, Kill for PIDs > 4. */
  ui.rowActions = function (o) {
    const b = [];
    if (o.ip && U.isPublicIp(o.ip)) b.push(actBtn('block', { ip: o.ip }, 'ban', `Block ${o.ip} in the firewall`, 'act-danger'));
    if (o.pid && Number(o.pid) > 4) b.push(actBtn('kill', { pid: o.pid, name: o.name || '', exe: o.exe || '' }, 'kill', `Kill ${o.name || 'process'} (PID ${o.pid})`, 'act-danger'));
    if (o.allow && o.allow.value) b.push(actBtn('allow', { kind: o.allow.kind, value: o.allow.value, label: o.allow.label || '' }, 'allow', `Allow ${o.allow.label || o.allow.value}`, 'act-ok'));
    return b.length ? `<div class="row-actions">${b.join('')}</div>` : '';
  };

  /* ================================================================== actions */
  const A = (PCS.actions = {});
  const refresh = () => { if (PCS.app) PCS.app.refresh(); };

  async function run(path, body, o) {
    const x = o || {};
    try {
      const r = await PCS.api.post(path, body);
      if (r && r.ok === false) {
        ui.toast({ kind: 'error', title: x.failTitle || 'Action refused', message: r.message || 'The engine refused the request.' });
        return r;
      }
      ui.toast({ kind: x.kind || 'success', title: x.title || 'Done', message: (r && r.message) || x.message || '' });
      refresh();
      return r || { ok: true };
    } catch (e) {
      ui.toast({ kind: 'error', title: 'Action failed', message: e && e.kind === 'network' ? 'Engine offline: the request was not delivered.' : (e && e.message) || 'Unknown error' });
      return null;
    }
  }

  A.kill = async function (p) {
    const pid = Number(p && p.pid);
    if (!pid || pid <= 4) return null;
    const name = p.name || 'this process';
    const ok = await ui.dialog({
      title: `Kill ${name}?`, icon: 'kill', tone: 'danger', confirmLabel: 'Kill process', confirmIcon: 'kill',
      body: `<p>The engine will terminate <b class="mono">${esc(name)}</b> (PID <span class="mono">${pid}</span>). Anything unsaved in that program is lost.</p>
        ${p.exe ? `<p class="mono small muted break">${esc(p.exe)}</p>` : ''}
        <p class="small muted">If it restarts on its own, check the Persistence view for the autostart entry.</p>`,
    });
    if (!ok) return null;
    return run('/api/actions/kill', { pid }, { title: 'Process terminated' });
  };

  /* What the firewall step looks like on each OS (the engine performs it; the UI only explains it). */
  const ELEVATION_PROMPT = {
    windows: 'Windows shows an administrator (UAC) prompt. Approve it to apply the rule.',
    macos: 'macOS asks for an administrator password. Enter it to apply the rule.',
    linux: 'Your desktop asks for an administrator password (polkit). Enter it to apply the rule.',
  };
  A.blockIp = async function (ip) {
    if (!ip) return null;
    const plat = U.platform();
    const ok = await ui.dialog({
      title: `Block ${ip}?`, icon: 'ban', tone: 'danger', confirmLabel: 'Request firewall rule', confirmIcon: 'ban',
      body: `<p>The engine adds <b class="mono">${esc(ip)}</b> to the blocklist and asks ${esc(U.osName(plat))} to create a firewall rule for it.</p>
        <p class="callout tone-warn">${icon('shield', { size: 16 })}<span>${esc(U.own(ELEVATION_PROMPT, plat) || 'The system may ask for administrator approval. Approve it to apply the rule.')}</span></p>`,
    });
    if (!ok) return null;
    return run('/api/actions/block_ip', { ip }, { kind: 'info', title: 'Firewall rule requested', message: 'Approve the admin prompt to apply it.' });
  };

  const KIND_LABEL = { process: 'This program', destination: 'This destination', privacy: 'Camera / mic use by this program', persistence: 'This autostart program' };
  /** choices: [{ kind, value, label? }] — the user picks one, adds a note, and it goes to the allowlist. */
  A.allow = async function (o) {
    const choices = (o.choices || [{ kind: o.kind, value: o.value, label: o.label }]).filter((c) => c && c.kind && c.value);
    if (!choices.length) return null;
    const multi = choices.length > 1;
    const fields = [];
    if (multi) {
      fields.push({ type: 'radio', name: 'choice', label: 'What should be trusted?', value: '0', options: choices.map((c, i) => ({ value: String(i), label: c.label || KIND_LABEL[c.kind] || c.kind, hint: c.value })) });
    }
    fields.push({ name: 'note', label: 'Note (why is this OK?)', placeholder: 'e.g. my own dev tool', value: o.note || '' });
    const res = await ui.dialog({
      title: 'Add to allowlist', icon: 'allow', confirmLabel: 'Allow', confirmIcon: 'allow',
      body: multi ? '<p class="muted">Matching alerts are closed and similar activity stops raising alerts.</p>'
        : `<p class="muted">${esc(KIND_LABEL[choices[0].kind] || choices[0].kind)}:</p><p class="mono break code-block">${esc(choices[0].value)}</p><p class="muted small">Matching alerts are closed and similar activity stops raising alerts.</p>`,
      fields,
    });
    if (!res) return null;
    const c = multi ? choices[Number(res.choice) || 0] : choices[0];
    return run('/api/actions/allow', { kind: c.kind, value: c.value, note: res.note || '' }, { title: 'Added to allowlist' });
  };

  A.ack = async function (id) {
    try {
      await PCS.api.post(`/api/alerts/${encodeURIComponent(id)}/ack`, {});
      if (PCS.app) PCS.app.patchAlert(id, { status: 'acknowledged' });
      ui.toast({ kind: 'success', title: 'Alert acknowledged' });
      refresh();
      return true;
    } catch (e) {
      ui.toast({ kind: 'error', title: 'Could not acknowledge', message: e.message });
      return false;
    }
  };

  A.ackAll = async function (severity, count) {
    const label = severity ? (U.own(U.SEV_LABEL, severity) || '').toLowerCase() : '';
    const ok = await ui.dialog({
      title: `Acknowledge all ${label} alerts?`, icon: 'checkCheck', confirmLabel: 'Acknowledge all',
      body: `<p>${count ? `${U.plural(count, `open ${label} alert`)} will` : `Every open ${label} alert will`} move to <b>acknowledged</b>. They stay in the history under “All”.</p>`,
    });
    if (!ok) return null;
    try {
      const r = await PCS.api.post('/api/alerts/ack_all', severity ? { severity } : {});
      ui.toast({ kind: 'success', title: 'Alerts acknowledged', message: `${U.plural((r && r.count) || 0, `${label} alert`)} acknowledged.` });
      refresh();
      return r;
    } catch (e) {
      ui.toast({ kind: 'error', title: 'Could not acknowledge', message: e.message });
      return null;
    }
  };

  A.blocklistAdd = (ip, note) => run('/api/actions/blocklist', { ip, note: note || '' }, { title: 'Blocklist updated' });
  A.unblocklist = (id) => run('/api/actions/unblocklist', { id }, { title: 'Blocklist updated' });
  A.unallow = (id) => run('/api/actions/unallow', { id }, { title: 'Allowlist updated' });

  /** Desktop pop-ups (system notifications raised by the engine). Off by default. */
  A.setNotify = async function (enabled, minSeverity) {
    const st = PCS.state;
    const prev = Object.assign({}, st.notify);
    const next = { enabled: !!enabled, min_severity: minSeverity || prev.min_severity || 'high' };
    st.notify = next;
    PCS.bus.emit('notify', next);
    try {
      const r = await PCS.api.post('/api/actions/notify', next);
      if (r && r.ok === false) throw new Error(r.message || 'Refused');
      ui.toast({ kind: 'success', title: next.enabled ? 'Desktop pop-ups on' : 'Desktop pop-ups off', message: next.enabled ? `Desktop notifications for ${next.min_severity} alerts and above.` : 'Alerts stay in the dashboard only.' });
      return true;
    } catch (e) {
      st.notify = prev;
      PCS.bus.emit('notify', prev);
      ui.toast({ kind: 'error', title: 'Setting not saved', message: e.kind === 'network' ? 'Engine offline.' : e.message });
      return false;
    }
  };

  /** Start at login (settings.autostart, API.md v1.1). Resolves to true when the engine accepted the change. */
  A.setAutostart = async function (enabled) {
    try {
      const r = await PCS.api.post('/api/actions/autostart', { enabled: !!enabled });
      if (r && r.ok === false) {
        ui.toast({ kind: 'error', title: 'Start at login not changed', message: r.message || 'The engine refused the request.' });
        return false;
      }
      ui.toast({ kind: 'success', title: enabled ? 'Starts at login' : 'No longer starts at login', message: (r && r.message) || '' });
      return true;
    } catch (e) {
      ui.toast({ kind: 'error', title: 'Setting not saved', message: e && e.kind === 'network' ? 'Engine offline.' : (e && e.message) || 'Unknown error' });
      return false;
    }
  };
})();
