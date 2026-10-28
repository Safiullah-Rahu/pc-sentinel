/* PC Sentinel view: Settings — allowlist / blocklist, desktop pop-ups, engine info, coverage, display. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;
  const KINDS = [
    ['process', 'Program'],
    ['destination', 'Destination IP'],
    ['privacy', 'Camera / mic program'],
    ['persistence', 'Autostart program'],
  ];
  /* Value placeholders per OS (paths look different on every system). */
  const EXAMPLE = {
    windows: { process: 'Full path to the .exe, e.g. C:\\Program Files\\nodejs\\node.exe', privacy: 'Full path to the .exe allowed to use camera or microphone', persistence: 'Full path to the .exe allowed to autostart' },
    macos: { process: 'Full path to the program, e.g. /opt/homebrew/bin/node', privacy: 'Full path to the app binary, e.g. /Applications/zoom.us.app/Contents/MacOS/zoom.us', persistence: 'Full path to the program allowed to autostart' },
    linux: { process: 'Full path to the program, e.g. /usr/bin/node', privacy: 'Full path to the program, e.g. /opt/zoom/zoom', persistence: 'Full path to the program allowed to autostart' },
  };
  const placeholder = (kind) => (kind === 'destination' ? 'e.g. 198.51.100.7' : (U.own(EXAMPLE, U.platform()) || EXAMPLE.windows)[kind] || '');
  const KIND_LABEL = Object.fromEntries(KINDS.map((k) => [k[0], k[1]]));
  const LEVELS = [['critical', 'Critical only'], ['high', 'High and above'], ['medium', 'Medium and above'], ['low', 'Low and above']];

  const view = {
    id: 'settings',
    title: 'Settings',
    search: 'Filter allowlist and blocklist…',

    mount(root) {
      this.root = root;
      this.data = null;
      root.innerHTML = `
        <div class="settings-grid">
          <div class="settings-col">
            <section class="panel brackets" aria-labelledby="h-allow">
              <div class="panel-head"><h2 class="hud-label" id="h-allow">${icon('shieldCheck', { size: 13 })}Allowlist</h2><span class="hud-sub" data-r="allow-count"></span></div>
              <p class="panel-note">Trusted programs, destinations and devices. Matching activity no longer raises alerts.</p>
              <form class="inline-form" data-form="allow" novalidate>
                <label class="field"><span class="field-label">Type</span>
                  <select class="input input-sm" name="kind">${KINDS.map((k) => `<option value="${k[0]}">${k[1]}</option>`).join('')}</select></label>
                <label class="field grow"><span class="field-label">Value</span>
                  <input class="input input-sm mono" name="value" placeholder="${esc(placeholder('process'))}" autocomplete="off" spellcheck="false" maxlength="400" required></label>
                <label class="field grow"><span class="field-label">Note</span>
                  <input class="input input-sm" name="note" placeholder="Why it’s OK" autocomplete="off" maxlength="200"></label>
                <button type="submit" class="btn btn-sm btn-primary">${icon('plus', { size: 15 })}Add</button>
              </form>
              <div class="table-wrap" data-r="allow">${U.skeleton(4)}</div>
            </section>
            <section class="panel brackets" aria-labelledby="h-block">
              <div class="panel-head"><h2 class="hud-label" id="h-block">${icon('ban', { size: 13 })}Blocklist</h2><span class="hud-sub" data-r="block-count"></span></div>
              <p class="panel-note">Known-bad addresses. Any connection to one raises a critical alert. Use “Block IP” on an alert to also add a firewall rule.</p>
              <form class="inline-form" data-form="block" novalidate>
                <label class="field"><span class="field-label">IP address</span>
                  <input class="input input-sm mono" name="ip" placeholder="e.g. 203.0.113.45" autocomplete="off" spellcheck="false" maxlength="64" required></label>
                <label class="field grow"><span class="field-label">Note</span>
                  <input class="input input-sm" name="note" placeholder="Source or reason" autocomplete="off" maxlength="200"></label>
                <button type="submit" class="btn btn-sm btn-primary">${icon('plus', { size: 15 })}Add</button>
              </form>
              <div class="table-wrap" data-r="block">${U.skeleton(3)}</div>
            </section>
          </div>
          <div class="settings-col">
            <section class="panel brackets" aria-labelledby="h-notify">
              <div class="panel-head"><h2 class="hud-label" id="h-notify">${icon('bell', { size: 13 })}Desktop pop-ups</h2></div>
              <div class="setting-row">
                <div><div class="setting-title">Desktop notifications for new alerts</div>
                  <div class="setting-desc" data-r="notify-desc">Off by default. Alerts always appear in the dashboard; this adds a system pop-up as well.</div></div>
                <button type="button" class="switch" role="switch" data-r="notify-switch" aria-checked="false" aria-label="Desktop pop-ups"><span class="switch-knob"></span></button>
              </div>
              <div class="setting-row">
                <label for="notify-min"><div class="setting-title">Minimum severity</div><div class="setting-desc">Pop up for alerts at or above this level.</div></label>
                <select class="input input-sm" id="notify-min" data-r="notify-min">${LEVELS.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select>
              </div>
            </section>
            <section class="panel brackets" aria-labelledby="h-startup">
              <div class="panel-head"><h2 class="hud-label" id="h-startup">${icon('power', { size: 13 })}Startup</h2></div>
              <div class="setting-row" data-r="autostart-row">
                <div><div class="setting-title">Start at login</div>
                  <div class="setting-desc" data-r="autostart-desc">Checking…</div></div>
                <button type="button" class="switch" role="switch" data-r="autostart-switch" aria-checked="false" aria-label="Start PC Sentinel at login" disabled><span class="switch-knob"></span></button>
              </div>
            </section>
            <section class="panel brackets" aria-labelledby="h-engine">
              <div class="panel-head"><h2 class="hud-label" id="h-engine">${icon('server', { size: 13 })}Engine</h2></div>
              <div data-r="engine">${U.skeleton(4)}</div>
            </section>
            <section class="panel brackets" aria-labelledby="h-cov">
              <div class="panel-head"><h2 class="hud-label" id="h-cov">${icon('radar', { size: 13 })}Coverage</h2></div>
              <div data-r="coverage">${U.skeleton(3)}</div>
            </section>
            <section class="panel brackets" aria-labelledby="h-display">
              <div class="panel-head"><h2 class="hud-label" id="h-display">${icon('sparkles', { size: 13 })}Display</h2></div>
              <div class="setting-row">
                <div><div class="setting-title">Background motion</div>
                  <div class="setting-desc">Animated grid, radar sweeps and flowing packets. Always off when your system asks apps to reduce motion.</div></div>
                <button type="button" class="switch" role="switch" data-r="fx-switch" aria-checked="${PCS.state.fx !== false}" aria-label="Background motion"><span class="switch-knob"></span></button>
              </div>
            </section>
          </div>
        </div>`;

      this.onSubmit = async (e) => {
        const form = e.target.closest('form[data-form]');
        if (!form) return;
        e.preventDefault();
        const f = form.elements;
        if (form.dataset.form === 'allow') {
          const kind = f.kind.value;
          const value = f.value.value.trim();
          if (!value) return this.invalid(f.value, 'Enter a value to allow.');
          if (kind === 'destination' && !U.isValidIp(value)) return this.invalid(f.value, 'That is not a valid IP address.');
          const r = await PCS.actions.allow({ kind, value, note: f.note.value.trim() });
          if (r && r.ok !== false) form.reset();
        } else {
          const ip = f.ip.value.trim();
          if (!U.isValidIp(ip)) return this.invalid(f.ip, 'Enter a valid IPv4 or IPv6 address.');
          const r = await PCS.actions.blocklistAdd(ip, f.note.value.trim());
          if (r && r.ok !== false) form.reset();
        }
        return null;
      };
      this.onChange = (e) => {
        if (e.target.name === 'kind') {
          e.target.form.elements.value.placeholder = placeholder(e.target.value);
        }
        if (e.target.matches('[data-r=notify-min]')) {
          PCS.actions.setNotify(PCS.state.notify.enabled, e.target.value);
        }
      };
      this.onClick = async (e) => {
        const rm = e.target.closest('[data-remove]');
        if (rm) {
          const [list, id] = rm.dataset.remove.split(':');
          const ok = await ui.dialog({
            title: list === 'allow' ? 'Remove from allowlist?' : 'Remove from blocklist?', icon: 'trash', tone: 'danger', confirmLabel: 'Remove',
            body: `<p class="mono break code-block">${esc(rm.dataset.value || '')}</p><p class="muted small">${list === 'allow' ? 'Matching activity will raise alerts again.' : 'Connections to this address will no longer raise a blocklist alert. Firewall rules are not touched.'}</p>`,
          });
          if (ok) {
            if (list === 'allow') PCS.actions.unallow(Number(id));
            else PCS.actions.unblocklist(Number(id));
          }
          return;
        }
        if (e.target.closest('[data-r=notify-switch]')) {
          PCS.actions.setNotify(!PCS.state.notify.enabled, PCS.state.notify.min_severity);
          return;
        }
        const as = e.target.closest('[data-r=autostart-switch]');
        if (as && !as.disabled) {
          const a = this.autostart();
          if (!a.supported || this.autostartBusy) return;
          const next = !a.enabled;
          this.autostartBusy = true;
          as.setAttribute('aria-checked', String(next)); // optimistic; reverted below if the engine refuses
          as.setAttribute('aria-busy', 'true');
          const ok = await PCS.actions.setAutostart(next);
          this.autostartBusy = false;
          as.removeAttribute('aria-busy');
          if (ok && this.data) this.data.autostart = Object.assign({}, a, { enabled: next });
          this.renderAutostart();
          return;
        }
        const fx = e.target.closest('[data-r=fx-switch]');
        if (fx) PCS.app.setFx(PCS.state.fx === false);
      };
      root.addEventListener('submit', this.onSubmit);
      root.addEventListener('change', this.onChange);
      root.addEventListener('click', this.onClick);
      this.offNotify = PCS.bus.on('notify', () => this.renderNotify());
      this.offSummary = PCS.bus.on('summary', () => this.renderEngine());
      this.offFx = PCS.bus.on('fx', () => {
        const sw = root.querySelector('[data-r=fx-switch]');
        if (sw) sw.setAttribute('aria-checked', String(PCS.state.fx !== false));
      });
      this.renderNotify();
      this.renderEngine();
    },
    unmount() {
      this.root.removeEventListener('submit', this.onSubmit);
      this.root.removeEventListener('change', this.onChange);
      this.root.removeEventListener('click', this.onClick);
      this.offNotify();
      this.offSummary();
      this.offFx();
    },

    invalid(input, msg) {
      input.setCustomValidity(msg);
      input.reportValidity();
      input.addEventListener('input', () => input.setCustomValidity(''), { once: true });
      return null;
    },

    async load() {
      const [s, sum] = await Promise.allSettled([PCS.api.get('/api/settings'), PCS.api.get('/api/summary')]);
      if (s.status === 'fulfilled') {
        this.data = s.value;
        this.error = null;
        PCS.app.setNotifyFromSettings(s.value);
      } else this.error = s.reason;
      if (sum.status === 'fulfilled') PCS.app.setSummary(sum.value);
      this.render();
    },

    render() {
      this.renderLists();
      this.renderNotify();
      this.renderAutostart();
      this.renderEngine();
    },

    /** settings.autostart = { supported, enabled, detail } (API.md v1.1); missing = not supported by this engine. */
    autostart() {
      const a = this.data && this.data.autostart && typeof this.data.autostart === 'object' ? this.data.autostart : null;
      return { known: !!a, supported: !!(a && a.supported === true), enabled: !!(a && a.enabled === true), detail: a && typeof a.detail === 'string' ? a.detail : '' };
    },

    renderAutostart() {
      const row = this.root.querySelector('[data-r=autostart-row]');
      const sw = this.root.querySelector('[data-r=autostart-switch]');
      const desc = this.root.querySelector('[data-r=autostart-desc]');
      if (!this.data) return; // keeps "Checking…" until settings arrive
      const a = this.autostart();
      if (this.autostartBusy) return;
      sw.setAttribute('aria-checked', String(a.supported && a.enabled));
      sw.disabled = !a.supported;
      row.classList.toggle('is-disabled', !a.supported);
      if (!a.supported) {
        desc.textContent = a.known
          ? `Not available on ${U.osName()}${a.detail ? ` (${a.detail})` : ''}.`
          : 'This engine version cannot change start-at-login.';
        return;
      }
      // detail comes from the engine (e.g. "Startup folder shortcut"): plain text only
      desc.textContent = `${a.enabled ? 'On' : 'Off'}${a.detail ? ` · ${a.detail}` : ''}. Monitoring starts in the background when you log in.`;
    },

    renderLists() {
      const a = this.root.querySelector('[data-r=allow]');
      const b = this.root.querySelector('[data-r=block]');
      if (!this.data) {
        a.innerHTML = ui.loading(this);
        b.innerHTML = '';
        return;
      }
      const allow = this.data.allowlist || [];
      const block = this.data.blocklist || [];
      this.root.querySelector('[data-r=allow-count]').textContent = U.plural(allow.length, 'entry', 'entries');
      this.root.querySelector('[data-r=block-count]').textContent = U.plural(block.length, 'address', 'addresses');
      const q = PCS.state.search;
      a.innerHTML = ui.table('set-allow', {
        rows: U.filterRows(allow, q, (x) => U.hay(x.kind, x.value, x.note)), key: (x) => String(x.id),
        defaultSort: { col: 'ts', dir: 'desc' },
        empty: U.emptyState({ icon: 'shieldCheck', title: 'Allowlist is empty', body: 'Use “Allow” on an alert, or add an entry above.', compact: true }),
        columns: [
          { id: 'kind', label: 'Type', sort: (x) => x.kind, render: (x) => `<span class="chip tone-neutral">${esc(U.own(KIND_LABEL, x.kind) || x.kind)}</span>` },
          { id: 'value', label: 'Value', sort: (x) => x.value, cls: 'col-main', render: (x) => `${U.copyBtn(x.value, U.middle(x.value, 64), 'mono path')}${x.note ? `<div class="cell-sub">${esc(x.note)}</div>` : ''}` },
          { id: 'ts', label: 'Added', sort: (x) => U.ms(x.ts), render: (x) => U.relTime(x.ts) },
          { id: 'rm', sr: 'Remove', render: (x) => `<button type="button" class="icon-btn sm act act-danger" data-remove="allow:${esc(x.id)}" data-value="${esc(x.value)}" aria-label="Remove ${esc(x.value)} from allowlist" title="Remove">${icon('trash', { size: 15 })}</button>` },
        ],
      });
      b.innerHTML = ui.table('set-block', {
        rows: U.filterRows(block, q, (x) => U.hay(x.ip, x.note)), key: (x) => String(x.id),
        defaultSort: { col: 'ts', dir: 'desc' },
        empty: U.emptyState({ icon: 'ban', title: 'Blocklist is empty', compact: true }),
        columns: [
          { id: 'ip', label: 'IP', sort: (x) => x.ip, render: (x) => U.copyBtn(x.ip, x.ip, 'mono') },
          { id: 'note', label: 'Note', sort: (x) => x.note, cls: 'col-main', render: (x) => (x.note ? esc(x.note) : '<span class="muted">—</span>') },
          { id: 'ts', label: 'Added', sort: (x) => U.ms(x.ts), render: (x) => U.relTime(x.ts) },
          { id: 'rm', sr: 'Remove', render: (x) => `<button type="button" class="icon-btn sm act act-danger" data-remove="block:${esc(x.id)}" data-value="${esc(x.ip)}" aria-label="Remove ${esc(x.ip)} from blocklist" title="Remove">${icon('trash', { size: 15 })}</button>` },
        ],
      });
    },

    renderNotify() {
      const n = PCS.state.notify || { enabled: false, min_severity: 'high' };
      const sw = this.root.querySelector('[data-r=notify-switch]');
      sw.setAttribute('aria-checked', String(!!n.enabled));
      const sel = this.root.querySelector('[data-r=notify-min]');
      if (document.activeElement !== sel) sel.value = n.min_severity || 'high';
      sel.disabled = !n.enabled;
    },

    renderEngine() {
      const s = PCS.state.summary;
      const el = this.root.querySelector('[data-r=engine]');
      const cov = this.root.querySelector('[data-r=coverage]');
      if (!s) return;
      const e = s.engine || {};
      const plat = U.platform(s);
      const form = this.root.querySelector('form[data-form=allow]');
      if (form && !form.elements.value.value) form.elements.value.placeholder = placeholder(form.elements.kind.value);
      el.innerHTML = ui.kv([
        ['Version', `<span class="mono">${esc(e.version || '—')}</span>`],
        ['System', esc(U.osLabel(s) || '—')],
        ['Host', `<span class="mono">${esc(e.host || '—')}</span>`],
        ['User', `<span class="mono">${esc(e.user || '—')}</span>`],
        ['Elevated', e.elevated ? '<span class="pill tone-ok">Yes</span>' : `<span class="pill tone-warn">No</span> <span class="muted small">${plat === 'macos' || plat === 'linux' ? 'Run PC Sentinel with administrator/root rights for more coverage' : 'some monitors need admin rights'}</span>`],
        ['Started', e.started ? `<span title="${esc(U.abs(e.started))}">${esc(U.shortTs(e.started))}</span>` : '—'],
        ['Uptime', '<span class="num" data-uptime></span>'],
        ['Data source', PCS.api.isMock ? '<span class="pill tone-warn">Built-in mock data</span>' : '<span class="pill tone-ok">Live engine</span> <span class="mono muted small">127.0.0.1:8777</span>'],
        ['Live stream', PCS.state.streamLive ? '<span class="pill tone-ok">Connected</span>' : '<span class="pill tone-warn">Reconnecting</span>'],
      ]);
      PCS.app.tickUptime();
      const c = s.coverage || {};
      const off = U.coverageList(s).filter((x) => x.admin && !U.coverageOn(c, x.key));
      cov.innerHTML = `<ul class="cov-list">${U.COVERAGE.map((x) => {
        const st = U.coverageState(s, x.key);
        const pill = st === 'on' ? '<span class="pill tone-ok">Active</span>'
          : st === 'na' ? U.naPill(plat)
            : `<span class="pill tone-muted">${x.admin ? 'Needs admin' : 'Off'}</span>`;
        return `<li class="is-${st}">${icon(x.icon, { size: 15 })}<span>${esc(x.label)}${x.key === 'canaries' && st === 'on' ? ` <span class="muted">(${esc(U.fmtInt(c.canaries))})</span>` : ''}</span>${pill}</li>`;
      }).join('')}</ul>${off.length ? `<p class="cov-hint">${icon('info', { size: 14 })}<span>${U.setupHint(off.map((x) => x.label).join(', '), plat)}</span></p>` : ''}`;
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.settings = view;
})();
