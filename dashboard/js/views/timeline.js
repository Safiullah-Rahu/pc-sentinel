/* PC Sentinel view: Timeline — every event (alerts + info observations), newest first, grouped by day. */
(function () {
  'use strict';
  const PCS = window.PCS;
  const U = PCS.util;
  const ui = PCS.ui;
  const icon = PCS.icon;
  const { esc } = U;

  const view = {
    id: 'timeline',
    title: 'Timeline',
    search: 'Filter events…',

    mount(root) {
      this.root = root;
      this.items = null;
      this.category = this.category || '';
      this.showInfo = this.showInfo !== false;
      root.innerHTML = `
        <div class="toolbar panel">
          <div class="cat-chips" role="group" aria-label="Category">
            ${['', ...U.CATEGORIES].map((c) => `<button type="button" class="cat-chip" data-cat="${c}" aria-pressed="${this.category === c}">${c ? icon(U.CAT_ICON[c], { size: 14 }) : ''}${c ? U.CAT_LABEL[c] : 'Everything'}</button>`).join('')}
          </div>
          <span class="spacer"></span>
          <button type="button" class="hud-toggle" data-r="info" aria-pressed="${this.showInfo}">${icon('info', { size: 14 })}Info events</button>
        </div>
        <div class="timeline" data-r="list">${U.skeleton(8)}</div>`;
      this.onClick = (e) => {
        const c = e.target.closest('[data-cat]');
        if (c) {
          this.category = c.dataset.cat;
          root.querySelectorAll('[data-cat]').forEach((b) => b.setAttribute('aria-pressed', String(b === c)));
          ui.resetTrack('timeline');
          this.items = null;
          this.render();
          this.load();
          return;
        }
        const i = e.target.closest('[data-r=info]');
        if (i) {
          this.showInfo = !this.showInfo;
          i.setAttribute('aria-pressed', String(this.showInfo));
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
        const r = await PCS.api.get(`/api/events?limit=300${this.category ? `&category=${encodeURIComponent(this.category)}` : ''}`);
        this.items = r.items || [];
        this.error = null;
      } catch (e) {
        this.error = e;
      }
      this.render();
    },

    render() {
      const el = this.root.querySelector('[data-r=list]');
      if (!this.items) {
        el.innerHTML = ui.loading(this);
        return;
      }
      let rows = this.items.filter((e) => this.showInfo || e.severity !== 'info');
      rows = U.filterRows(rows, PCS.state.search, (e) => U.hay(e.title, e.summary, e.category, e.severity));
      rows.sort((a, b) => (U.ms(b.ts) - U.ms(a.ts)) || ((b.id || 0) - (a.id || 0)));
      if (!rows.length) {
        el.innerHTML = U.emptyState({ icon: 'history', title: 'No events', body: 'Nothing recorded for this filter yet.' });
        return;
      }
      const fresh = ui.track('timeline', this.items.map((e) => String(e.id)));
      const groups = [];
      rows.forEach((e) => {
        const k = U.dayKey(e.ts);
        const g = groups[groups.length - 1];
        if (g && g.key === k) g.items.push(e);
        else groups.push({ key: k, label: U.dayLabel(e.ts), items: [e] });
      });
      el.innerHTML = groups.map((g) => `
        <section class="tl-day">
          <h2 class="tl-day-label"><span class="hud-label">${esc(g.label)}</span><span class="hud-sub">${U.plural(g.items.length, 'event')}</span></h2>
          <ol class="tl-list">${g.items.map((e) => `
            <li class="tl-item sev-${U.sevKey(e.severity)}${fresh.has(String(e.id)) ? ' is-new' : ''}">
              <time class="tl-time mono" datetime="${esc(e.ts)}" title="${esc(U.abs(e.ts))}">${esc(U.hms(e.ts))}</time>
              <span class="tl-node" aria-hidden="true">${icon(U.catIcon(e.category), { size: 14 })}</span>
              <div class="tl-body">
                <div class="tl-title">${esc(e.title)}${e.severity !== 'info' ? ` ${U.sevBadge(e.severity)}` : ''}</div>
                ${e.summary ? `<div class="tl-summary">${esc(e.summary)}</div>` : ''}
              </div>
              <span class="tl-cat">${esc(U.catLabel(e.category))}</span>
            </li>`).join('')}</ol>
        </section>`).join('');
    },
  };

  PCS.views = PCS.views || {};
  PCS.views.timeline = view;
})();
