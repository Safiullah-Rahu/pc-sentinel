/* PC Sentinel dashboard: engine API client (token header, error classification, SSE with reconnect).
   Falls back to the built-in mock engine (mock.js) when no token was injected or ?mock=1 is set. */
(function () {
  'use strict';
  const PCS = (window.PCS = window.PCS || {});

  // Built by concatenation so the engine's literal search-and-replace can never rewrite this file.
  const PLACEHOLDER = '__SENTINEL' + '_TOKEN__';
  const meta = document.querySelector('meta[name="sentinel-token"]');
  const token = ((meta && meta.getAttribute('content')) || '').trim();
  const params = new URLSearchParams(location.search);
  const isMock = !token || token === PLACEHOLDER || params.get('mock') === '1';
  const TIMEOUT_MS = 10000;

  class ApiError extends Error {
    constructor(message, status, kind) {
      super(message);
      this.status = status || 0;
      this.kind = kind || 'http'; // network | auth | http | parse
    }
  }

  /* connectivity status: null (unknown) | 'online' | 'offline' | 'unauthorized' */
  let status = null;
  let lastOk = null;
  const listeners = new Set();
  function setStatus(next) {
    if (next === 'online') lastOk = Date.now();
    if (next === status) return;
    status = next;
    listeners.forEach((fn) => {
      try { fn(next); } catch (e) { console.error(e); }
    });
  }

  async function request(method, path, body) {
    if (isMock) {
      try {
        const data = await PCS.mock.request(method, path, body);
        setStatus('online');
        return data;
      } catch (e) {
        if (e && e.status) throw new ApiError(e.message, e.status, 'http');
        setStatus('offline');
        throw new ApiError('Engine unreachable', 0, 'network');
      }
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    const headers = { 'X-Sentinel-Token': token, Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch(path, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        cache: 'no-store',
        credentials: 'same-origin',
        signal: ctrl.signal,
      });
    } catch (e) {
      clearTimeout(timer);
      setStatus('offline');
      throw new ApiError('Engine unreachable', 0, 'network');
    }

    let data = null;
    try {
      const text = await res.text();
      if (text) data = JSON.parse(text);
    } catch (e) {
      data = null;
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 401 || res.status === 403) {
      setStatus('unauthorized');
      throw new ApiError('The engine rejected the dashboard token', res.status, 'auth');
    }
    if (res.status >= 502 && res.status <= 504) {
      setStatus('offline');
      throw new ApiError('Engine unavailable', res.status, 'network');
    }
    setStatus('online');
    if (!res.ok) {
      let msg = data && (data.message || data.detail || data.error);
      if (typeof msg !== 'string') msg = `HTTP ${res.status}`;
      throw new ApiError(msg, res.status, 'http');
    }
    if (data === null && res.status !== 204) throw new ApiError('Unreadable response from the engine', res.status, 'parse');
    return data;
  }

  /** Server-Sent Events: named events metric / alert / summary. EventSource retries on its own;
      if the server answers with a hard error (stream CLOSED) we reconnect after 5 s. */
  function stream(h) {
    let es = null;
    let retry = null;
    let closed = false;
    const connect = () => {
      if (closed) return;
      es = isMock ? PCS.mock.stream() : new EventSource(`/api/stream?token=${encodeURIComponent(token)}`);
      es.onopen = () => { if (h.open) h.open(); };
      es.onerror = () => {
        if (h.error) h.error();
        if (es.readyState === 2 && !closed) {
          clearTimeout(retry);
          retry = setTimeout(connect, 5000);
        }
      };
      ['metric', 'alert', 'summary'].forEach((type) => {
        es.addEventListener(type, (e) => {
          let data;
          try { data = JSON.parse(e.data); } catch (err) { return; }
          if (h.any) h.any(type);
          if (h[type]) h[type](data);
        });
      });
    };
    connect();
    return {
      close() {
        closed = true;
        clearTimeout(retry);
        if (es) es.close();
      },
    };
  }

  PCS.api = {
    isMock,
    hasToken: !!token && token !== PLACEHOLDER,
    ApiError,
    get: (path) => request('GET', path),
    post: (path, body) => request('POST', path, body === undefined ? {} : body),
    stream,
    onStatus(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    get status() { return status; },
    get lastOk() { return lastOk; },
  };
})();
