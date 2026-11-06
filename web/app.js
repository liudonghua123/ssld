/* ssld console. Vanilla JS, one JS clock drives every story loop. */
(() => {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const mono = (v) => `<span class="mono">${esc(v)}</span>`;
  const SVGNS = 'http://www.w3.org/2000/svg';

  const S = {
    view: 'overview', theme: localStorage.getItem('ssld-theme') || 'system',
    lang: localStorage.getItem('ssld-lang') || 'en',
    overview: null, catalog: null, endpoints: [], events: [], certs: [], hooks: [],
    deliveries: [], workflows: [], runs: [], monitors: [], accesses: [], cas: [],
    leaves: [], plugins: [], channels: [], settings: {}, tools: [],
    clock: 0, running: true, raf: null, sse: null, lastRefresh: 0, runwayGeom: null,
  };

  const I18N = {
    en: {
      overview: 'Overview', certificates: 'Certificates', workflows: 'Workflows', monitors: 'Monitors',
      webhooks: 'Webhooks', events: 'Event stream', credentials: 'Credentials', privateca: 'Private CA',
      plugins: 'Plugins', api: 'API & MCP', settings: 'Settings',
      issue: 'Issue certificate', audit: 'Run audit', refresh: 'Refresh data',
    },
    zh: {
      overview: '总览', certificates: '证书', workflows: '工作流', monitors: '监控',
      webhooks: 'Webhook', events: '事件流', credentials: '凭据', privateca: '私有 CA',
      plugins: '插件', api: 'API 与 MCP', settings: '设置',
      issue: '签发证书', audit: '运行审计', refresh: '刷新数据',
    },
  };

  // ---- API ----------------------------------------------------------------
  async function api(path, opts = {}) {
    const init = { credentials: 'same-origin', ...opts, headers: { ...(opts.headers || {}) } };
    if (opts.body && typeof opts.body !== 'string') {
      init.body = JSON.stringify(opts.body);
      init.headers['Content-Type'] = 'application/json';
    }
    const res = await fetch(path, init);
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { code: res.status, message: text }; }
    if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);
    if (data && data.code && data.code !== 0) throw new Error(data.message || 'request failed');
    return data && 'data' in data ? data.data : data;
  }
  const post = (p, body) => api(p, { method: 'POST', body: body || {} });
  const put = (p, body) => api(p, { method: 'PUT', body: body || {} });
  const del = (p) => api(p, { method: 'DELETE' });

  function toast(message, isError = false) {
    const el = $('#toast');
    el.textContent = message;
    el.className = `toast show${isError ? ' error' : ''}`;
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.className = 'toast'; }, 3600);
  }
  const fmtTime = (v) => {
    if (!v) return '—';
    const d = new Date(v);
    if (isNaN(d)) return v;
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  };
  const shortTime = (v) => { const d = new Date(v); return isNaN(d) ? '—' : `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`; };
  const statePill = (state) => {
    const map = { valid: ['ok', 'Valid'], expiring: ['warn', 'Expiring'], expired: ['bad', 'Expired'],
      success: ['ok', 'Success'], fail: ['bad', 'Failed'], partial: ['warn', 'Partial'], running: ['neutral', 'Running'] };
    const [k, label] = map[state] || ['neutral', state || '—'];
    return `<span class="pill pill-${k}">${esc(label)}</span>`;
  };

  // ---- data ---------------------------------------------------------------
  async function refresh(silent = false) {
    try {
      const [ov, cap, ep, ev] = await Promise.all([
        api('/api/v1/overview'), api('/api/v1/capabilities'),
        api('/api/v1/endpoints'), api('/api/v1/events?limit=60'),
      ]);
      S.overview = ov; S.catalog = cap; S.endpoints = ep.endpoints || []; S.events = ev.list || [];
      S.lastRefresh = Date.now();
      renderOverview(); renderEventViews(); renderApiView(); renderCapabilityStrip();
      $('#navCertCount').textContent = ov.certificates?.total || '';
      $('#navHookCount').textContent = ov.webhooks?.subscriptions || '';
      $('#freshness').textContent = `Updated ${new Date().toLocaleTimeString()}`;
      if (!silent) loadViewData(S.view);
    } catch (e) {
      toast(`Cannot reach ssld: ${e.message}`, true);
      setLive(false);
    }
  }

  async function loadViewData(view) {
    try {
      switch (view) {
        case 'certificates': {
          const status = $('#certStatus').value, search = $('#certSearch').value;
          const d = await api(`/api/v1/certificates?status=${encodeURIComponent(status)}&search=${encodeURIComponent(search)}`);
          S.certs = d.list || []; renderCertificates(); break;
        }
        case 'workflows': {
          const [w, r] = await Promise.all([api('/api/v1/workflows'), api('/api/v1/workflow-runs?limit=30')]);
          S.workflows = w.list || []; S.runs = r.list || []; renderWorkflows(); break;
        }
        case 'monitors': {
          const d = await api('/api/v1/monitors'); S.monitors = d.list || []; renderMonitors(); break;
        }
        case 'webhooks': {
          const [h, d, s] = await Promise.all([api('/api/v1/webhooks'), api('/api/v1/webhook-deliveries?limit=30'), api('/api/v1/webhooks/stats')]);
          S.hooks = h.list || []; S.deliveries = d.list || []; renderWebhooks(s); break;
        }
        case 'events': renderEventViews(); break;
        case 'credentials': {
          const d = await api('/api/v1/accesses'); S.accesses = d.list || []; renderCredentials(); break;
        }
        case 'privateca': {
          const [c, l] = await Promise.all([api('/api/v1/ca'), api('/api/v1/leaves')]);
          S.cas = c.list || []; S.leaves = l.list || []; renderPrivateCa(); break;
        }
        case 'plugins': {
          const d = await api('/api/v1/plugins'); S.plugins = d.list || []; renderPlugins(); break;
        }
        case 'api': renderApiView(); break;
        case 'settings': {
          const [s, c] = await Promise.all([api('/api/v1/settings'), api('/api/v1/channels')]);
          S.settings = s.settings || {}; S.channels = c.list || []; renderSettings(); break;
        }
      }
    } catch (e) { toast(`${view}: ${e.message}`, true); }
  }

  // ---- overview -----------------------------------------------------------
  function renderOverview() {
    const o = S.overview; if (!o) return;
    const c = o.certificates || {}, w = o.workflows || {}, m = o.monitors || {}, h = o.webhooks || {};
    const kpis = [c.total || 0, c.expiring || 0, c.expired || 0, w.active || 0, Math.round(h.success_rate || 0)];
    $$('#kpiStrip .kpi').forEach((el, i) => {
      const valueEl = $('.kpi-value', el);
      countTo(valueEl, kpis[i], i === 4 ? '%' : '');
      el.classList.toggle('is-alert', i === 2 && kpis[i] > 0);
      el.classList.toggle('is-warn', i === 1 && kpis[i] > 0);
    });
    const recos = o.recommendations || [];
    const top = recos[0];
    $('#finding').textContent = top && top.severity !== 'ok'
      ? `${top.text} ${recos.length > 1 ? `${recos.length - 1} more items need attention.` : ''}`
      : `All ${c.total || 0} certificates are healthy. ${w.active || 0} workflows and ${m.active || 0} monitors are watching the fleet.`;
    $('#runwayMeta').textContent = `${c.total || 0} certificates · ${o.version}`;
    drawRunway(o.upcoming_expirations || [], (c.expiry_buckets || {}));
    const health = o.health_score ?? 100;
    $('#healthRing').style.strokeDashoffset = String(389.5 * (1 - health / 100));
    $('#healthRing').style.stroke = health < 60 ? 'var(--negative)' : 'var(--chart-1)';
    countTo($('#healthNumber'), health, '');
    $('#recommendations').innerHTML = (recos.slice(0, 4).map(r =>
      `<div class="reco ${esc(r.severity)}"><i></i><span>${esc(r.text)}</span></div>`).join(''));
    drawPipeline(o);
    renderEventFeed(o.recent_events || []);
    renderExpiryTable(o.upcoming_expirations || []);
  }

  function countTo(el, target, suffix) {
    if (!el) return;
    const from = Number(el.dataset.current || 0);
    const start = performance.now(), dur = 850;
    el.dataset.current = String(target);
    const step = (now) => {
      const k = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - k, 3);
      el.textContent = `${Math.round(from + (target - from) * eased)}${suffix}`;
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function svgEl(name, attrs, parent) {
    const e = document.createElementNS(SVGNS, name);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
    if (parent) parent.appendChild(e);
    return e;
  }

  function drawRunway(rows, buckets) {
    const svg = $('#runwaySvg'); svg.innerHTML = '';
    const list = rows.slice(0, 6);
    const max = 90;
    // Match the viewBox to the rendered width so the labels stay at their real
    // pixel size on narrow screens instead of being scaled into illegibility.
    const W = Math.max(280, Math.round(svg.getBoundingClientRect().width || 720));
    svg.setAttribute('viewBox', `0 0 ${W} 210`);
    const labelW = Math.round(Math.min(168, Math.max(88, W * 0.25)));
    const plotW = Math.max(80, W - labelW - 46);
    S.runwayGeom = { x: labelW, w: plotW, total: W };
    const g = svgEl('g', {}, svg);
    svgEl('line', { x1: labelW, y1: 12, x2: labelW, y2: 196, stroke: 'var(--rule)', 'stroke-width': 1 }, g);
    [0, 30, 60, 90].forEach(d => {
      const x = labelW + (d / max) * plotW;
      svgEl('line', { x1: x, y1: 12, x2: x, y2: 196, stroke: 'var(--rule)', 'stroke-width': 1 }, g);
      const t = svgEl('text', { x, y: 208, fill: 'var(--muted)', 'font-size': 12, 'text-anchor': 'middle', 'font-family': 'IBM Plex Mono, monospace' }, g);
      t.textContent = `${d}d`;
    });
    if (list.length === 0) {
      const t = svgEl('text', { x: labelW, y: 96, fill: 'var(--muted)', 'font-size': 13 }, g);
      t.textContent = 'No certificates yet. Issue one to start the runway.';
      return;
    }
    const maxChars = Math.max(8, Math.floor(labelW / 6.6));
    list.forEach((r, i) => {
      const y = 26 + i * 29;
      const days = Math.max(0, r.days_left ?? 0);
      const width = Math.max(3, Math.min(1, days / max) * plotW);
      const color = days < 0 ? 'var(--negative)' : days <= 30 ? 'var(--chart-3)' : 'var(--chart-1)';
      const label = (r.domains || [])[0] || `cert-${r.id}`;
      const t = svgEl('text', { x: 0, y: y + 12, fill: 'var(--text)', 'font-size': 12, 'font-family': 'IBM Plex Sans, sans-serif' }, g);
      t.textContent = label.length > maxChars ? `${label.slice(0, maxChars - 1)}…` : label;
      svgEl('rect', { x: labelW, y, width: plotW, height: 17, rx: 3, fill: 'var(--raised)' }, g);
      const bar = svgEl('rect', { x: labelW, y, width: 0, height: 17, rx: 3, fill: color }, g);
      bar.dataset.full = String(width);
      const v = svgEl('text', { x: W - 2, y: y + 12, fill: color, 'font-size': 12, 'text-anchor': 'end', 'font-family': 'IBM Plex Mono, monospace' }, g);
      v.textContent = `${days}d`;
    });
    $$('#runwaySvg rect[data-full]').forEach((bar, i) => {
      setTimeout(() => { bar.style.transition = 'width .9s cubic-bezier(.65,0,.35,1)'; bar.setAttribute('width', bar.dataset.full); }, 120 + i * 90);
    });
  }

  function drawPipeline(o) {
    const svg = $('#pipelineSvg'); svg.innerHTML = '';
    const labels = ['Issue', 'Deploy', 'Monitor', 'Renew'];
    const W = Math.max(280, Math.round(svg.getBoundingClientRect().width || 720));
    svg.setAttribute('viewBox', `0 0 ${W} 120`);
    const xs = [0.125, 0.375, 0.625, 0.875].map(k => Math.round(W * k));
    const r = Math.min(24, Math.max(16, W / 16));
    const gap = r + 10;
    const g = svgEl('g', {}, svg);
    for (let i = 0; i < 3; i++) {
      svgEl('path', { d: `M${xs[i] + gap} 54 H${xs[i + 1] - gap}`, stroke: 'var(--border)', 'stroke-width': 2, fill: 'none' }, g);
      const pulse = svgEl('circle', { cx: xs[i] + gap, cy: 54, r: 4, fill: 'var(--chart-1)', opacity: 0 }, g);
      pulse.classList.add('pipeline-pulse');
      pulse.dataset.from = String(xs[i] + gap);
      pulse.dataset.to = String(xs[i + 1] - gap);
      pulse.dataset.index = String(i);
    }
    xs.forEach((x, i) => {
      svgEl('circle', { cx: x, cy: 54, r, fill: 'var(--raised)', stroke: 'var(--border)', 'stroke-width': 1 }, g);
      const n = svgEl('text', { x, y: 58, 'text-anchor': 'middle', fill: 'var(--chart-1)', 'font-size': 13, 'font-family': 'IBM Plex Mono, monospace' }, g);
      n.textContent = String(i + 1);
      const t = svgEl('text', { x, y: 98, 'text-anchor': 'middle', fill: 'var(--text)', 'font-size': 12 }, g);
      t.textContent = labels[i];
    });
    const w = o.workflows || {}, h = o.webhooks || {};
    $('#pipelineFoot').textContent = `${w.runs || 0} recorded runs · ${w.active || 0} active workflows · ${h.deliveries || 0} webhook deliveries. Pulses show a certificate moving through the lifecycle.`;
  }

  function renderEventFeed(events) {
    const box = $('#eventFeed');
    if (!events.length) { box.innerHTML = '<p class="empty-line">Waiting for the first event.</p>'; return; }
    box.innerHTML = events.slice(0, 6).reverse().map(e => eventRow(e)).join('');
  }
  function eventRow(e) {
    return `<div class="event-row"><span class="event-time">${esc(shortTime(e.created_at))}</span><span class="event-name">${esc(e.event)}</span><span class="event-source">${esc(e.source || '')}</span></div>`;
  }

  function renderExpiryTable(rows) {
    const tbody = $('#expiryTable tbody');
    if (!rows.length) { tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No certificates yet. Issue one to get started.</td></tr>'; return; }
    tbody.innerHTML = rows.slice(0, 5).map(r => `<tr>
      <td class="domain">${esc((r.domains || [])[0] || '—')}<span class="sub">${esc((r.domains || []).slice(1).join(', '))}</span></td>
      <td>—</td><td>${esc(fmtTime(r.end_time))}</td><td class="num">${r.days_left}</td>
      <td>${statePill(r.days_left < 0 ? 'expired' : r.days_left <= 30 ? 'expiring' : 'valid')}</td></tr>`).join('');
  }

  // ---- view renderers -----------------------------------------------------
  function renderCertificates() {
    $('#certCount').textContent = `${S.certs.length} certificates`;
    const tbody = $('#certTable tbody');
    if (!S.certs.length) { tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No certificates match. Import a PEM or issue a new one.</td></tr>'; return; }
    tbody.innerHTML = S.certs.map(c => `<tr>
      <td class="domain">${esc(c.domains?.[0] || '—')}<span class="sub">${esc((c.domains || []).slice(1, 3).join(', '))}</span></td>
      <td>${esc(c.issuer || '—')}</td><td>${esc(fmtTime(c.end_time))}</td>
      <td class="num">${c.days_left}</td><td>${esc(c.source || '—')}</td><td>${statePill(c.status)}</td>
      <td class="actions"><a class="mini-button" href="/api/v1/certificates/${c.id}/export?format=zip">Export</a>
      <button class="mini-button" data-cert-inspect="${c.id}">Inspect</button>
      <button class="mini-button" data-cert-delete="${c.id}">Delete</button></td></tr>`).join('');
  }

  function renderWorkflows() {
    $('#wfCount').textContent = `${S.workflows.length} defined`;
    $('#workflowList').innerHTML = S.workflows.length ? S.workflows.map(w => `<div class="stack-item">
      <div><h3>${esc(w.name)}</h3><p>${w.node_count} nodes · ${esc(w.exec_type)} · ${w.active ? 'active' : 'paused'} · last: ${esc(w.last_run_status || 'never')}</p></div>
      <div class="item-actions"><button class="mini-button" data-wf-run="${w.id}">Run</button><button class="mini-button" data-wf-toggle="${w.id}" data-active="${w.active}">${w.active ? 'Pause' : 'Enable'}</button><button class="mini-button" data-wf-delete="${w.id}">Delete</button></div></div>`).join('')
      : '<p class="empty-line">No workflows. Build a pipeline to automate issue, deploy and notify.</p>';
    $('#runList').innerHTML = S.runs.length ? S.runs.map(r => `<div class="stack-item">
      <div><h3>${esc(r.workflow_name || `Workflow ${r.workflow_id}`)} ${statePill(r.status)}</h3><p>${esc(fmtTime(r.created_at))} · ${r.succeeded} succeeded / ${r.failed} failed · ${esc(r.exec_type)}</p></div>
      <div class="item-actions"><button class="mini-button" data-run-log="${r.id}">Log</button></div></div>`).join('')
      : '<p class="empty-line">No runs recorded yet.</p>';
  }

  function renderMonitors() {
    const tbody = $('#monitorTable tbody');
    if (!S.monitors.length) { tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No monitors. Add a domain to watch its live certificate.</td></tr>'; return; }
    tbody.innerHTML = S.monitors.map(m => `<tr>
      <td class="domain">${esc(m.name)}</td><td>${mono(m.target)}</td><td>${esc(m.monitor_type)}</td>
      <td class="num">${m.cycle} min</td><td>${esc(fmtTime(m.last_time))}</td>
      <td>${m.valid === -1 ? statePill('fail') : m.valid === 1 ? statePill('success') : '<span class="pill pill-neutral">Pending</span>'}</td>
      <td class="actions"><button class="mini-button" data-mon-check="${m.id}">Check</button><button class="mini-button" data-mon-delete="${m.id}">Delete</button></td></tr>`).join('');
  }

  function renderWebhooks(stats) {
    const s = stats || (S.overview?.webhooks || {});
    const cells = [['Subscriptions', s.subscriptions || 0], ['Deliveries', s.deliveries || 0],
      ['Success rate', `${s.success_rate ?? 0}%`], ['Pending retry', s.pending_retry || 0]];
    $('#hookStats').innerHTML = cells.map(([l, v]) => `<div class="stat-cell"><span class="stat-value">${esc(v)}</span><span class="stat-label">${esc(l)}</span></div>`).join('');
    $('#hookCount').textContent = `${S.hooks.length} subscriptions`;
    $('#hookList').innerHTML = S.hooks.length ? S.hooks.map(h => `<div class="stack-item">
      <div><h3>${esc(h.name)} ${h.active ? statePill('success') : '<span class="pill pill-neutral">Paused</span>'}</h3>
      <p>${esc(h.url)}<br>${esc((h.events || []).join(', ') || 'all events')} · ${h.method} · ${h.max_attempts} attempts · ${h.secret ? 'signed' : 'unsigned'}</p></div>
      <div class="item-actions"><button class="mini-button" data-hook-test="${h.id}">Test</button><button class="mini-button" data-hook-edit="${h.id}">Edit</button><button class="mini-button" data-hook-delete="${h.id}">Delete</button></div></div>`).join('')
      : '<p class="empty-line">No subscriptions. Create one to send lifecycle events anywhere.</p>';
    $('#deliveryList').innerHTML = S.deliveries.length ? S.deliveries.map(d => `<div class="stack-item">
      <div><h3>${esc(d.event)} ${d.success ? statePill('success') : statePill('fail')}</h3>
      <p>${esc(d.subscription_name)} · HTTP ${d.status_code || '—'} · ${d.attempts} attempt(s) · ${esc(fmtTime(d.created_at))}${d.error ? `<br>${esc(d.error)}` : ''}</p></div>
      <div class="item-actions">${d.success ? '' : `<button class="mini-button" data-del-replay="${d.id}">Replay</button>`}</div></div>`).join('')
      : '<p class="empty-line">No deliveries yet. Events appear here once a subscription fires.</p>';
  }

  function renderEventViews() {
    const catalog = (S.catalog?.events || []);
    $('#eventCatalog').innerHTML = catalog.map(e => `<span class="event-tag" title="${esc(e.detail)}">${esc(e.id)}</span>`).join('');
    $('#allEvents').innerHTML = S.events.length ? S.events.map(e => `<div class="stack-item">
      <div><h3>${mono(e.event)}</h3><p>${esc(e.source)} · ${esc(fmtTime(e.created_at))} · ${mono(e.id)}</p></div></div>`).join('')
      : '<p class="empty-line">No events recorded yet.</p>';
  }

  function renderCredentials() {
    const tbody = $('#accessTable tbody');
    if (!S.accesses.length) { tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No credentials. Add a DNS or host provider key.</td></tr>'; return; }
    tbody.innerHTML = S.accesses.map(a => `<tr>
      <td class="domain">${esc(a.name)}</td><td>${mono(a.provider)}</td><td>${esc(a.kind)}</td>
      <td>${esc(fmtTime(a.updated_at))}</td>
      <td class="actions"><button class="mini-button" data-access-test="${a.id}">Test</button><button class="mini-button" data-access-delete="${a.id}">Delete</button></td></tr>`).join('');
  }

  function renderCapabilityStrip() {
    if (!S.catalog) return;
    const c = S.catalog.counts || {};
    const cells = [['DNS providers', c.dns_providers], ['Deploy targets', c.deploy_targets],
      ['Certificate authorities', c.certificate_authorities], ['Event types', c.events]];
    $('#capabilityStrip').innerHTML = cells.map(([l, v]) => `<div class="stat-cell"><span class="stat-value">${v ?? '—'}</span><span class="stat-label">${l}</span></div>`).join('');
  }

  function renderPrivateCa() {
    $('#caCount').textContent = `${S.cas.length} authorities`;
    $('#leafCount').textContent = `${S.leaves.length} leaves`;
    $('#caList').innerHTML = S.cas.length ? S.cas.map(c => `<div class="stack-item"><div>
      <h3>${esc(c.name)} ${c.is_root ? '<span class="pill pill-neutral">Root</span>' : '<span class="pill pill-ok">Intermediate</span>'}</h3>
      <p>${esc(c.cn)} · ${esc(c.algorithm.toUpperCase())} · until ${esc(fmtTime(c.not_after))}</p></div>
      <div class="item-actions"><a class="mini-button" href="/api/v1/ca/${c.id}/download">Download</a><button class="mini-button" data-ca-delete="${c.id}">Delete</button></div></div>`).join('')
      : '<p class="empty-line">No authorities. Bootstrap a root, intermediate and leaf in one step.</p>';
    $('#leafList').innerHTML = S.leaves.length ? S.leaves.map(l => `<div class="stack-item"><div>
      <h3>${esc(l.cn)} ${statePill(l.status === 'expired' ? 'expired' : 'valid')}</h3>
      <p>CA ${l.ca_id} · ${l.days_left} days left · ${esc(fmtTime(l.not_after))}</p></div>
      <div class="item-actions"><a class="mini-button" href="/api/v1/leaves/${l.id}/download">Download</a><button class="mini-button" data-leaf-delete="${l.id}">Delete</button></div></div>`).join('')
      : '<p class="empty-line">No leaf certificates issued.</p>';
  }

  function renderPlugins() {
    $('#pluginCount').textContent = `${S.plugins.length} registered`;
    $('#pluginList').innerHTML = S.plugins.length ? S.plugins.map(p => `<div class="stack-item"><div>
      <h3>${esc(p.name)} ${p.enabled ? statePill('success') : '<span class="pill pill-neutral">Disabled</span>'}</h3>
      <p>${esc(p.id)} · v${esc(p.version)} · protocol ${p.protocol} · ${esc(p.status)}</p></div>
      <div class="item-actions"><button class="mini-button" data-plugin-toggle="${esc(p.id)}" data-enabled="${p.enabled}">${p.enabled ? 'Disable' : 'Enable'}</button></div></div>`).join('')
      : '<p class="empty-line">No plugins discovered. Place a plugin.json or metadata.json in the plugin directory and scan.</p>';
  }

  function renderApiView() {
    $('#endpointCount').textContent = `${S.endpoints.length} endpoints`;
    $('#endpointList').innerHTML = S.endpoints.map(e => {
      const [m, ...rest] = e.split(' ');
      return `<div class="code-line"><b>${esc(m)}</b><span>${esc(rest.join(' '))}</span></div>`;
    }).join('');
    const c = S.catalog?.counts || {};
    const tools = [
      ['fleet_overview', 'Read the whole fleet and get prioritised next actions'],
      ['issue_and_deploy', 'Issue and deploy a certificate in one call'],
      ['renew_expiring', 'Renew everything inside the renewal window'],
      ['inspect_certificate', 'Validity, chain, fingerprint and deployment history'],
      ['deploy_certificate', 'Deploy a stored certificate to many targets'],
      ['create_certificate_pipeline', 'Build a complete scheduled workflow'],
      ['run_workflow', 'Execute a workflow and summarise every node'],
      ['monitor_domain', 'Add live TLS monitoring with alert channels'],
      ['configure_webhook', 'Create signed, filtered, retrying subscriptions'],
      ['delivery_health', 'Delivery statistics and replay'],
      ['diagnose_domain', 'End-to-end diagnosis of a domain'],
      ['list_capabilities', 'Every CA, provider, target and event'],
      ['private_ca_bootstrap', 'Root, intermediate and leaf in one call'],
      ['security_audit', 'Expired, weak and unmonitored certificates'],
      ['rotate_credentials', 'Update a credential and test it'],
    ];
    S.tools = tools;
    $('#mcpToolCount').textContent = `${tools.length} coarse tools · ${c.rest_endpoints || S.endpoints.length} REST endpoints`;
    $('#mcpTools').innerHTML = tools.map(([n, d]) => `<div class="stack-item"><div><h3>${mono(n)}</h3><p>${esc(d)}</p></div></div>`).join('');
    $('#mcpSnippet').textContent = `// Connect any MCP client to the ssld streamable HTTP endpoint\n{\n  "mcpServers": {\n    "ssld": {\n      "url": "http://${location.host}/mcp",\n      "transport": "streamable-http"\n    }\n  }\n}\n\n// Or call the coarse tools directly\ncurl -X POST http://${location.host}/mcp \\\n  -H 'Content-Type: application/json' \\\n  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fleet_overview","arguments":{}}}'\n\n// Subscribe every certificate event\ncurl -X POST http://${location.host}/api/v1/webhooks \\\n  -H 'Content-Type: application/json' \\\n  -d '{"name":"ops","url":"https://ops.example/hook","events":["cert.*"],"secret":"change-me"}'`;
  }

  function renderSettings() {
    const keys = [
      ['theme', 'Theme', 'system, light or dark', ['system', 'light', 'dark']],
      ['language', 'Language', 'Interface language', ['en', 'zh']],
      ['renew_before_days', 'Renewal window', 'Days before expiry to trigger renewal'],
      ['default_ca', 'Default CA', 'letsencrypt, zerossl, google, buypass, sslcom'],
      ['default_algorithm', 'Key algorithm', 'RSA2048, RSA4096, EC256, EC384'],
      ['ari_enabled', 'ARI renewals', 'Use RFC 9773 renewal hints when available', ['0', '1']],
      ['webhook_enabled', 'Webhook delivery', 'Global switch for event delivery', ['0', '1']],
      ['mcp_enabled', 'MCP endpoint', 'Expose coarse tools to agents', ['0', '1']],
      ['plugin_dir', 'Plugin directory', 'Where module and deploy plugins live'],
      ['timeout', 'Session timeout', 'Seconds of idle time before logout'],
      ['secure', 'Secure entry', 'Secret path required before the console'],
      ['api_key', 'Open API key', 'Set to require signed API calls'],
    ];
    $('#settingsGrid').innerHTML = keys.map(([k, label, hint, options]) => {
      const val = S.settings[k] ?? '';
      const input = options
        ? `<select data-setting="${k}">${options.map(o => `<option value="${esc(o)}" ${String(val) === o ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`
        : `<input data-setting="${k}" value="${esc(val)}" autocomplete="off">`;
      return `<div class="setting-row"><label>${esc(label)}<span class="hint">${esc(hint)}</span></label>${input}</div>`;
    }).join('');
    $('#channelList').innerHTML = S.channels.length ? S.channels.map(c => `<div class="stack-item"><div>
      <h3>${esc(c.name)} <span class="pill pill-neutral">${esc(c.type)}</span></h3>
      <p>${esc(JSON.stringify(c.config || {}))}</p></div>
      <div class="item-actions"><button class="mini-button" data-chan-test="${c.id}">Test</button><button class="mini-button" data-chan-delete="${c.id}">Delete</button></div></div>`).join('')
      : '<p class="empty-line">No notification channels. Add SMTP, webhook, DingTalk, Feishu or WeCom.</p>';
  }

  // ---- navigation ---------------------------------------------------------
  function switchView(name) {
    S.view = name;
    $$('.view').forEach(v => v.classList.toggle('is-active', v.id === `view-${name}`));
    $$('.nav-item').forEach(b => {
      const on = b.dataset.view === name;
      b.classList.toggle('is-active', on);
      if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    $('#topbarView').textContent = I18N[S.lang][name] || name;
    $('.sidebar').classList.remove('open');
    $('#menuButton').setAttribute('aria-expanded', 'false');
    $('.sheet').scrollTop = 0;
    location.hash = name;
    loadViewData(name);
    if (name === 'overview') requestAnimationFrame(() => { S.clock = 0; });
  }

  // ---- modal --------------------------------------------------------------
  let modalSubmit = null;
  function openModal(title, html, onSubmit) {
    $('#modalTitle').textContent = title;
    $('#modalBody').innerHTML = html;
    $('#modalError').textContent = '';
    $('#modalLayer').hidden = false;
    modalSubmit = onSubmit;
    setTimeout(() => { const f = $('#modalBody input, #modalBody textarea, #modalBody select'); if (f) f.focus(); }, 60);
  }
  function closeModal() { $('#modalLayer').hidden = true; modalSubmit = null; }
  const field = (name, label, opts = {}) => {
    const { type = 'text', value = '', hint = '', span = false, options = null } = opts;
    const input = options
      ? `<select name="${name}">${options.map(o => `<option value="${esc(o.value ?? o)}" ${String(value) === String(o.value ?? o) ? 'selected' : ''}>${esc(o.label ?? o)}</option>`).join('')}</select>`
      : type === 'textarea'
        ? `<textarea name="${name}" placeholder="${esc(hint)}">${esc(value)}</textarea>`
        : `<input name="${name}" type="${type}" value="${esc(value)}" placeholder="${esc(hint)}" autocomplete="off">`;
    return `<div class="form-field ${span ? 'span-2' : ''}"><label>${esc(label)}</label>${input}${hint && type !== 'textarea' ? `<span class="field-hint">${esc(hint)}</span>` : ''}</div>`;
  };
  const formValues = () => Object.fromEntries($$('#modalBody [name]').map(el => [el.name, el.value]));
  const form = (inner) => `<div class="form-grid">${inner}</div>`;

  async function submitModal() {
    if (!modalSubmit) return closeModal();
    const btn = $('#modalSubmit'); btn.disabled = true; btn.textContent = 'Working…';
    try {
      await modalSubmit(formValues());
      closeModal(); await refresh(true); await loadViewData(S.view);
    } catch (e) {
      $('#modalError').textContent = e.message;
    } finally { btn.disabled = false; btn.textContent = 'Confirm'; }
  }

  function issueModal() {
    const providers = (S.catalog?.dns_providers || []).map(p => ({ value: p.id, label: p.name }));
    const cas = (S.catalog?.certificate_authorities || []).map(p => ({ value: p.id, label: p.name }));
    const dns = S.accesses.filter ? S.accesses.filter(a => a.kind === 'dns') : [];
    const html = form(
      field('domains', 'Domains', { span: true, hint: 'www.lumenlabs.dev, *.lumenlabs.dev' }) +
      field('email', 'Contact email', { span: true, hint: 'Required for ACME registration' }) +
      field('ca', 'Certificate authority', { options: cas }) +
      field('algorithm', 'Key algorithm', { options: ['RSA2048', 'RSA3072', 'RSA4096', 'EC256', 'EC384'] }) +
      field('dns_access_id', 'DNS credential id', { hint: 'Credential ids are on the Credentials page' }) +
      field('deploy_target', 'Deploy target', { options: (S.catalog?.deploy_targets || []).map(t => ({ value: t.id, label: t.name })) }) +
      field('cert_path', 'Certificate path', { value: 'data/deployed/cert.pem' }) +
      field('key_path', 'Private key path', { value: 'data/deployed/key.pem' }) +
      `<div class="form-field span-2"><label>Issue and deploy in one step</label><span class="field-hint">The MCP tool issue_and_deploy performs the same operation in a single call.</span></div>`
    );
    openModal('Issue certificate', html, async (v) => {
      if (!v.domains.trim() || !v.email.trim()) throw new Error('Domains and contact email are required');
      const out = await post('/api/v1/certificates/apply', {
        domains: v.domains.split(',').map(s => s.trim()).filter(Boolean), email: v.email,
        ca: v.ca, algorithm: v.algorithm, dns_access_id: Number(v.dns_access_id) || 0,
      });
      if (v.deploy_target && v.deploy_target !== '') {
        await post('/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'deploy_certificate',
          arguments: { cert_id: out.cert_id, targets: [v.deploy_target], cert_path: v.cert_path, key_path: v.key_path } } });
      }
      toast(`Certificate ${out.reused ? 'reused' : 'issued'} for ${(out.domains || []).join(', ')}`);
    });
  }

  function hookModal(existing) {
    const e = existing || {};
    const events = (S.catalog?.events || []).map(x => x.id);
    const selected = new Set(e.events || []);
    const checks = events.map(id => `<label class="check-item"><input type="checkbox" data-event="${esc(id)}" ${selected.has(id) || selected.size === 0 ? 'checked' : ''}>${esc(id)}</label>`).join('');
    const html = form(
      field('name', 'Name', { value: e.name || '', hint: 'A short label for this destination' }) +
      field('url', 'Destination URL', { value: e.url || '', hint: 'https://ops.example/hooks/ssld', span: true }) +
      field('secret', 'HMAC secret', { value: e.secret ? '******' : '', hint: 'Signs X-SSLD-Signature' }) +
      field('method', 'Method', { options: ['POST', 'PUT', 'GET'], value: e.method || 'POST' }) +
      field('event_mode', 'Filter mode', { options: ['include', 'exclude'], value: e.event_mode || 'include' }) +
      field('max_attempts', 'Retry attempts', { value: e.max_attempts || 5 }) +
      field('body_template', 'Body template', { type: 'textarea', value: e.body_template || '', span: true,
        hint: '{"event":"__event__","data":__payload__}' })
    ) + `<div class="form-field"><label>Events (empty selection means all)</label><div class="check-grid">${checks}</div></div>`;
    openModal(existing ? 'Edit subscription' : 'New webhook subscription', html, async (v) => {
      if (!v.url.trim()) throw new Error('Destination URL is required');
      const chosen = $$('#modalBody [data-event]:checked').map(x => x.dataset.event);
      const body = {
        name: v.name, url: v.url, secret: v.secret, method: v.method, event_mode: v.event_mode,
        max_attempts: Number(v.max_attempts) || 5, body_template: v.body_template,
        events: chosen.length === events.length ? [] : chosen, active: true,
        backoff_seconds: 60, timeout_seconds: 10,
      };
      if (existing) await put(`/api/v1/webhooks/${existing.id}`, body); else await post('/api/v1/webhooks', body);
      toast('Webhook subscription saved');
    });
  }

  function simpleModal(title, fields, endpoint, transform, method = 'POST') {
    openModal(title, form(fields.map(f => field(f[0], f[1], f[2] || {})).join('')), async (v) => {
      const body = transform ? transform(v) : v;
      if (method === 'PUT') await put(endpoint, body); else await post(endpoint, body);
      toast('Saved');
    });
  }

  // ---- live events --------------------------------------------------------
  function setLive(on) {
    $('#liveDot').classList.toggle('off', !on);
    $('#liveLabel').textContent = on ? 'Live events' : 'Polling only';
  }
  function connectSse() {
    try {
      const es = new EventSource('/api/v1/events/stream');
      S.sse = es;
      es.onopen = () => setLive(true);
      es.onerror = () => setLive(false);
      es.onmessage = () => {};
      const names = (S.catalog?.events || []).map(e => e.id);
      names.forEach(name => es.addEventListener(name, (ev) => {
        let payload; try { payload = JSON.parse(ev.data); } catch { return; }
        S.events.unshift(payload); S.events = S.events.slice(0, 60);
        const feed = $('#eventFeed');
        if (feed) {
          feed.insertAdjacentHTML('afterbegin', `<div class="event-row fresh">${eventRow(payload).replace(/^<div[^>]*>|<\/div>$/g, '')}</div>`);
          while (feed.children.length > 7) feed.lastElementChild.remove();
        }
        renderEventViews();
        if (S.view === 'overview') refresh(true);
      }));
    } catch { setLive(false); }
  }

  // ---- motion clock -------------------------------------------------------
  function initMotion() {
    const sheet = $('.sheet');
    $$('[data-motion]').forEach((el, i) => el.style.setProperty('--d', `${Math.min(i, 12) * 75}ms`));
    requestAnimationFrame(() => requestAnimationFrame(() => sheet.classList.add('in')));
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) return;
    let last = performance.now();
    const tick = (now) => {
      const dt = Math.min(0.05, (now - last) / 1000); last = now;
      if (S.running && S.view === 'overview') {
        S.clock += dt;
        const t = S.clock % 12;
        const scan = $('#runwayScan');
        if (scan) {
          const k = ((t % 3.4) / 3.4);
          const geom = S.runwayGeom || { x: 168, w: 520, total: 720 };
          scan.style.left = `${(geom.x / geom.total) * 100 + k * (geom.w / geom.total) * 100}%`;
          scan.style.opacity = k > 0.02 && k < 0.98 ? '.55' : '0';
        }
        $$('.pipeline-pulse').forEach((p) => {
          const idx = Number(p.dataset.index);
          const local = (t + idx * 0.35) % 3.2;
          const k = Math.min(1, local / 1.15);
          const from = Number(p.dataset.from), to = Number(p.dataset.to);
          p.setAttribute('cx', String(from + (to - from) * k));
          p.setAttribute('opacity', local < 1.4 ? String(Math.sin(Math.min(1, local / 1.4) * Math.PI) * 0.95) : '0');
        });
        const ring = $('#healthRing');
        if (ring && t > 8.2 && t < 9.4) {
          ring.style.transition = 'none';
          ring.style.strokeDashoffset = String(389.5 * (1 - (t - 8.2) / 1.2));
        } else if (ring && t >= 9.4) {
          ring.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(.65,0,.35,1)';
          ring.style.strokeDashoffset = String(389.5 * (1 - (S.overview?.health_score ?? 100) / 100));
        }
      }
      S.raf = requestAnimationFrame(tick);
    };
    S.raf = requestAnimationFrame(tick);
    const io = new IntersectionObserver((entries) => {
      S.running = entries.some(e => e.isIntersecting);
    }, { threshold: 0.25 });
    io.observe($('#view-overview'));
    document.addEventListener('visibilitychange', () => { if (document.hidden) S.running = false; else S.running = true; });
  }

  // ---- events -------------------------------------------------------------
  function bind() {
    $('#nav').addEventListener('click', (e) => {
      const b = e.target.closest('[data-view]'); if (b) switchView(b.dataset.view);
    });
    document.addEventListener('click', async (e) => {
      const goto = e.target.closest('[data-goto]');
      if (goto) {
        switchView(goto.dataset.goto);
        if (goto.dataset.openIssue) setTimeout(issueModal, 300);
        return;
      }
      const attr = (name) => e.target.closest(`[data-${name}]`)?.getAttribute(`data-${name}`);
      const act = async (name, fn) => { const id = attr(name); if (!id) return false; try { await fn(id); } catch (err) { toast(err.message, true); } return true; };
      if (await act('cert-delete', async id => { await del(`/api/v1/certificates/${id}`); toast('Certificate deleted'); await loadViewData('certificates'); })) return;
      if (await act('cert-inspect', async id => {
        const d = await api(`/api/v1/certificates/${id}/inspect`);
        openModal('Certificate detail', `<pre style="font-size:12px;white-space:pre-wrap">${esc(JSON.stringify(d.parsed, null, 2))}</pre>`, () => Promise.resolve());
        $('#modalSubmit').textContent = 'Close';
      })) return;
      if (await act('wf-run', async id => { const r = await post(`/api/v1/workflows/${id}/execute`); toast(`Run ${r.status}`); await loadViewData('workflows'); })) return;
      if (await act('wf-toggle', async id => { const el = e.target.closest('[data-wf-toggle]'); await post(`/api/v1/workflows/${id}/active`, { active: el.dataset.active !== 'true' }); await loadViewData('workflows'); })) return;
      if (await act('wf-delete', async id => { await del(`/api/v1/workflows/${id}`); await loadViewData('workflows'); })) return;
      if (await act('run-log', async id => { const d = await api(`/api/v1/workflow-runs/${id}/log`); openModal('Execution log', `<pre style="font-size:12px;white-space:pre-wrap">${esc((d.run.logs || []).join('\n'))}</pre>`, () => Promise.resolve()); $('#modalSubmit').textContent = 'Close'; })) return;
      if (await act('mon-check', async id => { const d = await post(`/api/v1/monitors/${id}/check`); toast(d.healthy ? 'Monitor healthy' : `Problem: ${(d.problems || []).join('; ')}`, !d.healthy); await loadViewData('monitors'); })) return;
      if (await act('mon-delete', async id => { await del(`/api/v1/monitors/${id}`); await loadViewData('monitors'); })) return;
      if (await act('hook-test', async id => { const d = await post(`/api/v1/webhooks/${id}/test`); toast(d.success ? 'Delivery succeeded' : `Delivery failed: ${d.error}`, !d.success); await loadViewData('webhooks'); })) return;
      if (await act('hook-edit', async id => { const h = S.hooks.find(x => x.id === id); hookModal(h); })) return;
      if (await act('hook-delete', async id => { await del(`/api/v1/webhooks/${id}`); await loadViewData('webhooks'); })) return;
      if (await act('del-replay', async id => { await post(`/api/v1/webhook-deliveries/${id}/redeliver`); toast('Delivery replayed'); await loadViewData('webhooks'); })) return;
      if (await act('access-test', async id => { const d = await post(`/api/v1/accesses/${id}/test`); toast(`Credential reachable: ${d.provider}`); })) return;
      if (await act('access-delete', async id => { await del(`/api/v1/accesses/${id}`); await loadViewData('credentials'); })) return;
      if (await act('ca-delete', async id => { await del(`/api/v1/ca/${id}`); await loadViewData('privateca'); })) return;
      if (await act('leaf-delete', async id => { await del(`/api/v1/leaves/${id}`); await loadViewData('privateca'); })) return;
      if (await act('plugin-toggle', async id => {
        const el = e.target.closest('[data-plugin-toggle]');
        await post(`/api/v1/plugins/${id}/${el.dataset.enabled === 'true' ? 'disable' : 'enable'}`);
        await loadViewData('plugins');
      })) return;
      if (await act('chan-test', async id => { await post(`/api/v1/channels/${id}/test`); toast('Test notification sent'); })) return;
      if (await act('chan-delete', async id => { await del(`/api/v1/channels/${id}`); await loadViewData('settings'); })) return;
    });

    $('#themeToggle').addEventListener('click', () => {
      const order = ['system', 'light', 'dark'];
      S.theme = order[(order.indexOf(S.theme) + 1) % 3];
      localStorage.setItem('ssld-theme', S.theme);
      document.documentElement.dataset.theme = S.theme;
      $('#themeLabel').textContent = S.theme[0].toUpperCase() + S.theme.slice(1);
    });
    $('#langButton').addEventListener('click', () => {
      S.lang = S.lang === 'en' ? 'zh' : 'en';
      localStorage.setItem('ssld-lang', S.lang);
      $('#langButton').textContent = S.lang.toUpperCase();
      $('#topbarView').textContent = I18N[S.lang][S.view] || S.view;
      $('#issueButton').textContent = I18N[S.lang].issue;
      $('#auditButton').textContent = I18N[S.lang].audit;
      $$('.nav-item').forEach(b => { const span = $('span', b); if (span && I18N[S.lang][b.dataset.view]) span.textContent = I18N[S.lang][b.dataset.view]; });
      toast(S.lang === 'zh' ? '界面语言已切换为中文' : 'Interface language set to English');
    });
    $('#refreshButton').addEventListener('click', () => { refresh(); toast('Data refreshed'); });
    $('#menuButton').addEventListener('click', () => {
      const open = $('.sidebar').classList.toggle('open');
      $('#menuButton').setAttribute('aria-expanded', String(open));
    });
    $('#globalSearch').addEventListener('input', (e) => {
      if (S.view !== 'certificates') switchView('certificates');
      $('#certSearch').value = e.target.value;
      clearTimeout($('#globalSearch')._t);
      $('#globalSearch')._t = setTimeout(() => loadViewData('certificates'), 250);
    });
    $('#certSearch').addEventListener('input', () => { clearTimeout($('#certSearch')._t); $('#certSearch')._t = setTimeout(() => loadViewData('certificates'), 250); });
    $('#certStatus').addEventListener('change', () => loadViewData('certificates'));
    $('#issueButton').addEventListener('click', issueModal);
    $('#auditButton').addEventListener('click', async () => {
      const d = await api('/api/v1/audit');
      openModal('Security audit', `<p>${d.count} finding(s), ${d.critical} critical.</p><pre style="font-size:12px;white-space:pre-wrap">${esc(JSON.stringify(d.findings, null, 2))}</pre>`, () => Promise.resolve());
      $('#modalSubmit').textContent = 'Close';
    });
    $('#importButton').addEventListener('click', () => simpleModal('Import PEM',
      [['cert', 'Certificate PEM', { type: 'textarea', span: true }], ['key', 'Private key PEM', { type: 'textarea', span: true }], ['issuer_cert', 'Chain PEM (optional)', { type: 'textarea', span: true }]],
      '/api/v1/certificates/import', null));
    $('#addHookButton').addEventListener('click', () => hookModal(null));
    $('#addMonitorButton').addEventListener('click', () => simpleModal('Add monitor',
      [['name', 'Name'], ['target', 'Target', { hint: 'www.lumenlabs.dev or mail.lumenlabs.dev:465' }],
       ['monitor_type', 'Type', { options: ['https', 'smtp'] }], ['cycle', 'Cycle (minutes)', { value: '60' }],
       ['advance_day', 'Alert days', { value: '30' }], ['report_types', 'Channels', { hint: 'comma separated ids or kinds' }]],
      '/api/v1/monitors', v => ({ ...v, active: true, cycle: Number(v.cycle) || 60,
        advance_day: Number(v.advance_day) || 30, repeat_send_gap: 10,
        report_types: (v.report_types || '').split(',').map(s => s.trim()).filter(Boolean) })));
    $('#templateButton').addEventListener('click', () => { location.href = '/api/v1/monitors/template?type=csv'; toast('Template downloaded'); });
    $('#addAccessButton').addEventListener('click', () => {
      const dns = (S.catalog?.dns_providers || []).map(p => ({ value: p.id, label: p.name }));
      const host = (S.catalog?.host_providers || []).map(p => ({ value: p.id, label: p.name }));
      simpleModal('Add credential',
        [['name', 'Name'], ['kind', 'Kind', { options: ['dns', 'host'] }],
         ['provider', 'Provider', { options: [...dns, ...host] }],
         ['config', 'Config JSON', { type: 'textarea', span: true, hint: '{"api_key":"...","url":"..."}' }]],
        '/api/v1/accesses', v => ({ ...v, config: (() => { try { return JSON.parse(v.config || '{}'); } catch { throw new Error('Config must be valid JSON'); } })() }));
    });
    $('#newWorkflowButton').addEventListener('click', () => simpleModal('New workflow',
      [['name', 'Name'], ['exec_type', 'Execution', { options: ['manual', 'auto'] }],
       ['content', 'Workflow tree JSON', { type: 'textarea', span: true, hint: 'Use Build pipeline to generate a complete tree' }]],
      '/api/v1/workflows', v => ({ ...v, active: true, content: (() => { try { return JSON.parse(v.content || '{}'); } catch { throw new Error('Content must be valid JSON'); } })() })));
    $('#buildWorkflowButton').addEventListener('click', () => simpleModal('Build certificate pipeline',
      [['name', 'Workflow name', { value: 'Certificate pipeline' }], ['domains', 'Domains', { span: true, hint: 'www.lumenlabs.dev, *.lumenlabs.dev' }],
       ['ca', 'CA', { options: (S.catalog?.certificate_authorities || []).map(p => ({ value: p.id, label: p.name })) }],
       ['dns_access_id', 'DNS credential id'], ['deploy_target', 'Deploy target', { options: (S.catalog?.deploy_targets || []).map(t => ({ value: t.id, label: t.name })) }],
       ['deploy_access_id', 'Host credential id']],
      '/api/v1/workflows/build', v => ({ ...v, active: true,
        dns_access_id: Number(v.dns_access_id) || 0, deploy_access_id: Number(v.deploy_access_id) || 0 })));
    $('#newCaButton').addEventListener('click', () => simpleModal('Create CA',
      [['name', 'Name'], ['cn', 'Common name'], ['algorithm', 'Algorithm', { options: ['rsa', 'ecdsa', 'sm2'] }],
       ['valid_days', 'Valid days', { value: '3650' }], ['root_id', 'Parent root id', { value: '0' }],
       ['c', 'Country', { value: 'CN' }]],
      '/api/v1/ca', v => ({ ...v, key_length: 2048, valid_days: Number(v.valid_days) || 3650, root_id: Number(v.root_id) || 0 })));
    $('#bootstrapCaButton').addEventListener('click', async () => {
      const r = await api('/mcp', { method: 'POST', body: { jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'private_ca_bootstrap', arguments: { cn: 'ssld Root CA', leaf_cn: 'internal.lumenlabs.dev' } } } });
      toast(`Created root ${r.result?.structuredContent?.root_ca_id ?? ''} and leaf chain`);
      await loadViewData('privateca');
    });
    $('#scanPluginsButton').addEventListener('click', async () => { await post('/api/v1/plugins/scan'); await loadViewData('plugins'); toast('Plugin directory scanned'); });
    $('#emitTestButton').addEventListener('click', async () => { await post('/api/v1/events/emit', { event: 'webhook.test', payload: { message: 'Console test event' } }); toast('Test event emitted'); });
    $('#addChannelButton').addEventListener('click', () => simpleModal('Add notification channel',
      [['name', 'Name'], ['type', 'Channel', { options: (S.catalog?.notification_channels || []).map(c => ({ value: c.id, label: c.name })) }],
       ['config', 'Config JSON', { type: 'textarea', span: true, hint: '{"url":"...","enabled":"1"}' }]],
      '/api/v1/channels', v => ({ ...v, config: (() => { try { return JSON.parse(v.config || '{}'); } catch { throw new Error('Config must be valid JSON'); } })() })));
    $('#saveSettingsButton').addEventListener('click', async () => {
      const settings = Object.fromEntries($$('[data-setting]').map(el => [el.dataset.setting, el.value]));
      try { await put('/api/v1/settings', { settings }); toast('Settings saved'); await refresh(true); }
      catch (err) { toast(err.message, true); }
    });
    $('#modalClose').addEventListener('click', closeModal);
    $('#modalCancel').addEventListener('click', closeModal);
    $('#modalBackdrop').addEventListener('click', closeModal);
    $('#modalSubmit').addEventListener('click', submitModal);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('#modalLayer').hidden) closeModal(); });
  }

  // ---- boot ---------------------------------------------------------------
  async function boot() {
    document.documentElement.dataset.theme = S.theme;
    $('#themeLabel').textContent = S.theme[0].toUpperCase() + S.theme.slice(1);
    $('#langButton').textContent = S.lang.toUpperCase();
    bind();
    initMotion();
    // Charts are drawn in real pixels; redraw them when the sheet changes width.
    let resizeTimer = null;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (!S.overview) return;
        const c = S.overview.certificates || {};
        drawRunway(S.overview.upcoming_expirations || [], c.expiry_buckets || {});
        drawPipeline(S.overview);
      }, 120);
    });
    const hash = location.hash.slice(1);
    await refresh();
    switchView($$('.nav-item').some(b => b.dataset.view === hash) ? hash : 'overview');
    connectSse();
    setInterval(() => refresh(true), 20000);
  }
  boot();
})();
