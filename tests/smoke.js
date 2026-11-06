#!/usr/bin/env node
/**
 * ssld end-to-end smoke test.
 *
 *   node tests/smoke.js [port]
 *   SSLD_HOST=127.0.0.1 SSLD_PORT=17979 node tests/smoke.js
 *
 * Requires a running ssld. It only uses the private-CA path, so no DNS
 * credentials and no real ACME order are needed. Safe to run repeatedly.
 */
const http = require('http');
const HOST = process.env.SSLD_HOST || '127.0.0.1';
const PORT = Number(process.argv[2] || process.env.SSLD_PORT || 7979);
let passed = 0, failed = 0;

function req(method, path, body, extra = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const r = http.request({ host: HOST, port: PORT, method, path, headers: {
      ...(data ? {
        'Content-Type': extra.form ? 'application/x-www-form-urlencoded' : 'application/json',
        'Content-Length': Buffer.byteLength(data)
      } : {}),
      ...(extra.headers || {})
    } }, res => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(buf); } catch { /* raw PEM / ZIP / backup document */ }
        resolve({ status: res.statusCode, raw: buf, json, headers: res.headers });
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}
const check = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  PASS  ${name}${detail ? ' · ' + detail : ''}`); }
  else { failed++; console.log(`  FAIL  ${name}${detail ? ' · ' + detail : ''}`); }
};
const ok = r => !!(r.json && r.json.code === 0);
const unwrap = r => r.json?.data;

(async () => {
  console.log(`\nssld smoke test → http://${HOST}:${PORT}\n`);

  console.log('[service]');
  const health = await req('GET', '/api/v1/health');
  check('health endpoint', health.status === 200 && health.json?.data?.status === 'ok');
  const eps = await req('GET', '/api/v1/endpoints');
  check('endpoint index', eps.json?.data?.count >= 100, `count=${eps.json?.data?.count}`);
  for (const p of ['/', '/app.js', '/styles.css', '/api/v1/openapi.json']) {
    check(`asset ${p}`, (await req('GET', p)).status === 200);
  }

  console.log('\n[private CA]');
  let caId = null;
  const existing = await req('GET', '/api/v1/ca');
  const candidates = (unwrap(existing)?.list || []).filter(c => c.root_id && c.root_id > 0);
  if (candidates.length) caId = candidates[0].id;
  else {
    const root = await req('POST', '/api/v1/ca', {
      name: 'Smoke Root', cn: 'Smoke Root CA', o: 'ssld', c: 'CN',
      algorithm: 'ecdsa', key_length: 256, valid_days: 3650, root_id: 0
    });
    check('root CA created', ok(root), `id=${unwrap(root)?.id}`);
    const rootId = unwrap(root)?.id;
    const inter = await req('POST', '/api/v1/ca', {
      name: 'Smoke Issuing', cn: 'Smoke Issuing CA', o: 'ssld', c: 'CN',
      algorithm: 'ecdsa', key_length: 256, valid_days: 1825, root_id: rootId
    });
    check('intermediate CA created', ok(inter), `id=${unwrap(inter)?.id}`);
    caId = unwrap(inter)?.id;
  }
  const rootDirect = await req('POST', '/api/v1/leaves', {
    ca_id: 1, cn: 'blocked.example.org', san: [], algorithm: 'ecdsa', key_length: 256, valid_days: 30
  });
  // Only meaningful when id 1 is a root; otherwise the guard is still exercised by id lookup.
  check('root direct-issue guard present', rootDirect.status === 400 || rootDirect.status === 404,
    `status=${rootDirect.status}`);

  const leaf = unwrap(await req('POST', '/api/v1/leaves', {
    ca_id: caId, cn: 'shop.lumenlabs.dev',
    san: ['shop.lumenlabs.dev', 'checkout.lumenlabs.dev'],
    algorithm: 'ecdsa', key_length: 256, valid_days: 300
  }));
  check('leaf issued with SANs', !!leaf?.cert && !!leaf?.key, `id=${leaf?.id}`);

  console.log('\n[certificate repository]');
  const imported = await req('POST', '/api/v1/certificates/import', {
    cert: leaf.cert, key: leaf.key, issuer_cert: ''
  });
  check('certificate imported', ok(imported), `id=${unwrap(imported)?.id}`);
  const cid = unwrap(imported)?.id;
  const list = await req('GET', '/api/v1/certificates');
  check('certificate listed', (unwrap(list)?.list || []).some(c => c.id === cid));
  const inspect = await req('GET', `/api/v1/certificates/${cid}/inspect`);
  const san = unwrap(inspect)?.parsed?.domains || [];
  check('inspect reports SANs', san.includes('checkout.lumenlabs.dev'), `domains=${san.join(',')}`);
  const preview = await req('POST', '/api/v1/certificates/preview', { cert: leaf.cert });
  check('preview parses PEM without storing', ok(preview), `sha256=${String(unwrap(preview)?.sha256 || '').slice(0, 12)}`);
  const zip = await req('GET', `/api/v1/certificates/${cid}/export`);
  check('ZIP export returns PK magic', zip.raw.slice(0, 2) === 'PK', `${zip.raw.length} bytes`);

  console.log('\n[workflow engine]');
  const built = await req('POST', '/api/v1/workflows/build', {
    name: 'Lumen edge pipeline', domains: ['shop.lumenlabs.dev'], ca: 'letsencrypt',
    dns_access_id: 0, deploy_target: 'localhost', deploy_access_id: 0, notify_channel: ''
  });
  check('pipeline builder', ok(built), `id=${unwrap(built)?.id}`);
  const run = await req('POST', `/api/v1/workflows/${unwrap(built)?.id}/execute`);
  check('workflow executed and recorded', ok(run), `status=${unwrap(run)?.status}`);
  const runs = await req('GET', '/api/v1/workflow-runs');
  check('run history recorded', (unwrap(runs)?.list || []).length > 0);

  console.log('\n[monitoring]');
  const mon = await req('POST', '/api/v1/monitors', {
    name: 'Lumen edge', target: 'shop.lumenlabs.dev', monitor_type: 'https',
    report_types: [], active: true, cycle: 60, repeat_send_gap: 10, advance_day: 30
  });
  check('monitor created', ok(mon), `id=${unwrap(mon)?.id}`);
  const tpl = await req('GET', '/api/v1/monitors/template?type=csv');
  check('import template downloadable', tpl.status === 200 && tpl.raw.includes('target'));
  const imp = await req('POST', '/api/v1/monitors/import', {
    format: 'csv', content: 'name,target,type\nLumen mail,mail.lumenlabs.dev,https\n'
  });
  check('batch import parses rows', ok(imp), JSON.stringify(unwrap(imp)).slice(0, 90));

  console.log('\n[compatibility gateway]');
  const compat = await req('POST', '/v1/overview/get_overviews', {});
  check('allinssl /v1/{group}/{action}', ok(compat), `health=${unwrap(compat)?.health_score}`);
  const compatForm = await req('POST', '/v1/cert/get_list', 'limit=5&search=', { form: true });
  check('form-urlencoded accepted', ok(compatForm));
  const shutdown = await req('POST', '/v1/setting/shutdown', {});
  check('CLI control action returns 410 Gone', shutdown.status === 410, `status=${shutdown.status}`);

  console.log('\n[webhook]');
  const hook = unwrap(await req('GET', '/api/v1/webhooks'));
  check('webhook list readable', Array.isArray(hook?.list || hook));
  const stats = await req('GET', '/api/v1/webhooks/stats');
  check('delivery statistics', ok(stats), `deliveries=${unwrap(stats)?.deliveries}`);
  const emitted = await req('POST', '/api/v1/events/emit', {
    event: 'cert.imported', payload: { id: cid, domains: ['shop.lumenlabs.dev'] }
  });
  check('event emitted (validated vocabulary)', ok(emitted), `id=${unwrap(emitted)?.id}`);
  const rejected = await req('POST', '/api/v1/events/emit', { event: 'not.a.real.event', payload: {} });
  check('unknown event rejected', rejected.status === 400);

  console.log('\n[audit + backup + settings]');
  const audit = await req('GET', '/api/v1/audit');
  check('security audit', ok(audit));
  const settings = await req('PUT', '/api/v1/settings', { renew_before_days: '45' });
  check('settings persisted', ok(settings));
  // Backup is a raw downloadable state document, not a JSON-RPC envelope.
  const backup = await req('GET', '/api/v1/backup');
  check('backup state document', backup.status === 200 && !!backup.json?.certs && !!backup.json?.settings,
    `${backup.raw.length} bytes`);
  const restore = await req('POST', '/api/v1/restore', { state: backup.raw });
  check('restore round-trips', ok(restore));

  console.log('\n[MCP high-level tools]');
  const tools = await req('POST', '/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  check('tools/list returns 15 tools', tools.json?.result?.tools?.length === 15);
  for (const name of ['fleet_overview', 'security_audit', 'delivery_health', 'list_capabilities', 'diagnose_domain']) {
    const args = name === 'diagnose_domain' ? { domain: 'shop.lumenlabs.dev' } : {};
    const r = await req('POST', '/mcp', {
      jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name, arguments: args }
    });
    const text = r.json?.result?.content?.[0]?.text || '';
    check(`MCP ${name}`, r.status === 200 && r.json?.result?.isError !== true && text.length > 2,
      `${text.length} chars`);
  }

  console.log(`\nRESULT: ${passed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('SMOKE ERROR', e); process.exit(1); });
