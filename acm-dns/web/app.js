(() => {
'use strict';
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const nf = new Intl.NumberFormat();
const MAX_ROWS = 150;
const SVG = 'http://www.w3.org/2000/svg';

let lastId = 0, es = null, rv = -1, bv = -1, fetching = false, bansData = [], started = false;
const statNodes = {};

async function post(path, body) {
  return fetch(path, { method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'acm' }, body: JSON.stringify(body || {}) });
}

// ---------- sign-in ----------
function showGate(msg) { $('gate').hidden = false; $('app').hidden = true; $('err').textContent = msg || ''; $('tok').focus(); setLive(false, 'signed out'); if (es) { es.close(); es = null; } started = false; }
async function signIn(token) {
  const r = await post('/api/login', { token });
  if (r.ok) { $('gate').hidden = true; $('tok').value = ''; start(); return true; }
  if (r.status === 429) { const s = r.headers.get('Retry-After') || '30'; showGate('Too many attempts. Wait ' + s + ' seconds.'); }
  else showGate('That token is not right.');
  return false;
}
$('go').addEventListener('click', () => signIn($('tok').value.trim()));
$('tok').addEventListener('keydown', (e) => { if (e.key === 'Enter') signIn($('tok').value.trim()); });
$('logout').addEventListener('click', async () => { await post('/api/logout'); showGate(''); });

// ---------- state ----------
async function loadState() {
  if (fetching) return; fetching = true;
  try {
    const r = await fetch('/api/state', { credentials: 'same-origin' });
    if (r.status === 401) { showGate(''); return false; }
    if (!r.ok) return false;
    const s = await r.json();
    rv = s.rv; bv = s.bv;
    renderRecords(s.records); renderBans(s.bans); renderClients(s.clients); renderConfig(s.config);
    renderStats(s.stats, s.records.length); renderChart(s.series); renderMeta(s.stats.uptime, s.config.listen);
    if (!started) { lastId = s.lastId; $('feed').textContent = ''; addEvents(s.events, false); }
    return true;
  } catch (e) { return false; } finally { fetching = false; }
}

async function start() {
  $('app').hidden = false; $('logout').hidden = false;
  if (!(await loadState())) return;
  started = true; connect();
}

function setLive(on, text) { $('live').classList.toggle('on', on); $('liveText').textContent = text; }

function connect() {
  if (es) es.close();
  es = new EventSource('/api/stream?after=' + lastId);
  es.onopen = () => setLive(true, 'live');
  es.onmessage = (m) => {
    const d = JSON.parse(m.data);
    lastId = d.lastId;
    addEvents(d.events, true);
    renderStats(d.stats, d.records); renderChart(d.series); renderMeta(d.stats.uptime);
    if (d.rv !== rv || d.bv !== bv) loadState();
  };
  es.onerror = () => { setLive(false, 'reconnecting'); es.close(); es = null; setTimeout(async () => { if (await loadState()) connect(); }, 2000); };
}
setInterval(() => { if (started) loadState(); }, 5000);
setInterval(tickBans, 1000);

// ---------- rendering ----------
function renderMeta(uptime, listen) {
  const m = $('meta'); if (!m.firstChild) { m.append(el('span'), el('span')); }
  if (listen) m.children[0].textContent = 'api ' + listen;
  m.children[1].textContent = 'up ' + dur(uptime);
}
function dur(s) { const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return h ? h + 'h ' + m + 'm' : m ? m + 'm ' + x + 's' : x + 's'; }

function renderStats(s, records) {
  const items = [
    ['total', 'Requests', nf.format(s.total), s.total ? 'avg ' + Math.round(s.avgUs) + ' µs' : ''],
    ['resolved', 'Resolved', nf.format(s.resolved), s.resolved + s.notFound ? Math.round(100 * s.resolved / (s.resolved + s.notFound)) + '% of lookups' : ''],
    ['registered', 'Registrations', nf.format(s.registered), ''],
    ['notFound', 'Not found', nf.format(s.notFound), nf.format(s.invalid) + ' malformed'],
    ['blocked', 'Blocked', nf.format(s.blocked), 'rate limit, bans, hijacks'],
    ['records', 'Names in registry', nf.format(records), ''],
  ];
  const root = $('stats');
  for (const [k, label, value, sub] of items) {
    let n = statNodes[k];
    if (!n) {
      const box = el('div', 'stat' + (k === 'blocked' ? ' blocked' : ''));
      const dt = el('dt', '', label), dd = el('dd'), sm = el('small');
      const dl = el('dl'); dl.style.display = 'block'; dl.append(dt, dd);
      box.append(dl, sm); root.append(box);
      n = statNodes[k] = { dd, sm };
    }
    n.dd.textContent = value; n.sm.textContent = sub;
  }
}

function renderChart(series) {
  const svg = $('chart'); svg.textContent = '';
  const W = 720, H = 170, n = series.length, gap = 2, bw = W / n - gap;
  let peak = 5;
  for (const p of series) peak = Math.max(peak, p.hit + p.miss + p.reg + p.blocked + p.bad);
  $('peak').textContent = 'peak ' + peak + ' req/s';
  const order = ['hit', 'reg', 'miss', 'bad', 'blocked'];
  series.forEach((p, i) => {
    let y = H;
    for (const k of order) {
      const v = p[k]; if (!v) continue;
      const h = Math.max(2, v / peak * (H - 6));
      const r = document.createElementNS(SVG, 'rect');
      r.setAttribute('x', i * (bw + gap)); r.setAttribute('width', bw);
      r.setAttribute('y', y - h); r.setAttribute('height', h); r.setAttribute('class', 'c-' + k);
      svg.append(r); y -= h;
    }
  });
}

const cls = { resolved: 'hit', registered: 'reg', refreshed: 'reg', overwritten: 'miss', 'not-found': 'miss', 'bad-request': 'bad',
  conflict: 'blocked', limit: 'blocked', full: 'blocked', 'rate-limited': 'blocked', banned: 'blocked', 'banned-ip': 'blocked', released: 'info', unbanned: 'info' };
const label = { 'rate-limited': 'rate limited', 'not-found': 'not found', 'bad-request': 'malformed', 'banned-ip': 'ip banned' };

function describe(e) {
  const w = el('span', 'what');
  if (e.kind === 'lookup' || e.kind === 'register') {
    w.append(el('span', 'k', e.kind), document.createTextNode(e.d || ''));
    if (e.dest) { w.append(el('span', 'dest', '  →  ' + e.dest)); }
    if (e.n) w.append(el('span', 'note', '  ' + e.n));
  } else if (e.kind === 'block') {
    w.append(el('span', 'k', 'blocked'), document.createTextNode((e.m || '') + ' ' + (e.p || '')));
    if (e.n) w.append(el('span', 'note', '  ' + e.n));
  } else {
    w.append(el('span', 'k', e.kind), document.createTextNode(e.n || e.d || ''));
  }
  return w;
}

function addEvents(evs, fresh) {
  const feed = $('feed');
  for (const e of evs) {
    const row = el('div', 'row' + (fresh ? ' fresh' : ''));
    const c = cls[e.r] || 'info';
    row.append(el('span', 't', new Date(e.t).toLocaleTimeString([], { hour12: false })), el('span', 'ip', e.ip), describe(e),
      el('span', 'badge ' + c, label[e.r] || e.r), el('span', 'u', e.s ? String(e.s) : ''), el('span', 'u', e.us ? e.us + ' µs' : ''));
    feed.prepend(row);
    if (fresh) setTimeout(() => row.classList.remove('fresh'), 900);
  }
  while (feed.children.length > MAX_ROWS) feed.lastChild.remove();
  if (!feed.children.length) feed.append(el('div', 'empty', 'No requests yet. Point a service at this server and they will appear here.'));
  else if (feed.firstChild.classList.contains('empty') && feed.children.length > 1) feed.firstChild.remove();
  $('feedCount').textContent = 'newest first';
}

function renderRecords(recs) {
  const box = $('records'); box.textContent = '';
  $('recCount').textContent = recs.length + (recs.length === 1 ? ' name' : ' names');
  if (!recs.length) { box.append(el('div', 'empty', 'Nothing registered yet.')); return; }
  for (const r of recs) {
    const it = el('div', 'item'), main = el('div', 'main');
    main.append(document.createTextNode(r.domain + '  '), el('em', '', r.ip));
    const b = el('button', '', 'Release'); b.title = 'Remove this name so another host can register it';
    b.addEventListener('click', async () => { if (confirm('Release ' + r.domain + '?')) { await post('/api/release', { domain: r.domain }); loadState(); } });
    it.append(main, el('span', 'sub', ago(r.updated)), b); box.append(it);
  }
}
function ago(ms) { const s = Math.max(0, Math.floor((Date.now() - ms) / 1000)); return s < 60 ? s + 's ago' : s < 3600 ? Math.floor(s / 60) + 'm ago' : Math.floor(s / 3600) + 'h ago'; }

function renderBans(bans) { bansData = bans; const box = $('bans'); box.textContent = '';
  if (!bans.length) { box.append(el('div', 'empty', 'No clients are blocked.')); return; }
  for (const b of bans) {
    const it = el('div', 'item'), main = el('div', 'main danger', b.ip), left = el('span', 'sub left');
    left.dataset.until = b.until;
    const u = el('button', '', 'Unban'); u.addEventListener('click', async () => { await post('/api/unban', { ip: b.ip }); loadState(); });
    const wrap = el('div', 'main'); wrap.append(main, el('div', 'sub', b.reason));
    it.append(wrap, left, u); box.append(it);
  }
  tickBans();
}
function tickBans() { for (const n of document.querySelectorAll('#bans .left')) { const s = Math.ceil((Number(n.dataset.until) - Date.now()) / 1000); n.textContent = s > 0 ? s + 's left' : 'expired'; } }

function renderClients(cs) { const box = $('clients'); box.textContent = '';
  if (!cs.length) { box.append(el('div', 'empty', 'No clients yet.')); return; }
  const top = Math.max(1, cs[0].reqs);
  for (const c of cs) {
    const it = el('div', 'item'), main = el('div', 'main', c.ip), bar = el('div', 'bar');
    bar.style.width = Math.max(4, 70 * c.reqs / top) + 'px';
    it.append(main, bar, el('span', 'n', nf.format(c.reqs)), el('span', 'sub', c.blocked ? nf.format(c.blocked) + ' blocked' : '')); box.append(it);
  }
}

function renderConfig(c) {
  const dl = $('cfg'); dl.textContent = '';
  const rows = [['Rate limit', c.rate + ' req/s, burst ' + c.burst], ['Auto-ban', '> ' + c.faultLimit + ' bad requests/min, ' + c.ban + ' doubling to ' + c.banMax],
    ['Name takeover', c.firstWriterWins ? 'refused (first writer wins)' : 'allowed, flagged'], ['Per-host quota', c.maxPerIP + ' names'], ['Registry cap', c.maxRecords + ' names'],
    ['Connections', c.maxConns + ' per client'], ['Record expiry', c.ttl === '0s' ? 'never' : c.ttl], ['Transport', c.tls ? 'HTTPS' : 'HTTP']];
  for (const [k, v] of rows) dl.append(el('dt', '', k), el('dd', '', v));
}

// ---------- boot ----------
(async () => {
  const m = /#t=([^&]+)/.exec(location.hash);
  if (m) { history.replaceState(null, '', location.pathname); if (await signIn(decodeURIComponent(m[1]))) return; }
  const r = await fetch('/api/state', { credentials: 'same-origin' });
  if (r.status === 401) showGate(''); else start();
})();
})();
