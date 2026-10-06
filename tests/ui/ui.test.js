// UI checks: loads the real page in jsdom against tests/ui/fake_server.py.
// Groups served: tcp 22 (0.0.0.0 + ::), udp 53 (0.0.0.0 + 127.0.0.53%lo), tcp 631, 4000, 4001, 7777, 8710.
// tcp 631 (::1 only) and 4001 answer HTTP.
const { JSDOM, VirtualConsole } = require('jsdom');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = async function run(BASE) {
  let passed = 0;
  const check = (cond, msg) => { if (!cond) throw new Error('FAIL: ' + msg); passed++; };
  const api = async (method, url, body) => (await fetch(BASE + url, {
    method, headers: { 'Content-Type': 'application/json' }, body: body && JSON.stringify(body),
  })).json();
  const groups = async () => Object.fromEntries((await api('GET', 'api/ports')).groups.map((g) => [g.id, g]));

  // Opens the page. `mutate` can rewrite the GET api/ports payload; every request is logged.
  async function open(opts = {}) {
    const html = await (await fetch(BASE)).text();
    const errors = [];
    const requests = [];
    const vc = new VirtualConsole();
    vc.on('jsdomError', (e) => errors.push(e.message));
    vc.on('error', (e) => errors.push(String(e)));
    const dom = new JSDOM(html, {
      url: BASE + (opts.hash || ''), runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
      beforeParse(win) {
        win.fetch = async (u, o) => {
          const method = (o && o.method) || 'GET';
          requests.push(method + ' ' + u);
          const res = await fetch(new URL(u, BASE), o);
          if (opts.mutate && method === 'GET' && String(u) === 'api/ports') {
            const json = await res.json();
            opts.mutate(json);
            return new Response(JSON.stringify(json), { status: res.status, headers: { 'Content-Type': 'application/json' } });
          }
          return res;
        };
        win.Element.prototype.scrollIntoView = function () {};
        win.alert = () => { throw new Error('alert() called'); };
        for (const [k, v] of Object.entries(opts.storage || {})) win.localStorage.setItem(k, v);
      },
    });
    await wait(600);
    return { win: dom.window, doc: dom.window.document, errors, requests };
  }

  let { win, doc, errors, requests } = await open();
  const rows = () => [...doc.querySelectorAll('#rows tr')];
  const rowFor = (port, proto = 'tcp') => rows().find((tr) => tr.querySelector('.port-num').textContent === String(port) && tr.querySelector('.proto-tag').textContent === proto);
  const focusedPort = () => doc.querySelector('#rows tr.is-focused .port-num').textContent;
  // Real key events target the focused element (or body), never `document`
  const key = (opts) => (doc.activeElement || doc.body).dispatchEvent(new win.KeyboardEvent('keydown', Object.assign({ bubbles: true, cancelable: true }, opts)));
  const keyOn = (el, opts) => el.dispatchEvent(new win.KeyboardEvent('keydown', Object.assign({ bubbles: true, cancelable: true }, opts)));
  const toasts = () => [...doc.querySelectorAll('.toast')].map((t) => t.textContent);
  const errorToasts = () => [...doc.querySelectorAll('.toast-error')].map((t) => t.textContent);

  // ── initial render ──
  check(rows().length === 7, 'one row per group: ' + rows().length);
  check(doc.getElementById('stat-total').textContent === '7', 'total stat');
  check(doc.getElementById('result-count').textContent === '7 of 7 ports', 'result count');
  check(/^Scanned (just now|1 min ago)$/.test(doc.getElementById('scanned-at').textContent), 'scanned label');
  check(doc.getElementById('hostname').textContent.length > 0, 'hostname');
  check(!requests.includes('POST api/rescan'), 'fresh data: no background rescan on load');
  const ssh = rowFor(22);
  check(ssh.querySelectorAll('.bind').length === 2 && ssh.querySelectorAll('.bind.is-faded').length === 1, 'ssh: 2 chips, :: faded');
  check(/duplicate bind/.test(ssh.querySelector('.bind.is-faded').title), 'faded chip tooltip says duplicate bind');
  check(ssh.querySelector('.name-btn').textContent === 'SSH', 'auto name shown');
  check(rowFor(7777).querySelector('.name-btn').textContent === 'Unnamed: click to name', 'unnamed ghost text');
  check(rowFor(22).querySelector('.pill-new'), 'NEW pill');
  check(rowFor(7777).querySelector('.svc-proc').textContent === 'process hidden', 'process hidden label');
  check(rowFor(53, 'udp').querySelector('.svc-proc').textContent === 'systemd-resolve · pid 500', 'process from a live bind');
  check(rowFor(22).querySelector('.svc-proc').textContent === 'sshd · pid 812', 'process + pid');

  // ── open-in-new-tab links for ports that answered HTTP ──
  const openLink = (port, proto) => rowFor(port, proto).querySelector('a.open-btn');
  const link = openLink(4001);
  check(link && link.getAttribute('href') === BASE.replace(/\/$/, '').replace(/:\d+$/, ':4001/'), 'http port links to the page host: ' + (link && link.getAttribute('href')));
  check(link.target === '_blank' && /noopener/.test(link.rel) && link.querySelector('svg') && /4001/.test(link.getAttribute('aria-label')), 'link opens a new tab, has icon + label');
  check(openLink(631).getAttribute('href') === 'http://localhost:631/', 'loopback-only port links to localhost');
  check(!openLink(22) && !openLink(53, 'udp') && !openLink(4000), 'no link for non-HTTP ports');
  link.addEventListener('click', (e) => e.preventDefault(), { once: true });  // jsdom can't navigate
  link.click();
  check(!doc.getElementById('drawer').classList.contains('open'), 'clicking the link does not open the drawer');
  rowFor(4001).querySelector('.more-btn').click();
  const dOpen = doc.getElementById('d-open');
  check(!dOpen.hidden && dOpen.getAttribute('href') === link.getAttribute('href') && dOpen.target === '_blank', 'drawer shows the link');
  key({ key: 'Escape' });
  rowFor(22).querySelector('.more-btn').click();
  check(dOpen.hidden, 'drawer hides the link for non-HTTP ports');
  key({ key: 'Escape' });

  // ── sorting ──
  const ports = () => rows().map((tr) => +tr.querySelector('.port-num').textContent);
  check(JSON.stringify(ports()) === JSON.stringify([...ports()].sort((a, b) => a - b)), 'default port asc');
  doc.querySelector('th[data-sort="name"] .sort-btn').click();
  let names = rows().map((tr) => tr.querySelector('.name-btn').textContent);
  check(names.slice(-4).every((n) => n.startsWith('Unnamed')) && doc.querySelector('th[data-sort="name"]').getAttribute('aria-sort') === 'ascending', 'name asc, unnamed last: ' + names);
  doc.querySelector('th[data-sort="name"] .sort-btn').click();
  names = rows().map((tr) => tr.querySelector('.name-btn').textContent);
  check(names.slice(-4).every((n) => n.startsWith('Unnamed')) && names[0] === 'SSH', 'name desc, unnamed still last: ' + names);
  doc.querySelector('th[data-sort="port"] .sort-btn').click();

  // ── filters ──
  doc.querySelector('.stat[data-card="unnamed"]').click();
  check(rows().length === 4 && doc.querySelector('.stat[data-card="unnamed"]').getAttribute('aria-pressed') === 'true', 'unnamed card');
  check(!doc.getElementById('reset-filters').hidden, 'reset filters visible');
  doc.querySelector('.stat[data-card="unnamed"]').click();
  check(rows().length === 7, 'card toggles back to total');
  const search = doc.getElementById('search');
  search.value = 'sshd'; search.dispatchEvent(new win.Event('input'));
  check(rows().length === 1 && doc.getElementById('result-count').textContent === '1 of 7 ports', 'search');
  key({ key: 'Escape' });
  check(search.value === '' && rows().length === 7, 'Esc clears search');
  doc.querySelector('.segmented button[data-proto="udp"]').click();
  check(rows().length === 1, 'udp filter');
  doc.querySelector('.segmented button[data-proto="all"]').click();
  const scope = doc.getElementById('scope-filter');
  scope.value = 'loopback'; scope.dispatchEvent(new win.Event('change'));
  check(rows().length === 3, 'loopback scope filter: ' + rows().length);
  scope.value = ''; scope.dispatchEvent(new win.Event('change'));
  search.value = 'zzzz-nothing'; search.dispatchEvent(new win.Event('input'));
  check(!doc.getElementById('empty').hidden && !doc.getElementById('empty-clear').hidden, 'empty state + clear button');
  doc.getElementById('empty-clear').click();
  check(rows().length === 7 && doc.getElementById('reset-filters').hidden, 'clear filters');

  // ── inline rename, undo, escaping ──
  rowFor(7777).querySelector('.name-btn').click();
  let input = rowFor(7777).querySelector('.name-input');
  check(input && doc.activeElement === input, 'inline input focused');
  input.value = '<img src=x onerror="window.pwned=1">Foo';
  keyOn(input, { key: 'Enter' });
  await wait(400);
  check(rowFor(7777).querySelector('.name-btn').textContent.startsWith('<img'), 'name rendered as text');
  check(!doc.querySelector('#rows img') && !win.pwned, 'no HTML injection');
  check((await groups())['tcp-7777'].name.startsWith('<img'), 'saved on server');
  const saved = [...doc.querySelectorAll('.toast')].pop();
  check(saved && /Renamed 7777\/tcp/.test(saved.textContent) && saved.querySelector('button').textContent === 'Undo', 'saved toast with undo');
  saved.querySelector('button').click();
  await wait(400);
  check((await groups())['tcp-7777'].name === '', 'undo restored name');
  check(rowFor(7777).querySelector('.name-btn').classList.contains('is-unnamed'), 'undo re-rendered');
  rowFor(7777).querySelector('.name-btn').click();
  input = rowFor(7777).querySelector('.name-input');
  input.value = 'nope';
  keyOn(input, { key: 'Escape' });
  await wait(200);
  check((await groups())['tcp-7777'].name === '' && !doc.querySelector('.name-input'), 'Esc cancels inline edit');

  // ── category popover ──
  const pop = doc.getElementById('popover');
  rowFor(22).querySelector('.cat-btn').click();
  check(!pop.hidden && pop.querySelector('.pop-item.is-current').textContent.includes('Remote Access'), 'popover open, current marked');
  [...pop.querySelectorAll('.pop-item')].find((b) => b.textContent.includes('Security')).click();
  await wait(400);
  check((await groups())['tcp-22'].binds.every((b) => b.category === 'Security'), 'category applied to every bind');
  check(rowFor(22).querySelector('.cat-btn .chip').textContent === 'Security', 'chip updated');
  rowFor(7777).querySelector('.cat-btn').click();
  pop.querySelector('.pop-new').click();
  const newCat = pop.querySelector('.pop-input');
  check(newCat && doc.activeElement === newCat, 'new category input');
  newCat.value = 'Home Lab';
  keyOn(newCat, { key: 'Enter' });
  await wait(500);
  check((await groups())['tcp-7777'].category === 'Home Lab' && pop.hidden, 'new category created + assigned');
  rowFor(7777).querySelector('.cat-btn').click();
  check(pop.querySelectorAll('.pop-del').length === 0, 'no delete button for an in-use category');
  key({ key: 'Escape' });
  check(pop.hidden, 'Esc closes popover');

  // ── drawer ──
  const drawer = doc.getElementById('drawer');
  rowFor(53, 'udp').querySelector('.col-binds').click();
  check(drawer.classList.contains('open') && win.location.hash === '#udp-53', 'drawer opens + hash');
  const bindList = doc.getElementById('d-binds').textContent;
  check(doc.getElementById('d-binds').children.length === 2 && /duplicate bind/.test(bindList) && !/ignored/.test(bindList), 'drawer labels duplicate bind (not ignored): ' + bindList);
  check(doc.getElementById('d-raw').textContent.includes('127.0.0.53%lo:53'), 'raw lines');
  const notes = doc.getElementById('d-notes');
  notes.focus(); notes.value = 'resolver'; notes.blur();
  await wait(400);
  check((await groups())['udp-53'].binds.every((b) => b.notes === 'resolver'), 'notes autosaved to every bind');

  // clipboard: plain-http LAN access has no navigator.clipboard
  const copyBtn = doc.getElementById('d-copy');
  const rawText = doc.getElementById('d-raw').textContent;
  Object.defineProperty(win.navigator, 'clipboard', { value: undefined, configurable: true });
  let copied = null;
  doc.execCommand = (cmd) => { copied = cmd === 'copy' ? doc.activeElement.value : null; return true; };
  copyBtn.focus();
  copyBtn.click();
  await wait(100);
  check(copied === rawText, 'textarea fallback copies the raw lines');
  check(toasts().some((t) => t.includes('Copied raw ss output')), 'copied toast');
  check(doc.activeElement === copyBtn && doc.querySelectorAll('body > textarea').length === 0, 'focus restored, textarea removed');
  doc.execCommand = () => false;
  copyBtn.click();
  await wait(100);
  check(errorToasts().some((t) => t.includes('Copy failed')), 'error toast when execCommand returns false');
  doc.querySelectorAll('.toast').forEach((t) => t.remove());
  doc.execCommand = () => { throw new Error('SecurityError'); };
  copyBtn.click();
  await wait(100);
  check(errorToasts().some((t) => t.includes('Copy failed')), 'error toast when execCommand throws');
  Object.defineProperty(win.navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('denied')) }, configurable: true });
  copied = null;
  doc.execCommand = (cmd) => { copied = doc.activeElement.value; return true; };
  copyBtn.click();
  await wait(100);
  check(copied === rawText, 'falls back when clipboard.writeText rejects');
  let viaApi = null;
  Object.defineProperty(win.navigator, 'clipboard', { value: { writeText: (t) => { viaApi = t; return Promise.resolve(); } }, configurable: true });
  copyBtn.click();
  await wait(100);
  check(viaApi === rawText, 'uses navigator.clipboard when available');

  key({ key: 'Escape' });
  check(!drawer.classList.contains('open') && win.location.hash === '', 'Esc closes drawer + clears hash');
  rowFor(4000).querySelector('.more-btn').click();
  check(drawer.classList.contains('open'), 'more button opens drawer');
  const dIgnored = doc.getElementById('d-ignored');
  dIgnored.checked = true; dIgnored.dispatchEvent(new win.Event('change'));
  await wait(400);
  check((await groups())['tcp-4000'].ignored && !rowFor(4000), 'drawer ignore hides row');
  doc.getElementById('drawer-backdrop').click();
  check(!drawer.classList.contains('open'), 'backdrop closes');

  // ── bulk ──
  rowFor(4001).querySelector('.row-check').click();
  rowFor(7777).querySelector('.row-check').click();
  check(!doc.getElementById('bulk-bar').hidden && doc.getElementById('bulk-count').textContent === '2 selected', 'bulk bar');
  check(doc.getElementById('select-all').indeterminate, 'header checkbox indeterminate');
  doc.getElementById('bulk-ignore').click();
  await wait(400);
  let g = await groups();
  check(g['tcp-4001'].ignored && g['tcp-7777'].ignored && doc.getElementById('bulk-bar').hidden, 'bulk ignore + selection pruned');
  // ignore + unignore a group that has an auto-ignored duplicate
  rowFor(22).querySelector('.row-check').click();
  doc.getElementById('bulk-ignore').click();
  await wait(400);
  g = await groups();
  check(g['tcp-22'].binds.every((b) => b.ignored), 'group ignore sets ignored on every bind');
  doc.querySelector('.stat[data-card="ignored"]').click();
  check(rows().length === 4, 'ignored card shows ignored groups: ' + rows().length);
  doc.getElementById('select-all').click();
  check(doc.getElementById('bulk-count').textContent === '4 selected', 'select all visible');
  doc.getElementById('bulk-unignore').click();
  await wait(400);
  g = await groups();
  check(['tcp-4000', 'tcp-4001', 'tcp-7777', 'tcp-22'].every((id) => !g[id].ignored), 'bulk unignore');
  check(g['tcp-22'].binds.every((b) => !b.ignored) && g['tcp-22'].binds[1].auto_ignored, 'unignore clears every bind; duplicate keeps auto_ignored');
  doc.querySelector('.stat[data-card="ignored"]').click();
  check(rowFor(22).querySelectorAll('.bind.is-faded').length === 1, 'duplicate chip still faded after unignore');

  // ── keyboard ──
  doc.activeElement.blur();
  key({ key: 'j' });
  check(focusedPort() === '22', 'j focuses first row');
  key({ key: 'j' });
  check(focusedPort() === '53', 'j moves down');
  key({ key: 'k' });
  check(focusedPort() === '22', 'k moves up');
  key({ key: 'x' });
  check(doc.getElementById('bulk-count').textContent === '1 selected', 'x selects');
  key({ key: 'x' });
  key({ key: 'e' });
  input = doc.querySelector('.name-input');
  check(input && doc.activeElement === input, 'e starts rename');
  input.value = 'OpenSSH';
  input.blur();
  await wait(400);
  check((await groups())['tcp-22'].name === 'OpenSSH', 'blur saves rename');
  key({ key: 'i' });
  await wait(400);
  check((await groups())['tcp-22'].ignored, 'i ignores focused row');
  check(focusedPort() === '53', 'focus moves to next row after ignore');
  await api('POST', 'api/ports/bulk', { keys: ['tcp|0.0.0.0|22', 'tcp|::|22'], changes: { ignored: false } });
  key({ key: 'Enter' });
  check(drawer.classList.contains('open') && win.location.hash === '#udp-53', 'Enter opens drawer');
  key({ key: 'Escape' });
  key({ key: '/' });
  check(doc.activeElement === search, '/ focuses search');
  keyOn(search, { key: 'j' });
  check(focusedPort() === '53', 'shortcuts disabled while typing');
  search.blur();
  key({ key: '?' });
  check(!doc.getElementById('help').hidden, '? opens help');
  key({ key: 'Escape' });
  check(doc.getElementById('help').hidden, 'Esc closes help');

  // ── errors become toasts, never alert() ──
  const realFetch = win.fetch;
  win.fetch = () => Promise.resolve(new Response(JSON.stringify({ error: 'disk full' }), { status: 500 }));
  rowFor(631).querySelector('.name-btn').click();
  input = doc.querySelector('.name-input');
  input.value = 'x';
  keyOn(input, { key: 'Enter' });
  await wait(300);
  check(errorToasts().some((t) => t.includes('Not saved: disk full')), 'error toast');
  win.fetch = realFetch;
  await wait(300);

  // ── rescan ──
  doc.getElementById('rescan-btn').click();
  check(doc.getElementById('rescan-btn').classList.contains('is-loading'), 'spinner while scanning');
  await wait(600);
  check(!doc.getElementById('rescan-btn').classList.contains('is-loading') && toasts().some((t) => /Scan complete/.test(t)), 'rescan finished');

  // ── theme + persistence ──
  doc.getElementById('theme-btn').click();
  check(doc.documentElement.getAttribute('data-theme') === 'light' && win.localStorage.getItem('pi-theme') === 'light', 'theme toggle persisted');
  doc.querySelector('.stat[data-card="public"]').click();
  doc.querySelector('th[data-sort="last_seen"] .sort-btn').click();
  const storage = { 'pi-theme': win.localStorage.getItem('pi-theme'), 'pi-state': win.localStorage.getItem('pi-state') };
  check(errors.length === 0, 'no page errors: ' + errors.join(' | '));
  win.close();

  // ── reload: filters/sort/theme restored, hash reopens drawer ──
  ({ win, doc, errors } = await open({ hash: '#tcp-22', storage }));
  check(doc.documentElement.getAttribute('data-theme') === 'light', 'theme restored before paint');
  check(doc.querySelector('.stat[data-card="public"]').getAttribute('aria-pressed') === 'true', 'card filter restored');
  check(doc.querySelector('th[data-sort="last_seen"]').getAttribute('aria-sort') === 'descending', 'sort restored');
  check(doc.getElementById('drawer').classList.contains('open') && doc.getElementById('d-title').textContent === 'OpenSSH', 'hash reopens drawer');
  check(errors.length === 0, 'no page errors after reload: ' + errors.join(' | '));
  win.close();

  // ── stale threshold comes from the server (PORT_INVENTORY_STALE_SECONDS) ──
  ({ win, doc, errors, requests } = await open({ mutate: (p) => { p.stale_after_seconds = 0; } }));
  await wait(400);
  check(requests.includes('POST api/rescan'), 'stale data triggers a background rescan');
  check(errors.length === 0, 'no page errors (stale): ' + errors.join(' | '));
  win.close();

  return passed;
};
