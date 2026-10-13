const { test } = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');
const fs = require('node:fs');
const path = require('node:path');
const script = fs.readFileSync(path.join(__dirname, '../assets/js/main.js'), 'utf8');
const root = path.join(__dirname, '../_site');
const sourceNotes = fs.readdirSync(path.join(__dirname, '../notes'), { withFileTypes: true }).filter((item) => item.isDirectory() && fs.existsSync(path.join(__dirname, '../notes', item.name, 'index.md'))).length;
const sourcePosts = fs.readdirSync(path.join(__dirname, '../_posts')).filter((name) => name.endsWith('.md')).length;
const data = () => JSON.parse(fs.readFileSync(path.join(root, 'search.json'), 'utf8'));
const pause = (ms = 25) => new Promise((resolve) => setTimeout(resolve, ms));

async function page(file, query = '', options = {}) {
  const pathname = file.replace(/index\.html$/, '');
  const dom = new JSDOM(fs.readFileSync(path.join(root, file), 'utf8'), {
    url: `https://lizisec.github.io/${pathname}${query}`,
    runScripts: 'outside-only', pretendToBeVisual: true,
  });
  const w = dom.window;
  w.matchMedia = () => ({ matches: options.desktop !== false, addEventListener() {} });
  w.fetch = options.fetch || (async () => ({ ok: true, json: async () => data() }));
  w.eval(script);
  await pause();
  return dom;
}
const select = (dom, name, value) => {
  const el = dom.window.document.querySelector(`[name="${name}"]`);
  el.value = value;
  el.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
};
const input = async (dom, value) => {
  const el = dom.window.document.querySelector('[data-search-input]');
  el.value = value;
  el.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  await pause(160);
};

test('home, taxonomy and 404 provide real navigation', async () => {
  for (const file of ['index.html', 'tags/index.html', '404.html']) {
    const dom = await page(file);
    try {
      assert.ok(dom.window.document.querySelector('h1'));
      assert.ok(dom.window.document.querySelector('a[href="/search/"]'));
      assert.ok(dom.window.document.querySelector('a[href="/notes/"]'));
    } finally { dom.window.close(); }
  }
});

test('full index includes every note and content beyond the old 2200-character limit', () => {
  const entries = data();
  assert.equal(entries.filter((e) => e.type === 'note').length, sourceNotes);
  assert.equal(entries.filter((e) => e.type === 'post').length, sourcePosts);
  assert.ok(entries.some((e) => e.text.length > 20000));
  assert.ok(entries.every((e) => !/<h[1-6][ >]|<pre[ >]/.test(e.text)));
});

test('search finds late-body keywords, highlights safely, supports URL and type filter', async () => {
  const entries = data();
  const longNote = entries.find((e) => e.type === 'note' && e.text.length > 20000);
  const words = longNote.text.slice(5000).match(/[A-Za-z][A-Za-z0-9_-]{8,}/g);
  const word = words.find((word) => !longNote.text.slice(0, 2200).toLowerCase().includes(word.toLowerCase()));
  assert.ok(word, 'fixture needs a term beyond the former cutoff');
  const dom = await page('search/index.html', `?q=${encodeURIComponent(word)}&type=note`);
  try {
    const doc = dom.window.document;
    assert.ok([...doc.querySelectorAll('.search-result-title')].some((a) => a.textContent === longNote.title));
    assert.ok(doc.querySelector('mark'));
    await input(dom, 'HTB Windows Hard');
    const expected = entries.filter((e) => e.type === 'note' && ['htb', 'windows', 'hard'].every((word) =>
      [e.title, e.platform, e.os, e.difficulty, e.track, e.status, ...(e.tags || []), e.text].join(' ').toLowerCase().includes(word)));
    // Full-text AND matching includes body terms, not just facet metadata.
    assert.equal(doc.querySelectorAll('.search-result-item').length, expected.length);
    assert.equal(new URL(dom.window.location.href).searchParams.get('q'), 'HTB Windows Hard');
    select(dom, 'type', 'post');
    assert.equal(doc.querySelectorAll('.search-result-item').length, 0);
    await input(dom, '<img src=x onerror=alert(1)>');
    assert.equal(doc.querySelector('.search-results img'), null);
    doc.querySelector('form').reset();
    assert.equal(doc.querySelector('[data-search-input]').value, '');
    assert.equal(new URL(dom.window.location.href).search, '');
    dom.window.history.pushState({}, '', '?q=SSH&type=post');
    dom.window.dispatchEvent(new dom.window.PopStateEvent('popstate'));
    assert.equal(doc.querySelector('[data-search-input]').value, 'SSH');
    assert.ok(doc.querySelector('.search-result-item'));
  } finally { dom.window.close(); }
});

test('failed and malformed search index shows a retry; retry recovers', async () => {
  let fail = true;
  const dom = await page('search/index.html', '?q=FTP', {
    fetch: async () => { if (fail) throw new Error('offline'); return { ok: true, json: async () => data() }; },
  });
  try {
    const doc = dom.window.document;
    assert.equal(doc.querySelector('[data-search-retry]').hidden, false);
    fail = false;
    doc.querySelector('[data-search-retry]').click();
    await pause();
    assert.equal(doc.querySelector('[data-search-retry]').hidden, true);
    assert.ok(doc.querySelector('.search-result-item'));
  } finally { dom.window.close(); }
  for (const bad of [{}, [{ title: 'bad', url: 'javascript:alert(1)' }]]) {
    const invalid = await page('search/index.html', '', { fetch: async () => ({ ok: true, json: async () => bad }) });
    try { assert.equal(invalid.window.document.querySelector('[data-search-retry]').hidden, false); }
    finally { invalid.window.close(); }
  }
});

test('note facets combine, restore from URL, show empty states and reset', async () => {
  const dom = await page('notes/index.html', '?platform=HTB&os=Windows&difficulty=Hard');
  try {
    const doc = dom.window.document;
    const visible = () => [...doc.querySelectorAll('[data-note-card]')].filter((card) => !card.hidden);
    assert.ok(visible().length);
    assert.ok(visible().every((card) => card.dataset.platform === 'HTB' && card.dataset.os === 'Windows' && card.dataset.difficulty === 'Hard'));
    select(dom, 'platform', 'VulnHub');
    assert.equal(visible().length, 0);
    assert.equal(doc.querySelector('[data-note-empty]').hidden, false);
    doc.querySelector('form').reset();
    assert.equal(visible().length, sourceNotes);
    assert.equal(dom.window.location.search, '');
    select(dom, 'status', 'WIP');
    assert.ok(visible().length);
    assert.ok(visible().every((card) => card.dataset.status === 'WIP'));
    dom.window.history.pushState({}, '', '?platform=HTB&q=forest');
    dom.window.dispatchEvent(new dom.window.PopStateEvent('popstate'));
    assert.equal(visible().length, 1);
    assert.equal(visible()[0].dataset.title, 'Forest');
  } finally { dom.window.close(); }
});

test('TOC includes every h1-h4, has valid encoded anchors and mobile collapse', async () => {
  const note = data().find((e) => e.title === 'WinterMute');
  for (const desktop of [true, false]) {
    const file = decodeURI(note.url).replace(/^\//, '') + 'index.html';
    const dom = await page(file, '', { desktop });
    try {
      const doc = dom.window.document;
      const toc = doc.querySelector('.js-toc');
      assert.equal(toc.hidden, false);
      assert.equal(toc.open, desktop);
      const headings = doc.querySelectorAll('.post-content h1, .post-content h2, .post-content h3, .post-content h4');
      const links = [...toc.querySelectorAll('a')];
      assert.equal(links.length, headings.length);
      assert.ok(links.every((a) => doc.getElementById(decodeURIComponent(a.hash.slice(1)))));
    } finally { dom.window.close(); }
  }
});

test('copy button sits outside code and writes the original payload only', async () => {
  const dom = await page('ssh-22-pentest-guide/index.html');
  try {
    const w = dom.window;
    const doc = w.document;
    let copied;
    Object.defineProperty(w, 'isSecureContext', { value: true });
    Object.defineProperty(w.navigator, 'clipboard', { value: { writeText: async (text) => { copied = text; } } });
    const wrapper = doc.querySelector('.code-block');
    assert.equal(wrapper.querySelector('pre button'), null);
    wrapper.querySelector('button').click();
    await pause();
    assert.equal(copied, wrapper.querySelector('code').textContent.replace(/\n$/, ''));
    assert.match(wrapper.querySelector('[role="status"]').textContent, /已复制/);
  } finally { dom.window.close(); }
});

test('HTML-looking titles and indexed body text render as text, never executable nodes', async () => {
  const title = '<img src=x onerror=alert(1)> needle';
  const dom = await page('search/index.html', '?q=needle', {
    fetch: async () => ({ ok: true, json: async () => [{
      type: 'post', title, url: '/ssh-22-pentest-guide/',
      text: 'needle &lt;script&gt;alert(1)&lt;/script&gt;', tags: [],
    }] }),
  });
  try {
    const results = dom.window.document.querySelector('.search-results');
    assert.equal(results.querySelectorAll('.search-result-item').length, 1);
    assert.equal(results.querySelector('.search-result-title').textContent, title);
    assert.equal(results.querySelector('img, script, iframe'), null);
    assert.match(results.querySelector('.search-result-snippet').textContent, /<script>/);
  } finally { dom.window.close(); }
});

test('pixel theme assets are self-hosted and used on controls and cards', () => {
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(root, 'assets/css/main.css'), 'utf8');
  assert.match(html, /assets\/lib\/nes\/nes\.min\.css/);
  assert.match(html, /class="nes-btn button button-primary"/);
  assert.match(html, /class="post-list-li nes-container is-dark"/);
  assert.match(css, /ZLabsPixel_12px_M_CN\.ttf\.woff2/);
  for (const asset of [
    'assets/lib/nes/nes.min.css', 'assets/lib/nes/LICENSE',
    'assets/fonts/zlabs-pixel-12px/ZLabsPixel_12px_M_CN.ttf.woff2',
    'assets/fonts/zlabs-pixel-12px/LICENSE-OFL',
  ]) assert.ok(fs.statSync(path.join(root, asset)).size > 0, asset);
});
