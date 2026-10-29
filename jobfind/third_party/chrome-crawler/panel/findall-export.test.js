'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

async function check(tabUrl, fail = false) {
  let handler, downloaded = false, payload, calls = [];
  const button = { addEventListener: (_, fn) => { handler = fn; } };
  const context = vm.createContext({
    document: { body: {}, title: 'Listings',
      createTreeWalker: (_, what, filter) => {
        const parentElement = { closest: () => false, getClientRects: () => [1] };
        const nodes = [
          { textContent: 'password must not be exported', parentElement: { ...parentElement, closest: () => true } },
          { textContent: 'hidden text', parentElement: { ...parentElement, getClientRects: () => [] } },
          { textContent: 'Rendered content', parentElement }
        ];
        return { nextNode: () => { while (nodes.length) { const node = nodes.shift(); if (filter.acceptNode(node) === 1) return node; } return null; } };
      },
      getElementById: () => button, createElement: () => ({ click: () => { downloaded = true; } }) },
    NodeFilter: { SHOW_TEXT: 4, FILTER_REJECT: 2, FILTER_ACCEPT: 1 },
    getComputedStyle: () => ({ visibility: 'visible' }),
    location: { href: tabUrl },
    window: { __crawlerExtract: { items: () => ({ method: 'json-ld', total: 1, items: [
      { title: 'Bicycle', url: 'https://example.org/1', price: 123, currency: 'RUB', details: 'Listing text' }
    ] }) } },
    chrome: { tabs: { query: async () => [{ id: 7, url: tabUrl }] },
      scripting: { executeScript: async opts => {
        calls.push(opts);
        if (fail) throw new Error('Cannot access tab');
        return opts.func ? [{ result: opts.func() }] : [];
      } }, runtime: { getManifest: () => ({ version: '0.7.5' }) } },
    Blob: class { constructor(parts) { payload = JSON.parse(parts[0]); this.size = parts[0].length; } },
    URL: { createObjectURL: () => 'blob:local', revokeObjectURL: () => {} },
    setTimeout: () => {},
    fetch: () => { throw new Error('Export must not call a provider'); }
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, 'findall-export.js'), 'utf8'), context);
  await handler();
  assert.equal(button.disabled, false);
  return { button, downloaded, payload, calls };
}

(async () => {
  const ok = await check('https://example.org/listings');
  assert.ok(ok.downloaded);
  assert.equal(ok.payload.schema, 'findall.chrome-crawler.v1');
  assert.equal(ok.payload.extension_version, '0.7.5');
  assert.equal(ok.payload.text, 'Rendered content');
  assert.equal(ok.payload.items.items[0].price, 123);
  assert.equal(ok.calls.length, 2);
  assert.equal(ok.calls[0].files[0], 'page/extract-items.js');
  assert.equal(ok.calls[1].world, undefined, 'Use the isolated world');
  for (const url of ['chrome://settings', 'file:///private', 'http://example.org']) {
    const bad = await check(url);
    assert.equal(bad.downloaded, false);
    assert.equal(bad.calls.length, 0);
  }
  const denied = await check('https://example.org', true);
  assert.equal(denied.downloaded, false);
  assert.equal(denied.button.textContent, 'Export failed');
  console.log('findall-export.test.js: OK');
})().catch(error => { console.error(error); process.exitCode = 1; });
