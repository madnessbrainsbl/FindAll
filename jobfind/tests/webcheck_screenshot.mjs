import assert from 'node:assert/strict';
import puppeteer from '../third_party/web-check/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js';

Object.defineProperty(process, 'platform', { value: 'win32' });
process.env.WC_SERVER = 'true';
process.env.CHROME_PATH = 'C:\\QA\\chrome.exe';
const setTimer = global.setTimeout;
global.setTimeout = (...args) => setTimer(...args).unref();
let closed = 0;
let navigationFails = false;
puppeteer.launch = async (options) => {
  assert.equal(options.executablePath, process.env.CHROME_PATH);
  assert.equal(options.headless, true);
  assert(!options.args.includes('--single-process'));
  assert(!options.args.includes('--no-zygote'));
  assert(!options.userDataDir);
  return {
    newPage: async () => ({
      emulateMediaFeatures: async () => {},
      setDefaultNavigationTimeout: () => {},
      goto: async () => { if (navigationFails) throw new Error('QA navigation failed'); },
      evaluate: async () => {},
      screenshot: async () => Buffer.from('QA image'),
    }),
    close: async () => { closed++; },
  };
};
const { handler } = await import('../third_party/web-check/api/screenshot.js');
const request = { query: { url: 'https://example.org/' }, url: '/api/screenshot' };
const response = { status(code) { this.code = code; return this; }, json(data) { this.data = data; } };
await handler(request, response);
assert.equal(response.code, 200);
assert.equal(Buffer.from(response.data.image, 'base64').toString(), 'QA image');
assert.equal(closed, 1);
navigationFails = true;
await handler(request, response);
assert.equal(response.code, 500);
assert.equal(response.data.error, 'QA navigation failed');
assert.equal(closed, 2);
