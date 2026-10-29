'use strict';

// FindAll adaptation: explicit local DOM export, independent of model/provider settings.
async function findallExportPage() {
  const button = document.getElementById('findallExport');
  button.disabled = true;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !/^https:\/\//i.test(tab.url || '')) throw new Error('Open an HTTPS page first');
    const target = { tabId: tab.id };
    await chrome.scripting.executeScript({ target, files: ['page/extract-items.js'] });
    const [{ result }] = await chrome.scripting.executeScript({ target, func: () => {
      const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, {
        acceptNode: node => {
          const parent = node.parentElement;
          return !parent || parent.closest('script,style,noscript,template,input,textarea,select,[contenteditable]') ||
            !parent.getClientRects().length || getComputedStyle(parent).visibility === 'hidden'
            ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
        }
      });
      let node, text = '', textTruncated = false;
      while ((node = walker.nextNode())) {
        text += ' ' + node.textContent.slice(0, 100001);
        if (text.length > 100000) { textTruncated = true; break; }
      }
      text = text.replace(/\s+/g, ' ').trim();
      const listing = window.__crawlerExtract.items(document, location.href, 100);
      return {
        schema: 'findall.chrome-crawler.v1', url: location.href, title: document.title.slice(0, 500),
        observed_at: new Date().toISOString(), text: text.slice(0, 100000), text_truncated: textTruncated,
        items: { method: listing.method, total: listing.total, items: listing.items.map(item => ({
          title: String(item.title || '').slice(0, 500), url: String(item.url || ''),
          details: String(item.details || '').slice(0, 2000), price: item.price ?? null,
          currency: String(item.currency || '').slice(0, 20)
        })) }
      };
    } });
    result.extension_version = chrome.runtime.getManifest().version;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    if (blob.size > 2000000) throw new Error('Page export exceeds 2 MB');
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'findall-chrome-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    button.textContent = 'Exported to Downloads';
  } catch (error) {
    button.textContent = 'Export failed';
    button.title = error.message || 'Could not read the active tab';
  } finally {
    button.disabled = false;
  }
}

document.getElementById('findallExport').addEventListener('click', findallExportPage);
