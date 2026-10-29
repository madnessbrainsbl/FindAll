"""Isolated execution of pinned upstream waymore with source-only HTTP budgets.

Only this child process patches requests. No target-site requests, notifications,
default user configuration, or public-suffix downloads are permitted.
"""
from __future__ import annotations
import contextlib
import io
import json
import os
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
HOSTS = {'web.archive.org', 'index.commoncrawl.org', 'otx.alienvault.com',
         'urlscan.io', 'www.virustotal.com', 'virustotal.com',
         '2.intelx.io', 'free.intelx.io', 'ghostarchive.org', 'www.ghostarchive.org'}


def install_transport(ledger, budget=6):
    import requests
    from jf.evidence_capture import validated_url
    original = requests.Session.send
    deadline = time.monotonic() + 35

    def send(session, request, **kwargs):
        host = (urlsplit(request.url).hostname or '').lower()
        if host not in HOSTS:
            raise requests.exceptions.RequestException('Request left archive source hosts')
        if len(ledger) >= budget or time.monotonic() >= deadline:
            raise requests.exceptions.RequestException('Source request budget reached')
        entry = dict(host=host, state='attempted')
        ledger.append(entry)
        try:
            validated_url(request.url)
            from requests.adapters import Retry
            for adapter in session.adapters.values():
                adapter.max_retries = Retry(total=0)
            kwargs.update(timeout=(5, 10), stream=True)
            response = original(session, request, **kwargs)
            chunks, count = [], 0
            for chunk in response.iter_content(65536):
                count += len(chunk)
                if count > 2_000_000 or time.monotonic() > deadline:
                    response.close()
                    raise requests.exceptions.RequestException('Source response budget reached')
                chunks.append(chunk)
            response._content = b''.join(chunks)
            response._content_consumed = True
            response.close()
            if 'html' in response.headers.get('Content-Type','') and any(marker in response.text.lower() for marker in ('cf-chl-', '<title>just a moment')):
                entry.update(state='blocked',http_status=response.status_code,detail='Archive source challenge page')
                raise requests.exceptions.RequestException('Archive source challenge')
            entry.update(http_status=response.status_code,
                         state='blocked' if response.status_code in (401, 403, 429) else
                         'error' if response.status_code >= 400 else 'ok')
            return response
        except requests.exceptions.Timeout:
            entry['state'] = 'timeout'
            raise
        except Exception as exc:
            if entry.get('state')!='blocked':
                entry['state'] = 'partial' if 'budget' in str(exc) else 'error'
                entry['detail'] = 'DNS resolution failed' if isinstance(exc,socket.gaierror) else \
                    'TLS validation failed' if isinstance(exc,requests.exceptions.SSLError) else \
                    'Archive request or response budget reached' if 'budget' in str(exc) else 'Archive source connection failed'
            raise requests.exceptions.RequestException('Archive source request failed') from None
    requests.Session.send = send


def main():
    request = json.loads(sys.stdin.read(16384))
    folder = Path(request['folder']).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    ledger = []
    report = dict(status='error', urls=[], requests=ledger)
    config_path = folder / 'config.yml'
    try:
        import tldextract
        # Bundled PSL: no additional network query or global cache mutation.
        tldextract.extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
        # Upstream compiles empty exclusions as an empty regex (matching every
        # URL). Sentinels prevent accidentally discarding the entire result set.
        config = {'FILTER_CODE': '-1', 'FILTER_MIME': '__findall_no_mime_exclusions__', 'FILTER_URL': '\u0000',
                  'FILTER_KEYWORDS': '', 'DEFAULT_OUTPUT_DIR': str(folder),
                  'WEBHOOK_DISCORD': '', 'TELEGRAM_BOT_TOKEN': '', 'TELEGRAM_CHAT_ID': ''}
        config.update(request.get('keys') or {})
        config_path.write_text(json.dumps(config), encoding='utf-8')
        os.environ['APPDATA'] = str(folder)
        os.environ['XDG_CONFIG_HOME'] = str(folder)
        sys.path[:0] = [str(ROOT / 'third_party' / 'waymore'), str(ROOT)]
        from waymore import waymore
        # Explicit -c is already supplied; do not create a default config in the
        # user's platform-specific configuration directory.
        waymore.ensureConfigExists = lambda: None
        install_transport(ledger)
        output = folder / 'urls.txt'
        args = ['waymore', '-i', request['domain'], '-mode', 'U', '--providers', request['provider'],
                '-oU', str(output), '-oR', str(folder / 'responses'), '-c', str(config_path),
                '-lr', '3', '-lcc', '1', '-r', '0', '-p', '1', '--stream', '-ow']
        if not request.get('subs', True):
            args.append('-n')
        for option, value in (('-from', request.get('from_date')), ('-to', request.get('to_date'))):
            if value:
                args.extend([option, value])
        sys.argv = args
        # Main handles errors internally. Keep its output private; inspect both
        # transport outcomes and explicit parse errors instead of assuming empty.
        stdout, stderr = io.StringIO(), io.StringIO()
        sys.stdin = io.StringIO('')
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                waymore.main()
            except SystemExit:
                pass
        urls = output.read_text(encoding='utf-8', errors='replace').splitlines()[:5000] if output.is_file() else []
        states = {item['state'] for item in ledger}
        parse_error = any(word in stderr.getvalue() or word in stdout.getvalue() for word in ('ERROR', '[ ERR ]', 'unexpected response'))
        report.update(urls=urls, status='partial' if urls and (states-{'ok'} or parse_error) else
                      'ok' if urls else 'blocked' if states and states <= {'blocked'} else
                      'timeout' if 'timeout' in states else 'error' if parse_error or states-{'ok'} else
                      'empty' if states else 'skipped')
        report['detail'] = next((item.get('detail') for item in ledger if item.get('detail')), '') or \
            ('Upstream source response could not be parsed' if parse_error else 'Bounded upstream waymore URL collection')
    except ImportError:
        report.update(status='skipped', detail='Run setup-archives.bat to install waymore dependencies')
    except Exception:
        report.update(status='error', detail='Upstream archive collector could not finish')
    finally:
        config_path.unlink(missing_ok=True)
    print(json.dumps(report))


if __name__ == '__main__':
    main()
