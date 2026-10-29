"""Adapters for installed research engines and explicitly selected local evidence."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / '.tools-venv' / 'Scripts'
HARVESTER = ROOT / '.harvester-venv' / 'Scripts' / 'theHarvester.exe'
PHONE = ROOT / 'third_party' / 'phoneinfoga' / 'phoneinfoga.exe'
HOST = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
USER = re.compile(r'^[A-Za-z0-9._-]{1,64}$')


def _delta():
    return {key: [] for key in ('profiles', 'web', 'emails', 'findings', 'businesses', 'statuses', 'errors', 'artifacts')}


def _status(delta, source, state, count=0, detail='', elapsed=None):
    row = {'source': source, 'status': state, 'count': count, 'detail': detail}
    if elapsed is not None:
        row['elapsed_seconds'] = round(elapsed, 2)
    delta['statuses'].append(row)
    if state in ('error', 'timeout', 'blocked') and detail:
        message = f'{source}: {detail}'
        if message not in delta['errors']:
            delta['errors'].append(message)


def _artifact(delta, path, source, kind='raw_json'):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    delta['artifacts'].append({'path': str(path), 'name': path.name, 'sha256': digest,
                              'artifact_id': digest, 'source': source, 'kind': kind})
    return digest


def _run(command, cwd, timeout, *, environment=None):
    env = {**os.environ, **(environment or {}), 'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8'}
    with tempfile.TemporaryFile() as capture:
        return _run_captured(command, cwd, timeout, env, capture)


def _run_captured(command, cwd, timeout, env, capture):
    process = subprocess.Popen([str(item) for item in command], cwd=str(cwd), env=env,
        stdin=subprocess.DEVNULL, stdout=capture, stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    code = 124
    try:
        process.wait(timeout=timeout)
        code = process.returncode
    except subprocess.TimeoutExpired:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True,
                           timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    capture.seek(0, os.SEEK_END)
    capture.seek(max(0, capture.tell() - 120000))
    return code, capture.read(120000).decode('utf-8', errors='replace')


def _harvest(domain, output, coverage):
    delta = _delta()
    if not HARVESTER.exists():
        _status(delta, 'theHarvester', 'skipped', detail='Run setup-research-tools.bat')
        return delta
    folder = Path(tempfile.mkdtemp(prefix='theharvester-', dir=output))
    started = time.monotonic()
    sources = 'hackertarget,rapiddns,crtsh,certspotter' if coverage == 'quick' else 'hackertarget,rapiddns,crtsh,certspotter,commoncrawl'
    launcher = [HARVESTER]
    proxy_flags = []
    if os.environ.get('JOBFIND_ACTIVE_PROXY'):
        # Upstream ignores HTTP_PROXY unless -p is selected. Supply the
        # command's route in memory without replacing the user's proxies.yaml.
        launcher = [HARVESTER.with_name('python.exe'), '-c',
            'import os; from theHarvester.lib.core import Core; '
            'Core.proxy_list=staticmethod(lambda: {"http":[os.environ["JOBFIND_ACTIVE_PROXY"]],"socks5":[]}); '
            'from theHarvester.theHarvester import main; main()']
        proxy_flags = ['-p']
    code, text = _run([*launcher, '-d', domain, '-b', sources, '-l', '100' if coverage == 'quick' else '500',
                       '-j', '2', '-f', 'result', *proxy_flags], folder, 70 if coverage == 'quick' else 240)
    log = folder / 'engine.log'
    log.write_text(text, encoding='utf-8')
    _artifact(delta, log, 'theHarvester', 'engine_log')
    report = folder / 'result.jsonl'
    if report.exists():
        _artifact(delta, report, 'theHarvester')
        records = [json.loads(line) for line in report.read_text(encoding='utf-8').splitlines() if line.strip()]
        for execution in (records[0].get('source_executions', []) if records else []):
            state = {'failed': 'error', 'completed': 'ok', 'complete': 'ok'}.get(execution.get('status'), execution.get('status', 'empty'))
            _status(delta, 'theHarvester / ' + execution.get('source', 'source'), state,
                execution.get('result_count', 0), execution.get('stop_reason') or execution.get('error_type') or '',
                float(execution.get('duration_ms', 0)) / 1000)
        for row in records[1:]:
            value = str(row.get('value', ''))
            providers = row.get('sources', [])
            url = next((item for item in providers if isinstance(item, str) and item.startswith('https://')), '')
            source = 'theHarvester / ' + ', '.join(str(item) for item in providers)
            if not url and 'crtsh' in str(providers).lower():
                url = 'https://crt.sh/?q=' + urllib.parse.quote('%.' + domain)
            if not url and 'certspotter' in str(providers).lower():
                url = 'https://api.certspotter.com/v1/issuances?domain=' + urllib.parse.quote(domain)
            if not url and 'hackertarget' in str(providers).lower():
                url = 'https://api.hackertarget.com/hostsearch/?q=' + urllib.parse.quote(domain)
            if not url and 'rapiddns' in str(providers).lower():
                url = 'https://rapiddns.io/subdomain/' + urllib.parse.quote(domain)
            if row.get('type') == 'email' and url:
                delta['emails'].append({'email': value, 'url': url, 'source': source,
                                        'attribution': 'Engine discovery; verify original publication'})
            else:
                delta['findings'].append({'event_type': row.get('type', 'Discovery'), 'value': value,
                    'source': source, 'module': 'theHarvester', 'url': url,
                    'sha256': delta['artifacts'][-1]['sha256'], 'status': 'Passive discovery; ownership unverified'})
    count = len(delta['findings']) + len(delta['emails'])
    state = ('timeout' if code == 124 else 'error' if code else 'partial'
        if any(row['status'] in ('error', 'partial', 'failed') for row in delta['statuses'])
        else 'ok' if count else 'empty')
    _status(delta, 'theHarvester', state, len(delta['findings']) + len(delta['emails']),
            f'Passive sources: {sources}' if code == 0 else text[-700:], time.monotonic() - started)
    return delta


def _ip_services(target, output):
    from .domain_recon import configured_keys, _api
    address = ipaddress.ip_address(target)
    if not address.is_global:
        raise ValueError('Public IP required for indexed service lookup')
    delta = _delta()
    keys = configured_keys()
    folder = Path(tempfile.mkdtemp(prefix='ip-services-', dir=output))
    def keep(name, data, source_url, services):
        path = folder / (name.lower().replace(' ', '-') + '.json')
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
        _artifact(delta, path, name)
        for service in services:
            delta['findings'].append({'event_type': 'Indexed service', 'value': json.dumps(service, ensure_ascii=False),
                'module': name, 'source': name, 'url': source_url,
                'status': 'Indexed public IP service; equipment ownership unverified'})
        _status(delta, name, 'ok' if services else 'empty', len(services))
    for name, key_name in [('Shodan InternetDB', None), ('Shodan hosts', 'SHODAN_API_KEY'), ('Censys', 'CENSYS_API_TOKEN'), ('ZoomEye', 'ZOOMEYE_API_KEY')]:
        key = keys.get(key_name, '') if key_name else ''
        if key_name and not key:
            _status(delta, name, 'skipped', detail='Missing ' + key_name)
            continue
        try:
            if name == 'Shodan InternetDB':
                url = f'https://internetdb.shodan.io/{target}'
                data = _api(url)
                keep(name, data, url, [{'ip': target, 'port': port, 'cpes': data.get('cpes', [])} for port in data.get('ports', [])])
            elif name == 'Shodan hosts':
                data = _api(f'https://api.shodan.io/shodan/host/{target}?' + urllib.parse.urlencode({'key': key, 'minify': 'false'}))
                keep(name, data, f'https://www.shodan.io/host/{target}', data.get('data', []))
            elif name == 'Censys':
                data = _api(f'https://api.platform.censys.io/v3/global/asset/host/{target}', headers={'Authorization': 'Bearer ' + key, 'Accept': 'application/vnd.censys.api.v3.host.v1+json'})
                keep(name, data, f'https://search.censys.io/hosts/{target}', data.get('result', {}).get('resource', {}).get('services', []))
            else:
                import base64
                data = _api('https://api.zoomeye.org/v2/search', headers={'API-KEY': key},
                    payload={'qbase64': base64.b64encode(f'ip="{target}"'.encode()).decode(), 'page': 1, 'pagesize': 30, 'fields': 'ip,port,service,product'})
                if data.get('code') != 60000:
                    raise ValueError('ZoomEye response did not indicate success')
                keep(name, data, 'https://www.zoomeye.org/searchResult?q=' + urllib.parse.quote(target),
                     [item for item in data.get('data', []) if item.get('ip') == target])
        except Exception as exc:
            detail = str(exc).replace(key, '[redacted]') if key else str(exc)
            _status(delta, name, 'empty' if name == 'Shodan InternetDB' and detail == 'HTTP 404' else 'error', detail=detail)
    return delta


def _instagram(username, output, coverage):
    delta = _delta()
    interpreter = TOOLS / 'python.exe'
    if not interpreter.exists():
        _status(delta, 'Instaloader', 'skipped', detail='Run setup-research-tools.bat')
        return delta
    folder = Path(tempfile.mkdtemp(prefix='instagram-', dir=output))
    report = folder / 'instagram.json'
    code, text = _run([interpreter, Path(__file__), '--instagram', username, report,
                       '10' if coverage == 'deep' else '3'], ROOT, 120 if coverage == 'deep' else 45)
    if report.exists():
        data = json.loads(report.read_text(encoding='utf-8'))
        _artifact(delta, report, 'Instaloader')
        if data.get('profile'):
            delta['profiles'].append(data['profile'])
        delta['web'].extend(data.get('posts', []))
        delta['errors'].extend(data.get('errors', []))
    count = len(delta['profiles']) + len(delta['web'])
    detail = '; '.join(delta['errors']) or text[-700:]
    blocked = any(word in detail.lower() for word in ('401 unauthorized', '403 forbidden', '429', 'login required', 'please wait a few minutes'))
    state = 'partial' if count and (code or delta['errors']) else 'timeout' if code == 124 else 'blocked' if blocked else 'error' if code else 'ok' if count else 'empty'
    _status(delta, 'Instaloader', state, count, detail if code else 'Public profile and bounded public posts')
    return delta


def _ghunt(email, output):
    delta = _delta()
    engine = TOOLS / 'ghunt.exe'
    if not engine.exists():
        _status(delta, 'GHunt', 'skipped', detail='Run setup-research-tools.bat')
        return delta
    if not (Path.home() / '.malfrats' / 'ghunt' / 'creds.m').exists():
        _status(delta, 'GHunt', 'skipped', detail='Google session required. Run ghunt-login.bat once, then repeat research.')
        return delta
    folder = Path(tempfile.mkdtemp(prefix='ghunt-', dir=output))
    report = folder / 'ghunt.json'
    code, text = _run([engine, 'email', email, '--json', report], ROOT, 100)
    if report.exists():
        data = json.loads(report.read_text(encoding='utf-8'))
        digest = _artifact(delta, report, 'GHunt')
        for container, row in data.items():
            profile = row.get('profile', {}) if isinstance(row, dict) else {}
            gaia = profile.get('personId')
            # Keep the upstream result as evidence. Names do not establish mailbox ownership.
            delta['findings'].append({'event_type': 'Google public profile',
                'value': json.dumps(profile, ensure_ascii=False)[:16000], 'module': 'GHunt',
                'source': container, 'url': f'https://www.google.com/maps/contrib/{gaia}' if gaia else '',
                'sha256': digest, 'artifact_id': digest, 'status': 'Google service response; identity unverified'})
            for field in ('play_games', 'maps', 'calendar'):
                if isinstance(row, dict) and row.get(field):
                    delta['findings'].append({'event_type': 'Google ' + field.replace('_', ' '),
                        'value': json.dumps(row[field], ensure_ascii=False)[:16000], 'module': 'GHunt',
                        'source': container, 'url': f'https://www.google.com/maps/contrib/{gaia}' if field == 'maps' and gaia else '',
                        'sha256': digest, 'artifact_id': digest, 'status': 'Service response; identity unverified'})
    _status(delta, 'GHunt', 'timeout' if code == 124 else 'ok' if code == 0 else 'error',
            len(delta['findings']), 'Authenticated public Google information' if not code else text[-700:])
    return delta


def _phone(number, output):
    from .phone_recon import collect
    return collect(number, output)


def supplement(query, kind, output, coverage='quick'):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    if kind == 'domain' and HOST.fullmatch(query.lower()):
        return _harvest(query.lower(), output, coverage)
    if kind == 'username' and USER.fullmatch(query.lstrip('@')):
        return _instagram(query.lstrip('@'), output, coverage)
    if kind == 'email' and re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', query):
        return _ghunt(query, output)
    if kind == 'phone' and re.fullmatch(r'\+[0-9]{8,15}', query):
        return _phone(query, output)
    if kind == 'ip':
        return _ip_services(query, output)
    delta = _delta()
    _status(delta, 'Additional engines', 'skipped', detail='No domain, username, email, or phone target')
    return delta


def map_search(query, location, output):
    delta = _delta()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    location = location.strip()
    if not location or len(location) > 160 or len(query) > 200:
        _status(delta, 'Overpass', 'skipped', detail='Set a city or administrative area (maximum 160 characters)')
        return delta
    expression = re.escape(query.strip())
    search = ('[out:json][timeout:25];area["name"=' + json.dumps(location, ensure_ascii=False) +
              ']["boundary"="administrative"]->.a;nwr(area.a)["name"~' +
              json.dumps(expression, ensure_ascii=False) + ',i];out center tags 50;')
    error = ''
    for endpoint in ('https://maps.mail.ru/osm/tools/overpass/api/interpreter',
                     'https://overpass-api.de/api/interpreter', 'https://overpass.private.coffee/api/interpreter'):
        try:
            request = urllib.request.Request(endpoint, data=urllib.parse.urlencode({'data': search}).encode(),
                headers={'User-Agent': 'FindAll/1.0 public research', 'Content-Type': 'application/x-www-form-urlencoded'})
            with urllib.request.urlopen(request, timeout=40) as response:
                raw = response.read(6000001)
            if len(raw) > 6000000:
                raise ValueError('Overpass response exceeds 6 MB')
            data = json.loads(raw)
            elements = data.get('elements')
            if not isinstance(elements, list):
                raise ValueError('Overpass did not return an elements array')
            elements = [row for row in elements if isinstance(row, dict)
                and row.get('type') in ('node', 'way', 'relation') and type(row.get('id')) is int
                and isinstance(row.get('tags', {}), dict)]
            folder = Path(tempfile.mkdtemp(prefix='overpass-', dir=output))
            report = folder / 'overpass.json'
            report.write_bytes(raw)
            _artifact(delta, report, 'OpenStreetMap Overpass')
            for row in elements[:50]:
                tags = {str(key): str(value) for key, value in row.get('tags', {}).items()}
                url = f'https://www.openstreetmap.org/{row["type"]}/{row["id"]}'
                item = {'name': tags.get('name', query), 'url': url, 'source': 'OpenStreetMap',
                    'address': ', '.join(tags[key] for key in ('addr:city', 'addr:street', 'addr:housenumber') if tags.get(key)),
                    'phones': [tags[key] for key in ('phone', 'contact:phone') if tags.get(key)],
                    'websites': [tags[key] for key in ('website', 'contact:website') if tags.get(key)],
                    'emails': [email.strip() for key in ('email', 'contact:email')
                        for email in re.split(r'[;,]', str(tags.get(key, '')))
                        if re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email.strip())],
                    'location': row.get('center', {k: row[k] for k in ('lat', 'lon') if k in row}), 'tags': tags}
                delta['businesses'].append(item)
                delta['web'].append({'title': item['name'], 'snippet': item['address'], 'url': url, 'source': 'OpenStreetMap'})
                delta['emails'].extend({'email': address, 'url': url, 'source': 'OpenStreetMap',
                    'attribution': 'Published object contact; verify currency'} for address in item['emails'])
            _status(delta, 'Overpass', 'ok' if delta['businesses'] else 'empty', len(delta['businesses']),
                    'Name matches inside the selected administrative area')
            return delta
        except Exception as exc:
            error = f'{type(exc).__name__}: {exc}'
    state = 'timeout' if 'Timeout' in error or 'timed out' in error.lower() else 'blocked' if re.search(r'HTTP Error (?:401|403|406|429)',error) else 'error'
    _status(delta, 'Overpass', state, detail=error)
    return delta


def local_metadata(paths, output):
    from defusedxml import ElementTree
    delta = _delta()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for value in list(paths)[:10]:
        path = Path(value).expanduser().resolve()
        try:
            if not path.is_file() or path.stat().st_size > 50_000_000:
                raise ValueError('Select an existing file up to 50 MB')
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            metadata = {'name': path.name, 'bytes': len(raw), 'extension': path.suffix.lower()}
            if path.suffix.lower() in ('.jpg', '.jpeg', '.tif', '.tiff', '.heic', '.png', '.webp'):
                import exifread
                with path.open('rb') as stream:
                    tags = exifread.process_file(stream, details=False)
                metadata['exif'] = {key: str(value)[:4000] for key, value in tags.items() if key != 'JPEGThumbnail'}
            elif path.suffix.lower() == '.pdf':
                from PyPDF2 import PdfReader
                reader = PdfReader(path)
                metadata['document'] = {str(key): str(value)[:4000] for key, value in (reader.metadata or {}).items()}
                metadata['pages'] = len(reader.pages)
            elif path.suffix.lower() in ('.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'):
                with zipfile.ZipFile(path) as archive:
                    name = 'docProps/core.xml' if 'docProps/core.xml' in archive.namelist() else 'meta.xml'
                    if name in archive.namelist():
                        if archive.getinfo(name).file_size > 1_000_000:
                            raise ValueError('Document metadata exceeds 1 MB')
                        xml = archive.read(name)
                        if b'<!DOCTYPE' in xml or b'<!ENTITY' in xml:
                            raise ValueError('XML entities are not supported')
                        metadata['document'] = {node.tag.split('}')[-1]: node.text for node in ElementTree.fromstring(xml).iter() if node.text and node.text.strip()}
            report = output / f'metadata-{digest[:16]}.json'
            report.write_text(json.dumps({'sha256': digest, 'metadata': metadata}, ensure_ascii=False, indent=2), encoding='utf-8')
            delta['artifacts'].append({'path': str(report), 'name': path.name, 'kind': 'local_metadata',
                'sha256': digest, 'artifact_id': digest, 'metadata': metadata, 'source': 'User-selected file'})
            delta['findings'].append({'event_type': 'File metadata', 'value': json.dumps(metadata, ensure_ascii=False),
                'module': 'EXIF/document metadata', 'source': 'User-selected file', 'url': '', 'sha256': digest,
                'artifact_id': digest, 'metadata': metadata, 'status': 'File metadata; authorship and dates unverified'})
            _status(delta, 'Local metadata / ' + path.name, 'ok', 1, 'SHA-256 and embedded file metadata')
        except Exception as exc:
            _status(delta, 'Local metadata / ' + path.name, 'error', detail=f'{type(exc).__name__}: {exc}')
    return delta


def _instagram_worker(username, report, limit):
    import instaloader
    result = {'profile': None, 'posts': [], 'errors': []}
    try:
        loader = instaloader.Instaloader(quiet=True, request_timeout=15, max_connection_attempts=1)
        profile = instaloader.Profile.from_username(loader.context, username)
        result['profile'] = {'site': 'Instagram', 'username': profile.username, 'bio': profile.biography,
            'name': profile.full_name, 'url': f'https://www.instagram.com/{profile.username}/',
            'website': profile.external_url, 'followers': profile.followers, 'source': 'Instaloader',
            'status': 'Public profile; account ownership unverified'}
        report.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
        if not profile.is_private:
            for index, post in enumerate(profile.get_posts()):
                if index >= limit:
                    break
                result['posts'].append({'title': f'{profile.username} / {post.shortcode}',
                    'url': f'https://www.instagram.com/p/{post.shortcode}/', 'snippet': (post.caption or '')[:16000],
                    'published_at': post.date_utc.isoformat(), 'source': 'Instaloader'})
                report.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
    except Exception as exc:
        detail = re.sub(r'https?://[^\s\"<>]+', '[source endpoint]', str(exc))
        result['errors'].append(f'Instaloader: {type(exc).__name__}: {detail}')
    report.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
    return 1 if result['errors'] else 0


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--instagram' and USER.fullmatch(sys.argv[2]):
        raise SystemExit(_instagram_worker(sys.argv[2], Path(sys.argv[3]), min(10, int(sys.argv[4]))))
    raise SystemExit('Use FindAll dossier to run these adapters.')
