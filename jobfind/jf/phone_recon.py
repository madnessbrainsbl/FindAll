"""PhoneInfoga scanners in the common evidence pipeline, without a web server."""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import dotenv_values

from . import additional_tools as tools

ENGINE = tools.ROOT / 'third_party' / 'phoneinfoga' / 'findall-phoneinfoga.exe'
KEYS = ('NUMVERIFY_API_KEY', 'GOOGLE_API_KEY', 'GOOGLECSE_CX')
SCANNERS = ('local', 'googlesearch', 'numverify', 'ovh', 'googlecse')
FIELDS = {
    'local': ('raw_local', 'local', 'e164', 'international', 'country_code', 'country', 'carrier'),
    'numverify': ('valid', 'number', 'local_format', 'international_format', 'country_prefix',
                  'country_code', 'country_name', 'location', 'carrier', 'line_type'),
    'ovh': ('found', 'number_range', 'city', 'zip_code'),
}


def _url(value):
    value = str(value or '')[:6000]
    try:
        parts = urlsplit(value)
        return value if parts.scheme in ('http', 'https') and parts.hostname and not parts.username and not parts.password else ''
    except ValueError:
        return ''


def collect(number, output, *, local_only=False):
    if not re.fullmatch(r'\+[1-9][0-9]{7,14}', number):
        raise ValueError('PhoneInfoga requires an international number, for example +12025550123')
    delta = tools._delta()
    if not ENGINE.is_file():
        tools._status(delta, 'PhoneInfoga', 'skipped', detail='Run setup-phoneinfoga.bat')
        return delta
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='phoneinfoga-', dir=output))
    saved = dotenv_values(tools.ROOT / 'osint-keys.env')
    keys = {name: os.environ.get(name, saved.get(name) or '').strip() for name in KEYS}
    observed = datetime.now(timezone.utc).isoformat()

    def clean(value):
        if isinstance(value, str):
            for key in keys.values():
                if key:
                    value = value.replace(key, '[redacted]')
            return value[:6000]
        if isinstance(value, list):
            return [clean(item) for item in value[:100]]
        if isinstance(value, dict):
            return {str(k): clean(v) for k, v in list(value.items())[:100]}
        return value

    for scanner in SCANNERS:
        source = 'PhoneInfoga / ' + scanner
        required = ('NUMVERIFY_API_KEY',) if scanner == 'numverify' else ('GOOGLE_API_KEY', 'GOOGLECSE_CX') if scanner == 'googlecse' else ()
        missing = [key for key in required if not keys[key]]
        if missing or local_only and scanner not in ('local', 'googlesearch'):
            tools._status(delta, source, 'skipped', detail='Local-only run' if local_only else 'Set ' + ', '.join(missing) + ' in osint-keys.env')
            continue
        code, raw = tools._run([ENGINE, scanner, number], folder, 25, environment=keys)
        try:
            response = json.loads(raw) if not code else {}
            if not isinstance(response, dict) or response.get('state') not in ('ok', 'empty', 'skipped', 'blocked', 'timeout', 'error'):
                response = {'state': 'error', 'detail': 'Invalid structured scanner response'}
        except (ValueError, TypeError):
            response = {'state': 'error', 'detail': 'Invalid structured scanner response'}
        if code:
            response = {'state': 'timeout' if code == 124 else 'error', 'detail': 'Scanner exceeded process deadline' if code == 124 else 'Scanner process failed'}
        response = clean(response)
        state = response['state']
        detail = response.get('detail', '')
        data = response.get('data')
        count = 0
        if state == 'ok' and not isinstance(data, dict):
            state, detail = 'error', 'Scanner data is not an object'
        report = folder / (scanner + '.json')
        report.write_text(json.dumps({'engine': 'PhoneInfoga v2.11.0', 'scanner': scanner,
            'observed_at': observed, **response}, ensure_ascii=False, indent=2), encoding='utf-8')
        digest = tools._artifact(delta, report, source)

        def finding(kind, value, url='', certainty='candidate', status=''):
            nonlocal count
            delta['findings'].append(dict(event_type=kind, title=kind, value=value,
                module='PhoneInfoga', source=source, url=url, sha256=digest, artifact_id=digest,
                observed_at=observed, certainty=certainty, status=status, attribution=status))
            count += 1

        if state == 'ok':
            if scanner in FIELDS:
                facts = {field: data[field] for field in FIELDS[scanner] if field in data}
                if not facts:
                    state, detail = 'error', 'Missing number-plan fields'
                elif scanner == 'ovh' and not data.get('found'):
                    state, detail = 'empty', 'No matching OVH number range'
                else:
                    finding('Phone numbering plan' if scanner == 'local' else 'Phone provider metadata',
                        json.dumps(facts, ensure_ascii=False), certainty='observed' if scanner == 'local' else 'candidate',
                        status='Number plan/provider response; no subscriber identity or current physical location')
                    detail = 'Number plan/provider metadata retained; no subscriber identity'
            elif scanner == 'googlesearch':
                for category, items in data.items():
                    for item in items[:80] if isinstance(items, list) else []:
                        if isinstance(item, dict) and (url := _url(item.get('url'))):
                            finding('Phone search query · ' + category.replace('_', ' '), str(item.get('dork', '')),
                                url, certainty='interpretation', status='Generated query; search not executed; no match established')
                detail = 'Generated search queries only; not executed'
            else:
                seen = set()
                items = data.get('items') or []
                if not isinstance(items, list):
                    state, detail = 'error', 'Search items are not an array'
                    items = []
                for item in items[:100]:
                    if isinstance(item, dict) and (url := _url(item.get('url'))) and url not in seen:
                        seen.add(url)
                        delta['web'].append(dict(title=str(item.get('title') or url), url=url,
                            source=source, snippet='Google CSE indexed result for phone-number queries',
                            sha256=digest, artifact_id=digest, observed_at=observed, certainty='candidate',
                            status='Indexed search candidate; number association and identity unverified',
                            attribution='Indexed search candidate; number association and identity unverified'))
                        count += 1
                detail = 'Indexed search candidates; association and identity unverified'
            if not count and state == 'ok':
                state = 'empty'
        tools._status(delta, source, state, count, detail)
        if scanner == 'local' and state != 'ok':
            break
    states = [row['status'] for row in delta['statuses']]
    successes = any(state == 'ok' for state in states)
    failures = [state for state in states if state in ('error', 'timeout', 'blocked')]
    overall = 'partial' if successes and failures else failures[0] if failures else 'ok' if successes else 'empty'
    tools._status(delta, 'PhoneInfoga', overall, len(delta['findings']) + len(delta['web']),
                  'Structured upstream scanners; per-scanner coverage recorded')
    return delta


def investigate(number, output, *, local_only=False):
    """A focused run saves the same dossier consumed by native UI, graph and AI."""
    import csv
    from . import dossier
    delta = collect(number, Path(output) / 'phoneinfoga', local_only=local_only)
    folder = dossier._folder(Path(output) / 'dossiers', number)
    result = dict(query=number, kind='phone', scope='full', coverage='quick',
        observed_at=datetime.now(timezone.utc).isoformat(), sections=dict(web=[], profiles=[], emails=[], domain=None),
        source_checks=[], artifacts=[], errors=[], settings=dict(phone_local_only=local_only),
        report_json=str(folder / 'dossier.json'), report_csv=str(folder / 'dossier.csv'))
    dossier.merge_delta(result, delta)
    with (folder / 'dossier.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=dossier.CSV_FIELDS)
        writer.writeheader()
        writer.writerows(dossier._report_rows(result))
    return dossier.save_relationship_graph(result)
