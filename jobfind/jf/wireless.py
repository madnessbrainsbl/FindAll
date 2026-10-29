"""WireTapper telemetry and radio observations integrated with FindAll evidence.

Upstream helpers retain h9zdev's non-commercial license. No upstream Flask app,
credential retrieval, synthetic RF points or network connection code is executed.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import csv
import hashlib
import importlib.util
import io
import ipaddress
import json
import math
import os
import re
import sqlite3
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from defusedxml import ElementTree as ET
from . import net

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / 'third_party' / 'wiretapper'
KEY_NAMES = ('WIGLE_API_NAME', 'WIGLE_API_TOKEN', 'OPENCELLID_API_KEY', 'SHODAN_API_KEY', 'CENSYS_API_TOKEN')
PROVIDERS = ('wigle', 'opencellid', 'shodan', 'censys')
MAX_BYTES, MAX_ROWS = 20_000_000, 1500
LICENSE = 'WireTapper © 2026 h9zdev — non-commercial; see LICENSE-NONCOMMERCIAL.md'
_MODULES = {}


def _module(name):
    if name not in _MODULES:
        spec = importlib.util.spec_from_file_location('findall_wiretapper_' + name, UPSTREAM / (name + '.py'))
        if not spec or not spec.loader:
            raise RuntimeError('WireTapper source is unavailable')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULES[name] = module
    return _MODULES[name]


def keys():
    stored = {}
    path = ROOT / 'osint-keys.env'
    if path.is_file():
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            k, sep, value = line.partition('=')
            if sep and k.strip() in KEY_NAMES:
                stored[k.strip()] = value.strip().strip('"\'')
    return {k: os.environ.get(k, stored.get(k, '')).strip() for k in KEY_NAMES}


def _number(value, low, high):
    try:
        n = float(value)
        return n if math.isfinite(n) and low <= n <= high else None
    except (TypeError, ValueError, OverflowError):
        return None


def _text(value, limit=240):
    return str(value).strip()[:limit] if value is not None else ''


def _point(lat, lon):
    return _number(lat, -90, 90), _number(lon, -180, 180)


def _read_records(path):
    """Bounded, read-only loaders. Never import arbitrary Python or SQLite views."""
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError('Select a telemetry file of at most 20 MB')
    ext = path.suffix.lower()
    if ext in ('.json', '.geojson'):
        data = json.loads(path.read_text(encoding='utf-8-sig'))
        if isinstance(data, dict) and data.get('type') == 'FeatureCollection':
            records = []
            features = data.get('features')
            if not isinstance(features, list):
                raise ValueError('GeoJSON features must be an array')
            for feat in features[:MAX_ROWS + 1]:
                if not isinstance(feat, dict):
                    records.append({'lat':'invalid', 'lon':'invalid'})
                    continue
                geom, props = feat.get('geometry') or {}, feat.get('properties') or {}
                coords = geom.get('coordinates', []) if isinstance(geom, dict) else []
                if not isinstance(geom, dict) or geom.get('type') != 'Point' or not isinstance(coords,(list,tuple)) or len(coords) < 2 or not isinstance(props, dict):
                    records.append({'lat':'invalid', 'lon':'invalid'})
                    continue
                records.append({**props, 'longitude': coords[0], 'latitude': coords[1]})
        elif isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = next((data[k] for k in ('records', 'results', 'data', 'devices', 'networks', 'items', 'rows', 'cells')
                            if isinstance(data.get(k), list)), [data])
        else:
            raise ValueError('JSON must contain records or a GeoJSON FeatureCollection')
    elif ext in ('.csv', '.tsv'):
        with path.open(encoding='utf-8-sig', newline='') as f:
            first = f.readline()
            if not first.startswith(('WigleWifi', '#')):
                f.seek(0)
            pos = f.tell()
            sample = f.read(8192)
            f.seek(pos)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=',;\t')
            except csv.Error:
                dialect = csv.excel_tab if ext == '.tsv' else csv.excel
            reader = csv.DictReader(f, dialect=dialect)
            if not reader.fieldnames or len(reader.fieldnames) > 100:
                raise ValueError('CSV requires at most 100 named columns')
            records = []
            for row in reader:
                records.append(row)
                if len(records) > MAX_ROWS:
                    break
    elif ext == '.kml':
        tree = ET.parse(path)
        records = []
        for pm in tree.iter():
            if pm.tag.rsplit('}', 1)[-1] != 'Placemark':
                continue
            point = next((x for x in pm.iter() if x.tag.rsplit('}', 1)[-1] == 'Point'), None)
            if point is None:
                continue
            coord = next((x.text for x in point.iter() if x.tag.rsplit('}', 1)[-1] == 'coordinates'), '') or ''
            parts = coord.strip().split(',')
            if len(parts) < 2:
                continue
            row = {'longitude': parts[0], 'latitude': parts[1]}
            for x in pm.iter():
                tag = x.tag.rsplit('}', 1)[-1]
                if tag == 'name':
                    row['name'] = x.text
                if tag == 'Data':
                    row[_text(x.attrib.get('name'))] = next((v.text for v in x if v.tag.rsplit('}', 1)[-1] == 'value'), '')
            records.append(row)
            if len(records) > MAX_ROWS:
                break
    elif ext in ('.db', '.sqlite', '.sqlite3'):
        uri = path.resolve().as_uri() + '?mode=ro&immutable=1'
        with sqlite3.connect(uri, uri=True, timeout=3) as conn:
            conn.row_factory = sqlite3.Row
            ticks = [0]
            def budget():
                ticks[0] += 1
                return int(ticks[0] > 2000)
            conn.set_progress_handler(budget, 1000)
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 100")]
            if not tables:
                return [], False
            def quoted(value):
                return '"' + value.replace('"', '""') + '"'
            scored = []
            for table in tables:
                cols = [r[1].lower() for r in conn.execute('PRAGMA table_info(' + quoted(table) + ')')]
                score = sum(k in cols for k in ('lat', 'latitude', 'trilat', 'lon', 'longitude', 'trilong', 'ssid', 'bssid'))
                scored.append((score, table))
            table = max(scored)[1]
            records = [dict(r) for r in conn.execute('SELECT * FROM ' + quoted(table) + ' LIMIT ?', (MAX_ROWS + 1,))]
    elif ext == '.xlsx':
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > 2000 or sum(i.file_size for i in archive.infolist()) > 64_000_000:
                raise ValueError('Expanded spreadsheet exceeds import budget')
        import openpyxl
        book = openpyxl.load_workbook(path, read_only=True, data_only=True, keep_links=False)
        try:
            rows = book.active.iter_rows(values_only=True)
            columns = next(rows, ())
            if len(columns) > 100:
                raise ValueError('Spreadsheet exceeds 100 columns')
            records = []
            for row in rows:
                records.append(dict(zip((_text(c) for c in columns), row)))
                if len(records) > MAX_ROWS:
                    break
        finally:
            book.close()
    else:
        raise ValueError('Supported telemetry: CSV, TSV, JSON, GeoJSON, KML, SQLite and XLSX')
    if not all(isinstance(row, dict) for row in records[:MAX_ROWS + 1]):
        raise ValueError('Telemetry rows must be objects')
    return records[:MAX_ROWS], len(records) > MAX_ROWS


def import_file(path, mappings=None):
    path = Path(path).resolve()
    records, limited = _read_records(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    engine, bridge = _module('telemetry_importer'), _module('findall_bridge')
    columns = list(dict.fromkeys(k for row in records[:50] for k in row if isinstance(k, str)))
    detected = engine.detect_column_matches(columns)
    # Reject fuzzy matches: e.g. "address" must not become a geographic axis.
    clean = lambda s: re.sub('[^a-z0-9]', '', s.lower())
    detected = {k: v for k, v in detected.items() if clean(v) in {clean(x) for x in engine.HEURISTICS[k]}}
    aliases = {'lat': ('lat', 'latitude', 'trilat'), 'lon': ('lon', 'longitude', 'trilong', 'lng'),
               'ssid': ('ssid', 'name'), 'bssid': ('bssid', 'mac', 'netid', 'device_id'),
               'signal': ('rssi', 'rssi_dbm', 'signal', 'level'), 'type': ('type', 'radio', 'protocol'), 'timestamp': ('timestamp', 'observed_at', 'lastupdt')}
    for field, names in aliases.items():
        exact = next((col for name in names for col in columns if col.casefold() == name), None)
        if exact:
            detected[field] = exact
    if mappings:
        if any(k not in engine.HEURISTICS or v not in columns for k, v in mappings.items()):
            raise ValueError('Column mapping must reference existing telemetry columns')
        detected.update(mappings)
    normalized, rejected = [], 0
    for i, row in enumerate(records):
        lat, lon = _point(row.get(detected.get('lat')), row.get(detected.get('lon')))
        camera = None
        if any(k in row for k in ('brand', 'operator', 'mountType', 'surveillanceZone', 'maps_url', 'coordinates', 'coords')):
            camera = bridge.normalize_camera_record(row, i, path.name)
            if camera and (lat is None or lon is None):
                lat, lon = _point(camera['lat'], camera['lon'])
        # Upstream process_file handles the actual mapped schema. Preserve missing
        # fields rather than its generated MAC/RSSI/time defaults.
        mapped = dict(row)
        location = lat is not None and lon is not None
        if (row.get(detected.get('lat')) not in (None, '') or row.get(detected.get('lon')) not in (None, '')) and not location:
            rejected += 1
            continue
        device = {}
        if location:
            row_mapping = dict(detected)
            if camera:
                mapped.update(_wiretapper_lat=lat, _wiretapper_lon=lon)
                row_mapping.update(lat='_wiretapper_lat', lon='_wiretapper_lon')
            response = engine.process_file(str(path), row_mapping, records=[mapped])
            if response.get('status') != 'success':
                rejected += 1
                continue
            device = response['devices'][0]
        name = _text(row.get(detected.get('ssid')) or row.get('label') or row.get('cellid'))
        mac = _text(row.get(detected.get('bssid')))
        if not name and not mac and not location:
            rejected += 1
            continue
        signal = _number(row.get(detected.get('signal')), -150, -1)
        protocol = _text(row.get(detected.get('type')) or 'unknown')
        item = {'name': name or 'Unnamed observation', 'device_id': mac, 'latitude': lat, 'longitude': lon,
                'rssi_dbm': signal, 'protocol': protocol,
                'category_candidate': bridge.classify_device(name, protocol),
                'observed_at': _text(row.get(detected.get('timestamp')), 100),
                'source': 'WireTapper / imported telemetry', 'source_url': '',
                'source_sha256': digest, 'source_row': i + 1,
                'certainty': 'candidate', 'location_basis': 'Imported coordinates; measurement basis unverified' if location else 'No coordinates supplied',
                'attribution': 'Imported observation; device class, location and target ownership unverified'}
        percent = _number(row.get('signal_percent'), 0, 100)
        if percent is not None:
            item['signal_percent'] = percent
        if camera:
            item['category_candidate'] = 'camera'
            # Preserve only fields actually supplied, not upstream default brand/agency.
            for key, choices in {'camera_brand':('brand','make'), 'operator':('operator','agency','department'),
                                 'direction':('direction','directions'), 'mount_type':('mountType','mount_type')}.items():
                item[key] = next((_text(row[k]) for k in choices if row.get(k) is not None), '')
        address = _text(row.get('ip') or row.get('ip_str'), 60)
        try:
            if address and ipaddress.ip_address(address).is_global:
                item['ip'] = address
        except ValueError:
            pass
        normalized.append(item)
    return normalized, {'sha256': digest, 'name': path.name, 'kind': 'selected_telemetry_source',
                        'path': str(path), 'artifact_id': digest}, detected, limited, rejected


def _api(url, params, headers=None):
    result = net.get(url, params=params, extra_headers=headers or {})
    if result.error or result.status != 200:
        state = 'blocked' if result.status in (401, 402, 403, 429) else 'timeout' if result.metadata.get('state') == 'timeout' else 'error'
        return None, state, f'HTTP {result.status}' if result.status else 'Network request failed or timed out'
    try:
        data = json.loads(result.body)
    except (ValueError, UnicodeError):
        return None, 'error', 'Source returned malformed JSON'
    if not isinstance(data, dict):
        return None, 'error', 'Source returned an unexpected JSON schema'
    if data.get('success') is False or data.get('error') or data.get('stat') == 'fail':
        return None, 'blocked' if data.get('success') is False else 'error', 'Source rejected the request'
    return data, 'ok', ''


def _area(provider, lat, lon, radius, configured):
    dlat = radius / 111.32
    dlon = min(180, dlat / max(.01, math.cos(math.radians(lat))))
    bounds = [max(-90, lat-dlat), max(-180, lon-dlon), min(90, lat+dlat), min(180, lon+dlon)]
    needed = {'wigle': ('WIGLE_API_NAME', 'WIGLE_API_TOKEN'), 'opencellid': ('OPENCELLID_API_KEY',), 'shodan': ('SHODAN_API_KEY',)}[provider]
    if any(not configured[k] for k in needed):
        return [], 'skipped', 'Missing ' + ' / '.join(needed)
    if provider == 'wigle':
        auth = base64.b64encode((configured['WIGLE_API_NAME'] + ':' + configured['WIGLE_API_TOKEN']).encode()).decode()
        url = 'https://api.wigle.net/api/v2/network/search'
        data, state, detail = _api(url, dict(latrange1=bounds[0], longrange1=bounds[1], latrange2=bounds[2], longrange2=bounds[3], resultsPerPage=100), {'Authorization': 'Basic ' + auth})
        raw = data.get('results') if data else []
    elif provider == 'opencellid':
        url = 'https://opencellid.org/cell/getInArea'
        data, state, detail = _api(url, dict(key=configured['OPENCELLID_API_KEY'], BBOX=','.join(map(str,bounds)), format='json', limit=50))
        raw = data.get('cells') if data else []
    else:
        url = 'https://api.shodan.io/shodan/host/search'
        data, state, detail = _api(url, dict(key=configured['SHODAN_API_KEY'], query=f'geo:{lat},{lon},{radius}', minify='true', page=1))
        raw = data.get('matches') if data else []
    if state != 'ok':
        return [], state, detail
    if not isinstance(raw, list) or any(not isinstance(x, dict) for x in raw[:100]):
        return [], 'error', 'Source returned malformed observation records'
    rows, rejected = [], 0
    for obj in raw[:100]:
        if provider == 'shodan':
            loc = obj.get('location') or {}
            x, y = _point(loc.get('latitude'), loc.get('longitude'))
            name, ident = _text(obj.get('product') or obj.get('org') or obj.get('ip_str')), _text(obj.get('ip_str'))
            category, ts = 'indexed_service', _text(obj.get('timestamp'))
            source = 'https://www.shodan.io/host/' + ident
        elif provider == 'opencellid':
            x, y = _point(obj.get('lat'), obj.get('lon'))
            ident = ':'.join(_text(obj.get(k)) for k in ('mcc','mnc','lac','cellid'))
            name, category, ts = 'Cell ' + ident, 'cell_record', _text(obj.get('updated'))
            source = 'https://opencellid.org/'
        else:
            x, y = _point(obj.get('trilat'), obj.get('trilong'))
            name, ident, category, ts = _text(obj.get('ssid')), _text(obj.get('netid')), 'wifi', _text(obj.get('lastupdt'))
            source = 'https://wigle.net/'
        if x is None or y is None:
            rejected += 1
            continue
        row = {'name':name or 'Unnamed indexed observation', 'device_id':ident, 'latitude':x, 'longitude':y,
               'rssi_dbm':None, 'protocol':_text(obj.get('radio') or obj.get('type') or obj.get('transport')),
               'category_candidate':category, 'observed_at':ts, 'source':'WireTapper / ' + provider,
               'source_url':source, 'certainty':'candidate', 'location_basis':'External database estimate; not an on-site measurement',
               'attribution':'Indexed observation; device identity, physical site and ownership unverified'}
        if provider == 'opencellid':
            row['data_license'] = 'OpenCelliD CC BY-SA 4.0 https://creativecommons.org/licenses/by-sa/4.0/'
        if provider == 'shodan':
            row.update(ip=ident, port=obj.get('port'))
        rows.append(row)
    limited = bool((provider == 'shodan' and data.get('total', 0) > len(raw)) or
                   (provider == 'wigle' and data.get('searchAfter')) or
                   (provider == 'opencellid' and len(raw) >= 50) or len(raw) > 100)
    return rows, 'partial' if rejected or limited else 'ok' if rows else 'empty', f'Indexed observations; {rejected} invalid locations omitted' + ('; first page only' if limited else '')


def parse_netsh(text):
    """Only BSSID/SSID and signal metadata; never retrieve Wi-Fi profiles/keys."""
    rows, ssid, current = [], '', None
    for line in text.splitlines():
        match = re.match(r'\s*SSID\s+\d+\s*:\s*(.*)', line)
        if match:
            ssid = match.group(1).strip()
        match = re.match(r'\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})', line)
        if match:
            current = {'name':ssid, 'device_id':match.group(1), 'category_candidate':'wifi', 'protocol':'Wi-Fi'}
            rows.append(current)
        match = re.search(r':\s*(\d{1,3})%\s*$', line)
        if current is not None and match:
            current['signal_percent'] = min(100, int(match.group(1)))
    return rows


def _wifi():
    if os.name != 'nt':
        return [], 'skipped', 'Windows Wi-Fi enumeration is unavailable on this OS; import telemetry instead'
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], capture_output=True,
             timeout=20, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        import ctypes
        encoding = 'cp' + str(ctypes.windll.kernel32.GetOEMCP())
        text = result.stdout.decode(encoding, errors='replace')
        if result.returncode:
            diagnostic_text = text + (result.stderr or b'').decode(encoding, errors='replace')
            if b'ms-settings:privacy-location' in result.stdout + (result.stderr or b'') or \
                    re.search(r'location permission|location services|определения местоположения', diagnostic_text, re.I):
                return [], 'blocked', 'Windows location permission required for Wi-Fi discovery; enable Location in Privacy & security settings'
            return [], 'blocked', 'Windows WLAN discovery unavailable; check adapter and location access'
        rows = parse_netsh(text)
        if not rows and not re.search(r'(?:number of networks(?: visible)?|количество сетей|число сетей)\s*:\s*0\b',text,re.I):
            return [], 'blocked', 'Windows WLAN returned no readable BSSID data; check adapter and location access'
        return rows, 'ok' if rows else 'empty', 'Windows WLAN discovery; signal percentage is not measured RSSI'
    except subprocess.TimeoutExpired:
        return [], 'timeout', 'Windows WLAN discovery timed out'
    except OSError:
        return [], 'error', 'Windows WLAN command is unavailable'


async def _ble_scan(seconds):
    from bleak import BleakScanner
    devices = await asyncio.wait_for(BleakScanner.discover(timeout=seconds, return_adv=True), seconds+10)
    bridge = _module('findall_bridge')
    rows = []
    for dev, advertisement in list(devices.values())[:300]:
        rssi = _number(advertisement.rssi,-150,-1)
        distance = bridge._bt_estimate_distance(rssi, advertisement.tx_power) if rssi is not None else None
        rows.append({'name':dev.name or advertisement.local_name or 'Unnamed BLE advertisement', 'device_id':dev.address,
            'rssi_dbm':rssi, 'estimated_distance_m':round(distance,2) if distance is not None and math.isfinite(distance) else None,
            'protocol':'BLE', 'category_candidate':bridge.classify_device(dev.name or '', 'bluetooth'),
            'distance_basis':'RSSI path-loss model; approximate, not measured location'})
    return rows


def _ble(seconds):
    try:
        rows = asyncio.run(_ble_scan(seconds))
        return rows, 'ok' if rows else 'empty', 'BLE advertisements; addresses may rotate and do not establish identity'
    except ImportError:
        return [], 'skipped', 'Install optional bleak dependency with setup-wireless.bat'
    except (TimeoutError, asyncio.TimeoutError):
        return [], 'timeout', 'BLE discovery timed out'
    except Exception:
        return [], 'blocked', 'Bluetooth adapter, permission or system service unavailable'


def _sdr():
    if os.name != 'nt':
        messages=io.StringIO()
        with contextlib.redirect_stdout(messages):
            hardware = _module('findall_bridge').check_usb_sdr_status()
        if messages.getvalue():
            return [],'blocked','USB device enumeration unavailable'
        return ([{'name':hardware['device'],'device_id':'','protocol':'USB','category_candidate':'sdr_hardware'}]
                if hardware.get('connected') else []), 'ok' if hardware.get('connected') else 'empty', 'USB presence only; no RF samples decoded'
    script = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $ErrorActionPreference='Stop'; $items=@(Get-PnpDevice -PresentOnly | Where-Object { $_.FriendlyName -match 'RTL.?SDR|HackRF|Airspy|Software Defined Radio' -or $_.InstanceId -match 'VID_0BDA&PID_283[28]|VID_1D50&PID_(6089|604B|60A1)' } | Select-Object -First 20 -ExpandProperty FriendlyName); ConvertTo-Json -InputObject $items -Compress"
    try:
        process = subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',script],capture_output=True,
            timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if process.returncode:
            return [],'blocked','USB device enumeration unavailable'
        names=json.loads(process.stdout.decode('utf-8-sig',errors='replace'))
        if not isinstance(names,list):
            return [],'error','USB enumeration response could not be parsed'
        rows=[dict(name=_text(name),device_id='',protocol='USB',category_candidate='sdr_hardware') for name in names if name]
        return rows,'ok' if rows else 'empty','USB presence only; no RF samples decoded'
    except subprocess.TimeoutExpired:
        return [],'timeout','USB enumeration timed out'
    except (OSError,ValueError):
        return [],'error','USB enumeration unavailable'


def _artifact(path, source, kind):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(path=str(path), name=path.name, source=source, kind=kind, sha256=digest, artifact_id=digest)


def export(result, folder):
    """Offline coordinate plot and interoperable evidence formats."""
    rows = result['records']
    jsonpath, csvpath, geop = folder/'wireless.json', folder/'wireless.csv', folder/'wireless.geojson'
    features = [{'type':'Feature', 'geometry':{'type':'Point','coordinates':[r['longitude'],r['latitude']]},
                 'properties':{k:v for k,v in r.items() if k not in ('latitude','longitude')}}
                for r in rows if r.get('latitude') is not None and r.get('longitude') is not None]
    geop.write_text(json.dumps({'type':'FeatureCollection','features':features},ensure_ascii=False,indent=2),encoding='utf-8')
    columns = ['name','device_id','protocol','category_candidate','latitude','longitude','rssi_dbm','signal_percent',
               'observed_at','collected_at','source','source_url','source_sha256','source_row','certainty','location_basis','attribution']
    with csvpath.open('w',encoding='utf-8-sig',newline='') as f:
        writer = csv.DictWriter(f,fieldnames=columns,extrasaction='ignore')
        writer.writeheader()
        for r in rows:
            writer.writerow({k: "'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for k,v in r.items()})
    mapfile = folder/'wireless-map.html'
    payload = json.dumps(rows,ensure_ascii=False).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    document = '''<!doctype html><meta charset="utf-8"><title>FindAll · Wireless observations</title>
<style>body{font:15px system-ui;background:#101722;color:#e7edf4;margin:28px}h1{font-size:24px}svg{width:100%;height:500px;background:#1c293a;border:1px solid #4c6077}circle{fill:#68dfcc;cursor:pointer}circle:hover{fill:#ffd379}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #384353}#details{white-space:pre-wrap;padding:16px;background:#1c293a}input{padding:9px;width:300px}p{color:#b7c5d6}</style>
<h1>Wireless observations</h1><p>Offline WGS84 coordinate plot. No basemap or inferred device positions. Indexed coordinates and imported locations are estimates; ownership is unverified.</p>
<input id="filter" placeholder="Filter name, identifier or source"><p id="count"></p><svg viewBox="0 0 1000 500" id="map"></svg><pre id="details">Select a point or row.</pre>
<table><thead><tr><th>Name</th><th>Protocol / class candidate</th><th>Coordinates</th><th>Signal</th><th>Source / observation time</th></tr></thead><tbody id="rows"></tbody></table>
<p>WireTapper © 2026 h9zdev · non-commercial. OpenCelliD data, when present: CC BY-SA 4.0, https://opencellid.org/ .</p>
<script id="data" type="application/json">PAYLOAD</script><script>
const data=JSON.parse(document.getElementById('data').textContent), ns='http://www.w3.org/2000/svg';
function draw(){const term=document.getElementById('filter').value.toLowerCase(),rows=data.filter(x=>JSON.stringify(x).toLowerCase().includes(term)),points=rows.filter(x=>x.latitude!=null&&x.longitude!=null),svg=document.getElementById('map'),tbody=document.getElementById('rows');svg.replaceChildren();tbody.replaceChildren();document.getElementById('count').textContent=`${rows.length} observations · ${points.length} supplied coordinates`;
let xs=points.map(x=>x.longitude),ys=points.map(x=>x.latitude),xmin=Math.min(...xs),xmax=Math.max(...xs),ymin=Math.min(...ys),ymax=Math.max(...ys);
for(const row of rows){const select=()=>document.getElementById('details').textContent=JSON.stringify(row,null,2);if(row.latitude!=null&&row.longitude!=null){let c=document.createElementNS(ns,'circle');c.setAttribute('cx',30+940*(row.longitude-xmin)/(xmax-xmin||1));c.setAttribute('cy',470-440*(row.latitude-ymin)/(ymax-ymin||1));c.setAttribute('r',5);c.onclick=select;let t=document.createElementNS(ns,'title');t.textContent=row.name;c.append(t);svg.append(c)}let tr=document.createElement('tr');tr.onclick=select;for(const val of [row.name,(row.protocol||'')+' / '+(row.category_candidate||''),row.latitude==null?'Not supplied':`${row.latitude}, ${row.longitude}`,row.rssi_dbm!=null?`${row.rssi_dbm} dBm`:row.signal_percent!=null?`${row.signal_percent}%`:'Unknown',row.source+' / '+(row.observed_at||'Time not supplied')]){let td=document.createElement('td');td.textContent=val;tr.append(td)}tbody.append(tr)}}
document.getElementById('filter').oninput=draw;draw();</script>'''
    mapfile.write_text(document.replace('PAYLOAD',payload),encoding='utf-8')
    result['reports'] = dict(json=str(jsonpath),csv=str(csvpath),geojson=str(geop),map=str(mapfile))
    result['artifacts'].extend(_artifact(p,'WireTapper',kind) for p,kind in [(csvpath,'telemetry_csv'),(geop,'telemetry_geojson'),(mapfile,'telemetry_map')])
    jsonpath.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return result


def collect(output, files=(), providers=(), latitude=None, longitude=None, radius_km=1,
            wifi=False, bluetooth=False, sdr=False, seconds=8, mappings=None, on_status=None):
    providers = list(dict.fromkeys(providers))
    if set(providers)-set(PROVIDERS) or not 0.1 <= radius_km <= 10 or not 1 <= seconds <= 30:
        raise ValueError('Choose listed providers, radius 0.1–10 km and discovery time 1–30 seconds')
    lat, lon = _point(latitude,longitude)
    if (latitude is not None or longitude is not None or any(p!='censys' for p in providers)) and (lat is None or lon is None):
        raise ValueError('Valid latitude and longitude are required for area lookups')
    if len(files)>10:
        raise ValueError('Select at most ten telemetry files')
    folder = Path(tempfile.mkdtemp(prefix='wireless-',dir=_mkdir(output)))
    result = dict(engine='WireTapper',license=LICENSE,records=[],statuses=[],artifacts=[],errors=[],collected_at=datetime.now(timezone.utc).isoformat())
    def status(source,state,count=0,detail=''):
        item=dict(source=source,status=state,count=count,detail=detail)
        result['statuses'].append(item)
        if state in ('error','blocked','timeout'):
            result['errors'].append(source+': '+detail)
        if on_status:
            on_status(item)
    for index, path in enumerate(files, 1):
        try:
            rows,artifact,detected,limited,rejected = import_file(path,mappings)
            result['artifacts'].append({**artifact,'source':'WireTapper / imported telemetry'})
            result['records'].extend(rows)
            status(f'WireTapper / telemetry file {index}','partial' if limited or rejected else 'ok' if rows else 'empty',len(rows),
                   f'File {index}: {rejected} invalid rows omitted'+('; limited to 1500 rows' if limited else ''))
        except ImportError:
            status(f'WireTapper / telemetry file {index}','skipped',detail='Install telemetry dependencies with setup-wireless.bat')
        except Exception:
            status(f'WireTapper / telemetry file {index}','error',detail=f'File {index}: could not parse selected telemetry; check format, size and columns')
    configured = keys()
    for provider in providers:
        if provider == 'censys':
            # Reuse current Censys host API, only for explicit imported public IPs.
            all_ips = list(dict.fromkeys(r['ip'] for r in result['records'] if r.get('ip')))
            ips = all_ips[:10]
            if not configured['CENSYS_API_TOKEN'] or not ips:
                status('WireTapper / censys','skipped',detail='Needs CENSYS_API_TOKEN and public IPs in selected telemetry; legacy v2 geo API is not used')
                continue
            if len(all_ips)>10:
                status('WireTapper / censys budget','partial',10,'First ten imported public IPs retained')
            for ip in ips:
                source='WireTapper / censys '+ip
                url='https://api.platform.censys.io/v3/global/asset/host/'+ip
                data,state,detail=_api(url,{}, {'Authorization':'Bearer '+configured['CENSYS_API_TOKEN'],'Accept':'application/vnd.censys.api.v3.host.v1+json'})
                if state == 'ok':
                    container=data.get('result')
                    resource=container.get('resource') if isinstance(container,dict) else None
                    services=resource.get('services') if isinstance(resource,dict) else None
                    if not isinstance(services,list) or any(not isinstance(s,dict) for s in services[:30]):
                        status(source,'error',detail='Source returned malformed host services')
                        continue
                    for service in services[:30]:
                        result['records'].append(dict(name='Indexed service '+ip,device_id=ip,ip=ip,port=service.get('port'),
                            protocol=_text(service.get('protocol')),category_candidate='indexed_service',latitude=None,longitude=None,rssi_dbm=None,
                            observed_at='',source='WireTapper / censys',source_url='https://search.censys.io/hosts/'+ip,
                            certainty='candidate',attribution='Indexed host service; physical location and target ownership unverified'))
                    status(source,'partial' if len(services)>30 else 'ok' if services else 'empty',min(30,len(services)),
                        'First 30 services retained' if len(services)>30 else '')
                else:
                    status(source,state,detail=detail)
            continue
        try:
            rows,state,detail=_area(provider,lat,lon,radius_km,configured)
            result['records'].extend(rows)
            status('WireTapper / '+provider,state,len(rows),detail)
        except Exception:
            status('WireTapper / '+provider,'error',detail='Source schema could not be parsed')
    for enabled,name,fn in ((wifi,'Wi-Fi',_wifi),(bluetooth,'BLE',lambda:_ble(seconds)),(sdr,'SDR USB',_sdr)):
        if enabled:
            rows,state,detail=fn()
            for row in rows:
                row.update(source='WireTapper / local '+name,source_url='',observed_at=result['collected_at'],
                    latitude=None,longitude=None,certainty='candidate',location_basis='No device coordinates measured',
                    attribution='Local hardware/discovery observation; classification and target ownership unverified')
            result['records'].extend(rows)
            status('WireTapper / local '+name,state,len(rows),detail)
    if len(result['records']) > 5000:
        result['records'] = result['records'][:5000]
        status('WireTapper / budget','partial',5000,'Combined output limited to 5000 observations')
    for row in result['records']:
        row['collected_at']=result['collected_at']
        row['observation_id']=hashlib.sha256(json.dumps(row,sort_keys=True,default=str).encode()).hexdigest()[:24]
    states={s['status'] for s in result['statuses']}
    bad=bool(states & {'partial','error','blocked','timeout','skipped'})
    result['status']='partial' if (result['records'] and bad) or 'partial' in states else 'ok' if result['records'] else 'error' if states & {'error','blocked','timeout'} else 'skipped' if not states or states=={'skipped'} else 'empty'
    if not states:
        status('WireTapper','skipped',detail='Select telemetry, indexed area sources or an explicit local discovery operation')
    return export(result,folder)


def _mkdir(output):
    path=Path(output).resolve()
    path.mkdir(parents=True,exist_ok=True)
    return path


def delta(result):
    """Preserve local artifact anchors and keep survey association a candidate."""
    report_path=Path(result['reports']['json'])
    artifact=_artifact(report_path,'WireTapper','wireless_report')
    digest=artifact['sha256']
    findings=[]
    for row in result['records']:
        encoded=json.dumps(row,ensure_ascii=False,sort_keys=True)
        findings.append(dict(event_type='Wireless observation',title=row['name'],value=encoded,module='WireTapper',
            source=row['source'],source_url=row.get('source_url',''),sha256=digest,artifact_id=digest,
            observed_at=row.get('observed_at') or row['collected_at'],certainty='candidate',verification='candidate',
            source_data=encoded,attribution=row['attribution'],latitude=row.get('latitude'),longitude=row.get('longitude'),
            data=row))
    return dict(findings=findings,artifacts=[*result['artifacts'],artifact],statuses=result['statuses'],errors=result['errors'],
                wireless=result)


def save_dossier(result, output, query='Wireless survey'):
    from . import dossier
    query = ' '.join(query.split())
    if not 2 <= len(query) <= 200:
        raise ValueError('Survey label must contain 2–200 characters')
    folder = dossier._folder(Path(output), query)
    saved = dict(query=query,kind='wireless',scope='full',coverage='quick',observed_at=result['collected_at'],
        sections=dict(web=[],profiles=[],emails=[],domain=None),source_checks=[],artifacts=[],errors=[],settings={},
        report_json=str(folder/'dossier.json'),report_csv=str(folder/'dossier.csv'))
    dossier.merge_delta(saved,delta(result))
    with (folder/'dossier.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=dossier.CSV_FIELDS)
        writer.writeheader()
        writer.writerows(dossier._report_rows(saved))
    dossier.save_relationship_graph(saved)
    return saved
