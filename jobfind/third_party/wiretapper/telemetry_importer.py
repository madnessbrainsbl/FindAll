import os
import re
import json
import sqlite3
import pandas as pd
import xml.etree.ElementTree as ET
from datetime import datetime

HEURISTICS = {
    'lat': ['lat', 'latitude', 'trilat', 'gpslat', 'gps_lat', 'currentlatitude', 'y', 'lat_deg', 'lat_wgs84', 'coord_y'],
    'lon': ['lon', 'lng', 'long', 'longitude', 'trilong', 'gpslon', 'gps_lon', 'currentlongitude', 'x', 'lon_deg', 'lon_wgs84', 'coord_x'],
    'ssid': ['ssid', 'name', 'netname', 'network_name', 'network', 'essid', 'title', 'placename', 'label', 'ap_name'],
    'bssid': ['bssid', 'mac', 'netid', 'address', 'hwaddr', 'mac_address', 'bssid_str', 'device_id'],
    'signal': ['signal', 'level', 'rssi', 'dbm', 'strength', 'qos', 'quality', 'pwr', 'rx_power'],
    'type': ['type', 'radio', 'network_type', 'gentype', 'auth', 'authmode', 'capabilities', 'protocol', 'encryption'],
    'timestamp': ['timestamp', 'time', 'firstseen', 'lastseen', 'lastupdt', 'firsttime', 'date', 'datetime', 'last_seen', 'observed_at']
}

def detect_column_matches(columns):
    """Smartly matches column names against known telemetry schemas."""
    detected = {}
    normalized_cols = {re.sub(r'[^a-z0-9]', '', str(c).lower()): c for c in columns}

    for key, patterns in HEURISTICS.items():
        matched = None
        for pat in patterns:
            pat_clean = re.sub(r'[^a-z0-9]', '', pat.lower())
            if pat_clean in normalized_cols:
                matched = normalized_cols[pat_clean]
                break
        if not matched:
            for clean_col, orig_col in normalized_cols.items():
                for pat in patterns:
                    pat_clean = re.sub(r'[^a-z0-9]', '', pat.lower())
                    if pat_clean in clean_col or clean_col in pat_clean:
                        matched = orig_col
                        break
                if matched:
                    break
        if matched:
            detected[key] = matched
    return detected

def parse_kml_data(file_path):
    """Parses KML file extracting Placemarks and coordinates."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        # Handle XML namespaces
        ns = {'kml': 'http://www.opengis.net/kml/2.2'}
        placemarks = root.findall('.//kml:Placemark', ns)
        if not placemarks:
            placemarks = root.findall('.//Placemark')

        rows = []
        for pm in placemarks:
            name_node = pm.find('kml:name', ns) if 'kml' in str(root.tag) else pm.find('name')
            desc_node = pm.find('kml:description', ns) if 'kml' in str(root.tag) else pm.find('description')
            coords_node = pm.find('.//kml:coordinates', ns) if 'kml' in str(root.tag) else pm.find('.//coordinates')

            name = name_node.text.strip() if name_node is not None and name_node.text else "KML Node"
            desc = desc_node.text.strip() if desc_node is not None and desc_node.text else ""

            lat, lon = None, None
            if coords_node is not None and coords_node.text:
                parts = coords_node.text.strip().split(',')
                if len(parts) >= 2:
                    try:
                        lon = float(parts[0].strip())
                        lat = float(parts[1].strip())
                    except ValueError:
                        pass

            row = {
                "name": name,
                "description": desc,
                "latitude": lat,
                "longitude": lon
            }
            # Search description for signal, mac, encryption
            if desc:
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', desc)
                if mac_match:
                    row['bssid'] = mac_match.group(0)
                sig_match = re.search(r'(-?\d{2,3})\s*(?:dBm|dbm|RSSI)?', desc)
                if sig_match:
                    try:
                        row['signal'] = int(sig_match.group(1))
                    except:
                        pass

            rows.append(row)
        return rows
    except Exception as e:
        print(f"KML parsing error: {e}")
        return []

def parse_geojson_data(file_path):
    """Parses GeoJSON FeatureCollection into flat tabular dictionaries."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        features = data.get('features', []) if isinstance(data, dict) else []
        rows = []
        for feat in features:
            props = feat.get('properties', {}) or {}
            geom = feat.get('geometry', {}) or {}
            coords = geom.get('coordinates', [])
            row = dict(props)
            if len(coords) >= 2:
                # GeoJSON coordinates format: [longitude, latitude]
                row['longitude'] = coords[0]
                row['latitude'] = coords[1]
            rows.append(row)
        return rows
    except Exception as e:
        print(f"GeoJSON parsing error: {e}")
        return []

def parse_sqlite_data(file_path):
    """Scans an SQLite database file for coordinate tables and extracts rows."""
    try:
        conn = sqlite3.connect(file_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = [r[0] for r in cursor.fetchall()]
        if not tables:
            conn.close()
            return []

        # Find best candidate table containing lat/lon/coords
        best_table = tables[0]
        max_score = -1
        for table in tables:
            cursor.execute(f"PRAGMA table_info('{table}')")
            cols = [col[1].lower() for col in cursor.fetchall()]
            score = 0
            if any(k in cols for k in ['lat', 'latitude', 'trilat']):
                score += 3
            if any(k in cols for k in ['lon', 'lng', 'longitude', 'trilong']):
                score += 3
            if any(k in cols for k in ['ssid', 'name', 'bssid']):
                score += 2
            if score > max_score:
                max_score = score
                best_table = table

        cursor.execute(f"SELECT * FROM '{best_table}' LIMIT 5000")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        print(f"SQLite parsing error: {e}")
        return []

def load_file_records(file_path):
    """Loads records from CSV, JSON, GeoJSON, KML, SQLite DB, or Excel files."""
    ext = os.path.splitext(file_path)[1].lower()
    records = []

    if ext in ['.geojson']:
        records = parse_geojson_data(file_path)

    elif ext in ['.kml']:
        records = parse_kml_data(file_path)

    elif ext in ['.db', '.sqlite', '.sqlite3']:
        records = parse_sqlite_data(file_path)

    elif ext in ['.json']:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = json.load(f)
            if isinstance(content, list):
                records = content
            elif isinstance(content, dict):
                # Common wrappers like WiGLE {"results": [...]}, or {"data": [...]}, or GeoJSON
                if content.get('type') == 'FeatureCollection' and 'features' in content:
                    return parse_geojson_data(file_path)
                for key in ['results', 'data', 'devices', 'networks', 'items', 'rows']:
                    if key in content and isinstance(content[key], list):
                        records = content[key]
                        break
                if not records and content:
                    records = [content]
        except Exception as e:
            print(f"JSON read error: {e}")

    elif ext in ['.xls', '.xlsx']:
        try:
            df = pd.read_excel(file_path, engine='openpyxl')
            records = df.where(pd.notnull(df), None).to_dict(orient='records')
        except Exception as e:
            print(f"Excel read error: {e}")

    else:
        # Defaults to CSV/TSV handling
        try:
            # Check if WiGLE CSV with comment line on top
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = [f.readline() for _ in range(3)]

            skiprows = 0
            if first_lines and (first_lines[0].startswith('WigleWifi') or first_lines[0].startswith('#')):
                skiprows = 1

            # Try reading with pandas
            try:
                df = pd.read_csv(file_path, skiprows=skiprows)
            except Exception:
                df = pd.read_csv(file_path)

            records = df.where(pd.notnull(df), None).to_dict(orient='records')
        except Exception as e:
            print(f"CSV read error: {e}")

    return records

def preview_file(file_path):
    """Generates preview metadata, columns list, detected mappings and first sample rows."""
    if not os.path.exists(file_path):
        return {"status": "error", "message": "File not found on server"}

    records = load_file_records(file_path)
    if not records:
        return {"status": "error", "message": "Could not parse valid records or table is empty"}

    # Extract unified columns
    all_columns = []
    seen = set()
    for row in records[:20]:
        if isinstance(row, dict):
            for k in row.keys():
                if k not in seen:
                    seen.add(k)
                    all_columns.append(k)

    detected = detect_column_matches(all_columns)
    preview_rows = records[:8]

    raw_base = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    parts = raw_base.split('_', 1)
    clean_filename = parts[1] if (len(parts) == 2 and parts[0].isdigit()) else raw_base

    return {
        "status": "success",
        "file_id": raw_base,
        "filename": clean_filename,
        "file_size": file_size,
        "format": ext.lstrip('.').upper() or 'CSV',
        "total_rows": len(records),
        "columns": all_columns,
        "preview_rows": preview_rows,
        "detected_mappings": detected,
        "helper_info": {
            "bssid": {
                "detected": detected.get('bssid'),
                "desc": "Hardware MAC / Device identifier used for unique signal clustering."
            },
            "signal": {
                "detected": detected.get('signal'),
                "desc": "Signal strength in dBm or RSSI. Displayed in tactical signal bars."
            },
            "type": {
                "detected": detected.get('type'),
                "desc": "Network protocol / encryption (e.g. WPA3, LTE, BLE, RF)."
            },
            "timestamp": {
                "detected": detected.get('timestamp'),
                "desc": "Time of intercept or last observation."
            }
        }
    }

def process_file(file_path, mappings, records=None):
    """Processes the full file and outputs normalized WireTapper device objects with bounds."""
    if not os.path.exists(file_path):
        return {"status": "error", "message": "Target file not found"}

    # FindAll bridge can supply bounded, validated records without reopening the file.
    records = load_file_records(file_path) if records is None else records
    if not records:
        return {"status": "error", "message": "Unable to extract records from file"}

    lat_col = mappings.get('lat')
    lon_col = mappings.get('lon')
    ssid_col = mappings.get('ssid')
    bssid_col = mappings.get('bssid')
    signal_col = mappings.get('signal')
    type_col = mappings.get('type')
    time_col = mappings.get('timestamp')

    if not lat_col or not lon_col:
        return {"status": "error", "message": "Latitude and Longitude column mappings are required"}

    devices = []
    min_lat, max_lat = 90.0, -90.0
    min_lon, max_lon = 180.0, -180.0
    valid_coords_count = 0

    raw_base = os.path.basename(file_path)
    parts = raw_base.split('_', 1)
    clean_filename = parts[1] if (len(parts) == 2 and parts[0].isdigit()) else raw_base

    for i, row in enumerate(records):
        if not isinstance(row, dict):
            continue

        raw_lat = row.get(lat_col)
        raw_lon = row.get(lon_col)
        if raw_lat is None or raw_lon is None:
            continue

        try:
            lat = float(str(raw_lat).strip())
            lon = float(str(raw_lon).strip())
            if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
                continue
        except (ValueError, TypeError):
            continue

        # Valid coordinate
        valid_coords_count += 1
        if lat < min_lat: min_lat = lat
        if lat > max_lat: max_lat = lat
        if lon < min_lon: min_lon = lon
        if lon > max_lon: max_lon = lon

        # SSID / Name
        ssid = "Unknown Target"
        if ssid_col and row.get(ssid_col) is not None:
            ssid = str(row[ssid_col]).strip() or "Unnamed Signal"

        # BSSID / MAC
        bssid = ""
        if bssid_col and row.get(bssid_col) is not None:
            bssid = str(row[bssid_col]).strip()
        if not bssid:
            # Generate deterministic pseudo-MAC for imported marker consistency
            bssid = f"IMP:{i%256:02X}:{(i*7)%256:02X}:{(i*13)%256:02X}:{(i*19)%256:02X}"

        # Signal dBm
        signal = -70
        if signal_col and row.get(signal_col) is not None:
            try:
                raw_sig = str(row[signal_col]).strip()
                sig_match = re.search(r'-?\d+', raw_sig)
                if sig_match:
                    signal = int(sig_match.group(0))
            except Exception:
                pass

        # Type / Protocol
        raw_type = ""
        if type_col and row.get(type_col) is not None:
            raw_type = str(row[type_col]).strip()

        # Timestamp
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        if time_col and row.get(time_col) is not None:
            ts = str(row[time_col]).strip()

        device = {
            "lat": lat,
            "lon": lon,
            "ssid": ssid,
            "bssid": bssid,
            "signal": signal,
            "type": raw_type or "upload",
            "vendor": f"Imported [{clean_filename}]",
            "timestamp": ts,
            "source": "upload",
            "filename": clean_filename
        }
        devices.append(device)

    if not devices:
        return {"status": "error", "message": "No valid coordinates found in the file using specified column mappings."}

    bounds = [
        [min_lat, min_lon],
        [max_lat, max_lon]
    ]

    return {
        "status": "success",
        "count": len(devices),
        "total_rows_scanned": len(records),
        "devices": devices,
        "bounds": bounds,
        "filename": clean_filename
    }
