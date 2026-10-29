"""Selected WireTapper helpers; no Flask startup, DB or scanner side effects.
Copyright (c) 2026 h9zdev. Non-commercial use only.
See LICENSE-NONCOMMERCIAL.md. Adaptation: FindAll bridge, 2026-10-03.
"""
import re
import os

_BT_ENV_PATH_LOSS = {'free_space': 2.0, 'outdoor': 2.2, 'indoor': 3.0}
_BT_DEFAULT_REF_OFFSET = 59

def classify_device(name, original_type):
    if not name:
        return original_type
    name_upper = name.upper()
    if any(k in name_upper for k in ["SDR", "RTL-SDR", "HACKRF", "ADSB", "SUBGHZ", "RF_BEACON", "HAM_RADIO", "RADIO", "433MHZ", "868MHZ", "915MHZ"]):
        return "sdr"
    if any(k in name_upper for k in ["CAR", "FORD", "TOYOTA", "BMW", "TESLA", "SYNC", "MAZDA", "HONDA", "UCONNECT", "HYUNDAI", "LEXUS", "NISSAN"]):
        return "car"
    if any(k in name_upper for k in ["TV", "BRAVIA", "VIZIO", "SAMSUNG", "LG", "ROKU", "FIRE", "SMARTVIEW", "KDL-"]):
        return "tv"
    if any(k in name_upper for k in ["HEADPHONE", "EARBUD", "BOSE", "SONY", "BEATS", "AUDIO", "AIRPOD", "JBL", "SENNHEISER"]):
        return "headphone"
    if any(k in name_upper for k in ["DASHCAM", "DASH CAM", "DVR", "70MAI", "VIOFO", "GARMIN DASH"]):
        return "dashcam"
    if any(k in name_upper for k in ["CAM", "SURVEILLANCE", "SECURITY", "NEST", "RING", "ARLO", "HIKVISION", "DAHUA", "REOLINK"]):
        return "camera"
    if any(k in name_upper for k in ["WATCH", "FITBIT", "GARMIN", "WHOOP"]):
        return "iot"
    return original_type

def _bt_estimate_distance(rssi: int, tx_power, env: str = "free_space"):
    """Estimate distance in meters using the log-distance path loss model.
    Derived from measured_power = tx_power - _BT_DEFAULT_REF_OFFSET (59 dB iBeacon offset).
    """
    if rssi == 0 or rssi is None:
        return None
    if tx_power is not None:
        measured_power = tx_power - _BT_DEFAULT_REF_OFFSET
    else:
        measured_power = -59
    n = _BT_ENV_PATH_LOSS.get(env, 2.0)
    try:
        return 10 ** ((measured_power - rssi) / (10 * n))
    except Exception:
        return None

def _parse_coordinates_string(val):
    """Extracts (lat, lon) tuple from composite coordinate string like '41.092545, -81.557472'."""
    if not val:
        return None, None
    s = str(val).strip().strip('"').strip("'")
    # Matches format "lat, lon" or "lat lon"
    parts = re.split(r'[,;\s]+', s)
    if len(parts) >= 2:
        try:
            lat = float(parts[0])
            lon = float(parts[1])
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                return lat, lon
        except ValueError:
            pass
    return None, None

def normalize_camera_record(row, idx, file_source=""):
    """Normalizes a raw dictionary row into a standardized tactical Camera object."""
    if not isinstance(row, dict):
        return None

    lat, lon = None, None

    # Check composite coordinates column first
    for k in ['coordinates', 'coords', 'coord', 'location', 'point']:
        if k in row and row[k]:
            clat, clon = _parse_coordinates_string(row[k])
            if clat is not None and clon is not None:
                lat, lon = clat, clon
                break

    # Check individual lat/lon columns
    if lat is None or lon is None:
        lat_candidates = ['latitude', 'lat', 'trilat', 'gps_lat', 'currentlatitude', 'lat_wgs84', 'coord_y', 'y']
        lon_candidates = ['longitude', 'lon', 'lng', 'long', 'trilong', 'gps_lon', 'currentlongitude', 'lon_wgs84', 'coord_x', 'x']

        for k in lat_candidates:
            if k in row and row[k] is not None and str(row[k]).strip() != '':
                try:
                    v = float(str(row[k]).strip())
                    if -90 <= v <= 90:
                        lat = v
                        break
                except ValueError:
                    pass

        for k in lon_candidates:
            if k in row and row[k] is not None and str(row[k]).strip() != '':
                try:
                    v = float(str(row[k]).strip())
                    if -180 <= v <= 180:
                        lon = v
                        break
                except ValueError:
                    pass

    # If coordinates couldn't be parsed, check if maps_url has embedded lat/lon
    if (lat is None or lon is None) and 'maps_url' in row and row['maps_url']:
        m = re.search(r'@(-?\d+\.\d+),(-?\d+\.\d+)', str(row['maps_url']))
        if m:
            try:
                lat = float(m.group(1))
                lon = float(m.group(2))
            except ValueError:
                pass

    if lat is None or lon is None:
        return None

    # Brand / Type identification
    brand = row.get('brand') or row.get('make') or row.get('type') or 'Flock Safety'
    if not brand or brand.lower() in ['infra', 'fixed', 'camera']:
        brand = 'Flock Safety'

    # Camera name / location
    name = (
        row.get('name') or
        row.get('info/comments') or
        row.get('note b') or
        row.get('road') or
        row.get('ssid') or
        row.get('description') or
        f"Flock Node #{idx + 1}"
    )
    if isinstance(name, str) and name.strip() == '':
        name = f"Flock ALPR Node #{idx + 1}"

    # Operator / Police Department / Agency
    operator = (
        row.get('operator') or
        row.get('agency') or
        row.get('department') or
        row.get('Country') or
        'Law Enforcement / Municipal ALPR'
    )

    # Direction (0-360 degrees or compass text)
    direction = row.get('direction') or row.get('directions') or None

    # Mount type
    mount_type = row.get('mountType') or row.get('mount_type') or row.get('config type') or 'pole'

    # Surveillance Zone
    zone = row.get('surveillanceZone') or row.get('zone') or 'traffic'

    # Notes / comments
    notes = (
        row.get('info/comments') or
        row.get('note a') or
        row.get('comment') or
        row.get('description') or
        ''
    )

    # Google Maps direct link
    maps_url = row.get('maps_url') or f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"

    # Unique Identifier
    cam_id = (
        str(row.get('osmId')) if row.get('osmId') else
        str(row.get('netid')) if row.get('netid') else
        str(row.get('note a')) if row.get('note a') else
        f"flock-{idx}-{abs(hash((lat, lon)))}"
    )

    return {
        "id": cam_id,
        "lat": round(lat, 6),
        "lon": round(lon, 6),
        "name": str(name),
        "brand": str(brand),
        "operator": str(operator),
        "direction": direction,
        "mount_type": str(mount_type),
        "zone": str(zone),
        "notes": str(notes),
        "maps_url": str(maps_url),
        "source_file": file_source
    }

def check_usb_sdr_status():
    """Checks if a physical USB SDR receiver (e.g. RTL-SDR, HackRF, Airspy) is attached via USB."""
    connected = False
    device_name = "SDR USB Dongle"
    freq_range = "24 MHz - 1766 MHz"

    usb_dir = "/sys/bus/usb/devices"
    if os.path.exists(usb_dir):
        try:
            for dev in os.listdir(usb_dir):
                vp_path = os.path.join(usb_dir, dev)
                id_vendor = os.path.join(vp_path, "idVendor")
                id_product = os.path.join(vp_path, "idProduct")
                product_file = os.path.join(vp_path, "product")

                vendor_id = ""
                product_id = ""
                product_str = ""

                if os.path.exists(id_vendor):
                    with open(id_vendor, 'r') as f:
                        vendor_id = f.read().strip().lower()
                if os.path.exists(id_product):
                    with open(id_product, 'r') as f:
                        product_id = f.read().strip().lower()
                if os.path.exists(product_file):
                    with open(product_file, 'r', errors='ignore') as f:
                        product_str = f.read().strip()

                if (vendor_id == '0bda' and product_id in ['2838', '2832']) or 'rtl' in product_str.lower():
                    connected = True
                    device_name = product_str or "RTL2838UHIDIR RTL-SDR Blog V4"
                    freq_range = "500 kHz - 1766 MHz"
                    break
                elif (vendor_id == '1d50' and product_id in ['6089', '604b']) or 'hackrf' in product_str.lower():
                    connected = True
                    device_name = product_str or "Great Scott Gadgets HackRF One"
                    freq_range = "1 MHz - 6 GHz"
                    break
                elif (vendor_id == '1d50' and product_id == '60a1') or 'airspy' in product_str.lower():
                    connected = True
                    device_name = product_str or "Airspy R2 / Mini"
                    freq_range = "24 MHz - 1800 MHz"
                    break
                elif 'sdr' in product_str.lower() or 'software defined radio' in product_str.lower():
                    connected = True
                    device_name = product_str
                    break
        except Exception as e:
            print(f"USB scan exception: {e}")

    return {
        "connected": connected,
        "device": device_name if connected else "No SDR Device Detected",
        "frequency_range": freq_range,
        "status": "Active Hardware Link" if connected else "Disconnected"
    }
