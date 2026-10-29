# FindAll WireTapper integration

Upstream: https://github.com/h9zdev/WireTapper
Pinned revision: 395bb9348f9c9458cb0b7994623c4c5ae937b544
Copyright (c) 2026 h9zdev. Preserve LICENSE-NONCOMMERCIAL.md.
README mentions CC BY-NC 4.0, while the license file contains custom non-commercial terms; this integration preserves both without relicensing upstream code.

FindAll executes telemetry_importer.detect_column_matches/process_file and selected device classification, RSSI-distance, camera-coordinate normalization and Linux USB SDR presence helpers in findall_bridge.py. These helpers were extracted from app.py/flock_manager.py without running application startup. process_file accepts bounded prevalidated records as a local patch. The Flask application is not imported: it initializes credential databases, contains simulated SDR map records and unrelated authentication/credential features. Imports are read-only, outputs preserve actual source fields and do not invent missing MAC, RSSI, timestamps or coordinates. Default camera brands/operators are not retained unless actually supplied. Device categories and RSSI distance remain estimates.

Public WiGLE/OpenCellID/Shodan area lookups use FindAll's transport and explicitly configured keys. Censys enrichment uses FindAll's current host lookup on explicitly imported IPs, avoiding the upstream legacy v2 geo API. Local Wi-Fi/BLE discovery is explicit and bounded. No RF signal decoder, Wi-Fi password retrieval, IRK identity recovery, network association or deauthentication is implemented by this bridge.

Entrypoints: jobfind.py wireless; wireless.bat / findall-ui.exe --page wireless; jf/dossier.py's explicit wireless_files phase; main Rust Wireless tab and Research telemetry paths. The wireless-ui CLI remains a compatibility launcher for the native EXE. There is no separate Python/Tkinter UI. JSON/CSV/GeoJSON/coordinate plot artifacts feed the existing dossier graph, Markdown, quality report and AI evidence selection. setup-wireless.bat installs pandas/openpyxl and the optional Bleak scanner.
