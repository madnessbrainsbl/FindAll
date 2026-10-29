# FindAll integration

Upstream: https://github.com/Diversan313/apex-parser
Pinned source commit: `20896bbb4b234d6ddb9e9f6d4d86c445d40aba32`.
MIT license is retained in LICENSE. The apex Python package is bundled as source.

FindAll uses upstream subscription decoding (plain, Base64 and JSON), expiry
detection, host/name parsing and URI-to-Xray conversion. It consumes the public
full, WhiteList, BlackList, AI, torrent and country subscriptions or user-supplied
HTTPS subscriptions. No private apex-sources repository or Telegram bot is needed.

Local modifications: config.py verifies TLS certificates; fetch.py exposes
parse_subscription(content) so the adapter can perform a bounded, verified
download before decoding. The integration does not call upstream main.py,
Telegram collectors, unbounded subscription downloads or upstream GeoIP probes.

The adapter jf/apex_network.py owns cache, node validation, semantic deduplication,
HTTPS probes, Xray installation and lifetime, and application-scoped routing.
Network state and raw share credentials stay in a local network/apex-state.json
next to the selected database. CLI/UI status does not return share credentials.
The selected route is applied to existing research commands, including commands
started by an older FindAll UI executable using the updated Python backend.

Xray is a separate official XTLS/Xray-core executable. Installer verifies the
official release .dgst SHA256 checksum and extracts only the executable and license.
It does not change Windows proxy settings or install a system VPN.
