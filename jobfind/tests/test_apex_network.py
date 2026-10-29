"""Run: .venv\Scripts\python.exe -m unittest test_apex_network -v"""

import base64
import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import jobfind
from jf import apex_network as apex, net

LINK = "vless://00000000-0000-4000-8000-000000000001@8.8.8.8:443?security=tls&sni=example.org#demo"


class ApexIntegrationTests(unittest.TestCase):
    def test_subscription_formats_and_protocols(self):
        fetch, _, xray = apex._modules()
        for body in (LINK, base64.b64encode(LINK.encode()).decode(), json.dumps([LINK])):
            links = fetch.parse_subscription(body)["configs"]
            self.assertEqual(len(links), 1)
            self.assertEqual(xray.link_to_xray_outbound(links[0]), xray.link_to_xray_outbound(LINK))
        links = [LINK, "trojan://secret@8.8.8.8:443?sni=example.org",
                 "ss://" + base64.b64encode(b"aes-128-gcm:secret").decode() + "@8.8.8.8:443",
                 "hysteria2://secret@8.8.8.8:443?sni=example.org",
                 "vmess://" + base64.b64encode(json.dumps({"add": "8.8.8.8", "port": "443",
                     "id": "00000000-0000-4000-8000-000000000001", "net": "tcp", "tls": "tls"}).encode()).decode()]
        for link in links:
            self.assertIsInstance(xray.link_to_xray_outbound(link), dict)
            self.assertIsInstance(apex._outbound(link), dict)

    def test_dedup_state_and_no_share_credentials_in_status(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(apex, "_url", side_effect=lambda value: value), \
                patch.object(apex, "_download", return_value=(LINK + "\n" + LINK.replace("#demo", "#other")).encode()):
            path = Path(tmp) / "state.json"
            result = apex.refresh(path)
            self.assertEqual(len(result["rows"]), 1)
            self.assertNotIn("link", result["rows"][0])
            self.assertNotIn("00000000-0000", json.dumps(result))
            self.assertFalse(result["enabled"])
            saved = path.read_bytes()
            with patch.object(apex, "_download", return_value=b"subscription expired"):
                with self.assertRaises(RuntimeError):
                    apex.refresh(path)
            self.assertEqual(path.read_bytes(), saved)

    def test_trust_boundaries(self):
        for url in ("file:///tmp/test", "http://example.org", "https://127.0.0.1", "https://user:pass@example.org"):
            with self.assertRaises(ValueError):
                apex._url(url)
        with self.assertRaises(ValueError):
            apex._outbound(LINK.replace("8.8.8.8", "127.0.0.1"))
        with self.assertRaises(ValueError):
            apex._outbound(LINK.replace("security=tls", "security=tls&allowInsecure=1"))

    def test_enable_requires_a_checked_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            with self.assertRaises(ValueError):
                apex.configure(path, True, "unknown")
            self.assertFalse(apex.configure(path, False)["enabled"])

    def test_install_verifies_checksum_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(apex, "CORE", Path(tmp)), \
                patch.object(apex, "executable", return_value=None), \
                patch.object(apex, "_download", side_effect=[
                    b'/XTLS/Xray-core/releases/tag/v1.2.3', b'SHA2-256= ' + b'0' * 64, b'corrupt archive']):
            with self.assertRaisesRegex(RuntimeError, "SHA256"):
                apex.install_core()
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_command_dispatch_applies_route(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(apex, "route", return_value=contextlib.nullcontext()) as route, \
                patch.object(jobfind, "cmd_projects", return_value=0):
            self.assertEqual(jobfind.main(["--db", str(Path(tmp) / "data.db"), "--network", "apex",
                                          "projects", "--kw", "python"]), 0)
            route.assert_called_once_with(Path(tmp) / "network" / "apex-state.json", "apex")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(jobfind.main(["network", "status"]), 0)

    def test_onion_command_uses_selected_route(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(apex, "route", return_value=contextlib.nullcontext()) as route, \
                patch.object(jobfind, "cmd_onion_search", return_value=0):
            self.assertEqual(jobfind.main(["--db", str(Path(tmp) / "data.db"), "--network", "apex",
                                          "onion-search", "--query", "privacy"]), 0)
            route.assert_called_once_with(Path(tmp) / "network" / "apex-state.json", "apex")

    def test_failover_and_no_direct_fallback(self):
        state = {"enabled": True, "selected": "a", "rows": [
            {"id": "a", "status": "ok", "latency_ms": 10, "link": "bad", "protocol": "vless", "host": "8.8.8.8", "port": 443},
            {"id": "b", "status": "ok", "latency_ms": 20, "link": "good", "protocol": "trojan", "host": "1.1.1.1", "port": 443}]}
        @contextlib.contextmanager
        def tunnel(link):
            if link == "bad":
                raise RuntimeError("failed")
            yield "http://127.0.0.1:43210"
        before = dict(os.environ)
        with patch.object(apex, "load", return_value=state), patch.object(apex, "tunnel", side_effect=tunnel), \
                patch.object(apex, "probe", return_value=12):
            with apex.route(Path("unused")):
                self.assertEqual(os.environ["JOBFIND_ACTIVE_PROXY"], "http://127.0.0.1:43210")
            with self.assertRaisesRegex(RuntimeError, "work failed"):
                with apex.route(Path("unused")):
                    raise RuntimeError("work failed")
            state["rows"] = []
            with self.assertRaisesRegex(RuntimeError, "No checked"):
                with apex.route(Path("unused")):
                    self.fail("must not fall back to direct")
        self.assertEqual(dict(os.environ), before)
        with patch.dict(os.environ, {"HTTP_PROXY": "http://existing.invalid:80"}):
            with apex.route(Path("unused"), "direct"):
                import urllib.request
                self.assertEqual(os.environ["NO_PROXY"], "*")
                self.assertNotIn("HTTP_PROXY", os.environ)
                handlers = [handler for handler in urllib.request._opener.handlers
                            if isinstance(handler, urllib.request.ProxyHandler)]
                self.assertTrue(all(not handler.proxies for handler in handlers))
            self.assertEqual(os.environ["HTTP_PROXY"], "http://existing.invalid:80")

    @unittest.skipUnless(apex.executable(), "Install official Xray to run the real transport check")
    def test_real_xray_transports_get_post_and_requests_and_stops(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"via":"xray"}')
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        outbound = {"protocol": "freedom", "settings": {"redirect": f"127.0.0.1:{server.server_port}"}}
        try:
            with patch.object(apex, "_outbound", return_value=outbound):
                with apex.tunnel("local-check") as proxy, apex._environment(proxy):
                    import requests
                    self.assertEqual(net.get("http://evidence.invalid/resource", retries=0).json(), {"via": "xray"})
                    self.assertEqual(net.post_json("http://evidence.invalid/resource", {"hello": 1}, retries=0).json(), {"hello": 1})
                    self.assertEqual(requests.get("http://evidence.invalid/resource", timeout=3).json(), {"via": "xray"})
                import socket
                port = int(proxy.rsplit(":", 1)[1])
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", port), timeout=0.5)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
