"""Offline integration checks: py -m unittest test_evidence_capture."""
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from jf import evidence_capture as capture
from jf import github_tools as tools

V3 = "a" * 56 + ".onion"
PUBLIC = [(2, 1, 6, "", ("93.184.216.34", 443))]


class EvidenceCaptureChecks(unittest.TestCase):
    def test_unicode_result_url_is_encoded_without_double_encoding(self):
        url = "https://public.org/wiki/Анна_Ахматова%20?name=Анна&literal=%2F"
        response = Mock(status=200)
        response.getheaders.return_value = [("Content-Type", "text/html; charset=utf-8")]
        response.read.side_effect = ["<title>Анна Ахматова</title>".encode(), b""]
        connection = Mock(sock=None)
        connection.getresponse.return_value = response
        connection.request.side_effect = lambda method, target, **kwargs: target.encode("ascii")
        with patch.object(capture.socket, "getaddrinfo", return_value=PUBLIC), \
                patch.object(capture, "_PinnedConnection", return_value=connection):
            page = capture.fetch_public(url)
        target = connection.request.call_args.args[1]
        self.assertEqual(target, "/wiki/%D0%90%D0%BD%D0%BD%D0%B0_%D0%90%D1%85%D0%BC%D0%B0%D1%82%D0%BE%D0%B2%D0%B0%20?name=%D0%90%D0%BD%D0%BD%D0%B0&literal=%2F")
        self.assertEqual(page["requested_url"], url)
        self.assertIn("Анна Ахматова", page["html"])

    def test_rejected_proxy_tunnel_is_not_replayed_with_reset_request_state(self):
        raw = Mock()
        raw.makefile.return_value = io.BytesIO(b"HTTP/1.0 502 Bad Gateway\r\n\r\n")
        with patch.dict(capture.os.environ, {"JOBFIND_ACTIVE_PROXY": "http://127.0.0.1:1111"}), \
                patch.object(capture.socket, "create_connection", return_value=raw) as connect:
            conn = capture._PinnedConnection("public.org", 443, ["93.184.216.34", "93.184.216.35"], 3, True)
            with self.assertRaisesRegex(OSError, "502"):
                conn.request("POST", "/lookup", body=b"x=1")
        self.assertEqual(connect.call_count, 1)
        self.assertNotIn(b"x=1", b"".join(call.args[0] for call in raw.sendall.call_args_list))

    def test_connect_fallback_keeps_request_state_and_sends_post_only_once(self):
        first, second, secured = Mock(), Mock(), Mock()
        secured.makefile.return_value = io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        context = Mock()
        context.wrap_socket.side_effect = [ConnectionResetError("TLS reset"), secured]
        with patch.object(capture.socket, "create_connection", side_effect=[first, second]), \
                patch.object(capture.ssl, "create_default_context", return_value=context):
            conn = capture._PinnedConnection("public.org", 443, ["93.184.216.34", "93.184.216.35"], 3, True)
            conn.request("POST", "/lookup", body=b"x=1")
            self.assertEqual(conn.getresponse().read(), b"OK")
        first.sendall.assert_not_called()
        self.assertEqual(b"".join(call.args[0] for call in secured.sendall.call_args_list).count(b"x=1"), 1)

    def test_address_fallback_does_not_extend_connection_deadline(self):
        raw = Mock()
        context = Mock()
        context.wrap_socket.side_effect = FileNotFoundError("TLS failed")
        with patch.object(capture.socket, "create_connection", return_value=raw) as connect, \
                patch.object(capture.ssl, "create_default_context", return_value=context), \
                patch.object(capture.time, "monotonic", side_effect=[0, 1, 5]):
            conn = capture._PinnedConnection("public.org", 443, ["93.184.216.34", "93.184.216.35"], 3, True)
            with self.assertRaises(TimeoutError):
                conn.connect()
        self.assertEqual(connect.call_count, 1)

    def test_tls_failure_tries_next_pinned_address_before_sending_request(self):
        first, second, secured = Mock(), Mock(), Mock()
        context = Mock()
        context.wrap_socket.side_effect = [FileNotFoundError(2, "TLS connection failed"), secured]
        with patch.object(capture.socket, "create_connection", side_effect=[first, second]) as connect, \
                patch.object(capture.ssl, "create_default_context", return_value=context):
            conn = capture._PinnedConnection("public.org", 443, ["93.184.216.34", "93.184.216.35"], 3, True)
            conn.connect()
        self.assertEqual([call.args[0] for call in connect.call_args_list], [("93.184.216.34", 443), ("93.184.216.35", 443)])
        first.close.assert_called_once()
        self.assertIs(conn.sock, secured)
        self.assertTrue(all(call.kwargs["server_hostname"] == "public.org" for call in context.wrap_socket.call_args_list))
        self.assertTrue(all(0 < call.args[1] <= 3 for call in connect.call_args_list))

    def test_certificate_failure_is_not_retried(self):
        raw = Mock()
        context = Mock()
        context.wrap_socket.side_effect = capture.ssl.SSLCertVerificationError("certificate rejected")
        with patch.object(capture.socket, "create_connection", return_value=raw) as connect, \
                patch.object(capture.ssl, "create_default_context", return_value=context):
            conn = capture._PinnedConnection("public.org", 443, ["93.184.216.34", "93.184.216.35"], 3, True)
            with self.assertRaises(capture.ssl.SSLCertVerificationError):
                conn.connect()
        self.assertEqual(connect.call_count, 1)
        raw.close.assert_called_once()

    def test_private_and_credentials_are_rejected(self):
        for url in ("file:///etc/passwd", "https://127.0.0.1", "https://user:pass@public.org", "https://public.org:8080", "https://local.test"):
            with self.assertRaises(ValueError):
                capture.validated_url(url)
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "224.0.0.1"):
            with patch.object(capture.socket, "getaddrinfo", return_value=[(2, 1, 6, "", (ip, 443))]):
                with self.assertRaises(ValueError):
                    capture.validated_url("https://public.org")
        with patch.object(capture.socket, "getaddrinfo", return_value=PUBLIC + [(2, 1, 6, "", ("10.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                capture.validated_url("https://public.org")

    def test_redirect_revalidates_target_and_blocks_private(self):
        class Response:
            status = 302
            def getheaders(self):
                return [("Location", "https://internal.org")]
        class Connection:
            sock = None
            def __init__(self, *args):
                pass
            def request(self, *args, **kwargs):
                pass
            def getresponse(self):
                return Response()
            def close(self):
                pass
        def answers(host, *args, **kwargs):
            return PUBLIC if host == "public.org" else [(2, 1, 6, "", ("10.0.0.1", 443))]
        with patch.object(capture.socket, "getaddrinfo", side_effect=answers), patch.object(capture, "_PinnedConnection", Connection):
            with self.assertRaises(ValueError):
                capture.fetch_public("https://public.org")

    def test_public_telegram_posts_and_published_email_capture(self):
        html = '<title>Public channel</title><script>hidden@evil.org</script><div class="tgme_widget_message" data-post="public_channel/42"><div class="tgme_widget_message_text">Contact careers@acme.org for roles</div><time datetime="2026-10-03T12:00:00Z"></time></div><a href="mailto:press@acme.org">Press</a>'
        body = html.encode()
        page = {"html": html, "body": body, "requested_url": "https://t.me/s/public_channel/42", "url": "https://t.me/s/public_channel/42",
                "observed_at": "2026-10-03T12:00:01Z", "http_status": 200, "content_type": "text/html", "sha256": hashlib.sha256(body).hexdigest()}
        with tempfile.TemporaryDirectory() as temp, patch.object(capture, "validated_url", return_value=(page["url"], "t.me", ["149.154.167.99"])), patch.object(capture, "fetch_public", return_value=page):
            callbacks = []
            result = capture.capture_results([{"url": "https://t.me/public_channel/42"}, {"url": "https://t.me/public_channel/42"}], Path(temp), on_status=callbacks.append, singlefile=False)
            self.assertEqual([row["email"] for row in result["emails"]], ["careers@acme.org", "press@acme.org"])
            self.assertEqual(result["web"][1]["published_at"], "2026-10-03T12:00:00Z")
            self.assertEqual(result["web"][1]["url"], "https://t.me/public_channel/42")
            self.assertEqual([row["state"] for row in callbacks], ["attempted", "ok", "skipped"])
            self.assertEqual(result["selection"]["duplicates"], 1)
            metadata = json.loads(Path(result["artifacts"][-1]).read_text(encoding="utf-8"))
            self.assertEqual(metadata["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(Path(result["artifacts"][0]).read_bytes(), body)

    def test_untrusted_offline_preview_cannot_load_resources(self):
        clean = capture._offline_preview('<script>x</script><meta http-equiv="refresh" content="0;url=file:///secret"><img src="file:///secret" onload="x()"><svg><use xlink:href="file:///secret"/></svg><a href="javascript:x()">Click</a><style>@import "file:///secret";</style>')
        self.assertNotIn("secret", clean)
        self.assertNotIn("javascript:", clean)
        self.assertNotIn("onload", clean)

    def test_each_selected_index_is_queried_and_failures_remain_visible(self):
        sample = f'<li class="result"><h4><a href="/search/redirect?redirect_url=http%3A%2F%2F{V3}%2F">Computer public hidden service</a></h4></li>'
        calls = []
        def fetch(url, **kwargs):
            calls.append(url)
            if "second.onion" in url:
                raise TimeoutError("Index timeout")
            return {"html": sample, "url": url, "observed_at": "2026-10-03T12:00:00Z"}
        second = "b" * 56 + ".onion"
        def request(engine, origin, query, page):
            return ("http://second.onion/search" if engine == "onionland" else "https://ahmia.fi/search/?q=computer", "GET", None)
        with tempfile.TemporaryDirectory() as temp, patch.object(tools, "_onion_origins", return_value={"ahmia": "https://ahmia.fi", "onionland": "http://"+second}), patch.object(tools, "_tor_proxy", return_value="127.0.0.1:9050"), patch.object(tools, "_onion_request", side_effect=request), patch.object(capture, "fetch_public", side_effect=fetch):
            result = tools.onion_search("computer", Path(temp), "ahmia,onionland")
            self.assertEqual(len(calls), 2)
            self.assertEqual(result["engines"], ["ahmia", "onionland"])
            self.assertEqual([row["state"] for row in result["statuses"]], ["ok", "error"])
            self.assertEqual(result["rows"][0]["url"], "http://"+V3+"/")
            self.assertIn("Index timeout", result["warnings"][0])

    def test_engine_parsers_decode_redirects_and_ignore_obsolete_addresses(self):
        samples = {"onionland": f'<div class="result-block"><div class="title">A</div><div class="link">http://{V3}/</div></div>',
                   "phobos": f'<div class="serp"><a class="titles" href="http://{V3}/">A</a></div>',
                   "haystack": f'<div class="result"><b><a href="/?url=http%3A%2F%2F{V3}%2F">A</a></b></div>',
                   "darksearchio": json.dumps({"data": [{"title": "A", "link": "http://"+V3+"/"}]})}
        for engine, sample in samples.items():
            self.assertEqual(tools.onion_rows(engine, sample)[0]["url"], "http://"+V3+"/")
        self.assertEqual(tools._onion_link("http://" + "a"*16 + ".onion/"), "")
        self.assertTrue(tools._onion_request("darksearchenginer", "http://"+V3, "computer", 1)[2])

    def test_onion_search_excludes_unrelated_index_entries_and_keeps_evidence(self):
        unrelated = f'<li class="result"><h4><a href="http://{V3}/shop">Generic shop</a></h4></li>'
        relevant = f'<li class="result"><h4><a href="http://{V3}/poetry">Poetry archive</a></h4><p>Об Анне Ахматовой</p></li>'
        for document, count, state in ((unrelated, 0, "error"), (unrelated + relevant, 1, "ok")):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp, \
                    patch.object(tools, "_onion_origins", return_value={"ahmia": "https://ahmia.fi"}), \
                    patch.object(capture, "fetch_public", return_value={"html": document,
                        "url": "https://ahmia.fi/search/?q=" + tools.urllib.parse.quote("Анна Ахматова"), "observed_at": "now"}):
                result = tools.onion_search("Анна Ахматова", Path(temp), "ahmia")
                self.assertEqual(len(result["rows"]), count)
                self.assertEqual(result["statuses"][0]["state"], state)
                self.assertEqual(result["statuses"][0]["filtered_count"], 1)
                if count:
                    self.assertIn("Анне Ахматовой", result["rows"][0]["snippet"])
                    self.assertEqual(len(result["rows"][0]["index_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
