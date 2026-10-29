"""Offline checks for the extra public collectors and Tor's Apex upstream."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from jf import extra_osint, github_tools


class ExtraOsintTest(unittest.TestCase):
    def test_whatsmyname_rule_and_https_profile(self):
        site = {"e_code": 200, "e_string": "ada", "m_string": "not found",
                "uri_check": "https://example.org/u/{account}", "cat": "social"}
        self.assertTrue(extra_osint.account_found(200, "hello ada", site))
        self.assertFalse(extra_osint.account_found(200, "not found ada", site))
        self.assertFalse(extra_osint.account_found(404, "ada", site))
        self.assertEqual(extra_osint.profile_url("ada", site), "https://example.org/u/ada")
        self.assertEqual(extra_osint.profile_url("ada", {**site, "uri_check": "http://example.org/{account}"}), "")
        page = {"web": [{"title": "Ada", "url": "https://vk.com/ada", "snippet": "page",
                         "source": "Public page · vk.com", "category": "Public page"}], "errors": []}
        wiki = {"web": [{"title": "Ada Lovelace", "url": "https://www.wikidata.org/wiki/Q7259",
                         "snippet": "mathematician", "source": "Wikidata", "category": "Reference"}],
                "findings": [], "errors": []}
        empty = {"web": [], "findings": [], "errors": []}
        with (patch.object(extra_osint, "public_pages", return_value=page),
              patch.object(extra_osint, "wikidata", return_value=wiki),
              patch.object(extra_osint, "duckduckgo_instant", return_value=empty),
              patch.object(extra_osint, "gleif", return_value={"web": [], "errors": []})):
            found = extra_osint.supplement("Ada Lovelace", "person")
        self.assertEqual([row["url"] for row in found["web"]],
                         ["https://vk.com/ada", "https://www.wikidata.org/wiki/Q7259"])
        self.assertEqual(found["profiles"], [])
        self.assertEqual(found["hostnames"], [])

    def test_holehe_keeps_registration_and_drops_recovery(self):
        rows = [
            {"exists": True, "rateLimit": False, "domain": "github.com", "name": "github",
             "emailrecovery": "hidden@example.org", "phoneNumber": "+1555"},
            {"exists": True, "rateLimit": True, "domain": "twitter.com", "name": "twitter"},
            {"exists": False, "domain": "spotify.com", "name": "spotify"},
        ]
        profiles = extra_osint.holehe_profiles(rows)
        self.assertEqual([row["url"] for row in profiles], ["https://github.com"])
        self.assertNotIn("hidden@example.org", str(profiles))
        self.assertNotIn("1555", str(profiles))

    def test_urlscan_keeps_https_pages_only(self):
        payload = {"results": [
            {"page": {"url": "http://example.org", "title": "plain"}},
            {"page": {"url": "https://example.org/a", "title": "secure"}},
            "skip",
        ]}
        rows = extra_osint.urlscan_rows(payload)
        self.assertEqual([row["url"] for row in rows], ["https://example.org/a"])
        self.assertEqual(rows[0]["source"], "urlscan.io")

    def test_github_archive_openpgp_and_rdap_parsers(self):
        profile = extra_osint.github_profile({
            "login": "ada", "html_url": "https://github.com/ada", "name": "Ada",
            "company": "Example", "blog": "https://ada.example", "bio": "public", "location": "Paris"})
        self.assertEqual(profile["profiles"][0]["url"], "https://github.com/ada")
        self.assertEqual(profile["web"][0]["url"], "https://ada.example")
        self.assertIn("name: Ada", profile["findings"][0]["value"])
        self.assertEqual(extra_osint.github_profile(
            {"login": "ada", "html_url": "http://github.com/ada"})["profiles"], [])

        rows = extra_osint.archive_rows("example.org", [
            ["original", "timestamp", "statuscode"],
            ["https://example.org/a", "20200101120000", "200"],
            ["https://other.example/a", "20200101120000", "200"],
            ["http://www.example.org/old", "20200202120000", "200"],
            ["javascript:alert(1)", "20200101120000", "200"],
        ])
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["url"].startswith("https://web.archive.org/web/") for row in rows))
        self.assertNotIn("other.example", str(rows))

        key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nsecretstuff\n"
        published = extra_osint.openpgp_published("ada@example.org", 200, key)
        self.assertNotIn("secretstuff", str(published))
        self.assertTrue(published["findings"][0]["url"].startswith("https://keys.openpgp.org/search?q="))
        self.assertEqual(extra_osint.openpgp_published("ada@example.org", 404, key)["findings"], [])

        self.assertEqual(extra_osint.rdap_summary(
            {"name": "GOOGLE", "country": "US", "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}]}),
            "GOOGLE; US; 8.8.8.0/24")
        private = extra_osint.ip_registration("10.1.1.1")
        self.assertEqual(private["findings"], [])
        self.assertIn("not a public", private["errors"][0])

    def test_public_tool_parsers_drop_scans_and_private_fields(self):
        found = extra_osint.sherlock_profiles(
            "\x1b[32m[+] GitHub: https://github.com/ada\x1b[0m\n"
            "[+] Plain: http://example.org/ada\n[+] Other: https://example.org/nobody\n", "ada")
        self.assertEqual([row["url"] for row in found], ["https://github.com/ada"])
        self.assertEqual(found[0]["source"], "Sherlock")

        social = extra_osint.social_analyzer_profiles(
            {"detected": [{"link": "https://example.org/ada", "status": "good", "text": "secret bio",
                           "metadata": "hidden"},
                          {"link": "http://example.org/ada", "status": "good"},
                          {"link": "https://example.org/ada2", "status": "bad"}]}, "ada")
        self.assertEqual([row["url"] for row in social], ["https://example.org/ada"])
        self.assertNotIn("secret", str(social))
        self.assertNotIn("hidden", str(social))

        bird = extra_osint.blackbird_profiles(
            [{"name": "GitHub", "url": "https://github.com/ada", "status": "FOUND",
              "metadata": [{"name": "phone", "value": "+15551212"}]},
             {"name": "Miss", "url": "https://example.org/ada", "status": "NOT-FOUND"}], "ada")
        self.assertEqual([row["url"] for row in bird], ["https://github.com/ada"])
        self.assertNotIn("1555", str(bird))

        self.assertEqual(extra_osint.anubis_hosts("example.org", ["www.example.org", "other.example"]),
                         [{"name": "www.example.org", "source": "Anubis"}])
        hosts, detail = extra_osint.hackertarget_hosts(
            "example.org", "www.example.org,93.184.216.34\nother.example,1.2.3.4\n")
        self.assertEqual(hosts, [{"name": "www.example.org", "source": "HackerTarget"}])
        self.assertEqual(detail, "")
        empty, reason = extra_osint.hackertarget_hosts("example.org", "API count exceeded")
        self.assertEqual(empty, [])
        self.assertIn("exceeded", reason)
        self.assertEqual(extra_osint.amass_hosts("example.org", "www.example.org\nnot-a-host\nother.example\n"),
                         [{"name": "www.example.org", "source": "Amass"}])
        page = extra_osint.httpx_page("example.org", "https://example.org [200] [Example]\nhttps://evil.test [200] [x]")
        self.assertEqual(page[0]["url"], "https://example.org/")
        self.assertNotIn("evil.test", str(page))
        web, names = extra_osint.commoncrawl_rows(
            "example.org",
            '{"url": "https://www.example.org/a", "status": "200"}\n'
            '{"url": "http://example.org/old", "status": "200"}\n'
            '{"url": "https://other.example/a", "status": "200"}\n')
        self.assertEqual([row["url"] for row in web], ["https://www.example.org/a"])
        self.assertEqual(names[0]["source"], "Common Crawl")

        self.assertEqual(extra_osint.ip_geo_summary(
            {"success": True, "country": "US", "region": "California", "city": "View",
             "connection": {"asn": 15169, "org": "Google"}}),
            "US; California; View; AS15169 Google")
        private = extra_osint.ip_geo("10.1.1.1")
        self.assertEqual(private["findings"], [])
        self.assertEqual(private["errors"], [])
        pages = extra_osint.public_page_rows("vk.com", [
            {"title": "Ada", "url": "https://vk.com/ada", "snippet": "page"},
            {"title": "Other", "url": "https://evil.test/ada", "snippet": "no"},
            {"title": "Plain", "url": "http://vk.com/ada", "snippet": "no"},
            {"title": "Wrapped", "url": "https://yandex.ru/clck?url=https%3A%2F%2Fvk.com%2Fwrapped", "snippet": "y"},
        ])
        self.assertEqual([row["url"] for row in pages], ["https://vk.com/ada", "https://vk.com/wrapped"])
        self.assertEqual(pages[0]["source"], "Public page · vk.com")
        wiki_web, wiki_notes = extra_osint.wikidata_rows({"search": [
            {"id": "Q7259", "label": "Ada Lovelace", "description": "mathematician"},
            {"id": "not-an-id", "label": "skip"},
        ]})
        self.assertEqual(wiki_web[0]["url"], "https://www.wikidata.org/wiki/Q7259")
        self.assertIn("mathematician", wiki_notes[0]["value"])
        self.assertNotIn("http://", str(wiki_web))
        instant, _notes = extra_osint.duckduckgo_rows({
            "Heading": "Ada", "AbstractText": "mathematician",
            "AbstractURL": "https://en.wikipedia.org/wiki/Ada_Lovelace",
            "RelatedTopics": [
                {"Text": "Note - detail", "FirstURL": "http://example.org/a"},
                {"Name": "Group", "Topics": [{"Text": "Child", "FirstURL": "https://example.org/child"}]},
            ],
        })
        self.assertEqual([row["url"] for row in instant],
                         ["https://en.wikipedia.org/wiki/Ada_Lovelace", "https://example.org/child"])
        self.assertNotIn("http://example", str(instant))
        lei = extra_osint.gleif_rows({"data": [
            {"attributes": {"value": "Analytical Engines"},
             "relationships": {"lei-records": {"data": {"id": "5493001KJTIIGC8Y1R12"}}}},
            {"attributes": {"value": "no lei"}},
        ]})
        self.assertEqual(lei[0]["url"], "https://search.gleif.org/#/record/5493001KJTIIGC8Y1R12")
        hosts, detail = extra_osint.reverse_name_hosts("8.8.8.8,dns.google\nnot a host\n")
        self.assertEqual(hosts, [{"name": "dns.google", "source": "HackerTarget"}])
        self.assertEqual(detail, "")
        empty_hosts, reason = extra_osint.reverse_name_hosts("API count exceeded")
        self.assertEqual(empty_hosts, [])
        self.assertIn("exceeded", reason)
        self.assertEqual(extra_osint.ip_names("10.1.1.1"), {"hostnames": [], "errors": []})
        self.assertEqual(extra_osint.ripe_summary(
            {"data": {"asns": [{"asn": 15169, "holder": "GOOGLE"}]}}), "AS15169 GOOGLE")
        self.assertEqual(extra_osint.ripe_prefix("10.1.1.1"), {"findings": [], "errors": []})
        self.assertEqual(extra_osint.otx_hosts("example.org", {"passive_dns": [
            {"hostname": "www.example.org"}, {"hostname": "other.example"}]}),
            [{"name": "www.example.org", "source": "OTX"}])
        with patch.object(extra_osint, "_otx_key", return_value=""):
            self.assertEqual(extra_osint.otx_passive("example.org"), {"hostnames": [], "errors": []})
        self.assertEqual(extra_osint.hostname_item("Www.Example.ORG"), ("www.example.org", "Subfinder"))
        self.assertEqual(extra_osint.hostname_item({"name": "a.example.org", "source": "Amass"}),
                         ("a.example.org", "Amass"))

        sherlock = extra_osint.sherlock_command("ada")
        self.assertIn("--local", sherlock)
        for flag in ("--nsfw", "--browse", "--tor", "--dump-response"):
            self.assertNotIn(flag, sherlock)
        social_cmd = extra_osint.social_command("ada")
        for flag in ("--extract", "--metadata", "--screenshots"):
            self.assertNotIn(flag, social_cmd)
        self.assertEqual(social_cmd[social_cmd.index("--top") + 1], "25")
        bird_cmd = extra_osint.blackbird_command("ada", "username")
        self.assertIn("--no-nsfw", bird_cmd)
        for flag in ("--ai", "--dump", "--permute", "--setup-ai"):
            self.assertNotIn(flag, bird_cmd)
        amass = extra_osint.amass_command("example.org", "dir", "out.txt")
        self.assertIn("-passive", amass)
        for flag in ("-active", "-brute", "-alts", "-p"):
            self.assertNotIn(flag, amass)
        httpx = extra_osint.httpx_command("example.org")
        self.assertEqual(httpx[httpx.index("-u") + 1], "https://example.org")
        self.assertEqual(httpx.count("-u"), 1)
        for flag in ("-ports", "-list", "-l", "-path"):
            self.assertNotIn(flag, httpx)

    def test_phone_plan_is_numbering_data(self):
        found = extra_osint.phone_plan("+442083661177")
        self.assertEqual(found["errors"], [])
        value = found["findings"][0]["value"]
        self.assertEqual(found["findings"][0]["module"], "numbering plan")
        self.assertNotIn("@", value)
        self.assertGreaterEqual(value.count(";"), 2)

    def test_tor_proxy_flag_and_stable_directory(self):
        with patch.dict(os.environ, {"JOBFIND_ACTIVE_PROXY": "http://127.0.0.1:20000"}):
            self.assertEqual(github_tools.tor_https_proxy(), "127.0.0.1:20000")
        with patch.dict(os.environ, {"JOBFIND_ACTIVE_PROXY": "socks5://127.0.0.1:1080"}):
            self.assertEqual(github_tools.tor_https_proxy(), "")
        seen = {}

        class Proc:
            def poll(self):
                return 1

            def terminate(self):
                pass

        def popen(command, **_kwargs):
            seen["command"] = command
            return Proc()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tor-tree"
            exe = root / "tor" / "tor.exe"
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"")
            (root / "data").mkdir()
            with (patch.object(github_tools.socket, "create_connection", side_effect=OSError("down")),
                  patch.object(github_tools.subprocess, "Popen", side_effect=popen),
                  patch.object(github_tools, "TOR", root),
                  patch.dict(os.environ, {"JOBFIND_ACTIVE_PROXY": "http://127.0.0.1:20000"})):
                with self.assertRaises(RuntimeError) as caught:
                    github_tools._tor_proxy(Path(tmp) / "scratch")
        command = seen["command"]
        data = command[command.index("--DataDirectory") + 1]
        self.assertEqual(Path(data), (github_tools.ROOT / "jobfind_out" / "tor-upstream").resolve())
        self.assertNotIn("scratch", data)
        self.assertIn("--HTTPSProxy", command)
        self.assertIn("127.0.0.1:20000", command)
        self.assertEqual(command[command.index("--ReachableORAddresses") + 1], "*:443")
        self.assertEqual(command[command.index("--ClientUseIPv6") + 1], "1")
        self.assertEqual(command[command.index("--ClientPreferIPv6ORPort") + 1], "1")
        self.assertNotIn("--UseBridges", command)
        self.assertIn("Apex", str(caught.exception))
        geoip = command[command.index("--GeoIPFile") + 1]
        self.assertTrue(Path(geoip).is_absolute())
        with tempfile.TemporaryDirectory(prefix="findall-bridge ") as tmp:
            tor = Path(tmp) / "tor.exe"
            tor.write_bytes(b"")
            transport = Path(tmp) / "pluggable_transports"
            transport.mkdir()
            (transport / "lyrebird.exe").write_bytes(b"fixture")
            (transport / "pt_config.json").write_text(json.dumps({
                "bridges": {"obfs4": ["obfs4 192.0.2.1:443 fixture cert=fixture iat-mode=0"]}
            }), encoding="utf-8")
            bridges = github_tools.tor_bridge_args(tor)
        self.assertEqual(bridges[:2], ["--UseBridges", "1"])
        plugin = bridges[bridges.index("--ClientTransportPlugin") + 1]
        exec_path = plugin.split("obfs4 exec ", 1)[1]
        self.assertTrue(exec_path.endswith("lyrebird.exe"))
        self.assertNotIn(" ", exec_path)
        self.assertGreaterEqual(bridges.count("--Bridge"), 1)

    def test_tor_prefers_direct_relays_when_upstream_is_available(self):
        class Proc:
            def poll(self): return 1
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tor.exe").write_bytes(b"")
            with patch.object(github_tools, "ROOT", root), patch.object(github_tools, "TOR", root), \
                    patch.object(github_tools.socket, "create_connection", side_effect=OSError("down")), \
                    patch.object(github_tools.subprocess, "Popen", return_value=Proc()) as start, \
                    patch.object(github_tools, "local_bridge_sets", return_value=[("bridge", ["--UseBridges", "1"])]), \
                    patch.object(github_tools, "moat_settings", return_value=[]), \
                    patch.dict(os.environ, {"JOBFIND_ACTIVE_PROXY": "http://127.0.0.1:20000"}):
                with self.assertRaises(RuntimeError):
                    github_tools._tor_proxy(root)
            first, second = [call.args[0] for call in start.call_args_list]
            self.assertNotIn("--UseBridges", first)
            self.assertIn("--HTTPSProxy", first)
            self.assertIn("--UseBridges", second)

    def test_tor_waits_for_descriptor_loading_without_killing_progress_at_50_percent(self):
        clock = {"now": 0, "started": False}
        class Connection:
            def __init__(self): self.sent = 0
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, value): pass
            def sendall(self, value): self.sent += 1
            def recv(self, size):
                return b"\x05\x00" if self.sent == 1 or clock["now"] >= 130 else b"\x05\x05"
        def connect(*args, **kwargs):
            if not clock["started"]: raise OSError("not started")
            return Connection()
        def sleep(seconds): clock["now"] += seconds
        process = MagicMock()
        process.poll.return_value = None
        def start(command, **kwargs):
            clock["started"] = True
            kwargs["stdout"].write(b"Bootstrapped 50% (loading_descriptors)\n")
            kwargs["stdout"].flush()
            return process
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tor.exe").write_bytes(b"")
            with patch.object(github_tools, "ROOT", root), patch.object(github_tools, "TOR", root), \
                    patch.object(github_tools, "local_bridge_sets", return_value=[("bridge", ["--UseBridges", "1"])]), \
                    patch.object(github_tools.socket, "create_connection", side_effect=connect), \
                    patch.object(github_tools.subprocess, "Popen", side_effect=start), \
                    patch.object(github_tools.time, "monotonic", side_effect=lambda: clock["now"]), \
                    patch.object(github_tools.time, "sleep", side_effect=sleep), \
                    patch.dict(os.environ, {"JOBFIND_ACTIVE_PROXY": ""}):
                self.assertEqual(github_tools._tor_proxy(root), "127.0.0.1:9050")
            self.assertGreaterEqual(clock["now"], 130)
            process.terminate.assert_not_called()

    def test_onionland_rows_skip_ads_and_keep_onion_links(self):
        html = """
        <div class="result-block"><div class="title">Sponsored</div>
          <div class="link">Ad http://aaaaaaaaaaaaaaaa.onion/ad</div></div>
        <div class="result-block"><div class="title">Daily News</div>
          <div class="link">http://bbbbbbbbbbbbbbbb.onion/news</div></div>
        <div class="result-block"><div class="title">Clear</div>
          <div class="link">https://example.org/news</div></div>
        """
        rows = github_tools.onionland_rows(html)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["engine"], "onionland")
        self.assertEqual(rows[0]["title"], "Daily News")
        self.assertEqual(rows[0]["url"], "http://bbbbbbbbbbbbbbbb.onion/news")

    def test_subdomain_center_and_robtex_keep_child_hosts(self):
        hosts = extra_osint.subdomaincenter_hosts(
            "example.org", ["www.example.org", "evil.com", "example.org"])
        self.assertEqual(hosts, [{"name": "www.example.org", "source": "Subdomain Center"}])
        text = "\n".join((
            '{"rrname":"www.example.org","rrdata":"203.0.113.5","rrtype":"A"}',
            '{"rrname":"example.org","rrdata":"ns.example.net","rrtype":"NS"}',
        ))
        self.assertEqual([row["name"] for row in extra_osint.robtex_hosts("example.org", text)],
                         ["www.example.org"])
        records = extra_osint.robtex_records("example.org", text)
        self.assertEqual([row["value"] for row in records],
                         ["A 203.0.113.5", "NS ns.example.net"])
        self.assertTrue(all(row["url"].startswith("https://www.robtex.com/dns-lookup/") for row in records))

    def test_moat_settings_use_one_snowflake_line(self):
        payload = {"settings": [{"bridges": {"type": "snowflake", "source": "bridgedb",
            "bridge_strings": [
                "snowflake 192.0.2.3:1 BBBB fingerprint=BBBB url=https://example.invalid/ fronts=example.invalid",
                "snowflake 192.0.2.4:1 CCCC fingerprint=CCCC url=https://example.invalid/ fronts=example.invalid"]}}]}
        with tempfile.TemporaryDirectory() as tmp:
            lyrebird = Path(tmp) / "lyrebird.exe"
            lyrebird.write_bytes(b"z")
            sets = github_tools.moat_bridge_sets(payload, lyrebird)
        self.assertEqual([label for label, _args in sets], ["moat-snowflake"])
        args = sets[0][1]
        self.assertEqual(args.count("--Bridge"), 1)
        plugin = args[args.index("--ClientTransportPlugin") + 1]
        self.assertTrue(plugin.startswith("snowflake exec "))
        self.assertNotIn(" ", plugin.split("snowflake exec ", 1)[1])
        self.assertNotIn("fingerprint=BBBB", " ".join(label for label, _args in sets))

    def test_tor_switches_bridge_set_when_the_first_does_not_connect(self):
        commands = []

        class Proc:
            def poll(self):
                return 1

            def terminate(self):
                pass

        def popen(command, **_kwargs):
            commands.append(command)
            return Proc()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tor-tree"
            exe = root / "tor" / "tor.exe"
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"")
            (root / "data").mkdir()
            transport = exe.parent / "pluggable_transports"
            transport.mkdir()
            (transport / "lyrebird.exe").write_bytes(b"x")
            (transport / "pt_config.json").write_text(json.dumps({"bridges": {
                "obfs4": ["obfs4 127.0.0.1:1 AAAA cert=test iat-mode=0"],
                "snowflake": ["snowflake 192.0.2.3:1 BBBB fingerprint=BBBB url=https://example.invalid/ fronts=example.invalid"],
                "meek": ["meek_lite 192.0.2.20:2 url=https://example.invalid/ front=example.invalid"],
            }}), encoding="utf-8")
            with (patch.object(github_tools.socket, "create_connection", side_effect=OSError("down")),
                  patch.object(github_tools.subprocess, "Popen", side_effect=popen),
                  patch.object(github_tools, "TOR", root),
                  patch.object(github_tools, "moat_settings", return_value=[]),
                  patch.dict(os.environ, {"JOBFIND_ACTIVE_PROXY": ""})):
                with self.assertRaises(RuntimeError) as caught:
                    github_tools._tor_proxy(Path(tmp) / "scratch")
        plugins = [command[command.index("--ClientTransportPlugin") + 1].split(" exec ", 1)[0]
                   for command in commands]
        self.assertEqual(plugins, ["obfs4", "snowflake", "meek_lite"])
        self.assertIn("obfs4", str(caught.exception))
        self.assertNotIn("cert=test", str(caught.exception))
