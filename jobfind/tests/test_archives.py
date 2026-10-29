"""Offline archive contracts: actual upstream parsing, evidence and source boundaries."""
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import requests
from jf import archives, evidence_capture, dossier, ai_agents, research_agent, waymore_worker


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def fixture(self,values):
        path=self.root/'urls.json';path.write_text(json.dumps(values),encoding='utf-8');return path
    def cdx(self):
        return [['original','timestamp','statuscode','mimetype'],
            ['https://example.org/api/v1?id=1','20230102030405','200','application/json'],
            ['https://example.org/api/v1?id=2','20230102030405','200','application/json'],
            ['https://sub.example.org/admin','20210203040506','403','text/html'],
            ['https://example.org/config.bak','20220304050607','200','text/plain'],
            ['https://example.org.evil.org/admin','20220304050607','200','text/html']]
    def test_scope_dates_and_parameter_collapse(self):
        r=archives.collect('example.org',self.root/'out',providers=[],imports=[self.fixture(self.cdx())],
            from_date='2023',to_date='202301',collapse_parameters=True,category='api',status_codes='200')
        self.assertEqual(len(r['records']),1)
        self.assertEqual(r['records'][0]['parameters'],['id'])
        self.assertEqual(r['records'][0]['snapshot_at'],'20230102030405')
        self.assertEqual(r['filtered_count'],2)
        self.assertTrue(Path(r['reports']['urls']).is_file())
    def test_no_subdomains_and_import_deduplicates(self):
        p=self.fixture(self.cdx())
        r=archives.collect('example.org',self.root/'out',providers=[],imports=[p,p],subs=False)
        self.assertEqual(len(r['records']),3)
        self.assertFalse(any('sub.example.org' in row['original_url'] for row in r['records']))
    def test_ndjson_gau_export_and_disabled_unified_collector(self):
        path=self.root/'gau.jsonl'
        path.write_text('\n'.join(json.dumps(x) for x in [dict(url='https://example.org/old.js',source='Common Crawl',mimetype='application/javascript'),
            dict(url='https://example.org/api/legacy',source='wayback',timestamp='20200102030405',statuscode='200')]),encoding='utf-8')
        r=archives.collect('example.org',self.root/'out',providers=[],imports=[path])
        self.assertEqual([row['source'] for row in r['records']],['commoncrawl','wayback'])
        saved=archives.save_dossier(r,self.root/'dossiers')
        saved['settings']['include_archives']=False
        with patch.object(archives,'collect') as collect:
            delta=dossier.run_tool(saved,'archive_search',{'target':'example.org'})
        collect.assert_not_called();self.assertEqual(delta['statuses'][0]['state'],'skipped')
    def test_unified_collector_merges_archive_records_and_child_state(self):
        r=archives.collect('example.org',self.root/'out',providers=[],imports=[self.fixture(self.cdx())])
        saved=archives.save_dossier(r,self.root/'dossiers')
        r['status']='partial'
        with patch.object(archives,'collect',return_value=r) as collect:
            delta=dossier.run_tool(saved,'archive_search',{'target':'example.org','limit':5})
        self.assertEqual(delta['status'],'partial');self.assertEqual(collect.call_args.kwargs['limit'],5)
        dossier.merge_delta(saved,delta)
        self.assertEqual(saved['sections']['archives']['status'],'partial')
    def test_invalid_targets_dates_options_fail_before_network(self):
        with patch.object(archives,'_index') as fetch:
            for domain in ['https://user:pass@example.org','example.org:8080','127.0.0.1','localhost','x.local']:
                with self.assertRaises(ValueError):archives.collect(domain,self.root)
            for args in [dict(from_date='20230230'),dict(from_date='2024',to_date='2023'),dict(captures=21),dict(category='rce')]:
                with self.assertRaises(ValueError):archives.collect('example.org',self.root,**args)
            fetch.assert_not_called()
    def test_cdx_passes_filters_and_never_requests_target(self):
        calls=[]
        def get(url,hosts,timeout):
            calls.append(url)
            return {'html':json.dumps(self.cdx())}
        with patch.object(archives,'_index',side_effect=get):
            r=archives.collect('example.org',self.root,providers=['wayback'],from_date='2020',to_date='2024')
        self.assertEqual(len(r['records']),4)
        params=parse_qs(urlsplit(calls[0]).query)
        self.assertEqual(params['from'],['2020']);self.assertEqual(params['to'],['2024'])
        self.assertEqual({urlsplit(u).hostname for u in calls},{'web.archive.org'})
    def test_blocked_empty_timeout_and_malformed_are_distinct(self):
        for response,state in [(RuntimeError('HTTP 429'),'blocked'),(TimeoutError('late'),'timeout'),({'html':'[]'},'empty'),({'html':'{}'},'error')]:
            with self.subTest(state=state),patch.object(archives,'_index',side_effect=response if isinstance(response,Exception) else None,return_value=response):
                r=archives.collect('example.org',self.root,providers=['wayback'])
                self.assertEqual(r['status'],state)
    def test_unknown_dates_are_kept_with_explicit_coverage_gap(self):
        p=self.fixture(['https://example.org/api/old'])
        r=archives.collect('example.org',self.root,providers=[],imports=[p],from_date='2020')
        self.assertEqual(r['status'],'partial');self.assertEqual(r['unknown_dates'],1)
    def test_selected_snapshot_capture_raw_hash_links_and_redaction(self):
        p=self.fixture(self.cdx())
        body=b'''<script>const cfg={"apiKey":"fixture-sensitive-value"};fetch('/api/hidden');</script><a href="https://example.org/old">Old</a><a href="https://evil.org/other">External</a>'''
        calls=[]
        def fetch(url,**kwargs):
            calls.append((url,kwargs))
            return dict(body=body,html=body.decode(),sha256=hashlib.sha256(body).hexdigest(),content_type='text/html',observed_at='2026-10-04T00:00:00Z')
        snapshot='https://web.archive.org/web/20230102030405/https://example.org/api/v1?id=1'
        with patch.object(evidence_capture,'fetch_public',side_effect=fetch):
            r=archives.collect('example.org',self.root,providers=[],imports=[p],captures=1,capture_urls=[snapshot])
        self.assertEqual(len(calls),1);self.assertIn('20230102030405id_/',calls[0][0])
        self.assertEqual(calls[0][1]['allowed_hosts'],{'web.archive.org'})
        first=r['records'][0]
        self.assertEqual(Path(first['capture_path']).read_bytes(),body)
        self.assertIn('https://example.org/api/hidden',first['extracted_links'])
        self.assertNotIn('https://evil.org/other',first['extracted_links'])
        safe=archives.delta(r)
        self.assertNotIn('fixture-sensitive-value',json.dumps(safe))
        self.assertEqual(first['indicators'],['apikey'])
        saved=archives.save_dossier(r,self.root/'dossiers')
        self.assertTrue(any(edge['kind']=='HistoricalUrlCandidate' for edge in saved['relationship_graph']['edges']))
        self.assertTrue(any(event['event']=='snapshot' for event in saved['history']['timeline']))
        evidence=ai_agents._evidence(saved)
        self.assertNotIn('fixture-sensitive-value',json.dumps(evidence))
        self.assertTrue(any(row['section']=='archives' for row in evidence))
    def test_uncollected_capture_url_rejected(self):
        with self.assertRaises(ValueError),patch.object(evidence_capture,'fetch_public') as fetch:
            archives.collect('example.org',self.root,providers=[],imports=[self.fixture(self.cdx())],captures=1,
                capture_urls=['https://example.org/admin'])
        fetch.assert_not_called()
    def test_archive_redirect_stops_before_target_dns_and_connection(self):
        class Response:
            status=302
            def getheaders(self):return [('Location','https://example.org/live')]
        class Connection:
            def __init__(self,*args):pass
            def request(self,*a,**kw):pass
            def getresponse(self):return Response()
            def close(self):pass
        with patch.object(evidence_capture,'validated_url',return_value=('https://web.archive.org/','web.archive.org',['93.184.216.34'])) as dns,patch.object(evidence_capture,'_PinnedConnection',Connection):
            with self.assertRaisesRegex(ValueError,'Archive redirect'):
                evidence_capture.fetch_public('https://web.archive.org/',allowed_hosts={'web.archive.org'})
            self.assertEqual(dns.call_count,1)
    def test_archive_ai_tool_respects_domain_and_disabled_setting(self):
        state=dict(query='example.org',kind='domain',scope='domain',settings={'include_archives':False})
        self.assertNotIn('archive_search',research_agent._allowed(state))
        state['settings']['include_archives']=True
        self.assertIn('archive_search',research_agent._allowed(state))
        state['kind']='person'
        self.assertNotIn('archive_search',research_agent._allowed(state))
    def test_actual_pinned_waymore_otx_parser_through_guarded_transport(self):
        payload=dict(domain='example.org',provider='otx',folder=str(self.root/'worker'),subs=True,keys={})
        output=io.StringIO()
        def response(session,request,**kwargs):
            r=requests.Response();r.status_code=200;r.url=request.url
            r._content=json.dumps({'full_size':2,'url_list':[{'url':'https://example.org/api/past','httpcode':200},
                {'url':'https://sub.example.org/admin','httpcode':200}]}).encode()
            r._content_consumed=True
            return r
        with patch.dict('os.environ',{},clear=False),patch('sys.stdin',io.StringIO(json.dumps(payload))),patch('sys.argv',[]),contextlib.redirect_stdout(output),\
                patch('requests.Session.send',response),patch.object(evidence_capture,'validated_url',return_value=('https://otx.alienvault.com/','otx.alienvault.com',['93.184.216.34'])):
            waymore_worker.main()
        result=json.loads(output.getvalue())
        self.assertEqual(result['status'],'ok',result)
        self.assertIn('https://example.org/api/past',result['urls'])
        self.assertEqual({r['host'] for r in result['requests']},{'otx.alienvault.com'})
        self.assertFalse((self.root/'worker/config.yml').exists())


if __name__=='__main__':unittest.main()
