"""Failures reproduced by the public live-tool checks, without network calls."""
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from jf import additional_tools, extra_osint, github_tools, net, dossier, spiderfoot_scan, two_gis, domain_recon, osint_contacts
from jf.resilience import transient_error


class LiveToolRegressions(unittest.TestCase):
    def test_www_redirect_keeps_scripts_from_the_observed_final_host(self):
        with patch.object(osint_contacts,'_public_host',return_value=True), patch.object(osint_contacts.net,'_polite_wait'), \
                patch.object(osint_contacts,'_get',side_effect=[
                    ('https://example.org/robots.txt','User-agent: *\nAllow: /'),
                    ('https://www.example.org/','<html><script src="/js/main.js"></script><script src="https://foreign.org/a.js"></script></html>')]):
            result=osint_contacts.parse_public_page('https://example.org/')
        self.assertEqual(result['scripts'],['https://www.example.org/js/main.js'])

    def test_compressed_page_and_robots_decode_with_a_size_limit(self):
        import gzip
        from email.message import Message
        from unittest.mock import MagicMock
        class Response:
            def __init__(self,body):
                self.body=body
                self.headers=Message()
                self.headers['Content-Type']='text/html; charset=utf-8'
                self.headers['Content-Encoding']='gzip'
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,limit):return self.body[:limit]
            def geturl(self):return 'https://example.org/'
        opener=MagicMock()
        opener.open.return_value=Response(gzip.compress(b'<html>Published page</html>'))
        with patch.object(osint_contacts.urllib.request,'build_opener',return_value=opener):
            url,body=osint_contacts._get('https://example.org/','example.org')
        self.assertIn('Published page',body)
        opener.open.return_value=Response(gzip.compress(b'a'*1_000_001))
        with patch.object(osint_contacts.urllib.request,'build_opener',return_value=opener):
            url,body=osint_contacts._get('https://example.org/robots.txt','example.org')
        self.assertEqual((url,body),('',''))

    def test_webcheck_service_does_not_retain_an_expired_command_proxy(self):
        from unittest.mock import MagicMock
        process=MagicMock()
        process.poll.return_value=None
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{
                'LOCALAPPDATA':directory,'JOBFIND_ACTIVE_PROXY':'http://127.0.0.1:12345','HTTPS_PROXY':'http://127.0.0.1:12345'}), \
                patch.object(github_tools,'_health',side_effect=[None,{'ready':True}]), \
                patch.object(github_tools.shutil,'which',return_value='node.exe'), \
                patch.object(domain_recon,'configured_keys',return_value={'SHODAN_API_KEY':''}), \
                patch.object(Path,'exists',return_value=True), patch.object(github_tools.subprocess,'Popen',return_value=process) as start:
            github_tools._start_web_check(Path(directory))
            self.assertNotIn('HTTPS_PROXY',start.call_args.kwargs['env'])
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{'LOCALAPPDATA':directory}), \
                patch.object(github_tools,'_health',side_effect=[None,{'ready':True}]), \
                patch.object(github_tools.shutil,'which',return_value='node.exe'), \
                patch.object(domain_recon,'configured_keys',return_value={'SHODAN_API_KEY':''}), \
                patch.object(Path,'exists',return_value=True), patch.object(github_tools.subprocess,'Popen',return_value=process) as start:
            github_tools._start_web_check(Path(directory),port=12346,proxy='http://127.0.0.1:12345')
            env=start.call_args.kwargs['env']
            self.assertEqual(env['HTTPS_PROXY'],'http://127.0.0.1:12345')
            self.assertIn('--proxy-server=http://127.0.0.1:12345',env['CHROMIUM_ARGS'])

    def test_webcheck_api_context_closes_its_own_server_after_an_error(self):
        from unittest.mock import MagicMock
        process=MagicMock(pid=424242)
        process.poll.return_value=None
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{'JOBFIND_ACTIVE_PROXY':'http://127.0.0.1:12345'}), \
                patch.object(github_tools,'_start_web_check',return_value=process) as start, \
                patch.object(github_tools.subprocess,'run') as stop:
            with self.assertRaisesRegex(RuntimeError,'provider failed'):
                with github_tools.web_check_api(Path(directory)) as endpoint:
                    self.assertTrue(endpoint.startswith('http://127.0.0.1:'))
                    raise RuntimeError('provider failed')
            self.assertEqual(start.call_args.kwargs['proxy'],'http://127.0.0.1:12345')
            if sys.platform=='win32':self.assertIn('424242',stop.call_args.args[0])
            process.wait.assert_called_once()

    def test_domain_addresses_keep_dns_failures_and_exclude_private_ips(self):
        from jf import domain_enrichment
        with patch.object(domain_enrichment,'dns_query',side_effect=[
                {'state':'success','records':[{'value':'1.1.1.1'},{'value':'10.0.0.1'}]},
                {'state':'timeout','records':[]}]) as query:
            ips,checks=domain_recon._public_ips('example.org')
        self.assertEqual(ips,['1.1.1.1'])
        self.assertEqual(checks[1]['state'],'timeout')
        self.assertEqual(query.call_args_list[1].args,('example.org','AAAA'))

    def test_two_gis_modern_links_and_partial_search_response_are_retained(self):
        import importlib
        sys.path.insert(0,str(two_gis.UPSTREAM))
        parser_module=importlib.import_module('parser_2gis.parser')
        chrome_utils=importlib.import_module('parser_2gis.chrome.utils')
        nodes=[SimpleNamespace(local_name='a',attributes={'href':'/moscow/firm/100'},backend_id=999),
            SimpleNamespace(local_name='a',attributes={'href':'https://foreign.example/firm/100'},backend_id=1)]
        response={'status':200,'url':'https://catalog.api.2gis.ru/3.0/items'}
        item={'id':'100','type':'branch','name_ex':{'primary':'Fixture Museum'},'address_name':'Fixture Street'}
        class Tree:
            def search(self,match):return [n for n in nodes if match(n)]
        class Remote:
            def get_document(self):return Tree()
            def get_responses(self,**kwargs):return [response]
            def wait_response(self,pattern,timeout=None):
                self.timeout=timeout
                return None
            def get_response_body(self,*args,**kwargs):return json.dumps({'meta':{'code':200},'result':{'items':[item]}})
            def execute_script(self,expression):return True
            def perform_click(self,*args,**kwargs):raise AssertionError('Stale backend node ID must not be used')
        remote=Remote()
        class Parser:
            _chrome_remote=remote
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def parse(self,writer):
                self._wait_requests_finished()
                found=self._get_links()
                if len(found)!=1:raise AssertionError('Foreign firm URL was retained')
                remote.perform_click(found[0])
                remote.wait_response('fixture')
        with tempfile.TemporaryDirectory() as directory, patch.object(parser_module,'get_parser',return_value=Parser()), \
                patch.object(chrome_utils,'locate_chrome_path',return_value='fixture.exe'):
            path=Path(directory)/'raw.json'
            state=two_gis._collect_worker('https://2gis.ru/moscow/search/museum',path,1,0)
            saved=json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(state['state'],'partial')
        self.assertEqual(saved[0]['name_ex']['primary'],'Fixture Museum')
        self.assertEqual(remote.timeout,30)

    def test_github_username_uses_owner_case_insensitively_and_drops_foreign_repos(self):
        import importlib
        spiderfoot_scan._load()
        module = importlib.import_module('modules.sfp_github').sfp_github()
        from spiderfoot import SpiderFootEvent
        own={'name':'earth-data','html_url':'https://github.com/NASA/earth-data','description':'Public data'}
        foreign={'name':'nasa','html_url':'https://github.com/foreign/nasa','description':'Different owner'}
        class Source:
            def fetchUrl(self, url, **kwargs):
                data={'total_count':2,'items':[own,foreign]} if '/search/repositories' in url else \
                    {'total_count':1,'items':[{'repos_url':'https://api.github.com/users/NASA/repos'}]} if '/search/users' in url else [own,foreign]
                return {'content':json.dumps(data)}
        module.setup(Source(), {'namesonly':True,'_fetchtimeout':5,'_useragent':'fixture'})
        module.debug=lambda *a,**k:None
        events=[]
        module.notifyListeners=events.append
        root=SpiderFootEvent('ROOT','nasa','fixture',None)
        module.handleEvent(SpiderFootEvent('USERNAME','nasa','fixture',root))
        self.assertTrue(events)
        self.assertTrue(all('NASA/earth-data' in e.data for e in events))
        self.assertFalse(any('foreign' in e.data for e in events))

    def test_tiktok_merges_with_profile_without_losing_collector_provenance(self):
        result={'query':'nasa','observed_at':'2026-10-13T00:00:00Z','sections':{'profiles':[
            {'url':'https://www.tiktok.com/@nasa','source':'Maigret'}]},'errors':[],'source_checks':[],'artifacts':[]}
        dossier.merge_delta(result, {'profiles':[{'url':'https://www.tiktok.com/@nasa','source':'TikTok Scraper','bio':'Public bio'}]})
        self.assertEqual(len(result['sections']['profiles']),1)
        self.assertEqual(result['sections']['profiles'][0]['sources'],['Maigret','TikTok Scraper'])

    def test_map_query_keeps_cyrillic_city_and_name(self):
        import io
        with tempfile.TemporaryDirectory() as directory, patch.object(additional_tools.urllib.request,'urlopen',
                return_value=io.BytesIO(b'{"elements":[]}')) as request:
            additional_tools.map_search('Ахматовой','Санкт-Петербург',Path(directory))
        body=additional_tools.urllib.parse.parse_qs(request.call_args.args[0].data.decode())['data'][0]
        self.assertIn('Санкт-Петербург',body)
        self.assertIn('Ахматовой',body)
        self.assertNotIn('\\u04',body)

    def test_subfinder_timeout_keeps_complete_target_hostnames(self):
        error = subprocess.TimeoutExpired('subfinder', 75,
            output=b'www.example.org\nforeign.org\napi.example.org\n', stderr=b'provider timed out')
        with patch.object(Path, 'is_file', return_value=True), patch.object(
                extra_osint.subprocess, 'run', side_effect=error):
            result = extra_osint.subfinder('example.org')
        self.assertEqual(result['hostnames'], ['www.example.org', 'api.example.org'])
        self.assertIn('time limit', result['errors'][0])

    def test_blackbird_does_not_read_or_delete_existing_results(self):
        with tempfile.TemporaryDirectory() as directory:
            vendor = Path(directory)
            (vendor/'src').mkdir(); (vendor/'data').mkdir(); (vendor/'results').mkdir()
            (vendor/'blackbird.py').write_text('# fixture', encoding='utf-8')
            (vendor/'data/wmn-data.json').write_text(json.dumps({'sites':[
                {'cat':'coding','uri_check':'https://example.org/{account}'}]*100}), encoding='utf-8')
            old = vendor/'results/old.json'
            old.write_text(json.dumps([{'status':'FOUND','url':'https://example.org/stale'}]))
            def fresh(command, timeout, cwd=None, env=None):
                self.assertNotEqual(Path(cwd), vendor)
                self.assertLessEqual(len(json.loads((Path(cwd)/'data/wmn-data.json').read_text())['sites']),48)
                result=Path(cwd)/'results'; result.mkdir()
                (result/'new.json').write_text(json.dumps([
                    {'status':'FOUND','url':'https://example.org/ada'}]))
                return '', '', False
            with patch.object(extra_osint,'BLACKBIRD',vendor), patch.object(extra_osint,'_run',side_effect=fresh):
                result=extra_osint.blackbird('ada','username')
            self.assertEqual([row['url'] for row in result['profiles']],['https://example.org/ada'])
            self.assertTrue(old.exists())
            self.assertEqual(result['planned'],48)

    def test_maigret_explicit_proxy_does_not_inherit_second_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            def run(command, **kwargs):
                self.assertIn('--proxy',command)
                self.assertNotIn('HTTPS_PROXY',kwargs['env'])
                folder=Path(command[command.index('--folderoutput')+1])
                (folder/'report_ada_simple.json').write_text('{}')
                return subprocess.CompletedProcess(command,0,'','Too many errors of type Request timeout')
            with patch.object(Path,'exists',return_value=True), patch.object(github_tools.subprocess,'run',side_effect=run), \
                    patch.dict(os.environ,{'JOBFIND_ACTIVE_PROXY':'http://127.0.0.1:12345','HTTPS_PROXY':'http://127.0.0.1:12345'}):
                result=github_tools.maigret_search('ada',Path(directory),20)
            self.assertEqual(result['status'],'error')
            self.assertTrue(result['warnings'])

    def test_instagram_keeps_partial_profile_and_reports_access_block(self):
        with tempfile.TemporaryDirectory() as directory:
            def run(command, cwd, timeout):
                Path(command[4]).write_text(json.dumps({'profile':{'url':'https://www.instagram.com/example/'},
                    'posts':[],'errors':['Instaloader: 401 Unauthorized']}))
                return 1,''
            with patch.object(Path,'exists',return_value=True), patch.object(additional_tools,'_run',side_effect=run):
                result=additional_tools._instagram('example',Path(directory),'quick')
            self.assertEqual(result['statuses'][0]['status'],'partial')
            self.assertEqual(len(result['profiles']),1)
            self.assertNotIn('Instaloader: ', result['errors'])

    def test_record_corruption_retries_but_certificate_failure_does_not(self):
        error=ssl.SSLError(1,'corrupted record')
        error.reason='DECRYPTION_FAILED_OR_BAD_RECORD_MAC'
        self.assertTrue(transient_error(error))
        self.assertFalse(transient_error(ssl.SSLCertVerificationError(1,'untrusted certificate')))

    def test_small_collector_budget_and_body_limit_reach_transport(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):
                self.limit=limit
                return b'public result'
        response=Response()
        with patch.object(net,'_polite_wait'), patch.object(net.urllib.request,'urlopen',return_value=response) as send:
            result=net.get('https://budget.example.org',timeout=4,max_bytes=512,retries=0)
        self.assertEqual(response.limit,512)
        self.assertLessEqual(send.call_args.kwargs['timeout'],4)
        self.assertEqual(result.status,200)
