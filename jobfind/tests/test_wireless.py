"""Synthetic, offline integration checks. Never discover real devices or call APIs."""
import hashlib
import asyncio
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from jf import wireless, dossier, ai_agents, net


class WirelessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.out=self.root/'out'

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self,name,data):
        p=self.root/name
        p.write_text(data if isinstance(data,str) else json.dumps(data),encoding='utf-8')
        return p

    def test_import_preserves_missing_fields_and_zero_coordinates(self):
        p=self.fixture('survey.json',[{'name':'Demo camera','latitude':0,'longitude':0,'password':'do-not-export'}])
        rows,art,cols,limited,rejected=wireless.import_file(p)
        self.assertEqual((rows[0]['latitude'],rows[0]['longitude']),(0,0))
        self.assertEqual(rows[0]['device_id'],'')
        self.assertIsNone(rows[0]['rssi_dbm'])
        self.assertEqual(rows[0]['observed_at'],'')
        self.assertNotIn('do-not-export',json.dumps(rows))
        self.assertEqual(art['sha256'],hashlib.sha256(p.read_bytes()).hexdigest())
        self.assertEqual(rows[0]['category_candidate'],'camera')

    def test_wigle_csv_header_and_actual_rssi(self):
        p=self.fixture('wifi.csv','WigleWifi-1.4,appRelease=demo\nMAC,SSID,CurrentLatitude,CurrentLongitude,RSSI,FirstSeen,Type\n02:00:00:00:00:01,Demo AP,12.5,24.5,-62,2026-01-01T00:00:00Z,WIFI\n')
        rows,*_=wireless.import_file(p)
        self.assertEqual(rows[0]['name'],'Demo AP')
        self.assertEqual(rows[0]['rssi_dbm'],-62)
        self.assertEqual(rows[0]['observed_at'],'2026-01-01T00:00:00Z')

    def test_invalid_nan_and_out_of_range_not_plotted(self):
        p=self.fixture('bad.json',[{'name':'One','lat':'NaN','lon':0},{'name':'Two','lat':91,'lon':1}])
        rows,_,_,_,bad=wireless.import_file(p)
        self.assertEqual((rows,bad),([],2))
        result=wireless.collect(self.out,files=[p])
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['records'],[])

    def test_unknown_address_is_not_fuzzy_matched_as_latitude(self):
        p=self.fixture('no-gps.json',[{'ssid':'Demo AP','address':'12.5'}])
        rows,*_=wireless.import_file(p)
        self.assertIsNone(rows[0]['latitude'])
        self.assertIsNone(rows[0]['longitude'])

    def test_manual_columns(self):
        p=self.fixture('columns.csv','North,East,Device\n12,24,Demo\n')
        rows,*_=wireless.import_file(p,{'lat':'North','lon':'East','ssid':'Device'})
        self.assertEqual((rows[0]['latitude'],rows[0]['longitude']),(12,24))
        with self.assertRaises(ValueError):wireless.import_file(p,{'lat':'Missing'})

    def test_geojson_point_order(self):
        p=self.fixture('survey.geojson',{'type':'FeatureCollection','features':[{'type':'Feature','geometry':{'type':'Point','coordinates':[24,12]},'properties':{'name':'Demo'}}]})
        rows,*_=wireless.import_file(p)
        self.assertEqual((rows[0]['latitude'],rows[0]['longitude']),(12,24))

    def test_kml_namespace_and_entities(self):
        p=self.fixture('survey.kml','<kml xmlns="http://www.opengis.net/kml/2.2"><Document><Placemark><name>Demo</name><Point><coordinates>24,12,0</coordinates></Point></Placemark></Document></kml>')
        rows,*_=wireless.import_file(p)
        self.assertEqual((rows[0]['name'],rows[0]['latitude']),('Demo',12))
        malicious=self.fixture('bad.kml','<!DOCTYPE kml [<!ENTITY x "expand">]><kml><Placemark><name>&x;</name></Placemark></kml>')
        result=wireless.collect(self.out,files=[malicious])
        self.assertEqual(result['status'],'error')

    def test_sqlite_is_read_only_and_quotes_table_names(self):
        p=self.root/'survey.db'
        with sqlite3.connect(p) as c:
            c.execute('CREATE TABLE "survey\'data" (name TEXT, latitude REAL, longitude REAL)')
            c.execute('INSERT INTO "survey\'data" VALUES (?,?,?)',('Demo',12,24))
        digest=hashlib.sha256(p.read_bytes()).hexdigest()
        rows,*_=wireless.import_file(p)
        self.assertEqual(rows[0]['latitude'],12)
        self.assertEqual(digest,hashlib.sha256(p.read_bytes()).hexdigest())
        self.assertFalse(p.with_name(p.name+'-journal').exists())

    def test_excel(self):
        import openpyxl
        p=self.root/'survey.xlsx'
        book=openpyxl.Workbook()
        book.active.append(['Name','Latitude','Longitude'])
        book.active.append(['Demo',12,24])
        book.save(p)
        book.close()
        rows,*_=wireless.import_file(p)
        self.assertEqual(rows[0]['name'],'Demo')

    def test_alpr_composite_coordinates_do_not_invent_operator(self):
        p=self.fixture('cameras.json',[{'name':'Camera 1','coordinates':'12, 24','brand':'Example'},
                                     {'name':'Camera 2','coordinates':'13, 25','brand':'Example'}])
        rows,*_=wireless.import_file(p)
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[1]['latitude'],13)
        self.assertEqual(rows[0]['operator'],'')

    def test_row_budget_is_explicit(self):
        p=self.fixture('many.json',[{'name':str(i),'lat':12,'lon':24} for i in range(wireless.MAX_ROWS+1)])
        result=wireless.collect(self.out,files=[p])
        self.assertEqual(result['status'],'partial')
        self.assertEqual(len(result['records']),wireless.MAX_ROWS)
        self.assertIn('limited',result['statuses'][0]['detail'])

    def test_malformed_and_empty_are_distinct_and_other_file_survives(self):
        invalid=self.fixture('bad.json','not JSON')
        valid=self.fixture('valid.json',[{'name':'Demo','lat':12,'lon':24}])
        result=wireless.collect(self.out,files=[invalid,valid])
        self.assertEqual(result['status'],'partial')
        self.assertEqual(len(result['records']),1)
        self.assertEqual([s['status'] for s in result['statuses']],['error','ok'])
        empty=self.fixture('empty.json',[])
        self.assertEqual(wireless.collect(self.out,files=[empty])['status'],'empty')

    def test_missing_keys_make_no_request(self):
        with patch.object(wireless,'keys',return_value=dict.fromkeys(wireless.KEY_NAMES,'')),patch.object(net,'get') as get:
            result=wireless.collect(self.out,providers=['wigle','opencellid','shodan','censys'],latitude=0,longitude=0)
        get.assert_not_called()
        self.assertEqual(result['status'],'skipped')

    def test_api_block_timeout_and_malformed_json_are_distinct(self):
        cases=[(net.HttpResult(403,b'', 'https://example.org',error='HTTP 403'),'blocked'),
               (net.HttpResult(0,b'', 'https://example.org',error='failed',metadata={'state':'timeout'}),'timeout'),
               (net.HttpResult(200,b'bad', 'https://example.org'),'error'),
               (net.HttpResult(200,b'{"results":[]}', 'https://example.org'),'ok')]
        for response,expected in cases:
            with self.subTest(state=expected),patch.object(net,'get',return_value=response):
                _,state,detail=wireless._api('https://example.org',{'key':'secret-token'})
                self.assertEqual(state,expected)
                self.assertNotIn('secret-token',detail)

    def test_indexed_cell_is_not_confirmed_tower_or_measured_rssi(self):
        configured=dict.fromkeys(wireless.KEY_NAMES,'demo-token')
        response={'cells':[{'lat':12,'lon':24,'cellid':4,'mcc':1,'mnc':2,'lac':3,'averageSignalStrength':0}]}
        with patch.object(wireless,'_api',return_value=(response,'ok','')) as request:
            rows,state,detail=wireless._area('opencellid',12,24,1,configured)
        self.assertEqual(rows[0]['category_candidate'],'cell_record')
        self.assertIsNone(rows[0]['rssi_dbm'])
        self.assertIn('estimate',rows[0]['location_basis'])
        self.assertTrue(request.call_args.args[0].startswith('https://'))

    def test_wifi_percent_is_not_rssi(self):
        raw='SSID 1 : Demo\n    BSSID 1 : 02:00:00:00:00:01\n    Сигнал : 83%\n'
        rows=wireless.parse_netsh(raw)
        self.assertEqual(rows[0]['signal_percent'],83)
        self.assertNotIn('rssi_dbm',rows[0])

    def test_wifi_zero_exit_permission_message_is_not_an_empty_survey(self):
        api=SimpleNamespace(kernel32=SimpleNamespace(GetOEMCP=lambda:65001))
        for text,expected in [('Location permission is required','blocked'),
                              ('Number of networks visible : 0','empty'),
                              ('Количество сетей : 0','empty')]:
            process=SimpleNamespace(returncode=0,stdout=text.encode('utf-8'))
            with self.subTest(text=text),patch.object(wireless.os,'name','nt'),patch('ctypes.windll',api,create=True),patch.object(wireless.subprocess,'run',return_value=process):
                self.assertEqual(wireless._wifi()[1],expected)

    def test_local_hardware_keeps_coordinates_unknown(self):
        row=dict(name='Demo SDR',device_id='',protocol='USB',category_candidate='sdr_hardware')
        with patch.object(wireless,'_sdr',return_value=([row],'ok','USB only')):
            result=wireless.collect(self.out,sdr=True)
        self.assertIsNone(result['records'][0]['latitude'])
        geo=json.loads(Path(result['reports']['geojson']).read_text())
        self.assertEqual(geo['features'],[])

    def test_exports_escape_html_and_csv_formulas(self):
        p=self.fixture('escape.json',[{'name':'</script><script>alert(1)</script>','lat':12,'lon':24},
                                     {'name':'=1+1','lat':13,'lon':25}])
        result=wireless.collect(self.out,files=[p])
        document=Path(result['reports']['map']).read_text(encoding='utf-8')
        self.assertNotIn('</script><script>alert',document)
        self.assertIn("'=1+1",Path(result['reports']['csv']).read_text(encoding='utf-8-sig'))

    def test_dossier_graph_and_ai_artifact_attribution(self):
        p=self.fixture('survey.json',[{'name':'Demo AP','lat':12,'lon':24}])
        result=wireless.collect(self.out,files=[p])
        saved=wireless.save_dossier(result,self.out/'dossiers')
        self.assertEqual(saved['kind'],'wireless')
        self.assertEqual(saved['sections']['findings'][0]['certainty'],'candidate')
        self.assertTrue(Path(saved['graph_path']).is_file())
        evidence=ai_agents._evidence(saved)
        self.assertTrue(any(row['provenance']=='local_artifact' and 'Demo AP' in row['text'] for row in evidence))
        self.assertFalse(any(edge['certainty']=='observed' and edge['kind']=='CollectedFinding' for edge in saved['relationship_graph']['edges']))
        anchor=next(row for row in evidence if row['provenance']=='local_artifact' and 'Demo AP' in row['text'])
        claims,rejected=ai_agents._validated_claims(json.dumps({'claims':[
            {'statement':'Imported Demo AP observation', 'quote':'Demo AP', 'evidence_id':anchor['id']},
            {'statement':'Imported nonexistent observation', 'quote':'Invented device', 'evidence_id':anchor['id']}]}),evidence)
        self.assertEqual(len(claims),1)
        self.assertEqual(rejected,1)
        self.assertEqual(claims[0]['source_url'],anchor['url'])

    def test_native_json_reimport_preserves_signal_and_identifiers(self):
        p=self.fixture('native.json',[{'name':'Demo AP','latitude':12,'longitude':24,'device_id':'02:00:00:00:00:01',
                'rssi_dbm':-62,'signal_percent':83,'protocol':'Wi-Fi','observed_at':'2026-10-03T00:00:00Z'}])
        original=wireless.collect(self.out,files=[p])
        rows,*_=wireless.import_file(original['reports']['json'])
        for key in ('device_id','rssi_dbm','signal_percent','protocol','observed_at'):
            self.assertEqual(rows[0][key],original['records'][0][key])

    def test_ble_uses_actual_advertisement_and_estimate_without_coordinates(self):
        from bleak import BleakScanner
        from unittest.mock import AsyncMock
        dev=SimpleNamespace(name='Demo headphones',address='02:00:00:00:00:01')
        adv=SimpleNamespace(rssi=-65,tx_power=None,local_name='')
        with patch.object(BleakScanner,'discover',new=AsyncMock(return_value={'a':(dev,adv)})):
            rows=asyncio.run(wireless._ble_scan(1))
        self.assertEqual(rows[0]['rssi_dbm'],-65)
        self.assertGreater(rows[0]['estimated_distance_m'],0)
        self.assertNotIn('latitude',rows[0])
        with patch.object(wireless,'_ble_scan',side_effect=TimeoutError):
            self.assertEqual(wireless._ble(1)[1],'timeout')

    def test_research_phase_preserves_partial_import_checks_and_csv(self):
        p=self.fixture('research.json',[{'name':'Demo AP','lat':12,'lon':24},{'name':'Invalid','lat':200,'lon':24}])
        with patch.object(dossier.extra_osint,'supplement',return_value={}):
            result=dossier.collect('fixture@example.org','email','email',self.out/'dossiers',
                include_spiderfoot=False,include_extra_tools=False,capture_pages=-1,wireless_files=[p])
        self.assertEqual(len(result['sections']['wireless']['records']),1)
        self.assertEqual(next(row['state'] for row in result['source_checks'] if row['source']=='wireless'),'partial')
        self.assertIn('Demo AP',Path(result['report_csv']).read_text(encoding='utf-8-sig'))
        self.assertTrue(any(row['provenance']=='local_artifact' for row in ai_agents._evidence(result)))

    def test_mixed_geojson_does_not_hide_omitted_geometry(self):
        p=self.fixture('mixed.geojson',{'type':'FeatureCollection','features':[
            {'type':'Feature','geometry':{'type':'Point','coordinates':[24,12]},'properties':{'name':'Demo'}},
            {'type':'Feature','geometry':{'type':'Polygon','coordinates':[]},'properties':{}}]})
        result=wireless.collect(self.out,files=[p])
        self.assertEqual(result['status'],'partial')
        self.assertEqual(len(result['records']),1)

    def test_censys_uses_modern_api_and_rejects_bad_schema(self):
        p=self.fixture('ip.json',[{'name':'Demo','lat':12,'lon':24,'ip':'8.8.8.8'}])
        configured=dict.fromkeys(wireless.KEY_NAMES,'test-token')
        with patch.object(wireless,'keys',return_value=configured),patch.object(wireless,'_api',return_value=({'result':[]},'ok','')) as call:
            result=wireless.collect(self.out,files=[p],providers=['censys'])
        self.assertIn('/v3/global/asset/host/',call.call_args.args[0])
        self.assertEqual(result['statuses'][-1]['status'],'error')
        self.assertEqual(result['status'],'partial')


if __name__=='__main__':unittest.main()
