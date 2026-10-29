"""Passive archive indices and selected historical responses in unified dossiers."""
from __future__ import annotations
import ast
import calendar
import csv
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit
from bs4 import BeautifulSoup
from . import evidence_capture

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = ('wayback', 'commoncrawl', 'otx', 'urlscan', 'virustotal', 'intelx', 'ghostarchive')
SOURCE_URLS = dict(wayback='https://web.archive.org/cdx/search/cdx',
                  commoncrawl='https://index.commoncrawl.org/', otx='https://otx.alienvault.com/',
                  urlscan='https://urlscan.io/', virustotal='https://www.virustotal.com/',
                  intelx='https://intelx.io/', ghostarchive='https://ghostarchive.org/')
CATEGORIES = ('api', 'admin', 'debug', 'backup', 'config', 'javascript', 'parameters', 'other')
KEY_NAMES = ('URLSCAN_API_KEY', 'VIRUSTOTAL_API_KEY', 'INTELX_API_KEY')
TEXT_TYPES = {'text/html', 'text/plain', 'application/xhtml+xml', 'application/json',
              'application/javascript', 'text/javascript', 'text/css', 'application/xml', 'text/xml'}
_HELPERS = None


def _helpers():
    """Execute only pure, unmodified upstream replay-URL helpers (MIT)."""
    global _HELPERS
    if _HELPERS is None:
        source = ROOT / 'third_party/waymore/waymore/waymore.py'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            tree = ast.parse(source.read_text(encoding='utf-8'))
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
                 node.name in {'fixArchiveOrgUrl', 'addRawModifier'}]
        if len(nodes) != 2:
            raise RuntimeError('Pinned waymore helpers unavailable')
        scope = {}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), scope)
        _HELPERS = scope
    return _HELPERS


def domain_name(value):
    value = str(value).strip()
    if value.startswith(('http://', 'https://')):
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.port:
            raise ValueError('Enter a public domain without credentials or port')
        value = parsed.hostname or ''
    value = value.rstrip('.').encode('idna').decode('ascii').lower()
    if not evidence_capture.DOMAIN.fullmatch(value) or value.endswith(('.local', '.localhost', '.internal', '.test', '.invalid')):
        raise ValueError('Enter a public DNS domain')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Archive search requires a DNS domain')


def date_value(value, end=False):
    if not value:
        return ''
    if not re.fullmatch(r'(?:\d{4}|\d{6}|\d{8})', value):
        raise ValueError('Archive dates use YYYY, YYYYMM or YYYYMMDD')
    parsed=datetime.strptime(value, {4:'%Y', 6:'%Y%m', 8:'%Y%m%d'}[len(value)])
    if end:
        month=12 if len(value)==4 else parsed.month
        day=calendar.monthrange(parsed.year,month)[1] if len(value)<8 else parsed.day
        parsed=parsed.replace(month=month,day=day,hour=23,minute=59,second=59)
    return parsed.strftime('%Y%m%d%H%M%S')


def redacted(value):
    value = re.sub(r'(?i)([?&](?:api[_-]?key|access[_-]?token|token|password|secret|auth|signature)=)[^&#\s]*', r'\1[redacted]', str(value))
    value = re.sub(r'''(?i)(["']?(?:api[_-]?key|access[_-]?token|token|password|secret|authorization)["']?\s*[=:]\s*["']?)[^\s"';&<>]+''', r'\1[redacted]', value)
    return re.sub(r'(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]+', r'\1[redacted]', value)


def categories(url):
    path = unquote(urlsplit(url).path).lower()
    tags = []
    if re.search(r'/(?:api|graphql|swagger|v\d+)(?:/|\.|$)', path): tags.append('api')
    if re.search(r'/(?:admin|administrator|wp-admin|manage|console)(?:/|\.|$)', path): tags.append('admin')
    if re.search(r'/(?:test|debug|dev|staging|phpinfo)(?:/|\.|$)', path): tags.append('debug')
    if re.search(r'\.(?:bak|sql|old|backup|zip|tar|gz|7z)(?:$|/)', path): tags.append('backup')
    if re.search(r'/(?:\.git|\.env|config)(?:/|\.|$)|\.(?:ini|conf|cfg|yml|yaml)$', path): tags.append('config')
    if path.endswith(('.js', '.mjs', '.map')): tags.append('javascript')
    if urlsplit(url).query: tags.append('parameters')
    return tags or ['other']


def record(url, domain, provider, timestamp='', status='', mime='', subs=True, **extra):
    url = _helpers()['fixArchiveOrgUrl'](str(url).strip())
    if len(url) > 4096 or '\\' in url or any(ord(c)<32 for c in url):
        return None
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or '').rstrip('.').encode('idna').decode('ascii').lower()
        if parsed.scheme not in ('http','https') or parsed.username is not None or parsed.password is not None:
            return None
        if host != domain and not (subs and host.endswith('.'+domain)):
            return None
        parsed.port  # validate malformed ports; never request the original URL
        original = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', parsed.query, ''))
    except (ValueError, UnicodeError):
        return None
    timestamp = str(timestamp)
    if not re.fullmatch(r'\d{14}', timestamp):
        timestamp = ''
    else:
        try: datetime.strptime(timestamp, '%Y%m%d%H%M%S')
        except ValueError: timestamp = ''
    snapshot = 'https://web.archive.org/web/'+timestamp+'/'+original if provider=='wayback' and timestamp else ''
    return dict(original_url=original, url=snapshot or SOURCE_URLS.get(provider, SOURCE_URLS['wayback']),
                source_url=snapshot or SOURCE_URLS.get(provider, SOURCE_URLS['wayback']),
                source=provider, snapshot_at=timestamp, archived=True, http_status=str(status), mime_type=str(mime),
                categories=categories(original), parameters=sorted({k for k,v in parse_qsl(parsed.query, keep_blank_values=True)})[:40],
                certainty='historical candidate; current availability and vulnerability unverified', **extra)


def _index(url, hosts, timeout=15):
    from . import net, diagnostics
    deadline=time.monotonic()+timeout
    for attempt in range(2):
        net._polite_wait(urlsplit(url).hostname, deadline=deadline)
        try:
            response=evidence_capture.fetch_public(url, allowed_hosts=hosts, timeout=max(2,deadline-time.monotonic()),
                request_headers={'Accept':'application/json,text/plain'},
                accepted_types={'application/json','text/plain','application/x-ndjson'})
            diagnostics.record_network(dict(host=urlsplit(url).hostname,method='GET',status=200,state='ok',attempts=attempt+1))
            return response
        except (TimeoutError,ConnectionError,RuntimeError) as exc:
            code=re.search(r'HTTP (\d{3})',str(exc))
            code=int(code.group(1)) if code else 0
            retry=attempt==0 and deadline-time.monotonic()>3 and (isinstance(exc,(TimeoutError,ConnectionError)) or code in {500,502,503,504})
            if not retry:
                diagnostics.record_network(dict(host=urlsplit(url).hostname,method='GET',status=code,
                    state='blocked' if code in {401,403,429} else 'timeout' if isinstance(exc,TimeoutError) else 'error',attempts=attempt+1))
                raise
    raise TimeoutError('Archive index time budget reached')


def _table(table, domain, provider, subs):
    if not isinstance(table, list) or (table and not isinstance(table[0], list)):
        raise ValueError('Archive returned an invalid CDX table')
    if not table: return []
    header = table[0]
    if 'original' not in header or 'timestamp' not in header:
        raise ValueError('Archive returned unexpected CDX columns')
    rows = []
    for values in table[1:]:
        if not isinstance(values, list) or len(values)!=len(header):
            raise ValueError('Archive returned a malformed CDX row')
        item = dict(zip(header, values))
        row = record(item['original'], domain, provider, item.get('timestamp',''),
                     item.get('statuscode',''), item.get('mimetype',''), subs)
        if row: rows.append(row)
    return rows


def _keys():
    stored = {}
    path = ROOT/'osint-keys.env'
    if path.is_file():
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            key, sep, val = line.partition('=')
            if sep and key.strip() in KEY_NAMES: stored[key.strip()] = val.strip().strip('"\'')
    return {key:os.environ.get(key, stored.get(key,'')) for key in KEY_NAMES}


def _waymore(domain, provider, folder, subs, start, end, timeout):
    keys = _keys()
    required = {'virustotal':'VIRUSTOTAL_API_KEY', 'intelx':'INTELX_API_KEY'}.get(provider)
    if required and not keys[required]:
        return [], 'skipped', 'Set '+required+' in osint-keys.env', []
    work = Path(tempfile.mkdtemp(prefix=provider+'-', dir=folder))
    args = dict(domain=domain, provider=provider, folder=str(work), subs=subs,
                from_date=date_value(start), to_date=date_value(end,True), keys=keys)
    try:
        process = subprocess.run([sys.executable, str(ROOT/'jf/waymore_worker.py')],
            input=json.dumps(args), capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=max(1,min(40,timeout)), cwd=ROOT, creationflags=0x08000000 if os.name=='nt' else 0)
        data = json.loads(process.stdout)
        if not isinstance(data.get('urls'),list) or data.get('status') not in {'ok','empty','error','partial','skipped','blocked','timeout'}:
            raise ValueError('Invalid worker response')
        from . import diagnostics
        for request in (data.get('requests') or [])[:6]:
            diagnostics.record_network(dict(host=request.get('host',''),method='GET',
                state=request.get('state','error'),status=request.get('http_status',0),attempts=1))
        rows = [record(url,domain,provider,subs=subs) for url in data['urls'][:5000]]
        return [r for r in rows if r], data['status'], data.get('detail','Bounded upstream waymore URL collection'), data.get('requests',[])
    except subprocess.TimeoutExpired:
        path = work/'urls.txt'
        urls = path.read_text(encoding='utf-8',errors='replace').splitlines()[:5000] if path.is_file() else []
        rows = [record(url,domain,provider,subs=subs) for url in urls]
        return [r for r in rows if r], 'partial' if any(rows) else 'timeout', 'Upstream source reached its time limit', []
    except Exception:
        return [], 'error', 'Upstream collector response could not be read', []
    finally:
        (work/'config.yml').unlink(missing_ok=True)


def import_file(path, domain, subs=True):
    path = Path(path).resolve()
    if not path.is_file() or path.stat().st_size>10_000_000:
        raise ValueError('Select an archive export of at most 10 MB')
    body = path.read_bytes()
    text = body.decode('utf-8-sig')
    try: data = json.loads(text)
    except json.JSONDecodeError:
        data=[]
        for line in text.splitlines()[:5001]:
            if not line.strip(): continue
            try:data.append(json.loads(line))
            except json.JSONDecodeError:data.append(line)
    if isinstance(data,dict): data = data.get('records',data.get('urls',[]))
    if not isinstance(data,list): raise ValueError('Expected URL lines, CDX JSON, or archive records')
    if data and isinstance(data[0],list):
        rows = _table(data[:5002],domain,'wayback',subs)
    else:
        rows=[]
        for item in data[:5001]:
            if isinstance(item,str): row=record(item,domain,'wayback',subs=subs,imported=True)
            elif isinstance(item,dict):
                provider=str(item.get('source','wayback')).lower().replace(' ','')
                provider=provider if provider in PROVIDERS else 'wayback'
                row=record(item.get('original_url') or item.get('url',''),domain,provider,
                    item.get('snapshot_at') or item.get('timestamp',''),item.get('http_status') or item.get('statuscode',''),
                    item.get('mime_type') or item.get('mimetype',''),subs,imported=True)
                if row and item.get('discovered_in'):
                    match=re.fullmatch(r'https://web\.archive\.org/web/(\d{14})/(https?://.+)',str(item['discovered_in']))
                    reference=record(match[2],domain,'wayback',match[1],subs=subs) if match else None
                    if reference:
                        row.update(discovered_in=reference['source_url'],url=reference['source_url'],source_url=reference['source_url'],
                            certainty='URL referenced in archived content; independent snapshot and current availability unverified',capture_status='not_indexed')
                    else:row=None
            else: row=None
            if row: rows.append(row)
    return rows, dict(path=str(path), kind='archive_import',source='Archive export',sha256=hashlib.sha256(body).hexdigest()), len(data)>5000


def _capture(row, folder, timeout):
    """Only dated Wayback replays; off-archive redirects cannot touch the target."""
    url=_helpers()['addRawModifier'](row['source_url'])
    data=evidence_capture.fetch_public(url,allowed_hosts={'web.archive.org'},timeout=min(20,timeout),accepted_types=TEXT_TYPES)
    path=folder/(data['sha256']+'.response')
    path.write_bytes(data['body'])
    text=data['html']
    if 'html' in data['content_type']:
        soup=BeautifulSoup(text,'html.parser')
        # JS is searched separately; extracted text never executes it.
        text=soup.get_text(' ',strip=True)+'\n'+'\n'.join(s.get_text() for s in soup.find_all('script'))
    indicators=sorted(set(m.group(0).lower() for m in re.finditer(r'api[_-]?key|access[_-]?token|password|secret|authorization',text,re.I)))
    links=[]
    patterns = [m.group(0).strip('"\'') for m in re.finditer(r'''https?://[^\s"'<>]+|["']/[^\s"'<>]{1,240}["']''',data['html'])]
    # HTML attributes and JS quoted paths, normalized against the historical URL.
    if 'html' in data['content_type']:
        patterns.extend(tag.get(attr,'') for tag in soup.find_all(['a','script','link']) for attr in ('href','src') if tag.get(attr))
    for value in patterns[:500]:
        candidate=record(urljoin(row['original_url'],value),row['domain'],'wayback',subs=row['include_subdomains'],
                         discovered_in=row['source_url'])
        if candidate and candidate['original_url'] not in links: links.append(candidate['original_url'])
    row.update(capture_sha256=data['sha256'],sha256=data['sha256'],capture_path=str(path),
               captured_at=data['observed_at'],text=redacted(text)[:4000],indicators=indicators,
               extracted_links=links[:100],capture_status='ok')
    return dict(path=str(path),sha256=data['sha256'],kind='archived_response',source='Wayback',source_url=row['source_url'])


def collect(domain, output, *, providers=('wayback','commoncrawl','otx','urlscan'),
            subs=True, from_date='', to_date='', limit=500, captures=0, category='',
            status_codes='', mime='', collapse_parameters=False, imports=(), time_budget=120, capture_urls=(), on_status=None):
    domain=domain_name(domain)
    start,end=date_value(from_date),date_value(to_date,True)
    if start and end and start>end: raise ValueError('Archive start date must precede end date')
    providers=list(dict.fromkeys(providers))
    if set(providers)-set(PROVIDERS) or not 1<=limit<=5000 or not 0<=captures<=20 or not 5<=time_budget<=300 or len(imports)>5:
        raise ValueError('Use listed providers, 1–5000 URLs, 0–20 responses and 5–300 seconds')
    wanted={x for x in category.split(',') if x}
    codes={x for x in status_codes.split(',') if x}
    if wanted-set(CATEGORIES) or any(not re.fullmatch(r'[1-5]\d\d',x) for x in codes):
        raise ValueError('Invalid category or HTTP status filter')
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    folder=Path(tempfile.mkdtemp(prefix='archives-',dir=output))
    result=dict(engine='Wayback CDX + Common Crawl + waymore 8.9',domain=domain,records=[],statuses=[],errors=[],artifacts=[],
        collected_at=datetime.now(timezone.utc).isoformat(),limits=dict(urls=limit,responses=captures,time_seconds=time_budget),
        settings=dict(providers=providers,include_subdomains=subs,from_date=from_date,to_date=to_date,category=category,
                      status_codes=status_codes,mime=mime,collapse_parameters=collapse_parameters))
    deadline=time.monotonic()+time_budget
    candidates=[]
    def status(source,state,count=0,detail='',**extra):
        row=dict(source=source,status=state,count=count,detail=detail,**extra)
        result['statuses'].append(row)
        if state in {'error','blocked','timeout'}: result['errors'].append(source+': '+detail)
        if on_status: on_status(row)
    for index,path in enumerate(imports,1):
        try:
            rows,artifact,limited=import_file(path,domain,subs)
            result['artifacts'].append(artifact);candidates.extend(rows)
            status('Archive import '+str(index),'partial' if limited else 'ok' if rows else 'empty',len(rows))
        except Exception: status('Archive import '+str(index),'error',detail='Selected archive export could not be parsed')
    for provider in providers:
        remaining=deadline-time.monotonic()
        if remaining<2:
            status(provider,'skipped',detail='Combined archive time budget reached');continue
        try:
            if provider=='wayback':
                params=dict(url=('*.' if subs else '')+domain+'/*',output='json',fl='original,timestamp,statuscode,mimetype',collapse='urlkey',limit=limit+1)
                if from_date: params['from']=from_date
                if to_date: params['to']=to_date
                url=SOURCE_URLS[provider]+'?'+urlencode(params)
                response=_index(url,{'web.archive.org'},min(20,remaining))
                rows=_table(json.loads(response['html']),domain,provider,subs)
                state='partial' if len(rows)>limit else 'ok' if rows else 'empty'
            elif provider=='commoncrawl':
                catalogue=json.loads(_index('https://index.commoncrawl.org/collinfo.json',{'index.commoncrawl.org'},min(15,remaining))['html'])
                if not isinstance(catalogue,list) or not catalogue: raise ValueError('Invalid crawl catalogue')
                selected=[]
                for item in catalogue:
                    at=re.sub(r'\D','',str(item.get('from','')))[:14]
                    until=re.sub(r'\D','',str(item.get('to','')))[:14]
                    if start and until and until<start or end and at and at>end: continue
                    if urlsplit(item.get('cdx-api','')).hostname!='index.commoncrawl.org': continue
                    selected.append(item)
                    if len(selected)>=2:break
                rows=[]
                for item in selected:
                    if deadline-time.monotonic()<2:break
                    response=_index(item['cdx-api']+'?'+urlencode(dict(url=('*.' if subs else '')+domain+'/*',output='json',pageSize=limit+1)),
                                    {'index.commoncrawl.org'},min(15,deadline-time.monotonic()))
                    for line in response['html'].splitlines()[:limit+1]:
                        data=json.loads(line)
                        row=record(data['url'],domain,provider,data.get('timestamp',''),data.get('status',''),data.get('mime',''),subs)
                        if row: rows.append(row)
                state='partial' if rows else 'empty'
            else:
                rows,state,detail,requests=_waymore(domain,provider,folder,subs,from_date,to_date,remaining)
                candidates.extend(rows);status(provider,state,len(rows),detail,requests=requests);continue
            candidates.extend(rows)
            status(provider,state,min(len(rows),limit), 'Bounded index sample; complete archive coverage is not implied' if state=='partial' else '')
        except Exception as exc:
            state='timeout' if isinstance(exc,(TimeoutError,subprocess.TimeoutExpired)) else 'blocked' if re.search(r'HTTP (?:401|403|429)',str(exc)) else 'error'
            status(provider,state,detail='Archive source request failed ('+type(exc).__name__+')')
    known={};filtered=0;unknown_dates=0
    for row in candidates:
        stamp=row['snapshot_at']
        if ((start and stamp and stamp<start) or (end and stamp and stamp>end)
                or wanted and not wanted.intersection(row['categories']) or codes and row['http_status'] not in codes
                or mime and not row['mime_type'].startswith(mime)):
            filtered+=1;continue
        if (start or end) and not stamp:unknown_dates+=1
        key=row['original_url']
        if collapse_parameters:
            parsed=urlsplit(key);key=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,urlencode([(k,'') for k in row['parameters']]),''))
        # Keep distinct snapshots/providers even when collapsing parameter values.
        key=(key,row['source'],stamp)
        if key not in known:known[key]=row
    if len(known)>limit:status('Archive budget','partial',limit,'Combined URL limit reached')
    result['records']=list(known.values())[:limit]
    if unknown_dates:status('Archive dates','partial',unknown_dates,'Some source URLs have no snapshot date; date range cannot be verified for them')
    result.update(filtered_count=filtered,unknown_dates=unknown_dates)
    for row in result['records']:
        row.update(observed_at=result['collected_at'],domain=domain,include_subdomains=subs)
    if len(capture_urls)>20 or set(capture_urls)-{row['source_url'] for row in result['records']}:
        raise ValueError('Choose at most twenty snapshots from the collected archive records')
    selected=[row for row in result['records'] if row['snapshot_at'] and row['source']=='wayback' and not row.get('discovered_in')
              and (not capture_urls or row['source_url'] in capture_urls)][:captures]
    if captures and not selected:status('Wayback responses','skipped',detail='No dated Wayback snapshots available for capture')
    for index,row in enumerate(selected,1):
        source='Wayback response '+str(index)
        if deadline-time.monotonic()<2:
            row['capture_status']='skipped';status(source,'skipped',detail='Combined time budget reached');continue
        try:
            result['artifacts'].append(_capture(row,folder,deadline-time.monotonic()))
            status(source,'ok',1)
        except Exception as exc:
            state='timeout' if isinstance(exc,TimeoutError) else 'blocked' if re.search(r'HTTP (?:401|403|429)',str(exc)) else 'error'
            row['capture_status']=state;status(source,state,detail='Archived response unavailable ('+type(exc).__name__+')')
    existing={r['original_url'] for r in result['records']}
    for parent in selected:
        for url in parent.get('extracted_links',[]):
            if url in existing or len(result['records'])>=limit: continue
            child=record(url,domain,'wayback',subs=subs,discovered_in=parent['source_url'])
            if child:
                if wanted and not wanted.intersection(child['categories']) or codes or mime: continue
                child.update(source_url=parent['source_url'],url=parent['source_url'],observed_at=result['collected_at'],
                    snapshot_at=parent['snapshot_at'],sha256=parent['capture_sha256'],
                    certainty='URL referenced in archived content; independent snapshot and current availability unverified',
                    capture_status='not_indexed',domain=domain,include_subdomains=subs)
                result['records'].append(child);existing.add(url)
    states={s['status'] for s in result['statuses']}
    result['status']='partial' if result['records'] and states-{'ok','empty'} else 'ok' if result['records'] else \
        'blocked' if states=={'blocked'} else 'timeout' if 'timeout' in states else 'error' if 'error' in states else 'partial' if 'partial' in states else 'skipped' if not states or states=={'skipped'} else 'empty'
    result['reports']=dict(json=str(folder/'archives.json'),csv=str(folder/'archives.csv'),urls=str(folder/'urls.txt'))
    with (folder/'archives.csv').open('w',encoding='utf-8-sig',newline='') as f:
        columns=['original_url','source_url','source','snapshot_at','http_status','mime_type','categories','parameters','certainty','capture_status','capture_sha256']
        writer=csv.DictWriter(f,fieldnames=columns,extrasaction='ignore');writer.writeheader()
        for row in result['records']:
            writer.writerow({k:"'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for k,v in row.items()})
    (folder/'urls.txt').write_text('\n'.join(dict.fromkeys(r['original_url'] for r in result['records'])),encoding='utf-8')
    (folder/'archives.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return result


def delta(result):
    path=Path(result['reports']['json']);digest=hashlib.sha256(path.read_bytes()).hexdigest()
    findings=[]
    for row in result['records']:
        summary=redacted(row['original_url'])+' · '+','.join(row['categories'])+' · '+(row['snapshot_at'] or 'Snapshot date unknown')
        findings.append(dict(title=summary,value=summary,event_type='Historical URL',source='Archives / '+row['source'],
            source_url=redacted(row['source_url']),archived=True,snapshot_at=row['snapshot_at'],
            sha256=digest,artifact_id=digest,observed_at=result['collected_at'],certainty='candidate',
            attribution=row['certainty'],data=dict(parameters=row['parameters'],categories=row['categories'],
                mime_type=row['mime_type'],http_status=row['http_status'],text=redacted(row.get('text',''))[:2000],
                indicators=row.get('indicators',[]),extracted_links=[redacted(x) for x in row.get('extracted_links',[])[:20]])))
        findings[-1]['source_data']=json.dumps(findings[-1]['data'],ensure_ascii=False)
    # Redacted section is fed to AI and exports. Raw historical bytes/URLs remain
    # in explicitly local collector artifacts, never copied into model prompts.
    def clean(value):
        if isinstance(value,str): return redacted(value)
        if isinstance(value,list): return [clean(x) for x in value]
        if isinstance(value,dict): return {k:clean(v) for k,v in value.items()}
        return value
    safe=clean(result)
    return dict(archives=safe,findings=findings,statuses=result['statuses'],errors=result['errors'],
                artifacts=[*clean(result['artifacts']),dict(path=str(path),source='Archives',kind='archive_report',sha256=digest)])


def save_dossier(result, output):
    from . import dossier
    folder=dossier._folder(Path(output),result['domain'])
    saved=dict(query=result['domain'],kind='domain',scope='domain',coverage='quick',observed_at=result['collected_at'],
        sections=dict(web=[],profiles=[],emails=[],domain=None),source_checks=[],artifacts=[],errors=[],
        settings=dict(include_archives=True,archive_options=result['settings'],capture_pages=-1),
        report_json=str(folder/'dossier.json'),report_csv=str(folder/'dossier.csv'))
    dossier.merge_delta(saved,delta(result))
    with (folder/'dossier.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=dossier.CSV_FIELDS);writer.writeheader();writer.writerows(dossier._report_rows(saved))
    dossier.save_relationship_graph(saved)
    return saved
