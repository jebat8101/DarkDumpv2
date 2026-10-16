"""
darkdump_webapp/app.py
Flask web interface for Darkdump.
Run:  python darkdump_webapp/app.py   (from the darkdump project root)
Then open http://127.0.0.1:5000
"""

import sys
sys.dont_write_bytecode = True
import os
import json
import csv
import io
import queue
import threading

from flask import Flask, render_template, request, Response, stream_with_context

def _find_darkdump_root():
    candidates = []
    try:
        here = os.path.dirname(os.path.realpath(__file__))
        candidates.append(here)
        candidates.append(os.path.dirname(here))
    except Exception:
        pass
    cwd = os.path.abspath(os.getcwd())
    for _ in range(5):
        candidates.append(cwd)
        parent = os.path.dirname(cwd)
        if parent == cwd:
            break
        cwd = parent
    for d in candidates:
        if os.path.isfile(os.path.join(d, 'darkdump.py')):
            return d
    raise ImportError(
        "Could not find darkdump.py.\n"
        "Place darkdump_webapp/ inside the darkdump project folder and run:\n"
        "  python darkdump_webapp/app.py"
    )

DARKDUMP_DIR = _find_darkdump_root()
if DARKDUMP_DIR not in sys.path:
    sys.path.insert(0, DARKDUMP_DIR)

from darkdump import Darkdump, Configuration, AhmiaBlacklist
from headers.agents import Headers             

import random
import re
import requests

app = Flask(__name__)

PROXY_URL = Configuration.__socks5init__


def _proxy_cfg():
    return {'http': PROXY_URL, 'https': PROXY_URL}


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _check_tor(proxy_config: dict):
    """Returns (is_tor: bool, ip: str)."""
    try:
        r = requests.get(
            'https://check.torproject.org/api/ip',
            proxies=proxy_config, timeout=15
        )
        if r.status_code == 200:
            d = r.json()
            return d.get('IsTor', False), d.get('IP', 'unknown')
    except Exception:
        pass
    return False, 'unknown'


def _fetch_engine(dd, ek: str, query: str, amount: int, hdrs: dict, active_proxy):
    """Dispatch to the Darkdump fetcher for one engine key."""
    if ek == 'ahmia':
        return dd._fetch_ahmia(query, amount, hdrs, active_proxy)
    elif ek == 'notevil':
        return dd._fetch_notevil(query, amount, hdrs, active_proxy or {})
    elif ek == 'tordex':
        return dd._fetch_tordex(query, amount, hdrs, active_proxy or {})
    elif ek == 'tor66':
        return dd._fetch_tor66(query, amount, hdrs, active_proxy or {})
    elif ek == 'onionland':
        return dd._fetch_onionland(query, amount, hdrs, active_proxy or {})
    elif ek == 'excavator':
        return dd._fetch_excavator(query, amount, hdrs, active_proxy or {})
    elif ek == 'torch':
        return dd._fetch_torch(query, amount, hdrs, active_proxy or {})
    elif ek == 'darksearch':
        return dd._fetch_darksearch(query, amount, hdrs, active_proxy or {})
    elif ek == 'vormweb':
        return dd._fetch_vormweb(query, amount, hdrs, active_proxy or {})
    return []


@app.route('/')
def index():
    engines = {
        '__all__': {
            'name':         'All Engines',
            'all_engines':  True,
            'count':        len(Configuration.SEARCH_ENGINES),
            'filtered':     False,   # includes unfiltered engines, so warn
            'tor_required': False,   # proxy is still forced on by the UI
        },
    }
    engines.update({
        k: {
            'name':         v['name'],
            'filtered':     v['filtered'],
            'tor_required': v['tor_required'],
        }
        for k, v in Configuration.SEARCH_ENGINES.items()
    })
    return render_template('index.html', engines=engines)


@app.route('/tor-status')
def tor_status():
    """Quick Tor connectivity check — returns JSON."""
    proxy_config = _proxy_cfg()
    is_tor, ip = _check_tor(proxy_config)
    return {'tor': is_tor, 'ip': ip}


@app.route('/search')
def search():
    """
    SSE stream. Params:
      q, engine, amount, proxy, dedupe, scrape, images
    """
    query      = request.args.get('q', '').strip()
    engine_key = request.args.get('engine', 'ahmia').lower()
    amount     = min(int(request.args.get('amount', 10)), 50)
    use_proxy  = request.args.get('proxy',  '0') == '1'
    dedupe     = request.args.get('dedupe', '0') == '1'
    scrape     = request.args.get('scrape', '0') == '1'
    images     = request.args.get('images', '0') == '1'

    def err_stream(msg):
        yield _sse('error', {'message': msg})
        yield _sse('done', {})

    if not query:
        return Response(stream_with_context(err_stream('No query provided.')),
                        mimetype='text/event-stream')

    search_all = engine_key == '__all__'

    if not search_all and engine_key not in Configuration.SEARCH_ENGINES:
        return Response(stream_with_context(err_stream(f"Unknown engine '{engine_key}'.")),
                        mimetype='text/event-stream')

    if search_all:
        engine_list  = list(Configuration.SEARCH_ENGINES.keys())
        use_proxy    = True   # most engines are Tor-only; clearnet ones also work via Tor
        proxy_config = _proxy_cfg()
    else:
        engine = Configuration.SEARCH_ENGINES[engine_key]
        if engine['tor_required']:
            use_proxy = True
        engine_list  = [engine_key]
        proxy_config = _proxy_cfg() if use_proxy else {}

    result_queue: queue.Queue = queue.Queue()

    def run_crawl():
        try:
            engines_to_run  = list(engine_list)
            local_proxy     = proxy_config
            local_use_proxy = use_proxy

            if local_use_proxy:
                is_tor, tor_ip = _check_tor(local_proxy)
                if is_tor:
                    result_queue.put(('tor_ok', {'ip': tor_ip}))
                elif search_all:
                    # Keep going with the clearnet-capable engines
                    engines_to_run = [k for k in engines_to_run
                                      if not Configuration.SEARCH_ENGINES[k]['tor_required']]
                    local_proxy, local_use_proxy = {}, False
                    result_queue.put(('engine', {
                        'engine': '__tor__', 'name': 'Tor', 'status': 'skipped',
                        'message': 'Tor is not running — searching clearnet-capable engines only',
                    }))
                    if not engines_to_run:
                        result_queue.put(('error', {
                            'message': 'Tor is not running or not reachable on localhost:9050.'
                        }))
                        return
                else:
                    result_queue.put(('error', {
                        'message': 'Tor is not running or not reachable on localhost:9050.'
                    }))
                    return

            headers = {'User-Agent': random.choice(Headers.user_agents)}
            dd = Darkdump()

            seen_urls = set()
            seen_meta = set()
            idx = 0
            grand_total = 0

            for ek in engines_to_run:
                eng_i        = Configuration.SEARCH_ENGINES[ek]
                active_proxy = local_proxy if local_use_proxy else None

                if search_all:
                    result_queue.put(('engine', {'engine': ek, 'name': eng_i['name'],
                                                 'status': 'fetching'}))

                try:
                    results = _fetch_engine(dd, ek, query, amount, headers, active_proxy)
                    results = dd._filter_blacklisted(results)
                except Exception as exc_engine:
                    if search_all:
                        result_queue.put(('engine', {'engine': ek, 'name': eng_i['name'],
                                                     'status': 'error', 'message': str(exc_engine)}))
                        continue
                    raise

                if not search_all:
                    if not results:
                        result_queue.put(('error', {'message': 'No results returned from engine.'}))
                        return
                    result_queue.put(('count', {'total': len(results)}))

                engine_count = 0
                for result in results:
                    site_url    = result.get('site_url', '')
                    title       = result.get('title', 'No title available')
                    description = result.get('description', 'No description available')

                    if not site_url or site_url in seen_urls:
                        continue

                    if dedupe:
                        fp = (
                            re.sub(r'\s+', ' ', title.strip().lower()),
                            re.sub(r'\s+', ' ', description.strip().lower()),
                        )
                        if fp in seen_meta:
                            continue
                        seen_meta.add(fp)

                    seen_urls.add(site_url)
                    idx += 1

                    payload = {
                        'idx':         idx,
                        'title':       title,
                        'description': description,
                        'url':         site_url,
                        'scrape_data': None,
                        'engine':      ek,
                        'engine_name': eng_i['name'],
                    }

                    if scrape:
                        try:
                            sd = dd._scrape_site(
                                site_url, headers, local_proxy,
                                scrape_images=images, debug_mode=False, idx=idx
                            )
                            if sd:
                                payload['scrape_data'] = {
                                    'metadata':       sd.get('metadata', {}),
                                    'links_count':    sd.get('links_count', 0),
                                    'emails':         sd.get('emails', []),
                                    'documents':      sd.get('documents', []),
                                    'images_gallery': sd.get('images_gallery', None),
                                }
                        except Exception:
                            pass

                    result_queue.put(('result', payload))
                    engine_count += 1

                grand_total += engine_count

                if search_all:
                    result_queue.put(('engine', {'engine': ek, 'name': eng_i['name'],
                                                 'status': 'ok', 'count': engine_count}))

            if search_all and grand_total == 0:
                result_queue.put(('error', {'message': 'No results returned from any engine.'}))

        except Exception as exc:
            result_queue.put(('error', {'message': str(exc)}))
        finally:
            result_queue.put(('done', {}))

    threading.Thread(target=run_crawl, daemon=True).start()

    def stream():
        # 'all' queries every engine sequentially, so allow more silence
        # between events before declaring the search stalled.
        idle_timeout = 120 if not search_all else 300
        while True:
            try:
                event, data = result_queue.get(timeout=idle_timeout)
                yield _sse(event, data)
                if event == 'done':
                    break
            except queue.Empty:
                yield _sse('error', {'message': 'Search timed out.'})
                break

    return Response(
        stream_with_context(stream()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/breach')
def breach():
    """
    SSE stream for breach intel scan.
    Params: q, engine, amount, proxy. engine='__all__' scans every engine.
    """
    target     = request.args.get('q', '').strip()
    engine_key = request.args.get('engine', 'ahmia').lower()
    amount     = min(int(request.args.get('amount', 10)), 50)
    use_proxy  = request.args.get('proxy', '0') == '1'

    def err_stream(msg):
        yield _sse('error', {'message': msg})
        yield _sse('done', {})

    if not target:
        return Response(stream_with_context(err_stream('No target provided.')),
                        mimetype='text/event-stream')

    search_all = engine_key == '__all__'

    if not search_all and engine_key not in Configuration.SEARCH_ENGINES:
        return Response(stream_with_context(err_stream(f"Unknown engine '{engine_key}'.")),
                        mimetype='text/event-stream')

    if search_all:
        engine_list  = list(Configuration.SEARCH_ENGINES.keys())
        use_proxy    = True   # most engines are Tor-only; clearnet ones also work via Tor
        proxy_config = _proxy_cfg()
    else:
        engine = Configuration.SEARCH_ENGINES[engine_key]
        if engine['tor_required']:
            use_proxy = True
        engine_list  = [engine_key]
        proxy_config = _proxy_cfg() if use_proxy else {}

    result_queue: queue.Queue = queue.Queue()

    def run_breach():
        try:
            engines_to_run  = list(engine_list)
            local_proxy     = proxy_config
            local_use_proxy = use_proxy

            if local_use_proxy:
                is_tor, tor_ip = _check_tor(local_proxy)
                if is_tor:
                    result_queue.put(('tor_ok', {'ip': tor_ip}))
                elif search_all:
                    # Keep going with the clearnet-capable engines
                    engines_to_run = [k for k in engines_to_run
                                      if not Configuration.SEARCH_ENGINES[k]['tor_required']]
                    local_proxy, local_use_proxy = {}, False
                    result_queue.put(('engine', {
                        'engine': '__tor__', 'name': 'Tor', 'status': 'skipped',
                        'message': 'Tor is not running — scanning clearnet-capable engines only',
                    }))
                    if not engines_to_run:
                        result_queue.put(('error', {
                            'message': 'Tor is not running or not reachable on localhost:9050.'
                        }))
                        return
                else:
                    result_queue.put(('error', {
                        'message': 'Tor is not running or not reachable on localhost:9050.'
                    }))
                    return

            import re as _re
            is_email  = '@' in target and '.' in target.split('@')[-1]
            is_domain = '.' in target and not is_email and ' ' not in target

            username_variants = []
            if is_email:
                user, domain = target.split('@', 1)
                for sep in ['.', '_', '-', '']:
                    parts = _re.split(r'[._\-]', user)
                    if len(parts) >= 2:
                        username_variants.append(sep.join(parts))
                username_variants = list(dict.fromkeys(username_variants))
            elif not is_domain:
                base = _re.sub(r'[._\-\s]+', '', target)
                username_variants = list(dict.fromkeys([
                    base, target.replace(' ', '_'),
                    target.replace(' ', '.'), target.replace(' ', '-')
                ]))

            if is_email:
                user, domain = target.split('@', 1)
                queries = [
                    f'"{target}" leak', f'"{target}" breach',
                    f'"{target}" credentials', f'"{target}" dump',
                    f'"{target}" password', f'"{target}" combolist',
                    f'"{domain}" breach emails', f'"{domain}" combolist',
                    f'"{domain}" credential dump', f'"{domain}" data leak .sql',
                    f'"{target}" md5', f'"{target}" sha1', f'"{target}" pastebin',
                ]
                for v in username_variants[:3]:
                    if v != user:
                        queries.append(f'"{v}" "{domain}" password')
            elif is_domain:
                queries = [
                    f'"{target}" breach', f'"{target}" leak',
                    f'"{target}" credentials dump', f'"{target}" database leak',
                    f'"{target}" combolist', f'"{target}" employee passwords',
                    f'"{target}" data dump', f'"{target}" hacked',
                    f'"{target}" .sql dump', f'"{target}" stealer logs',
                    f'"{target}" infostealer', f'"{target}" credential stuffing',
                ]
            else:
                queries = [
                    f'"{target}" password leak', f'"{target}" credentials',
                    f'"{target}" breach', f'"{target}" dump',
                    f'"{target}" combolist', f'"{target}" leaked database',
                    f'"{target}" pastebin', f'"{target}" stealer',
                ]
                for v in username_variants[:3]:
                    if v != target:
                        queries.append(f'"{v}" password')

            seen_q = set()
            queries = [q for q in queries if not (q in seen_q or seen_q.add(q))]

            # Artefact extraction
            EMAIL_RE  = _re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
            HASH_RE   = _re.compile(r'\b[0-9a-fA-F]{32,64}\b')
            PASS_RE   = _re.compile(r'(?:password|passwd|pass|pwd)\s*[:=]\s*([^\s,;\|]{4,64})', _re.IGNORECASE)

            def extract_artefacts(text):
                a = {}
                emails = EMAIL_RE.findall(text)
                if emails: a['emails'] = list(dict.fromkeys(emails))[:5]
                hashes = HASH_RE.findall(text)
                if hashes: a['hashes'] = list(dict.fromkeys(hashes))[:5]
                passwords = PASS_RE.findall(text)
                if passwords: a['password_hints'] = list(dict.fromkeys(passwords))[:3]
                return a

            CRITICAL_SIGS = ['combolist','stealer','infostealer','plaintext','fullz','cracked']
            HIGH_SIGS     = ['breach','leak','dump','database','hacked','.sql','pastebin']
            MEDIUM_SIGS   = ['password','credentials','account','login']

            def classify(title, desc, url):
                c = (title+' '+desc+' '+url).lower()
                for s in CRITICAL_SIGS:
                    if s in c: return 'CRITICAL'
                for s in HIGH_SIGS:
                    if s in c: return 'HIGH'
                for s in MEDIUM_SIGS:
                    if s in c: return 'MEDIUM'
                return 'INFO'

            def categorise(title, url):
                c = (title+' '+url).lower()
                if any(p in c for p in ['paste','bin','ghostbin']): return 'paste-site'
                if any(p in c for p in ['market','shop','vendor']): return 'market'
                if any(p in c for p in ['forum','board','chan']): return 'forum'
                if any(p in c for p in ['leak','dump','breach','stealer']): return 'leak-index'
                return 'other'

            result_queue.put(('breach_start', {
                'target':   target,
                'type':     'email' if is_email else 'domain' if is_domain else 'keyword',
                'queries':  len(queries),
                'engine':   'all engines' if search_all else engine_key,
            }))

            dd        = Darkdump()
            headers   = {'User-Agent': random.choice(Headers.user_agents)}
            seen_urls = set()
            total     = 0

            for q_idx, query in enumerate(queries, start=1):
                result_queue.put(('breach_query', {'idx': q_idx, 'total': len(queries), 'query': query}))

                for ek in engines_to_run:
                    eng_i        = Configuration.SEARCH_ENGINES[ek]
                    active_proxy = local_proxy if local_use_proxy else None

                    if search_all:
                        result_queue.put(('engine', {'engine': ek, 'name': eng_i['name'],
                                                     'status': 'fetching'}))

                    try:
                        results = _fetch_engine(dd, ek, query, amount, headers, active_proxy)
                        results = dd._filter_blacklisted(results)
                    except Exception as e:
                        if search_all:
                            result_queue.put(('engine', {'engine': ek, 'name': eng_i['name'],
                                                         'status': 'error', 'message': str(e)}))
                            continue
                        result_queue.put(('error', {'message': f"Query failed: {e}"}))
                        continue

                    engine_count = 0
                    for result in results:
                        site_url = result.get('site_url', '')
                        if not site_url or site_url in seen_urls:
                            continue
                        seen_urls.add(site_url)
                        total += 1
                        engine_count += 1
                        title = result.get('title', 'No title available')
                        desc  = result.get('description', 'No description available')
                        result_queue.put(('result', {
                            'idx':          total,
                            'title':        title,
                            'description':  desc,
                            'url':          site_url,
                            'engine':       ek,
                            'engine_name':  eng_i['name'],
                            'breach_query': query,
                            'severity':     classify(title, desc, site_url),
                            'category':     categorise(title, site_url),
                            'artefacts':    extract_artefacts(title + ' ' + desc),
                            'scrape_data':  None,
                        }))

                    if search_all:
                        result_queue.put(('engine', {'engine': ek, 'name': eng_i['name'],
                                                     'status': 'ok', 'count': engine_count}))

        except Exception as exc:
            result_queue.put(('error', {'message': str(exc)}))
        finally:
            result_queue.put(('done', {}))

    threading.Thread(target=run_breach, daemon=True).start()

    def stream():
        # 'all' scans every engine for every query, so allow more silence
        # between events before declaring the scan stalled.
        idle_timeout = 300 if search_all else 120
        while True:
            try:
                event, data = result_queue.get(timeout=idle_timeout)
                yield _sse(event, data)
                if event == 'done':
                    break
            except queue.Empty:
                yield _sse('error', {'message': 'Breach scan timed out.'})
                break

    return Response(
        stream_with_context(stream()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/export', methods=['POST'])
def export():
    """
    Accept a JSON body: { format: 'json'|'csv'|'txt', results: [...] }
    Returns the file as a download.
    """
    body    = request.get_json(force=True)
    fmt     = body.get('format', 'json').lower()
    results = body.get('results', [])
    query   = body.get('query', '')
    engine  = body.get('engine', '')

    if fmt == 'json':
        payload = json.dumps({
            'query':        query,
            'engine':       engine,
            'result_count': len(results),
            'results':      results,
        }, indent=2, ensure_ascii=False)
        return Response(
            payload,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename="darkdump_results.json"'}
        )

    if fmt == 'csv':
        buf = io.StringIO()
        fieldnames = ['idx', 'title', 'url', 'description']
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for r in results:
            writer.writerow({
                'idx':         r.get('idx', ''),
                'title':       r.get('title', ''),
                'url':         r.get('url', ''),
                'description': r.get('description', ''),
            })
        return Response(
            buf.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename="darkdump_results.csv"'}
        )

    # txt (default)
    lines = [
        'Darkdump Results',
        '=' * 60,
        f'Query:   {query}',
        f'Engine:  {engine}',
        f'Results: {len(results)}',
        '=' * 60, '',
    ]
    for r in results:
        sd = r.get('scrape_data')
        lines.append(f"[{r.get('idx', '')}] {r.get('title', '')}")
        lines.append(f"    URL:         {r.get('url', '')}")
        lines.append(f"    Description: {r.get('description', '')}")
        if sd:
            lines.append(f"    Links:       {sd.get('links_count', 0)}")
            emails = ', '.join(sd.get('emails', [])) or 'none'
            lines.append(f"    Emails:      {emails}")
            docs = ', '.join(sd.get('documents', [])) or 'none'
            lines.append(f"    Documents:   {docs}")
            if sd.get('images_gallery'):
                lines.append(f"    Images:      {sd['images_gallery']}")
        lines.append('')
    return Response(
        '\n'.join(lines),
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename="darkdump_results.txt"'}
    )


if __name__ == '__main__':
    import logging
    import flask.cli
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    flask.cli.show_server_banner = lambda *_: None

    from banner.banner import Banner
    from darkdump import notice, Colors
    Banner().LoadDarkdumpBanner()
    print(notice)
    print(f"  Web interface running at {Colors.BOLD}{Colors.G}http://127.0.0.1:50001{Colors.END}\n")
    app.run(debug=False, host='127.0.0.1', port=50001, threaded=True)
