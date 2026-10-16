'''
MIT License
Copyright (c) 2026 Josh Schiavone

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

__version__ = 4

import sys
sys.dont_write_bytecode = True

import nltk

import requests
from bs4 import BeautifulSoup
import os
import time
import argparse
import random
import re
import json
import socket
import hashlib

from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlsplit, urlunsplit
import posixpath

from headers.agents import Headers
from banner.banner import Banner

from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.probability import FreqDist
from textblob import TextBlob

notice = '''
Note: 
    This tool is not to be used for illegal purposes.
    The author is not responsible for any misuse of Darkdump.
    May God bless you all.
    https://joshschiavone.com - https://github.com/josh0xA
'''

class Colors:
    W = '\033[0m'  # white 
    R = '\033[31m'  # red
    G = '\033[32m'  # green
    O = '\033[33m'  # orange
    B = '\033[34m'  # blue
    P = '\033[35m'  # purple
    C = '\033[36m'  # cyan
    GR = '\033[37m'  # gray
    BOLD = '\033[1m'
    END = '\033[0m'

class ResultSaver:
    """
    Collects scan results during a crawl and writes them to disk in the
    format inferred from the output filename extension.

    Supported formats
    -----------------
    .json  -- structured JSON array, one object per result
    .csv   -- RFC 4180 CSV with a header row
    .txt   -- human-readable plain-text report (default / fallback)

    Usage
    -----
    saver = ResultSaver("results.json", query="hacking", engine="ahmia")
    saver.add(title, description, site_url, scrape_data=None)
    saver.save()           # writes the file
    saver.print_summary()  # prints confirmation line to stdout
    """

    def __init__(self, filepath: str, query: str = '', engine: str = ''):
        self.filepath = filepath
        self.query = query
        self.engine = engine
        self.records: list = []
        ext = os.path.splitext(filepath)[1].lower()
        if ext == '.json':
            self.fmt = 'json'
        elif ext == '.csv':
            self.fmt = 'csv'
        else:
            self.fmt = 'txt'

    def add(self, title: str, description: str, site_url: str,
            scrape_data: dict = None):
        """Append one result. scrape_data is the dict returned by _scrape_site."""
        record = {
            'title': title,
            'description': description,
            'url': site_url,
        }
        if scrape_data:
            record.update(scrape_data)
        self.records.append(record)

    def save(self):
        """Write all collected records to self.filepath."""
        if not self.records:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.filepath)), exist_ok=True)
        try:
            if self.fmt == 'json':
                self._save_json()
            elif self.fmt == 'csv':
                self._save_csv()
            else:
                self._save_txt()
        except Exception as e:
            print(f"{Colors.BOLD + Colors.R}[Save Error] Could not write to "
                  f"\'{self.filepath}\': {e}{Colors.END}")

    def print_summary(self):
        """Print a confirmation line after saving."""
        if not self.records:
            return
        print(
            f"\n{Colors.BOLD + Colors.C}[ Saved {len(self.records)} result(s) "
            f"-> {os.path.abspath(self.filepath)} ]{Colors.END}"
        )

    def _save_json(self):
        payload = {
            'query': self.query,
            'engine': self.engine,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'result_count': len(self.records),
            'results': self.records,
        }
        with open(self.filepath, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    def _save_csv(self):
        import csv as _csv
        # Build a superset of all field names present across all records
        fieldnames = ['title', 'description', 'url']
        for r in self.records:
            for k in r:
                if k not in fieldnames:
                    fieldnames.append(k)

        with open(self.filepath, 'w', newline='', encoding='utf-8') as f:
            writer = _csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for record in self.records:
                # Flatten list/dict values to strings for CSV compatibility
                flat = {}
                for k, v in record.items():
                    flat[k] = json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
                writer.writerow(flat)

    def _save_txt(self):
        with open(self.filepath, 'w', encoding='utf-8') as f:
            f.write("Darkdump Scan Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"Query   : {self.query}\n")
            f.write(f"Engine  : {self.engine}\n")
            f.write(f"Time    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Results : {len(self.records)}\n")
            f.write("=" * 60 + "\n\n")
            for idx, r in enumerate(self.records, start=1):
                f.write(f"[{idx}] {r.get('title', 'No title')}\n")
                f.write(f"    URL         : {r.get('url', '')}\n")
                f.write(f"    Description : {r.get('description', '')}\n")
                if 'metadata' in r:
                    f.write(f"    Metadata    : {json.dumps(r['metadata'])}\n")
                if 'links_count' in r:
                    f.write(f"    Links found : {r['links_count']}\n")
                if 'emails' in r:
                    emails = r['emails']
                    f.write(f"    Emails      : {', '.join(emails) if emails else 'None'}\n")
                if 'documents' in r:
                    docs = r['documents']
                    f.write(f"    Documents   : {', '.join(docs) if docs else 'None'}\n")
                if 'images_gallery' in r:
                    f.write(f"    Images      : {r['images_gallery']}\n")
                f.write("\n")


class Configuration:
    DARKDUMP_ERROR_CODE_STANDARD = -1
    DARKDUMP_SUCCESS_CODE_STANDARD = 0
    DARKDUMP_MIN_DATA_RETRIEVE_LENGTH = 1
    DARKDUMP_RUNNING = False

    DARKDUMP_OS_UNIX_LINUX = False
    DARKDUMP_OS_WIN32_64 = False
    DARKDUMP_OS_DARWIN = False

    DARKDUMP_REQUESTS_SUCCESS_CODE = 200
    DARKDUMP_PROXY = False
    DARKDUMP_TOR_RUNNING = False

    # --live: probes every result URL before it is printed
    DARKDUMP_LIVENESS_TIMEOUT = 25   # seconds to wait for a single onion to answer
    DARKDUMP_LIVENESS_WORKERS = 6    # concurrent probes (each gets its own Tor circuit)

    descriptions = []
    urls = []

    __socks5init__ = "socks5h://localhost:9050"

    # --- Search engine definitions ---
    # Each engine dict keys:
    #   'base'        : clearnet base URL for nonce fetching, or None
    #   'api'         : clearnet search URL template with {query} placeholder, or None
    #   'onion'       : .onion search URL template with {query} placeholder
    #   'tor_required': True = onion-only, Tor proxy is mandatory
    #   'filtered'    : True = engine actively screens out illegal/abusive content
    #   'result_tag'  : (tag, class) tuple for BeautifulSoup result item selection
    #   'needs_nonce' : whether a hidden CSRF nonce must be fetched from base first
    #   'parser'      : internal fetcher method name (maps to _fetch_<parser>)
    #
    # Engine overview
    # ---------------
    # ahmia    - Clearnet + Tor. Tor Project-endorsed since 2014. Strict CSAM/abuse
    #            filtering. Requires a hidden CSRF nonce fetched from the homepage.
    #
    # notevil    - Tor-only. Ahmia fork with partial content filtering (strips the
    #              most extreme material while keeping a broader index than Ahmia).
    #              Click-count ranking. Results are <li class="result"> elements.
    #
    # tordex     - Clearnet + Tor. UNFILTERED uncensored index. Uses .onion when
    #              proxy is active, clearnet (tordex.cc/search) otherwise.
    #              Results use .container h5 a selector.
    #
    # tor66      - Tor-only. UNFILTERED crawled index with category directory.
    #              Results parsed from <b> elements following the first <hr>.
    #
    # onionland  - Tor-only. Minimal filtering; indexes Tor, I2P, and clearnet.
    #              Results use .result-block .title a with redirect URL decoding.
    #
    # torch      - Tor-only. Oldest Tor search engine. Results come from its
    #              htdig "omega" CGI as a results table. UNFILTERED; huge but
    #              stale index.
    #
    # vormweb    - Clearnet + Tor. Actively screens illegal content and badges
    #              every result with a trust level (verified/warning/risky).
    #
    # darksearch - Clearnet JSON API. UNFILTERED. Public access was discontinued
    #              in January 2022 and the host no longer resolves; the entry is
    #              kept so the engine works again if the service ever returns.
    SEARCH_ENGINES = {
        'ahmia': {
            'name': 'Ahmia',
            'base': 'https://ahmia.fi',
            'api': 'https://ahmia.fi/search/?q={query}',
            'onion': 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}',
            'tor_required': False,
            'filtered': True,
            'result_tag': ('li', 'result'),
            'needs_nonce': True,
            'parser': 'ahmia',
        },
        'notevil': {
            'name': 'Not Evil',
            'base': None,
            'api': None,
            'onion': 'http://notevil2ebbr5xjww6nryjta7bycbriyi2vh7an3wcuovlznvobykmad.onion',
            'tor_required': True,
            'filtered': True,
            'result_tag': ('li', 'result'),
            'needs_nonce': False,
            'parser': 'notevil',
        },
        'tordex': {
            'name': 'TorDex',
            'base': 'https://tordex.cc',
            # Clearnet endpoint (used when proxy is off)
            'api': 'https://tordex.cc/search?query={query}',
            # Onion endpoint (used when proxy/Tor is enabled)
            'onion': 'http://tordexpmg4xy32rfp4ovnz7zq5ujoejwq2u26uxxtkscgo5u3losmeid.onion/search?query={query}',
            'tor_required': False,   # clearnet works without Tor; onion used when -p supplied
            'filtered': False,
            'result_tag': ('h5', None),
            'needs_nonce': False,
            'parser': 'tordex',
        },
        'tor66': {
            'name': 'Tor66',
            'base': None,
            'api': None,
            'onion': 'http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}&sorttype=rel',
            'tor_required': True,
            'filtered': False,
            'result_tag': ('li', None),
            'needs_nonce': False,
            'parser': 'tor66',
        },
        'onionland': {
            'name': 'OnionLand',
            'base': None,
            'api': None,
            # v3 onion address confirmed in OnionSearch core.py (2024)
            'onion': 'http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}&page=1',
            'tor_required': True,
            'filtered': False,  # Minimal content filtering
            'result_tag': ('div', 'result-block'),
            'needs_nonce': False,
            'parser': 'onionland',
        },
        'excavator': {
            'name': 'Excavator',
            'base': None,
            'api': None,
            'onion': 'http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion',
            'tor_required': True,
            'filtered': False,
            'result_tag': ('div', 'result'),
            'needs_nonce': False,
            'parser': 'excavator',
        },
        'torch': {
            'name': 'Torch',
            'base': None,
            'api': None,
            # Legacy host meta-refreshes to /cgi-bin/omega/omega. Only the P=
            # query parameter is sent: passing DB= makes the CGI reset the
            # connection.
            'onion': 'http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega?P={query}',
            'tor_required': True,
            'filtered': False,
            'result_tag': ('td', None),
            'needs_nonce': False,
            'parser': 'torch',
        },
        'vormweb': {
            'name': 'VormWeb',
            'base': 'https://vormweb.de',
            'api': 'https://vormweb.de/en/search?q={query}',
            # Onion mirrors the clearnet site byte-for-byte (verified 2024).
            'onion': 'http://volkancfgpi4c7ghph6id2t7vcntenuly66qjt6oedwtjmyj4tkk5oqd.onion/en/search?q={query}',
            'tor_required': False,
            'filtered': True,
            'result_tag': ('div', 'query-box'),
            'needs_nonce': False,
            'parser': 'vormweb',
        },
        'darksearch': {
            'name': 'DarkSearch (offline)',
            'base': 'https://darksearch.io',
            'api': 'https://darksearch.io/api/search?query={query}&page=1',
            'onion': None,
            'tor_required': False,
            'filtered': False,
            'result_tag': None,
            'needs_nonce': False,
            'parser': 'darksearch',
        },
    }

    VALID_ENGINES = list(SEARCH_ENGINES.keys())


class Platform(object):
    def __init__(self, execpltf):
        self.execpltf = execpltf

    def get_operating_system_descriptor(self):
        cfg = Configuration()
        clr = Colors()

        if self.execpltf:
            if sys.platform == "linux" or sys.platform == "linux2":
                cfg.DARKDUMP_OS_UNIX_LINUX = True
                print(clr.BOLD + clr.W + "Operating System: " + clr.G + sys.platform + clr.END)
            if sys.platform == "win64" or sys.platform == "win32":
                cfg.DARKDUMP_OS_WIN32_64 = True
                print(clr.BOLD + clr.W + "Operating System: " + clr.G + sys.platform + clr.END)
            if sys.platform == "darwin":
                cfg.DARKDUMP_OS_DARWIN = True
                print(clr.BOLD + clr.W + "Operating System: " + clr.G + sys.platform + clr.END)
        else:
            pass

    def clean_screen(self):
        if self.execpltf:
            if sys.platform in ("linux", "linux2", "darwin"):
                os.system('clear')
            else:
                os.system('cls')

    def check_tor_connection(self, proxy_config):
        test_url = 'https://check.torproject.org/api/ip'
        try:
            response = requests.get(test_url, proxies=proxy_config, timeout=20)
            if response.status_code == 200:
                data = response.json()
                if data.get('IsTor', False):
                    print(f"{Colors.BOLD + Colors.G}Tor service is active.{Colors.END}")
                    print(f"{Colors.BOLD + Colors.P}Current IP Address via Tor: {Colors.END}{data.get('IP')}")
                    return True
            print(f"{Colors.BOLD + Colors.R}Connection successful but not through Tor.{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.BOLD + Colors.R}Tor is inactive or not configured properly: {str(e)}{Colors.END}")
            return False


class AhmiaBlacklist:
    """
    Fetches and caches Ahmia's MD5-hashed .onion blacklist.
    The list is refreshed at most once per hour within a process.

    """
    BLACKLIST_URL = 'https://ahmia.fi/blacklist/banned/'
    TTL = 3600  # seconds

    _hashes: set = set()
    _fetched_at: float = 0.0

    @classmethod
    def load(cls) -> None:
        """Fetch the blacklist if the cache is stale."""
        if time.time() - cls._fetched_at < cls.TTL and cls._hashes:
            return
        try:
            resp = requests.get(cls.BLACKLIST_URL, timeout=15)
            resp.raise_for_status()
            cls._hashes = {line.strip() for line in resp.text.splitlines() if len(line.strip()) == 32}
            cls._fetched_at = time.time()
        except Exception:
            # If the fetch fails, keep whatever we had (or nothing).
            pass

    @classmethod
    def is_banned(cls, url: str) -> bool:
        """Return True if the .onion hostname of *url* is on the blacklist."""
        if not cls._hashes:
            return False
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ''
            if not host.endswith('.onion'):
                return False
            md5 = hashlib.md5(host.encode()).hexdigest()
            return md5 in cls._hashes
        except Exception:
            return False


class Darkdump(object):


    @staticmethod
    def _filter_blacklisted(results: list) -> list:
        """Remove any result whose .onion hostname is on Ahmia's blacklist."""
        AhmiaBlacklist.load()
        return [r for r in results if not AhmiaBlacklist.is_banned(r.get('site_url', ''))]

    def _liveness_probe(self, url, headers, proxy_config=None, timeout=None):
        """
        Probe one result URL and report whether the host is currently alive.

        A host counts as live when it answers with an HTTP status below 500 —
        2xx/3xx/4xx all mean the service is up (a 404 is a live server that
        simply has no page there). Connection failures and timeouts mean the
        onion is dead. .onion hosts are probed through the Tor proxy whenever
        one is supplied; clearnet URLs are probed directly.

        Returns (alive: bool, detail: str), where detail is the HTTP status or
        the exception class name.
        """
        timeout  = timeout or Configuration.DARKDUMP_LIVENESS_TIMEOUT
        is_onion = urlsplit(url).netloc.endswith('.onion')
        proxies  = proxy_config if (is_onion and proxy_config) else None
        try:
            response = requests.get(url, headers=headers, proxies=proxies,
                                    timeout=timeout, stream=True)
            with response:
                if response.status_code < 500:
                    return True, str(response.status_code)
                return False, f"HTTP {response.status_code}"
        except requests.exceptions.RequestException as e:
            return False, type(e).__name__

    def _filter_live_results(self, results, headers, proxy_config=None,
                             debug_mode=False):
        """
        Probe every result URL concurrently and return only the live ones,
        preserving the original order. Used by --live. Prints one colored line
        per probed URL plus a summary.
        """
        if not results:
            return results

        print(f"{Colors.BOLD + Colors.C}[ Liveness check: probing {len(results)} "
              f"link(s) over Tor ]{Colors.END}")

        statuses = {}
        with ThreadPoolExecutor(max_workers=min(
                Configuration.DARKDUMP_LIVENESS_WORKERS, len(results))) as pool:
            futures = {
                pool.submit(self._liveness_probe, r['site_url'], headers,
                            proxy_config): idx
                for idx, r in enumerate(results)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    alive, detail = future.result()
                except Exception as e:
                    alive, detail = False, type(e).__name__
                statuses[idx] = (alive, detail)

                site_url = results[idx]['site_url']
                if alive:
                    print(f"{Colors.BOLD}[+] {Colors.G}LIVE {detail}{Colors.END} "
                          f"{Colors.P}{site_url}{Colors.END}")
                else:
                    print(f"{Colors.BOLD}[x] {Colors.R}DEAD {detail}{Colors.END} "
                          f"{Colors.P}{site_url}{Colors.END}")
                    if debug_mode:
                        print(f"    {Colors.GR}[DEBUG] liveness probe failed: "
                              f"{detail}{Colors.END}")

        live = [r for idx, r in enumerate(results) if statuses.get(idx, (False, ''))[0]]
        print(f"{Colors.BOLD}[ Liveness: {len(live)}/{len(results)} live, "
              f"{len(results) - len(live)} dead — showing live links only ]"
              f"{Colors.END}\n")
        return live

    def clean_text(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        text = soup.get_text()
        text = re.sub(r'[\r\n]+', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        return text.strip()

    def extract_keywords(self, text):
        clean_text = self.clean_text(text)
        stop_words = set(stopwords.words('english'))
        word_tokens = word_tokenize(clean_text.lower())
        filtered_text = [w for w in word_tokens if w.isalnum() and w not in stop_words]
        freq_dist = FreqDist(filtered_text)
        return list(freq_dist)[:18]

    def analyze_text(self, text):
        words = word_tokenize(text)
        stop_words = set(stopwords.words('english'))
        filtered_words = [w for w in words if w.lower() not in stop_words and w.isalnum()]
        freq_dist = FreqDist(filtered_words)
        top_words = freq_dist.most_common(10)
        blob = TextBlob(text)
        sentiment = blob.sentiment
        return {
            'top_words': top_words,
            'sentiment': {
                'polarity': sentiment.polarity,
                'subjectivity': sentiment.subjectivity,
            },
        }

    def sanitize_filename(self, url):
        keepcharacters = (' ', '.', '_', '-')
        return "".join(c for c in url if c.isalnum() or c in keepcharacters).rstrip()

    def generate_html(self, image_urls, base_url):
        filename = self.sanitize_filename(base_url) + '.html'
        filepath = os.path.join('dd_scrape_image_dump', filename)
        os.makedirs('dd_scrape_image_dump', exist_ok=True)
        html_content = '<html><head><title>Image Gallery</title></head><body>'
        for url in image_urls:
            html_content += f'<img src="{url}" alt="Image" style="padding: 10px; height: 200px;"><br>'
        html_content += '</body></html>'
        with open(filepath, 'w') as f:
            f.write(html_content)
        return filepath

    def extract_links(self, soup):
        return [a['href'] for a in soup.find_all('a', href=True)]

    def extract_metadata(self, soup):
        meta_data = {}
        for meta in soup.find_all('meta'):
            meta_name = meta.get('name') or meta.get('property')
            if meta_name:
                meta_data[meta_name] = meta.get('content')
        return meta_data

    def extract_emails(self, soup):
        text = soup.get_text()
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        return email_pattern.findall(text)

    def extract_document_links(self, soup):
        doc_types = [
            '.pdf', '.doc', '.docx', '.xlsx', '.xls', '.ppt', '.pptx',
            '.txt', '.csv', '.rtf', '.odt', '.ods', '.odp', '.epub',
            '.mobi', '.log', '.msg', '.wpd', '.wps', '.tex', '.vsd',
            '.xml', '.json', '.xps', '.md', '.code', '.mp3', '.wav',
            '.mp4', '.avi', '.mov', '.flv', '.wma', '.aac', '.dll',
            '.exe', '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
            '.vmdk', '.iso', '.bin', '.img', '.dmg',
        ]
        return [
            a['href'] for a in soup.find_all('a', href=True)
            if any(a['href'].endswith(dt) for dt in doc_types)
        ]

    def _fetch_ahmia(self, query, amount, headers, proxy_config=None):
        """
        Fetch results from Ahmia (clearnet by default; routes through Tor when
        proxy_config is supplied). Handles the hidden CSRF nonce on the homepage.
        Result markup: <li class="result"> containing <a>, <cite>, <p>.
        """
        engine = Configuration.SEARCH_ENGINES['ahmia']
        req_kwargs = {'headers': headers, 'timeout': 15}
        if proxy_config:
            req_kwargs['proxies'] = proxy_config

        homepage = requests.get(engine['base'], **req_kwargs)
        if homepage.status_code != 200:
            raise Exception(f"Couldn't fetch {engine['base']} (HTTP {homepage.status_code})")

        soup = BeautifulSoup(homepage.content, 'html.parser')
        nonce_el = soup.select_one('#searchForm input[type="hidden"]')
        if nonce_el is None:
            raise Exception("Couldn't find nonce on Ahmia homepage")

        nonce = f"&{nonce_el.attrs['name']}={nonce_el.attrs['value']}"
        url = engine['api'].format(query=query) + nonce

        page = requests.get(url, **req_kwargs)
        if page.status_code != 200:
            raise Exception(f"Ahmia search request failed (HTTP {page.status_code})")

        soup = BeautifulSoup(page.content, 'html.parser')
        result_page = soup.find(id='ahmiaResultsPage')
        if result_page is None:
            raise Exception("Couldn't extract results container from Ahmia")

        tag, cls = engine['result_tag']
        raw = result_page.find_all(tag, class_=cls)
        results = []
        for item in raw[:amount]:
            cite  = item.find('cite')
            a_tag = item.find('a')
            p_tag = item.find('p')
            site_url = cite.text.strip() if cite else ''
            if "http://" not in site_url and "https://" not in site_url:
                site_url = "http://" + site_url
            results.append({
                'title':       a_tag.text.strip() if a_tag else 'No title available',
                'description': p_tag.text.strip() if p_tag else 'No description available',
                'site_url':    site_url,
            })
        return results

    def _fetch_notevil(self, query, amount, headers, proxy_config):
        """
        Fetch results from Not Evil via its .onion address (Tor required).

        Not Evil has changed its search path across versions. We try the known
        paths in order and use whichever returns a 200.
        Result markup: <li class="result"> containing <a> and <p>.
        """
        engine   = Configuration.SEARCH_ENGINES['notevil']
        base     = engine['onion']
        encoded  = requests.utils.quote(query)
        engine_host = base.split('/')[2]

        search_paths = [
            f"/search?q={encoded}",
            f"/?q={encoded}",
            f"/index.php?q={encoded}",
            f"/search?phrase={encoded}",
        ]

        response = None
        for path in search_paths:
            try:
                r = requests.get(base + path, headers=headers, proxies=proxy_config, timeout=30)
                if r.status_code == 200:
                    response = r
                    break
            except Exception:
                continue

        if response is None:
            raise Exception("Not Evil: no search path returned a valid response")

        soup = BeautifulSoup(response.content, 'html.parser')
        results = []

        tag, cls = engine['result_tag']
        raw = soup.find_all(tag, class_=cls)

        # Fallback: scan for .onion links if expected markup isn't present
        if not raw:
            for a_tag in soup.find_all('a', href=lambda h: h and '.onion' in h and engine_host not in h):
                if len(results) >= amount:
                    break
                site_url    = a_tag['href'].strip()
                title       = a_tag.get_text(strip=True) or 'No title available'
                parent      = a_tag.parent
                description = parent.get_text(' ', strip=True).replace(title, '').strip()
                description = description[:200] if description else 'No description available'
                results.append({
                    'title':       title,
                    'description': description,
                    'site_url':    site_url,
                })
            return results

        for item in raw[:amount]:
            a_tag = item.find('a', href=True)
            p_tag = item.find('p')
            if not a_tag:
                continue
            site_url = a_tag['href'].strip()
            if site_url and 'http' not in site_url:
                site_url = 'http://' + site_url
            results.append({
                'title':       a_tag.get_text(strip=True) or 'No title available',
                'description': p_tag.get_text(strip=True) if p_tag else 'No description available',
                'site_url':    site_url,
            })
        return results

    def _fetch_tordex(self, query, amount, headers, proxy_config=None):
        """
        Fetch results from TorDex.

        Uses the .onion endpoint when a Tor proxy_config is supplied, otherwise
        falls back to the clearnet endpoint (tordex.cc/search) — both serve
        identical HTML. The HTML structure uses .container h5 a for results.

        NOTE: TorDex is completely unfiltered. Results may include illegal or
        harmful content. Use only for legitimate research purposes.
        """
        engine = Configuration.SEARCH_ENGINES['tordex']
        q = requests.utils.quote(query)

        if proxy_config:
            url = engine['onion'].format(query=q)
            response = requests.get(url, headers=headers, proxies=proxy_config, timeout=30)
        else:
            url = engine['api'].format(query=q)
            response = requests.get(url, headers=headers, timeout=20)

        if response.status_code != 200:
            raise Exception(f"TorDex request failed (HTTP {response.status_code})")

        soup = BeautifulSoup(response.content, 'html.parser')
        results = []

        # Primary: .container h5 a
        anchors = soup.select('.container h5 a')

        if not anchors:
            for a_tag in soup.find_all('a', href=lambda h: h and '.onion' in h):
                if len(results) >= amount:
                    break
                site_url    = a_tag['href'].strip()
                title       = a_tag.get_text(strip=True) or 'No title available'
                parent      = a_tag.parent
                description = parent.get_text(' ', strip=True).replace(title, '').strip()
                description = description[:200] if description else 'No description available'
                results.append({'title': title, 'description': description, 'site_url': site_url})
            return results

        for a_tag in anchors[:amount]:
            site_url = a_tag['href'].strip()
            if site_url and 'http' not in site_url:
                site_url = 'http://' + site_url
            title = a_tag.get_text(strip=True) or 'No title available'
            h5    = a_tag.parent
            p_tag = h5.find_next_sibling('p') if h5 else None
            description = p_tag.get_text(strip=True) if p_tag else 'No description available'
            results.append({
                'title':       title,
                'description': description,
                'site_url':    site_url,
            })
        return results

    def _fetch_tor66(self, query, amount, headers, proxy_config):
        """
        Fetch results from Tor66 via its .onion address (Tor required).

        Tor66 renders search results as <b> elements that follow the first <hr>
        divider on the page. Each result <b> contains an <a href> with the title
        and URL. This selector is confirmed by OnionSearch core.py:
            soup.find('hr').find_all_next('b')

        Fallback: any <a> pointing to a .onion href.

        NOTE: Tor66 is completely unfiltered. Results may include illegal or
        harmful content. Use only for legitimate research purposes.
        """
        engine = Configuration.SEARCH_ENGINES['tor66']
        url = engine['onion'].format(query=requests.utils.quote(query))
        response = requests.get(url, headers=headers, proxies=proxy_config, timeout=30)
        if response.status_code != 200:
            raise Exception(f"Tor66 request failed (HTTP {response.status_code})")

        soup = BeautifulSoup(response.content, 'html.parser')
        results = []

        # Primary: <b> blocks that follow the first <hr> separator
        hr = soup.find('hr')
        b_tags = hr.find_all_next('b') if hr else []

        if not b_tags:
            # Fallback: scan all .onion hrefs
            for a_tag in soup.find_all('a', href=lambda h: h and '.onion' in h):
                if len(results) >= amount:
                    break
                site_url    = a_tag['href'].strip()
                title       = a_tag.get_text(strip=True) or 'No title available'
                parent      = a_tag.parent
                description = parent.get_text(' ', strip=True).replace(title, '').strip()
                description = description[:200] if description else 'No description available'
                results.append({'title': title, 'description': description, 'site_url': site_url})
            return results

        for b_tag in b_tags:
            if len(results) >= amount:
                break
            a_tag = b_tag.find('a', href=True)
            if not a_tag:
                continue
            site_url = a_tag['href'].strip()
            if site_url and 'http' not in site_url:
                site_url = 'http://' + site_url
            title = a_tag.get_text(strip=True) or 'No title available'
            # Description text sits directly after the <b> block as a text node or <br>
            desc_parts = []
            for sibling in b_tag.next_siblings:
                tag_name = getattr(sibling, 'name', None)
                if tag_name == 'b':
                    break   # next result block starts
                if tag_name == 'br':
                    continue
                text = sibling.get_text(strip=True) if tag_name else str(sibling).strip()
                if text:
                    desc_parts.append(text)
                    if len(' '.join(desc_parts)) >= 200:
                        break
            description = ' '.join(desc_parts)[:200] or 'No description available'
            results.append({
                'title':       title,
                'description': description,
                'site_url':    site_url,
            })
        return results

    def _fetch_onionland(self, query, amount, headers, proxy_config):
        """
        Fetch results from OnionLand via its .onion address (Tor required).

        OnionLand indexes Tor, I2P, and clearnet. We filter to .onion results only
        since Darkdump is a dark web tool. Results use .result-block .title a;
        the destination URL is double-encoded as the 'l' query param in the href
        (confirmed by OnionSearch core.py: unquote(unquote(get_parameter(href, 'l')))).

        Description text sits in the first <p> tag inside the .result-block that
        is NOT the URL line — we skip any <p> whose text looks like a raw URL.

        NOTE: OnionLand does minimal content filtering. Results may include
        harmful or illegal content. Use only for legitimate research.
        """
        from urllib.parse import urlparse, parse_qs, unquote as _unquote

        engine = Configuration.SEARCH_ENGINES['onionland']
        url = engine['onion'].format(query=requests.utils.quote(query))
        response = requests.get(url, headers=headers, proxies=proxy_config, timeout=30)
        if response.status_code != 200:
            raise Exception(f"OnionLand request failed (HTTP {response.status_code})")

        soup = BeautifulSoup(response.text, 'html5lib')
        results = []

        for a_tag in soup.select('.result-block .title a'):
            if len(results) >= amount:
                break

            # Skip ad links
            href = a_tag.get('href', '')
            if href.startswith('/ads/'):
                continue

            # Extract destination URL — double-encoded in the 'l' query param
            try:
                qs = parse_qs(urlparse(href).query)
                raw = qs.get('l', [''])[0]
                site_url = _unquote(_unquote(raw))
            except Exception:
                site_url = ''

            if not site_url:
                continue

            # Only keep .onion results — skip I2P (.i2p) and clearnet
            if '.onion' not in site_url:
                continue

            title = a_tag.get_text(strip=True) or 'No title available'

            # Description: find the first <p> in the result block that isn't
            # just a URL or the site address line
            description = 'No description available'
            block = a_tag.find_parent(class_='result-block')
            if block:
                for p in block.find_all('p'):
                    text = p.get_text(strip=True)
                    # Skip empty, very short, or raw-URL paragraphs
                    if text and len(text) > 20 and not text.startswith('http'):
                        description = text[:200]
                        break
                # Fallback: grab all non-link text from the block
                if description == 'No description available':
                    all_text = block.get_text(' ', strip=True)
                    # Strip the title from the block text to leave the snippet
                    snippet = all_text.replace(title, '').strip()
                    snippet = re.sub(r'https?://\S+', '', snippet).strip()
                    snippet = re.sub(r'\s+', ' ', snippet)
                    if len(snippet) > 20:
                        description = snippet[:200]

            results.append({
                'title':       title,
                'description': description,
                'site_url':    site_url,
            })

        return results

    def _fetch_excavator(self, query, amount, headers, proxy_config):
        """
        Fetch results from Excavator via its .onion address (Tor required).

        Probes known search paths in order since the exact endpoint may vary.
        Parses generic result containers and falls back to scanning .onion hrefs.
        """
        engine      = Configuration.SEARCH_ENGINES['excavator']
        base        = engine['onion']
        encoded     = requests.utils.quote(query)
        engine_host = base.split('/')[2]

        search_paths = [
            f"/search?q={encoded}",
            f"/search?query={encoded}",
            f"/?q={encoded}",
            f"/index.php?q={encoded}",
        ]

        response = None
        for path in search_paths:
            try:
                r = requests.get(base + path, headers=headers, proxies=proxy_config, timeout=30)
                if r.status_code == 200:
                    response = r
                    break
            except Exception:
                continue

        if response is None:
            raise Exception("Excavator: no search path returned a valid response")

        soup    = BeautifulSoup(response.text, 'html5lib')
        results = []

        tag, cls = engine['result_tag']
        raw = soup.find_all(tag, class_=cls) if cls else soup.find_all(tag)

        for item in raw:
            if len(results) >= amount:
                break
            a_tag = item.find('a', href=True)
            if not a_tag:
                continue
            href = a_tag['href'].strip()
            if '.onion' not in href or engine_host in href:
                continue
            site_url = href if href.startswith('http') else 'http://' + href
            title    = a_tag.get_text(strip=True) or 'No title available'

            description = 'No description available'
            for p in item.find_all('p'):
                text = p.get_text(strip=True)
                if text and len(text) > 20 and not text.startswith('http'):
                    description = text[:200]
                    break
            if description == 'No description available':
                snippet = re.sub(r'https?://\S+', '', item.get_text(' ', strip=True))
                snippet = re.sub(r'\s+', ' ', snippet).replace(title, '').strip()
                if len(snippet) > 20:
                    description = snippet[:200]

            results.append({'title': title, 'description': description, 'site_url': site_url})

        # Fallback: scan all .onion hrefs on the page
        if not results:
            for a_tag in soup.find_all('a', href=lambda h: h and '.onion' in h and engine_host not in h):
                if len(results) >= amount:
                    break
                href     = a_tag['href'].strip()
                site_url = href if href.startswith('http') else 'http://' + href
                title    = a_tag.get_text(strip=True) or 'No title available'
                parent   = a_tag.parent
                snippet  = parent.get_text(' ', strip=True).replace(title, '').strip()
                description = snippet[:200] if len(snippet) > 20 else 'No description available'
                results.append({'title': title, 'description': description, 'site_url': site_url})

        return results

    def _fetch_torch(self, query, amount, headers, proxy_config):
        """
        Fetch results from Torch via its .onion address (Tor required).

        The legacy Torch host meta-refreshes to its htdig "omega" search CGI,
        which serves 10 results per page. Pages beyond the first are requested
        by replaying the page's hidden state fields (xP, xDB, xFILTERS, tkn,
        ...) together with the page-number button "["; a fresh search therefore
        only sends P=, since the CGI resets the connection when given partial
        state. Up to 10 pages are fetched (100 results).

        Each result row is a table cell whose title is a <b><a href> element
        followed by a <small> snippet.

        Fallback: any <a> pointing to a .onion href.

        NOTE: Torch is completely unfiltered. Results may include illegal or
        harmful content. Use only for legitimate research purposes.
        """
        engine   = Configuration.SEARCH_ENGINES['torch']
        q        = requests.utils.quote(query)
        url      = engine['onion'].format(query=q)
        endpoint = url.split('?')[0]
        session  = requests.Session()

        results = []
        seen    = set()
        page    = 1
        params  = None

        while len(results) < amount and page <= 10:
            if page == 1:
                response = session.get(url, headers=headers, proxies=proxy_config, timeout=60)
            else:
                response = session.get(endpoint, headers=headers, proxies=proxy_config,
                                       params=params, timeout=60)

            if response.status_code != 200:
                if page == 1:
                    raise Exception(f"Torch request failed (HTTP {response.status_code})")
                break

            # The omega page has no meta charset, so rely on the HTTP header
            # (response.text) instead of letting BeautifulSoup guess from bytes.
            soup = BeautifulSoup(response.text, 'html.parser')

            # Primary: title anchors inside result table cells
            new_results = 0
            for a_tag in soup.select('td b a[href]'):
                if len(results) >= amount:
                    break
                site_url = a_tag['href'].strip()
                if not site_url.startswith('http') or site_url in seen:
                    continue
                seen.add(site_url)
                new_results += 1

                title = a_tag.get_text(strip=True) or 'No title available'
                small = a_tag.find_next('small')
                description = small.get_text(' ', strip=True) if small else ''
                if not description:
                    description = 'No description available'

                results.append({
                    'title':       title,
                    'description': description[:200],
                    'site_url':    site_url,
                })

            # Fallback: scan all .onion hrefs if the table selector found
            # nothing at all on the first page.
            if page == 1 and not results:
                for a_tag in soup.find_all('a', href=lambda h: h and '.onion' in h):
                    if len(results) >= amount:
                        break
                    site_url = a_tag['href'].strip()
                    if site_url in seen:
                        continue
                    seen.add(site_url)
                    title  = a_tag.get_text(strip=True) or 'No title available'
                    parent = a_tag.parent
                    snippet = parent.get_text(' ', strip=True).replace(title, '').strip() if parent else ''
                    description = snippet[:200] if len(snippet) > 20 else 'No description available'
                    results.append({'title': title, 'description': description, 'site_url': site_url})
                return results

            if len(results) >= amount or new_results == 0:
                break

            # Replay the page's hidden state fields to reach the next page.
            hidden = {i['name']: i.get('value', '')
                      for i in soup.find_all('input', attrs={'type': 'hidden'})
                      if i.get('name')}
            if not hidden:
                break

            page += 1
            params = dict(hidden)
            params['P'] = query
            params['['] = str(page)

        return results

    def _fetch_darksearch(self, query, amount, headers, proxy_config):
        """
        Fetch results from the DarkSearch JSON API.

        DarkSearch discontinued public access in January 2022 and its host no
        longer resolves. The original API call is kept intact so the engine
        works again if the service ever returns; until then this raises a
        descriptive error.

        NOTE: DarkSearch was completely unfiltered.
        """
        engine = Configuration.SEARCH_ENGINES['darksearch']
        q      = requests.utils.quote(query)

        try:
            response = requests.get(engine['api'].format(query=q), headers=headers, timeout=20)
        except requests.RequestException:
            raise Exception(
                "DarkSearch has been offline since January 2022 — public access "
                "was discontinued and darksearch.io no longer resolves."
            )

        if response.status_code != 200:
            raise Exception(f"DarkSearch request failed (HTTP {response.status_code})")

        try:
            data = response.json().get('data', [])
        except ValueError:
            raise Exception("DarkSearch returned a non-JSON response.")

        results = []
        for item in data[:amount]:
            site_url = (item.get('link') or '').strip()
            if not site_url:
                continue
            results.append({
                'title':       item.get('title') or 'No title available',
                'description': item.get('description') or 'No description available',
                'site_url':    site_url,
            })
        return results

    def _fetch_vormweb(self, query, amount, headers, proxy_config):
        """
        Fetch results from VormWeb.

        Uses the .onion endpoint when a Tor proxy_config is supplied, otherwise
        the clearnet site (vormweb.de/en/search) — both serve identical HTML.
        Each result is a div.query-box whose a#urllink anchor holds the title
        and URL; the description is the following <li>.

        VormWeb screens illegal content and badges every result with a trust
        level (verified / warning / risky), so results are filtered by design.
        """
        engine = Configuration.SEARCH_ENGINES['vormweb']
        q      = requests.utils.quote(query)

        if proxy_config:
            url      = engine['onion'].format(query=q)
            response = requests.get(url, headers=headers, proxies=proxy_config, timeout=30)
        else:
            url      = engine['api'].format(query=q)
            response = requests.get(url, headers=headers, timeout=20)

        if response.status_code != 200:
            raise Exception(f"VormWeb request failed (HTTP {response.status_code})")

        soup    = BeautifulSoup(response.content, 'html.parser')
        results = []

        for box in soup.select('div.query-box'):
            if len(results) >= amount:
                break
            a_tag = box.find('a', id='urllink') or box.find('a', href=True)
            if not a_tag:
                continue
            site_url = a_tag['href'].strip()
            if not site_url.startswith('http'):
                continue

            title = a_tag.get_text(strip=True) or 'No title available'
            li    = box.find('li')
            description = li.get_text(' ', strip=True) if li else ''
            if not description or description.lower().startswith('no description'):
                description = 'No description available'

            results.append({
                'title':       title,
                'description': description[:200],
                'site_url':    site_url,
            })
        return results

    def _scrape_site(self, site_url, headers, proxy_config, scrape_images, debug_mode, idx):
        """
        Scrape a single onion site for metadata, links, emails, documents,
        and optionally images. Returns a dict for ResultSaver, or None on failure.
        """
        try:
            site_response = requests.get(site_url, headers=headers, proxies=proxy_config, timeout=20)
            site_soup     = BeautifulSoup(site_response.content, 'html.parser')
            metadata      = self.extract_metadata(site_soup)
            links         = self.extract_links(site_soup)
            emails        = self.extract_emails(site_soup)
            documents     = self.extract_document_links(site_soup)

            images_gallery_path = None
            image_urls          = []
            images_str          = ""
            if scrape_images:
                images     = site_soup.find_all('img')
                image_urls = [img['src'] for img in images if img.get('src')]
                image_urls = [u if u.startswith('http') else site_url + u for u in image_urls]
                if image_urls:
                    html_path           = self.generate_html(image_urls, site_url)
                    images_gallery_path = os.path.abspath(html_path)
                    images_str = (
                        f"{Colors.BOLD}| Images Gallery: {Colors.END}"
                        f"{Colors.G}{images_gallery_path}{Colors.END}\n"
                    )

            print('-' * 50)
            print(f"{Colors.BOLD}{idx}.\n --- [+] Website: {Colors.END}{Colors.P}{site_url}{Colors.END}")
            print(f"{Colors.BOLD}| Metadata: {Colors.END}{Colors.G}{json.dumps(metadata)}{Colors.END}")
            print(f"{Colors.BOLD}| Links Found: {Colors.END}{Colors.G}{len(links)}{Colors.END}")
            print(f"{Colors.BOLD}| Emails Found: {Colors.END}{Colors.G}{', '.join(emails) if emails else 'No emails found.'}{Colors.END}")
            print(f"{Colors.BOLD}| Documents Found: {Colors.END}{Colors.G}{', '.join(documents) if documents else 'No document links found.'}{Colors.END}")

            if scrape_images:
                if image_urls:
                    print(images_str)
                else:
                    print(f"{Colors.BOLD + Colors.GR} No images found. Skipping parse. {Colors.END}")

            scrape_data = {
                'metadata':    metadata,
                'links_count': len(links),
                'emails':      emails,
                'documents':   documents,
            }
            if images_gallery_path:
                scrape_data['images_gallery'] = images_gallery_path
            return scrape_data

        except Exception as e:
            print(f"{Colors.BOLD + Colors.O} Dead onion, skipping...: {site_url} {Colors.END}")
            if debug_mode:
                print(f"{Colors.BOLD + Colors.R}[DEBUG] Exception: {e}{Colors.END}")
            return None

    def _normalize_url(self, url, base=None):
        """
        Resolve *url* against *base* and normalize it for crawling:
        lowercase host, drop the fragment. Returns None when the result
        is not a usable http(s) URL.
        """
        url = (url or '').strip()
        if not url:
            return None
        if base:
            url = urljoin(base, url)
        try:
            parsed = urlsplit(url)
        except ValueError:
            return None
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            return None
        path = parsed.path or '/'
        # urljoin leaves dot segments in absolute URLs; collapse them so the
        # same page is not fetched twice under different spellings.
        if '/.' in path:
            normalized = posixpath.normpath(path)
            if path.endswith('/') and not normalized.endswith('/'):
                normalized += '/'
            if normalized.startswith('//'):
                normalized = '/' + normalized.lstrip('/')
            path = normalized
        return urlunsplit((parsed.scheme, parsed.netloc.lower(), path, parsed.query, ''))

    def _page_filename(self, url, idx):
        """Build a unique, filesystem-safe .html filename for a crawled URL."""
        parsed = urlsplit(url)
        name   = parsed.path.strip('/') or 'index'
        name   = re.sub(r'\.html?$', '', name, flags=re.IGNORECASE)
        name   = re.sub(r'[^A-Za-z0-9._-]+', '_', name)[:80].strip('._') or 'index'
        if parsed.query:
            name += '_' + re.sub(r'[^A-Za-z0-9._-]+', '_', parsed.query)[:40]
        return f"{idx:04d}_{name}.html"

    def _parse_sitemap(self, content):
        """Extract every <loc> URL from a sitemap or sitemapindex document."""
        return [
            u.strip() for u in re.findall(r'<loc>\s*(.*?)\s*</loc>', content, re.IGNORECASE | re.DOTALL)
            if u.strip()
        ]

    def _classify_url(self, url):
        """
        Bucket a URL by page kind, using the path shapes forum software
        (XenForo and relatives) uses.
        """
        parsed   = urlsplit(url)
        path     = parsed.path.lower()
        query    = parsed.query.lower()
        segments = [s for s in path.split('/') if s]

        file_exts = ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip',
                     '.rar', '.7z', '.tar', '.gz', '.txt', '.json', '.xml', '.csv',
                     '.sql', '.db', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg',
                     '.ico', '.mp4', '.mp3')
        if path.endswith(file_exts) or '/attachments/' in path:
            return 'file'
        if segments[:1] in (['threads'], ['posts']) or 'threads' in segments or 'threads/' in query:
            return 'thread'
        if segments[:1] in (['forums'], ['categories']) or 'forums' in segments or 'forums/' in query:
            return 'board'
        if segments[:1] == ['members']:
            return 'member'
        if segments[:1] == ['tags']:
            return 'tag'
        if any(seg in path for seg in ('/whats-new', '/find-new', '/latest', '/recent',
                                       '/search', '/login', '/register', '/lost-password',
                                       '/account', '/conversations', '/alerts', '/help',
                                       '/misc', '/online', '/news-feed', '/watched', '/goto/')):
            return 'system'
        if path in ('', '/') or path.endswith('/index.php'):
            return 'index'
        return 'other'

    def _url_section(self, url):
        """Top-level path segment — the site's first-level section."""
        segments = [p for p in urlsplit(url).path.split('/') if p]
        return segments[0] if segments else '/'

    def _rewrite_host(self, url, host, scheme):
        """Move a URL onto *host* and *scheme*, keeping path and query intact."""
        try:
            parsed = urlsplit(url)
        except ValueError:
            return url
        return urlunsplit((scheme, host, parsed.path or '/', parsed.query, ''))

    def crawl_site(self, start_url, depth=3, max_pages=200, delay=2.0,
                   use_proxy=False, wordlist=None, debug_mode=False,
                   output_file=None, urls_only=False, url_list=None,
                   resume=False, rewrite_host=True, max_sitemaps=300):
        """
        Crawl one site (clearnet or .onion) starting from *start_url*.

        Modes:
          * default    — link crawl: sitemap seeds plus breadth-first link
                         following up to *depth*
          * urls_only  — inventory only: walk the whole sitemap tree and list
                         every URL; no pages are downloaded
          * url_list   — download exactly the URLs from *url_list* (one per
                         line), for fetching a site in resumable batches

        Reachable HTML pages are saved under dd_crawl_dump/<host>/ together
        with urls.json (full URL inventory), urls.txt (plain URL list, usable
        as --url-list input) and state.json (resume bookkeeping). Hosts
        declared in sitemaps that differ from the crawl host are rewritten
        onto it unless *rewrite_host* is False. Requests are sequential with
        a pause of *delay* seconds between them.
        """
        raw_url   = start_url
        start_url = self._normalize_url(raw_url)
        if not start_url:
            print(f"{Colors.BOLD + Colors.R}Error: '{raw_url}' is not a valid http(s) URL.{Colors.END}")
            return False
        started_at = time.time()

        if urls_only and url_list:
            print(f"{Colors.BOLD + Colors.R}Error: use either --urls-only or --url-list, not both.{Colors.END}")
            return False

        depth        = max(0, depth)
        max_pages    = max(1, max_pages)
        delay        = max(0.0, delay)
        max_sitemaps = max(1, max_sitemaps)
        host         = urlsplit(start_url).netloc
        scheme       = urlsplit(start_url).scheme
        is_onion     = host.endswith('.onion')

        if is_onion and not use_proxy:
            print(f"{Colors.BOLD + Colors.O}Note: {host} is a Tor hidden service. "
                  f"Enabling the proxy automatically.{Colors.END}")
        if is_onion:
            use_proxy = True
        proxy_config = {
            'http':  Configuration.__socks5init__,
            'https': Configuration.__socks5init__,
        } if use_proxy else {}

        if use_proxy and Platform(True).check_tor_connection(proxy_config) is False:
            print(f"{Colors.BOLD + Colors.R}Tor is required to crawl {host}. Aborting.{Colors.END}")
            return False

        probes = []
        if wordlist:
            if urls_only or url_list:
                print(f"{Colors.BOLD + Colors.O}Note: --wordlist is ignored in "
                      f"--urls-only/--url-list mode.{Colors.END}")
            elif not os.path.isfile(wordlist):
                print(f"{Colors.BOLD + Colors.R}Error: wordlist file not found: {wordlist}{Colors.END}")
                return False
            else:
                with open(wordlist, 'r', errors='ignore') as f:
                    probes = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                if not probes:
                    print(f"{Colors.BOLD + Colors.O}Wordlist is empty; continuing with link crawling only.{Colors.END}")

        list_urls = None
        if url_list:
            if not os.path.isfile(url_list):
                print(f"{Colors.BOLD + Colors.R}Error: URL list file not found: {url_list}{Colors.END}")
                return False
            with open(url_list, 'r', errors='ignore') as f:
                list_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if not list_urls:
                print(f"{Colors.BOLD + Colors.R}Error: URL list file is empty: {url_list}{Colors.END}")
                return False

        headers  = {'User-Agent': random.choice(Headers.user_agents)}
        dump_dir = os.path.join('dd_crawl_dump', self.sanitize_filename(host.replace(':', '_')))
        os.makedirs(dump_dir, exist_ok=True)
        index_path = os.path.join(dump_dir, 'urls.json')
        txt_path   = os.path.join(dump_dir, 'urls.txt')
        state_path = os.path.join(dump_dir, 'state.json')

        if urls_only:
            print(f"{Colors.BOLD + Colors.C}[ URL inventory — {host} | sitemaps only, no pages fetched ]{Colors.END}")
        elif url_list:
            print(f"{Colors.BOLD + Colors.C}[ Download batch — {host} | max {max_pages} pages | "
                  f"delay {delay}s ]{Colors.END}")
        else:
            print(f"{Colors.BOLD + Colors.C}[ Crawling {host} | depth {depth} | "
                  f"max {max_pages} pages | delay {delay}s ]{Colors.END}")
        if probes:
            print(f"{Colors.BOLD + Colors.C}[ Wordlist: {len(probes)} path(s) from {wordlist} ]{Colors.END}")
        print(f"{Colors.BOLD + Colors.O}Note: read-only crawl, one request at a time over Tor. "
              f"Press Ctrl+C to stop early.{Colors.END}\n")

        # ---------------------------------------------------------------- state
        queue         = deque()
        queued        = set()
        visited       = set()
        inventory     = {}          # url -> entry dict (the whole URL map)
        mirror_hosts  = set()       # foreign hosts declared by the site's sitemaps
        sitemaps_seen = []
        fetched       = 0
        responded     = 0
        ok_count      = 0
        errors        = 0
        saved_count   = 0
        rewrite_count = 0

        state_prev = {}
        next_index = 1
        state_loaded = False
        if resume and os.path.isfile(state_path):
            try:
                with open(state_path) as f:
                    prev_state = json.load(f)
                state_prev = prev_state.get('done', {}) or {}
                next_index = int(prev_state.get('next_index', 1) or 1)
                state_loaded = True
            except Exception as e:
                print(f"{Colors.BOLD + Colors.O}Could not read {state_path} ({e}); starting fresh.{Colors.END}")
        done = dict(state_prev)
        if resume and not state_loaded:
            # No state yet: continue numbering after any pages saved by earlier runs.
            try:
                existing = [int(f.split('_', 1)[0]) for f in os.listdir(dump_dir)
                            if f[:4].isdigit() and f.endswith('.html')]
                if existing:
                    next_index = max(existing) + 1
                    print(f"{Colors.BOLD + Colors.O}No state file found; continuing page numbering "
                          f"at {next_index}.{Colors.END}")
            except Exception:
                pass
        if resume and os.path.isfile(index_path):
            try:
                with open(index_path) as f:
                    old_doc = json.load(f)
                for item in old_doc.get('urls', []) or []:
                    u = item.get('url')
                    if not u:
                        continue
                    inventory[u] = {
                        'url': u,
                        'type': item.get('type') or self._classify_url(u),
                        'section': item.get('section') or self._url_section(u),
                        'source': item.get('source', 'sitemap'),
                        'status': item.get('status'),
                        'saved_file': item.get('saved_file'),
                        'blocked': bool(item.get('blocked', False)),
                    }
                    if item.get('title'):
                        inventory[u]['title'] = item['title']
            except Exception:
                pass

        def same_site(url):
            h = urlsplit(url).netloc
            return h == host or h in mirror_hosts

        def add_url(url, source, base=None):
            """Normalize, host-check/rewrite and record a URL. Returns it or None."""
            nonlocal rewrite_count
            norm = self._normalize_url(url, base=base or start_url)
            if not norm:
                return None
            url_host = urlsplit(norm).netloc
            if source != 'list' and url_host != host:
                if source == 'sitemap' or url_host in mirror_hosts:
                    mirror_hosts.add(url_host)
                    if rewrite_host:
                        norm = self._rewrite_host(norm, host, scheme)
                        rewrite_count += 1
                else:
                    return None     # external link — not part of this site
            entry = inventory.get(norm)
            if entry is None:
                inventory[norm] = {
                    'url': norm,
                    'type': self._classify_url(norm),
                    'section': self._url_section(norm),
                    'source': source,
                    'status': None,
                    'saved_file': None,
                    'blocked': False,
                }
            return norm

        def fetch_page(url):
            try:
                return requests.get(url, headers=headers, proxies=proxy_config, timeout=30), None
            except Exception as e:
                return None, str(e)[:120]

        def save_page(url, response):
            nonlocal next_index, saved_count
            filename = self._page_filename(url, next_index)
            with open(os.path.join(dump_dir, filename), 'wb') as f:
                f.write(response.content)
            next_index += 1
            saved_count += 1
            return os.path.join(dump_dir, filename)

        def save_state():
            try:
                state_doc = {
                    'target':     start_url,
                    'host':       host,
                    'updated_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
                    'next_index': next_index,
                    'done':       done,
                }
                with open(state_path, 'w') as f:
                    json.dump(state_doc, f, indent=2)
            except Exception:
                pass

        def process_response(url, response, level=0, is_probe=False, quiet_404=False):
            """Record a fetched page: save HTML, classify, update inventory."""
            nonlocal fetched, responded, ok_count
            fetched   += 1
            responded += 1
            status = response.status_code
            ctype  = response.headers.get('Content-Type', '')
            is_html = ('html' in ctype.lower()
                       or (not ctype.strip() and b'<' in response.content[:512]))
            title      = ''
            saved_file = None
            soup       = None
            if is_html and response.content:
                soup  = BeautifulSoup(response.content, 'html.parser')
                title = (soup.title.get_text(strip=True) if soup.title else '')[:150]

            blocked = status in (401, 403)
            if (status == 200 and response.url and '/login/' in response.url
                    and '/login/' not in url):
                blocked = True      # bounced to the login wall

            if status == 200 and is_html and response.content:
                ok_count  += 1
                saved_file = save_page(url, response)

            entry = inventory.get(url)
            if entry is None:
                entry = inventory[url] = {
                    'url': url, 'type': self._classify_url(url),
                    'section': self._url_section(url),
                    'source': 'list' if url_list else 'link',
                    'status': None, 'saved_file': None, 'blocked': False,
                }
            entry.update({
                'status': status, 'saved_file': saved_file, 'blocked': blocked,
                'title': title, 'size': len(response.content), 'depth': level,
            })
            if is_probe:
                entry['probe'] = True
            if response.url and response.url != url:
                entry['redirected_to'] = response.url

            # Resume bookkeeping: an answered URL is done unless it may succeed
            # later (server errors, throttling). Blocked pages count as done.
            if status < 500 and status != 429:
                done[url] = {'status': status, 'saved_file': saved_file}
                if len(done) % 5 == 0:
                    save_state()

            if not (status == 404 and quiet_404):
                color  = Colors.G if status == 200 else Colors.O
                marker = '[probe]' if is_probe else ('[+]' if status == 200 else '[!]')
                tag    = f" {Colors.GR}{title}{Colors.END}" if title else ''
                wall   = f" {Colors.R}(login wall){Colors.END}" if blocked else ''
                print(f"{Colors.BOLD}{marker} {color}{status}{Colors.END} {Colors.P}{url}{Colors.END}{tag}{wall}")
            return soup

        def mark_redirect(response, url):
            """Track a redirect's final URL so it is not fetched a second time."""
            if response.url and response.url != url:
                final = add_url(response.url, source='link')
                if final and same_site(final):
                    queued.discard(final)
                    visited.add(final)

        sitemap_count   = 0
        sitemap_cap_hit = False

        def load_sitemap(sitemap_url):
            nonlocal sitemap_count, sitemap_cap_hit
            sm_url = self._normalize_url(sitemap_url, base=start_url)
            if not sm_url or sm_url in queued:
                return
            if sitemap_count >= max_sitemaps:
                if not sitemap_cap_hit:
                    sitemap_cap_hit = True
                    print(f"{Colors.BOLD + Colors.O}Reached the sitemap limit "
                          f"({max_sitemaps}); ignoring further sitemap links.{Colors.END}")
                return
            sm_host = urlsplit(sm_url).netloc
            if sm_host != host:
                mirror_hosts.add(sm_host)
            queued.add(sm_url)
            sitemap_count += 1
            try:
                response = requests.get(sm_url, headers=headers, proxies=proxy_config, timeout=30)
                time.sleep(delay)
            except Exception as e:
                if debug_mode:
                    print(f"{Colors.BOLD + Colors.R}[DEBUG] sitemap fetch failed: {sm_url} — {e}{Colors.END}")
                return
            if response.status_code != 200:
                return
            sitemaps_seen.append(sm_url)
            print(f"{Colors.BOLD}[+] {Colors.G}200{Colors.END} {Colors.P}{sm_url}{Colors.END} (sitemap)")
            for loc in self._parse_sitemap(response.text):
                if urlsplit(loc).path.endswith('.xml'):
                    if urlsplit(loc).netloc and urlsplit(loc).netloc != host and rewrite_host:
                        loc = self._rewrite_host(loc, host, scheme)
                    load_sitemap(loc)
                else:
                    add_url(loc, source='sitemap')

        def enqueue(url, d, base=None):
            if d > depth:
                return
            norm = add_url(url, source='link', base=base)
            if norm and same_site(norm) and norm not in queued:
                queued.add(norm)
                queue.append((norm, d))

        try:
            # Seed: robots.txt (+ any Sitemap: lines it declares) and /sitemap.xml
            robots_url = self._normalize_url('/robots.txt', base=start_url)
            try:
                robots = requests.get(robots_url, headers=headers, proxies=proxy_config, timeout=30)
                time.sleep(delay)
            except Exception:
                robots = None
            if robots is not None and robots.status_code == 200:
                print(f"{Colors.BOLD}[+] {Colors.G}200{Colors.END} {Colors.P}{robots_url}{Colors.END} (robots.txt)")
                for line in robots.text.splitlines():
                    if line.strip().lower().startswith('sitemap:'):
                        load_sitemap(line.split(':', 1)[1].strip())
            load_sitemap('/sitemap.xml')
            load_sitemap('/sitemap.php')       # XenForo-style index, harmless if absent

            if inventory:
                print(f"{Colors.BOLD}| Sitemap seeds: {Colors.END}{Colors.G}{len(inventory)} URL(s) discovered{Colors.END}")

            if urls_only:
                pass        # inventory done — nothing to download by design
            elif url_list:
                # Download batch: fetch exactly the listed URLs, in order.
                list_normed = []
                for u in list_urls:
                    norm = add_url(u, source='list')
                    if norm and norm not in list_normed:
                        list_normed.append(norm)
                total     = len(list_normed)
                remaining = [u for u in list_normed if u not in done]
                already   = total - len(remaining)
                if state_loaded or already:
                    print(f"{Colors.BOLD}| Resuming: {Colors.END}{Colors.G}{already}{Colors.END} of "
                          f"{total} URL(s) already done, {Colors.G}{len(remaining)}{Colors.END} remaining.{Colors.END}")
                if not remaining:
                    print(f"{Colors.BOLD + Colors.G}All {total} URLs are already downloaded.{Colors.END}")
                for url in remaining:
                    if fetched >= max_pages:
                        print(f"{Colors.BOLD + Colors.O}Batch limit reached ({max_pages} pages); "
                              f"run again with --resume to continue.{Colors.END}")
                        break
                    response, error = fetch_page(url)
                    if error:
                        errors += 1
                        entry = inventory.setdefault(url, {
                            'url': url, 'type': self._classify_url(url),
                            'section': self._url_section(url), 'source': 'list',
                            'status': None, 'saved_file': None, 'blocked': False,
                        })
                        entry['status'] = 'ERR'
                        entry['error']  = error
                        print(f"{Colors.BOLD}[x] {Colors.R}ERR{Colors.END} {Colors.P}{url}{Colors.END}")
                        if debug_mode:
                            print(f"{Colors.BOLD + Colors.R}[DEBUG] {error}{Colors.END}")
                        time.sleep(delay)
                        continue
                    soup = process_response(url, response)
                    mark_redirect(response, url)
                    if soup:
                        for href in self.extract_links(soup):
                            add_url(href, source='link', base=url)
                    time.sleep(delay)
            else:
                enqueue(start_url, 0)

                # Optional wordlist probes: guessed paths that may not be linked
                if probes:
                    base  = start_url if start_url.endswith('/') else start_url + '/'
                    found = 0
                    print(f"\n{Colors.BOLD + Colors.C}[ Probing wordlist paths ]{Colors.END}")
                    for word in probes:
                        if fetched >= max_pages:
                            print(f"{Colors.BOLD + Colors.O}Reached max-pages limit ({max_pages}); "
                                  f"stopping probes.{Colors.END}")
                            break
                        probe_url = self._normalize_url(word, base=base)
                        if not probe_url or urlsplit(probe_url).netloc != host:
                            continue
                        if probe_url in visited or probe_url in queued or probe_url in done:
                            continue
                        visited.add(probe_url)
                        add_url(probe_url, source='link')
                        response, error = fetch_page(probe_url)
                        if error:
                            errors += 1
                            entry = inventory.setdefault(probe_url, {
                                'url': probe_url, 'type': self._classify_url(probe_url),
                                'section': self._url_section(probe_url), 'source': 'link',
                                'status': None, 'saved_file': None, 'blocked': False,
                            })
                            entry['status'] = 'ERR'
                            entry['error']  = error
                            print(f"{Colors.BOLD}[x] {Colors.R}ERR{Colors.END} {Colors.P}{probe_url}{Colors.END}")
                            if debug_mode:
                                print(f"{Colors.BOLD + Colors.R}[DEBUG] probe error {probe_url}: {error}{Colors.END}")
                            time.sleep(delay)
                            continue
                        soup = process_response(probe_url, response, is_probe=True,
                                                quiet_404=not debug_mode)
                        mark_redirect(response, probe_url)
                        if response.status_code == 200:
                            found += 1
                            if soup and depth >= 1:
                                for href in self.extract_links(soup):
                                    enqueue(href, 1, base=probe_url)
                        time.sleep(delay)
                    print(f"{Colors.BOLD}| Probe hits (200): {Colors.END}{Colors.G}{found}{Colors.END}\n")

                # Breadth-first link crawl
                while queue and fetched < max_pages:
                    url, d = queue.popleft()
                    if url in visited or url in done:
                        continue
                    visited.add(url)
                    response, error = fetch_page(url)
                    if error:
                        errors += 1
                        entry = inventory.setdefault(url, {
                            'url': url, 'type': self._classify_url(url),
                            'section': self._url_section(url), 'source': 'link',
                            'status': None, 'saved_file': None, 'blocked': False,
                        })
                        entry['status'] = 'ERR'
                        entry['error']  = error
                        print(f"{Colors.BOLD}[x] {Colors.R}ERR{Colors.END} {Colors.P}{url}{Colors.END}")
                        if debug_mode:
                            print(f"{Colors.BOLD + Colors.R}[DEBUG] {error}{Colors.END}")
                        time.sleep(delay)
                        continue
                    soup = process_response(url, response, level=d)
                    mark_redirect(response, url)
                    if soup and d < depth:
                        for href in self.extract_links(soup):
                            enqueue(href, d + 1, base=url)
                    time.sleep(delay)

        except KeyboardInterrupt:
            print(f"\n{Colors.BOLD + Colors.R}Interrupted — saving progress so far.{Colors.END}")

        # ------------------------------------------------------------- outputs
        counts_by_type    = {}
        counts_by_section = {}
        for entry in inventory.values():
            counts_by_type[entry['type']] = counts_by_type.get(entry['type'], 0) + 1
            counts_by_section[entry['section']] = counts_by_section.get(entry['section'], 0) + 1

        inventory_doc = {
            'target':            start_url,
            'host':              host,
            'updated_at':        time.strftime('%Y-%m-%dT%H:%M:%S'),
            'sitemaps':          sitemaps_seen,
            'mirror_hosts':      sorted(mirror_hosts),
            'counts_by_type':    counts_by_type,
            'counts_by_section': counts_by_section,
            'stats': {
                'requests':      fetched,
                'reachable':     ok_count,
                'errors':        errors,
                'saved_files':   saved_count,
                'sitemaps':      len(sitemaps_seen),
                'rewritten':     rewrite_count,
            },
            'urls': sorted(inventory.values(), key=lambda e: e['url']),
        }
        try:
            with open(index_path, 'w') as f:
                json.dump(inventory_doc, f, indent=2)
        except Exception as e:
            print(f"{Colors.BOLD + Colors.R}Could not write {index_path}: {e}{Colors.END}")
        try:
            with open(txt_path, 'w') as f:
                for u in sorted(inventory):
                    f.write(u + '\n')
        except Exception as e:
            print(f"{Colors.BOLD + Colors.R}Could not write {txt_path}: {e}{Colors.END}")
        if resume or url_list or fetched > 0:
            save_state()

        if output_file:
            try:
                if output_file.lower().endswith('.json'):
                    with open(output_file, 'w') as f:
                        json.dump(inventory_doc, f, indent=2)
                elif output_file.lower().endswith('.csv'):
                    import csv as _csv
                    with open(output_file, 'w', newline='') as f:
                        writer = _csv.DictWriter(
                            f, fieldnames=['url', 'type', 'section', 'status', 'saved_file', 'title'],
                            extrasaction='ignore')
                        writer.writeheader()
                        for entry in sorted(inventory.values(), key=lambda e: e['url']):
                            writer.writerow({k: entry.get(k, '') for k in writer.fieldnames})
                else:
                    with open(output_file, 'w') as f:
                        if urls_only:
                            for u in sorted(inventory):
                                f.write(u + '\n')
                        else:
                            f.write(f"# Crawl of {start_url} — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                            for entry in sorted(inventory.values(), key=lambda e: e['url']):
                                if entry.get('status') is None and entry.get('saved_file') is None:
                                    continue
                                line = f"{entry.get('status')}\t{entry['url']}"
                                if entry.get('title'):
                                    line += f"\t{entry['title']}"
                                f.write(line + '\n')
                print(f"{Colors.BOLD + Colors.G}Output also saved to: {output_file}{Colors.END}")
            except Exception as e:
                print(f"{Colors.BOLD + Colors.R}Could not write output file {output_file}: {e}{Colors.END}")

        print('-' * 50)

        if urls_only:
            est_hours = len(inventory) * (delay + 3.5) / 3600.0
            print(f"{Colors.BOLD}[ URL inventory — {host} ]{Colors.END}")
            print(f"{Colors.BOLD}| Sitemap files fetched: {Colors.END}{Colors.G}{len(sitemaps_seen)}{Colors.END}")
            print(f"{Colors.BOLD}| URLs found: {Colors.END}{Colors.G}{len(inventory)}{Colors.END}")
            for t, n in sorted(counts_by_type.items(), key=lambda kv: -kv[1]):
                print(f"{Colors.BOLD}|   {t}: {Colors.END}{Colors.G}{n}{Colors.END}")
            top = ', '.join(f"{s} ({n})" for s, n in
                            sorted(counts_by_section.items(), key=lambda kv: -kv[1])[:12])
            print(f"{Colors.BOLD}| Top sections: {Colors.END}{Colors.G}{top}{Colors.END}")
            if mirror_hosts:
                action = 'rewrote' if rewrite_host else 'kept on'
                print(f"{Colors.BOLD}| Mirror hosts: {Colors.END}{Colors.G}{', '.join(sorted(mirror_hosts))}"
                      f" ({action} {rewrite_count} URL(s)){Colors.END}")
            print(f"{Colors.BOLD}| urls.txt: {Colors.END}{Colors.G}{os.path.abspath(txt_path)}{Colors.END}")
            print(f"{Colors.BOLD}| urls.json: {Colors.END}{Colors.G}{os.path.abspath(index_path)}{Colors.END}")
            if len(inventory):
                print(f"\n{Colors.BOLD}Download everything in batches (estimated ~{est_hours:.1f} h total over Tor):{Colors.END}")
                print(f"  darkdump-cli --crawl {start_url} --url-list {txt_path} --max-pages 500 --delay {delay:g} --resume")
        elif url_list:
            remaining = sum(1 for u in inventory if u not in done and inventory[u].get('status') is None)
            progress  = (len(done) / len(inventory) * 100.0) if inventory else 0.0
            rate      = ((time.time() - started_at) / fetched) if fetched else (delay + 3.5)
            est_batch = min(remaining, 500) * rate / 60.0 if remaining else 0.0
            print(f"{Colors.BOLD}[ Batch summary — {host} ]{Colors.END}")
            print(f"{Colors.BOLD}| Fetched this run: {Colors.END}{Colors.G}{fetched}{Colors.END}"
                  f"  {Colors.BOLD}| Saved: {Colors.END}{Colors.G}{saved_count}{Colors.END}"
                  f"  {Colors.BOLD}| Errors: {Colors.END}{Colors.G}{errors}{Colors.END}")
            print(f"{Colors.BOLD}| Inventory: {Colors.END}{Colors.G}{len(inventory)}{Colors.END} URL(s), "
                  f"{Colors.G}{len(done)}{Colors.END} done ({progress:.2f}%), "
                  f"{Colors.G}{remaining}{Colors.END} remaining")
            if fetched:
                print(f"{Colors.BOLD}| Observed rate: {Colors.END}{Colors.G}{rate:.1f}s per page{Colors.END} "
                      f"(Tor latency varies)")
            print(f"{Colors.BOLD}| urls.txt: {Colors.END}{Colors.G}{os.path.abspath(txt_path)}{Colors.END}")
            print(f"{Colors.BOLD}| urls.json: {Colors.END}{Colors.G}{os.path.abspath(index_path)}{Colors.END}")
            if remaining:
                print(f"\n{Colors.BOLD}Continue ({remaining} left; a 500-page batch takes "
                      f"~{est_batch:.0f} min at this rate):{Colors.END}")
                print(f"  darkdump-cli --crawl {start_url} --url-list {txt_path} --max-pages 500 --delay {delay:g} --resume")
            else:
                print(f"{Colors.BOLD + Colors.G}All inventory URLs have been downloaded.{Colors.END}")
        else:
            print(f"{Colors.BOLD}[ Crawl summary — {host} ]{Colors.END}")
            print(f"{Colors.BOLD}| Requests sent: {Colors.END}{Colors.G}{fetched}{Colors.END}")
            print(f"{Colors.BOLD}| Reachable pages: {Colors.END}{Colors.G}{ok_count}{Colors.END}")
            print(f"{Colors.BOLD}| Pages saved: {Colors.END}{Colors.G}{saved_count}{Colors.END}")
            print(f"{Colors.BOLD}| Errors: {Colors.END}{Colors.G}{errors}{Colors.END}")
            print(f"{Colors.BOLD}| URLs discovered: {Colors.END}{Colors.G}{len(inventory)}{Colors.END}")
            print(f"{Colors.BOLD}| URL index: {Colors.END}{Colors.G}{os.path.abspath(index_path)}{Colors.END}")
            print(f"{Colors.BOLD}| Dump folder: {Colors.END}{Colors.G}{os.path.abspath(dump_dir)}{Colors.END}")
        if mirror_hosts and not urls_only:
            action = 'rewrote' if rewrite_host else 'kept on'
            print(f"{Colors.BOLD}| Mirror hosts: {Colors.END}{Colors.G}{', '.join(sorted(mirror_hosts))}"
                  f" ({action} {rewrite_count} URL(s)){Colors.END}")
        if responded == 0 and not urls_only:
            print(f"{Colors.BOLD + Colors.R}No page responded — the site may be down, "
                  f"or Tor could not reach it.{Colors.END}")
        return True if urls_only else responded > 0

    def crawl(self, query, amount, engine_key='ahmia', use_proxy=False,
              scrape_sites=False, scrape_images=False, debug_mode=False,
              output_file=None, dedupe=False, live_check=False):

        engine_key = engine_key.lower()
        search_all = engine_key == 'all'

        if not search_all and engine_key not in Configuration.SEARCH_ENGINES:
            print(f"{Colors.BOLD + Colors.R}Unknown engine '{engine_key}'. "
                  f"Valid options: {', '.join(Configuration.VALID_ENGINES)}, all{Colors.END}")
            return

        engine_keys  = list(Configuration.SEARCH_ENGINES) if search_all else [engine_key]
        engine       = Configuration.SEARCH_ENGINES[engine_key] if not search_all else None
        engine_label = 'all engines' if search_all else engine['name']
        headers = {'User-Agent': random.choice(Headers.user_agents)}
        proxy_config = {
            'http':  Configuration.__socks5init__,
            'https': Configuration.__socks5init__,
        } if use_proxy else {}

        # Tor-only engines: auto-enable proxy if the user forgot -p ('all'
        # includes Tor-only engines, so it enables the proxy too)
        if (search_all or engine['tor_required']) and not use_proxy:
            if search_all:
                print(
                    f"{Colors.BOLD + Colors.O}Note: 'all' queries every configured engine, "
                    f"including Tor-only ones. Enabling the proxy automatically.{Colors.END}"
                )
            else:
                print(
                    f"{Colors.BOLD + Colors.O}Warning: {engine['name']} is a Tor-only search engine. "
                    f"Enabling proxy automatically.{Colors.END}"
                )
            proxy_config = {
                'http':  Configuration.__socks5init__,
                'https': Configuration.__socks5init__,
            }
            use_proxy = True

        # --live probes every result link over Tor, so the proxy is needed even
        # for engines whose search page works over clearnet.
        if live_check and not use_proxy:
            print(
                f"{Colors.BOLD + Colors.O}Note: '--live' probes every result link "
                f"over Tor. Enabling the proxy automatically.{Colors.END}"
            )
            proxy_config = {
                'http':  Configuration.__socks5init__,
                'https': Configuration.__socks5init__,
            }
            use_proxy = True

        # Warn and confirm when using unfiltered engines
        if search_all:
            unfiltered_names = [
                Configuration.SEARCH_ENGINES[k]['name'] for k in engine_keys
                if not Configuration.SEARCH_ENGINES[k].get('filtered', True)
            ]
            print(
                f"\n{Colors.BOLD + Colors.R}[!] WARNING: 'all' also queries unfiltered engines: "
                f"{', '.join(unfiltered_names)}.{Colors.END}\n"
                f"{Colors.BOLD + Colors.O}    Results may include illegal, harmful, or disturbing content.\n"
                f"    This tool is intended for legitimate research purposes only.{Colors.END}\n"
            )
            try:
                confirm = input(f"{Colors.BOLD}    Continue with all engines? [y/N]: {Colors.END}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                confirm = 'n'
            if confirm != 'y':
                print(f"{Colors.BOLD + Colors.R}Aborted.{Colors.END}")
                return
            print()
        elif not engine.get('filtered', True):
            print(
                f"\n{Colors.BOLD + Colors.R}[!] WARNING: {engine['name']} is an unfiltered search engine.{Colors.END}\n"
                f"{Colors.BOLD + Colors.O}    Results may include illegal, harmful, or disturbing content.\n"
                f"    This tool is intended for legitimate research purposes only.{Colors.END}\n"
            )
            try:
                confirm = input(f"{Colors.BOLD}    Continue with {engine['name']}? [y/N]: {Colors.END}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                confirm = 'n'
            if confirm != 'y':
                print(f"{Colors.BOLD + Colors.R}Aborted.{Colors.END}")
                return
            print()

        # clearnet_only engines must never go through Tor
        is_clearnet_only = engine.get('clearnet_only', False) if not search_all else False
        if is_clearnet_only and use_proxy:
            print(
                f"{Colors.BOLD + Colors.O}Note: {engine['name']} is a clearnet-only engine. "
                f"Ignoring proxy flag.{Colors.END}"
            )
            proxy_config = {}
            use_proxy = False

        if (scrape_sites or use_proxy) and not is_clearnet_only:
            if Platform(True).check_tor_connection(proxy_config) is False:
                if not search_all:
                    return
                # Tor is down: keep going with the clearnet-capable engines
                engine_keys  = [k for k in engine_keys
                                if not Configuration.SEARCH_ENGINES[k]['tor_required']]
                proxy_config = {}
                use_proxy    = False
                if not engine_keys:
                    print(f"{Colors.BOLD + Colors.R}No engines left to query without Tor.{Colors.END}")
                    return
                print(
                    f"{Colors.BOLD + Colors.O}Continuing without Tor — "
                    f"Tor-only engines will be skipped.{Colors.END}\n"
                )
                if live_check:
                    print(
                        f"{Colors.BOLD + Colors.O}Liveness check disabled — "
                        f"probing onions requires Tor.{Colors.END}\n"
                    )
                    live_check = False

        if not search_all:
            print(f"{Colors.BOLD + Colors.C}[ Engine: {engine['name']} ]{Colors.END}\n")

        # Query every selected engine. In 'all' mode a failing engine is
        # reported and skipped instead of aborting the whole run.
        results = []
        for ek in engine_keys:
            eng_i        = Configuration.SEARCH_ENGINES[ek]
            active_proxy = proxy_config if use_proxy else None

            if search_all:
                print(f"{Colors.BOLD + Colors.C}[ Engine: {eng_i['name']} ]{Colors.END}")

            try:
                if ek == 'ahmia':
                    r = self._fetch_ahmia(query, amount, headers, active_proxy)
                elif ek == 'notevil':
                    r = self._fetch_notevil(query, amount, headers, active_proxy or {})
                elif ek == 'tordex':
                    r = self._fetch_tordex(query, amount, headers, active_proxy or {})
                elif ek == 'tor66':
                    r = self._fetch_tor66(query, amount, headers, active_proxy or {})
                elif ek == 'onionland':
                    r = self._fetch_onionland(query, amount, headers, active_proxy or {})
                elif ek == 'excavator':
                    r = self._fetch_excavator(query, amount, headers, active_proxy or {})
                elif ek == 'torch':
                    r = self._fetch_torch(query, amount, headers, active_proxy or {})
                elif ek == 'darksearch':
                    r = self._fetch_darksearch(query, amount, headers, active_proxy or {})
                elif ek == 'vormweb':
                    r = self._fetch_vormweb(query, amount, headers, active_proxy or {})
                else:
                    r = []
            except Exception as e:
                print(f"{Colors.BOLD + Colors.R}Error fetching results from {eng_i['name']}: {e}{Colors.END}")
                if search_all:
                    print()
                    continue
                return

            r = self._filter_blacklisted(r) # Extremely important as this increases safe searching
            for item in r:
                item['engine'] = eng_i['name']

            if search_all:
                print(f"  {Colors.BOLD + Colors.G}{len(r)}{Colors.END} result(s)\n")

            results.extend(r)

        if not results:
            print(f"{Colors.BOLD + Colors.O}No results returned from {engine_label}.{Colors.END}")
            return

        # --live: probe every result link and keep only the ones that respond.
        if live_check:
            results = self._filter_live_results(results, headers, proxy_config,
                                                debug_mode)
            if not results:
                print(f"{Colors.BOLD + Colors.O}No live links among the results "
                      f"from {engine_label}.{Colors.END}")
                return

        saver      = ResultSaver(output_file, query=query, engine=engine_key) if output_file else None
        seen_urls  = set()
        seen_meta  = set()   # fingerprints for metadata-based deduplication

        if dedupe:
            print(f"{Colors.BOLD + Colors.C}[ Deduplication: ON — results with identical title+description will be hidden ]{Colors.END}\n")

        for idx, result in enumerate(results, start=1):
            site_url    = result['site_url']
            title       = result['title']
            description = result['description']
            source_note = (f" {Colors.BOLD + Colors.GR}[{result['engine']}]{Colors.END}"
                           if search_all else '')

            if not site_url or site_url in seen_urls:
                continue

            # Metadata-based deduplication: fingerprint on normalised title +
            # description. Different URLs that share the same content (mirrors,
            # re-indexed duplicates) are suppressed when --unique is active.
            if dedupe:
                fingerprint = (
                    re.sub(r'\s+', ' ', title.strip().lower()),
                    re.sub(r'\s+', ' ', description.strip().lower()),
                )
                if fingerprint in seen_meta:
                    if debug_mode:
                        print(f"{Colors.BOLD + Colors.GR}[DEDUPE] Skipping duplicate metadata: {site_url}{Colors.END}")
                    continue
                seen_meta.add(fingerprint)

            seen_urls.add(site_url)

            try:
                if scrape_sites:
                    print(f"{Colors.BOLD}{idx}. --- [+] Website: {Colors.END}{Colors.P}{title}{Colors.END}{source_note}")
                    print(f"{Colors.BOLD}| Information: {Colors.END}{Colors.G}{description}{Colors.END}")
                    print(f"{Colors.BOLD}| Onion Link: {Colors.END}{Colors.G}{site_url}{Colors.END}")
                    scrape_data = self._scrape_site(
                        site_url, headers, proxy_config, scrape_images, debug_mode, idx
                    )
                    if saver:
                        saver.add(title, description, site_url, scrape_data)
                else:
                    print(f"{Colors.BOLD}{idx}. --- [+] Website: {Colors.END}{Colors.P}{title}{Colors.END}{source_note}")
                    print(f"{Colors.BOLD}\t Information: {Colors.END}{Colors.G}{description}{Colors.END}")
                    print(f"{Colors.BOLD}| Onion Link: {Colors.END}{Colors.G}{site_url}{Colors.END}\n")
                    if saver:
                        saver.add(title, description, site_url)

            except KeyboardInterrupt:
                print(f"{Colors.BOLD + Colors.R} Quitting... {Colors.END}")
                break

        if saver:
            saver.save()
            saver.print_summary()


    def breach_intel(self, target: str, amount: int = 10, engine_key: str = 'ahmia',
                     use_proxy: bool = False, debug_mode: bool = False,
                     output_file: str = None, deep_scrape: bool = False,
                     query_delay: float = 1.5, live_check: bool = False):
        """
        Advanced breach and credential leak intelligence scan.

        Features
        --------
        - Smart query generation  : detects email / domain / username / keyword
                                    and builds tailored query sets including
                                    paste-site operators, file extensions, hash
                                    type hints, and username permutations.
        - Result analysis         : regex-extracts credential artefacts (emails,
                                    MD5/SHA-1/SHA-256/bcrypt hashes, passwords
                                    adjacent to the target) from result snippets.
        - Severity classification : categorises each hit as CRITICAL / HIGH /
                                    MEDIUM / INFO based on URL / title / snippet
                                    signals (paste sites, combolists, markets).
        - Deep scrape mode        : when deep_scrape=True, follows each hit URL
                                    through Tor and extracts full page metadata.
        - Rate limiting           : configurable per-query delay to avoid engine
                                    rate-limits (default 1.5 s).
        - Structured output       : saves a richer JSON/CSV/TXT report that
                                    includes severity, artefacts, and categories.
        - All-engine mode         : with -e all every generated query runs against
                                    every configured engine. Each hit is tagged with
                                    its source engine, failing engines are skipped,
                                    and when Tor is down the Tor-only engines are
                                    dropped instead of aborting the scan.

        Usage
        -----
        python3 darkdump.py --breach -q "example.com" -e ahmia
        python3 darkdump.py --breach -q "admin@corp.com" -e notevil -p --breach-deep
        python3 darkdump.py --breach -q "john_doe" -e tor66 -o report.json
        python3 darkdump.py --breach -q "example.com" -e all
        """
        import time as _time
        import hashlib as _hashlib

        is_email  = '@' in target and '.' in target.split('@')[-1]
        is_domain = '.' in target and not is_email and ' ' not in target

        target_type = 'email' if is_email else 'domain' if is_domain else 'keyword'

        username_variants = []
        if is_email:
            user, domain = target.split('@', 1)
            for sep in ['.', '_', '-', '']:
                parts = re.split(r'[._\-]', user)
                if len(parts) >= 2:
                    username_variants.append(sep.join(parts))
            username_variants = list(dict.fromkeys(username_variants))  # dedupe
        elif not is_domain:
            # Normalise common separators for username permutations
            base = re.sub(r'[._\-\s]+', '', target)
            username_variants = [base, target.replace(' ', '_'),
                                  target.replace(' ', '.'), target.replace(' ', '-')]
            username_variants = list(dict.fromkeys(username_variants))

        queries = []

        if is_email:
            user, domain = target.split('@', 1)
            # Direct hits
            queries += [
                f'"{target}" leak',
                f'"{target}" breach',
                f'"{target}" credentials',
                f'"{target}" dump',
                f'"{target}" password',
                f'"{target}" combolist',
                f'"{target}" database',
                f'"{domain}" breach emails',
                f'"{domain}" combolist',
                f'"{domain}" credential dump',
                f'"{domain}" data leak .sql',
                f'"{domain}" employee passwords',
            ]
            # Username variant hits
            for v in username_variants[:3]:
                if v != user:
                    queries.append(f'"{v}" "{domain}" password')
            # Hash / paste context
            queries += [
                f'"{target}" md5',
                f'"{target}" sha1',
                f'"{target}" sha256',
                f'"{target}" pastebin',
            ]

        elif is_domain:
            queries += [
                f'"{target}" breach',
                f'"{target}" leak',
                f'"{target}" credentials dump',
                f'"{target}" database leak',
                f'"{target}" combolist',
                f'"{target}" employee passwords',
                f'"{target}" data dump',
                f'"{target}" hacked',
                f'"{target}" .sql dump',
                f'"{target}" plaintext passwords',
                f'"{target}" stealer logs',
                f'"{target}" infostealer',
                f'"{target}" credential stuffing',
                f'"{target}" leaked database 2024',
                f'"{target}" leaked database 2025',
            ]

        else:
            queries += [
                f'"{target}" password leak',
                f'"{target}" credentials',
                f'"{target}" breach',
                f'"{target}" dump',
                f'"{target}" combolist',
                f'"{target}" leaked database',
                f'"{target}" pastebin',
                f'"{target}" stealer',
            ]
            for v in username_variants[:3]:
                if v != target:
                    queries.append(f'"{v}" password')

        # Deduplicate while preserving order
        seen_q = set()
        queries = [q for q in queries if not (q in seen_q or seen_q.add(q))]

        EMAIL_RE    = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
        MD5_RE      = re.compile(r'\b[0-9a-fA-F]{32}\b')
        SHA1_RE     = re.compile(r'\b[0-9a-fA-F]{40}\b')
        SHA256_RE   = re.compile(r'\b[0-9a-fA-F]{64}\b')
        BCRYPT_RE   = re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}')
        # Password patterns: "password: VALUE" or "pass:VALUE" adjacent to target
        PASS_RE     = re.compile(
            r'(?:password|passwd|pass|pwd)\s*[:=]\s*([^\s,;\|]{4,64})',
            re.IGNORECASE
        )

        def extract_artefacts(text):
            artefacts = {}
            emails  = EMAIL_RE.findall(text)
            if emails:
                artefacts['emails'] = list(dict.fromkeys(emails))[:10]
            hashes = []
            for pat, htype in [(MD5_RE, 'md5'), (SHA1_RE, 'sha1'),
                               (SHA256_RE, 'sha256'), (BCRYPT_RE, 'bcrypt')]:
                found = pat.findall(text)
                for h in found[:5]:
                    hashes.append({'type': htype, 'value': h})
            if hashes:
                artefacts['hashes'] = hashes
            passwords = PASS_RE.findall(text)
            if passwords:
                artefacts['password_hints'] = list(dict.fromkeys(passwords))[:5]
            return artefacts

        CRITICAL_SIGNALS = [
            'combolist', 'credential dump', 'stealer log', 'infostealer',
            'plaintext password', 'cracked', 'fullz', 'combo', 'config'
        ]
        HIGH_SIGNALS = [
            'breach', 'leak', 'dump', 'database', 'hacked', 'exposed',
            'pastebin', 'paste', '.sql', 'data leak'
        ]
        MEDIUM_SIGNALS = [
            'password', 'credentials', 'account', 'login', 'access'
        ]

        PASTE_PATTERNS  = ['paste', 'bin', 'ghostbin', 'hastebin', 'dpaste', 'rentry']
        MARKET_PATTERNS = ['market', 'shop', 'store', 'vendor']
        FORUM_PATTERNS  = ['forum', 'board', 'chan', 'thread', 'post', 'discuss']
        LEAK_PATTERNS   = ['leak', 'breach', 'dump', 'combolist', 'database', 'stealer']

        def classify_severity(title, description, url):
            combined = (title + ' ' + description + ' ' + url).lower()
            for sig in CRITICAL_SIGNALS:
                if sig in combined:
                    return 'CRITICAL'
            for sig in HIGH_SIGNALS:
                if sig in combined:
                    return 'HIGH'
            for sig in MEDIUM_SIGNALS:
                if sig in combined:
                    return 'MEDIUM'
            return 'INFO'

        def classify_category(title, url):
            combined = (title + ' ' + url).lower()
            if any(p in combined for p in PASTE_PATTERNS):
                return 'paste-site'
            if any(p in combined for p in MARKET_PATTERNS):
                return 'market'
            if any(p in combined for p in FORUM_PATTERNS):
                return 'forum'
            if any(p in combined for p in LEAK_PATTERNS):
                return 'leak-index'
            return 'other'

        SEVERITY_COLOR = {
            'CRITICAL': Colors.BOLD + Colors.R,
            'HIGH':     Colors.BOLD + Colors.O,
            'MEDIUM':   Colors.BOLD + Colors.C,
            'INFO':     Colors.GR,
        }

        engine_key = engine_key.lower()
        search_all = engine_key == 'all'

        if not search_all and engine_key not in Configuration.SEARCH_ENGINES:
            print(f"{Colors.BOLD + Colors.R}Unknown engine '{engine_key}'. "
                  f"Valid options: {', '.join(Configuration.VALID_ENGINES)}, all{Colors.END}")
            return

        if search_all:
            engine_keys  = list(Configuration.SEARCH_ENGINES)
            engine_label = 'all engines'
        else:
            engine_keys  = [engine_key]
            engine_label = Configuration.SEARCH_ENGINES[engine_key]['name']

        engine = Configuration.SEARCH_ENGINES[engine_key] if not search_all else None

        proxy_config = {
            'http':  Configuration.__socks5init__,
            'https': Configuration.__socks5init__,
        } if use_proxy else {}

        # Tor-only engines: auto-enable proxy if the user forgot -p ('all'
        # includes Tor-only engines, so it enables the proxy too)
        if (search_all or engine['tor_required']) and not use_proxy:
            if search_all:
                print(
                    f"{Colors.BOLD + Colors.O}Note: 'all' queries every configured engine, "
                    f"including Tor-only ones. Enabling the proxy automatically.{Colors.END}"
                )
            else:
                print(f"{Colors.BOLD + Colors.O}Tor proxy enabled automatically for {engine['name']}.{Colors.END}")
            proxy_config = {
                'http':  Configuration.__socks5init__,
                'https': Configuration.__socks5init__,
            }
            use_proxy = True

        # --live probes every result link over Tor, even for clearnet engines.
        if live_check and not use_proxy:
            proxy_config = {
                'http':  Configuration.__socks5init__,
                'https': Configuration.__socks5init__,
            }
            use_proxy = True
            print(f"{Colors.BOLD + Colors.O}Note: '--live' probes every result link "
                  f"over Tor. Enabling the proxy automatically.{Colors.END}")

        if use_proxy:
            if Platform(True).check_tor_connection(proxy_config) is False:
                if not search_all:
                    return
                # Tor is down: keep going with the clearnet-capable engines
                engine_keys  = [k for k in engine_keys
                                if not Configuration.SEARCH_ENGINES[k]['tor_required']]
                proxy_config = {}
                use_proxy    = False
                if not engine_keys:
                    print(f"{Colors.BOLD + Colors.R}No engines left to query without Tor.{Colors.END}")
                    return
                print(
                    f"{Colors.BOLD + Colors.O}Continuing without Tor — "
                    f"Tor-only engines will be skipped.{Colors.END}\n"
                )
                if live_check:
                    print(
                        f"{Colors.BOLD + Colors.O}Liveness check disabled — "
                        f"probing onions requires Tor.{Colors.END}\n"
                    )
                    live_check = False

        engine_line = (
            f"{Colors.BOLD}Engines    : {Colors.END}"
            f"{', '.join(Configuration.SEARCH_ENGINES[k]['name'] for k in engine_keys)}\n"
            if search_all else ''
        )
        print(
            f"\n{Colors.BOLD + Colors.C}[ Breach Intel Scan ]{Colors.END}\n"
            f"{Colors.BOLD}Target     : {Colors.END}{Colors.P}{target}{Colors.END}\n"
            f"{Colors.BOLD}Type       : {Colors.END}{target_type}\n"
            f"{Colors.BOLD}Engine     : {Colors.END}{engine_label}\n"
            + engine_line +
            f"{Colors.BOLD}Queries    : {Colors.END}{len(queries)}\n"
            f"{Colors.BOLD}Deep scrape: {Colors.END}{'on' if deep_scrape else 'off'}\n"
            f"{Colors.BOLD}Query delay: {Colors.END}{query_delay}s\n"
        )

        all_results = []
        seen_urls   = set()
        dd          = Darkdump()
        interrupted = False

        # Run every query against every selected engine. In 'all' mode a failing
        # engine is reported and skipped instead of aborting the whole scan.
        for q_idx, query in enumerate(queries, start=1):
            print(f"{Colors.BOLD + Colors.C}[{q_idx}/{len(queries)}]{Colors.END} {query}")

            for ek in engine_keys:
                eng          = Configuration.SEARCH_ENGINES[ek]
                active_proxy = proxy_config if use_proxy else None

                if search_all:
                    print(f"  {Colors.BOLD + Colors.GR}[{eng['name']}]{Colors.END}")

                try:
                    headers = {'User-Agent': random.choice(Headers.user_agents)}
                    results = []

                    if ek == 'ahmia':
                        results = dd._fetch_ahmia(query, amount, headers, active_proxy)
                    elif ek == 'notevil':
                        results = dd._fetch_notevil(query, amount, headers, active_proxy or {})
                    elif ek == 'tordex':
                        results = dd._fetch_tordex(query, amount, headers, active_proxy or {})
                    elif ek == 'tor66':
                        results = dd._fetch_tor66(query, amount, headers, active_proxy or {})
                    elif ek == 'onionland':
                        results = dd._fetch_onionland(query, amount, headers, active_proxy or {})
                    elif ek == 'excavator':
                        results = dd._fetch_excavator(query, amount, headers, active_proxy or {})
                    elif ek == 'torch':
                        results = dd._fetch_torch(query, amount, headers, active_proxy or {})
                    elif ek == 'darksearch':
                        results = dd._fetch_darksearch(query, amount, headers, active_proxy or {})
                    elif ek == 'vormweb':
                        results = dd._fetch_vormweb(query, amount, headers, active_proxy or {})

                    results = dd._filter_blacklisted(results)

                    # --live: probe the fresh URLs of this query's results; dead
                    # onions are dropped before severity analysis.
                    if live_check:
                        fresh, fresh_seen = [], set()
                        for result in results:
                            u = result.get('site_url', '')
                            if u and u not in seen_urls and u not in fresh_seen:
                                fresh_seen.add(u)
                                fresh.append(result)
                        results = dd._filter_live_results(fresh, headers, proxy_config,
                                                          debug_mode)

                    new_count = 0
                    for result in results:
                        site_url    = result.get('site_url', '')
                        title       = result.get('title', 'No title available')
                        description = result.get('description', 'No description available')

                        if not site_url or site_url in seen_urls:
                            continue
                        seen_urls.add(site_url)
                        new_count += 1

                        # ── Analysis ───────────────────────────────────────────
                        severity   = classify_severity(title, description, site_url)
                        category   = classify_category(title, site_url)
                        artefacts  = extract_artefacts(title + ' ' + description)
                        scrape_data = None

                        # ── Deep scrape ─────────────────────────────────────────
                        if deep_scrape:
                            try:
                                scrape_data = dd._scrape_site(
                                    site_url, headers, proxy_config,
                                    scrape_images=False, debug_mode=debug_mode,
                                    idx=len(all_results) + 1
                                )
                                # Enrich artefacts from scraped page text
                                if scrape_data:
                                    page_emails = scrape_data.get('emails', [])
                                    if page_emails:
                                        artefacts.setdefault('emails', [])
                                        artefacts['emails'] = list(
                                            dict.fromkeys(artefacts['emails'] + page_emails)
                                        )[:20]
                            except Exception as e:
                                if debug_mode:
                                    print(f"    {Colors.O}[scrape error] {e}{Colors.END}")

                        enriched = {
                            'title':       title,
                            'description': description,
                            'site_url':    site_url,
                            'engine':      eng['name'],
                            'breach_query': query,
                            'severity':    severity,
                            'category':    category,
                            'artefacts':   artefacts,
                            'scrape_data': scrape_data,
                        }
                        all_results.append(enriched)

                        sev_col = SEVERITY_COLOR.get(severity, Colors.GR)
                        print(
                            f"  {sev_col}[{severity}]{Colors.END} "
                            f"{Colors.P}{title}{Colors.END}\n"
                            f"  {Colors.GR}{site_url}{Colors.END}\n"
                            f"  {Colors.GR}category={category}{Colors.END}"
                        )
                        if artefacts:
                            for k, v in artefacts.items():
                                print(f"  {Colors.C}{k}{Colors.END}: {v}")

                    if new_count == 0:
                        if search_all:
                            print(f"  {Colors.GR}[{eng['name']}] no new results.{Colors.END}")
                        else:
                            print(f"  {Colors.GR}No new results.{Colors.END}")

                except KeyboardInterrupt:
                    print(f"{Colors.BOLD + Colors.R} Quitting... {Colors.END}")
                    interrupted = True
                    break
                except Exception as e:
                    if search_all:
                        print(f"  {Colors.BOLD + Colors.O}[{eng['name']}] error: {e}{Colors.END}")
                    else:
                        print(f"  {Colors.BOLD + Colors.O}Error: {e}{Colors.END}")
                    if debug_mode:
                        import traceback
                        traceback.print_exc()

            if interrupted:
                break

            # Rate limit between queries
            if q_idx < len(queries):
                _time.sleep(query_delay)

        severity_counts = {}
        category_counts = {}
        engine_counts   = {}
        for r in all_results:
            severity_counts[r['severity']]  = severity_counts.get(r['severity'], 0) + 1
            category_counts[r['category']]  = category_counts.get(r['category'], 0) + 1
            engine_counts[r['engine']]      = engine_counts.get(r['engine'], 0) + 1

        print(f"\n{Colors.BOLD + Colors.C}[ Breach Intel Complete ]{Colors.END}")
        print(f"{Colors.BOLD}Total unique results : {Colors.END}{len(all_results)}")
        print(f"{Colors.BOLD}Queries run          : {Colors.END}{len(queries)}")
        if severity_counts:
            print(f"{Colors.BOLD}By severity          : {Colors.END}", end='')
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']:
                if sev in severity_counts:
                    sc = SEVERITY_COLOR.get(sev, Colors.GR)
                    print(f"{sc}{sev}={severity_counts[sev]}{Colors.END} ", end='')
            print()
        if category_counts:
            cats = ', '.join(f"{k}={v}" for k, v in sorted(category_counts.items()))
            print(f"{Colors.BOLD}By category          : {Colors.END}{cats}")
        if search_all and engine_counts:
            engs = ', '.join(f"{k}={v}" for k, v in sorted(engine_counts.items()))
            print(f"{Colors.BOLD}By engine            : {Colors.END}{engs}")

        if output_file and all_results:
            ext = os.path.splitext(output_file)[1].lower()
            if ext == '.json':
                payload = {
                    'target':       target,
                    'target_type':  target_type,
                    'engine':       engine_key,
                    'query_count':  len(queries),
                    'result_count': len(all_results),
                    'severity_summary':  severity_counts,
                    'category_summary':  category_counts,
                    'engine_summary':    engine_counts,
                    'results': [
                        {
                            'title':        r['title'],
                            'url':          r['site_url'],
                            'engine':       r['engine'],
                            'description':  r['description'],
                            'breach_query': r['breach_query'],
                            'severity':     r['severity'],
                            'category':     r['category'],
                            'artefacts':    r['artefacts'],
                        }
                        for r in all_results
                    ],
                }
                os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
                with open(output_file, 'w', encoding='utf-8') as f:
                    import json as _json
                    _json.dump(payload, f, indent=2, ensure_ascii=False)
                print(f"\n{Colors.BOLD + Colors.C}[ Saved -> {os.path.abspath(output_file)} ]{Colors.END}")
            else:
                # Fall back to ResultSaver for csv/txt
                saver = ResultSaver(output_file, query=f"breach:{target}", engine=engine_key)
                for r in all_results:
                    saver.add(
                        r['title'],
                        f"[{r['severity']}][{r['category']}] "
                        f"engine={r['engine']} | query={r['breach_query']} | {r['description']} | "
                        f"artefacts={r['artefacts']}",
                        r['site_url'],
                    )
                saver.save()
                saver.print_summary()



def darkdump_main():
    clr = Colors()
    bn  = Banner()

    Platform(True).clean_screen()
    Platform(True).get_operating_system_descriptor()
    bn.LoadDarkdumpBanner()
    print(notice)

    engine_help = (
        f"search engine to use (default: ahmia). choices: {', '.join(Configuration.VALID_ENGINES)}, all. "
        "ahmia: clearnet + Tor, Tor Project-endorsed, strict abuse filtering. "
        "notevil: Tor-only, Ahmia fork, partial content filtering. "
        "tordex: clearnet + Tor, fully uncensored index (UNFILTERED, prompt required). "
        "tor66: Tor-only, crawled index with directory (UNFILTERED, prompt required). "
        "onionland: Tor-only, indexes Tor + I2P + clearnet (UNFILTERED, prompt required). "
        "excavator: Tor-only, general dark web index (UNFILTERED, prompt required). "
        "torch: Tor-only, oldest Tor search index, large but stale (UNFILTERED, prompt required). "
        "vormweb: clearnet + Tor, screens illegal content and badges results by trust level. "
        "darksearch: clearnet JSON API, offline since January 2022 (kept for API compatibility). "
        "all: query every configured engine in one pass; engines that fail are skipped."
    )

    parser = argparse.ArgumentParser(
        description="Darkdump is an interface for scraping the deepweb. Made by yours truly."
    )
    parser.add_argument("-v", "--version", help="returns darkdump's version", action="store_true")
    parser.add_argument("-q", "--query",   help="the keyword or string you want to search on the deepweb", type=str)
    parser.add_argument("-a", "--amount",  help="the amount of results you want to retrieve", type=int, default=10)
    parser.add_argument("-p", "--proxy",   help="use tor proxy for scraping", action="store_true")
    parser.add_argument("-i", "--images",  help="scrape images and visual content from the site", action="store_true")
    parser.add_argument("-s", "--scrape",  help="scrape the actual site for content and look for keywords", action="store_true")
    parser.add_argument("-d", "--debug",   help="enable debug output", action="store_true")
    parser.add_argument("-u", "--unique",  help="hide duplicate results that share the same title and description (metadata-based deduplication)", action="store_true")
    parser.add_argument(
        "--live",
        help=(
            "only list live results: probe every result link over Tor before it is printed and "
            "skip the onions that no longer respond. works with normal searches and --breach; "
            "the Tor proxy is enabled automatically. example: darkdump.py -q wiki -e ahmia --live"
        ),
        action="store_true",
    )
    parser.add_argument("-e", "--engine",  help=engine_help, type=str, default='ahmia',
                        choices=Configuration.VALID_ENGINES + ['all'], metavar='ENGINE')
    parser.add_argument(
        "--breach",
        help=(
            "run an advanced breach/credential leak intelligence scan for the given -q target. "
            "auto-detects email/domain/keyword and generates targeted queries including "
            "paste-site operators, hash types, username permutations, and stealer log terms. "
            "extracts credential artefacts from result snippets and classifies results by "
            "severity (CRITICAL/HIGH/MEDIUM/INFO) and category (paste-site/forum/market/leak-index). "
            "example: darkdump.py --breach -q admin@example.com -e notevil -p "
            "(pass -e all to sweep every configured engine)"
        ),
        action="store_true",
    )
    parser.add_argument(
        "--breach-deep",
        help="combine breach scan with deep scraping of each result page (requires -p/Tor)",
        action="store_true",
        dest="breach_deep",
    )
    parser.add_argument(
        "--breach-delay",
        help="seconds to wait between breach queries to avoid rate limits (default: 1.5)",
        type=float,
        default=1.5,
        dest="breach_delay",
        metavar="SECONDS",
    )
    parser.add_argument(
        "-o", "--output",
        help=(
            "save results to a file. format inferred from extension: "
            ".json -> JSON, .csv -> CSV, anything else -> plain text. "
            "example: -o results.json"
        ),
        type=str, default=None, metavar='FILE',
    )
    parser.add_argument(
        "--crawl",
        help=(
            "crawl a whole site directly from a URL — no search query needed. follows same-host links "
            "up to --depth, seeds robots.txt/sitemap.xml, optionally probes --wordlist paths, and saves "
            "every reachable page plus a URL index under dd_crawl_dump/. .onion URLs automatically use "
            "the Tor proxy. example: --crawl http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion"
        ),
        type=str, default=None, metavar='URL',
    )
    parser.add_argument(
        "--depth",
        help="maximum link depth to follow when crawling (default: 3)",
        type=int, default=3, metavar='N',
    )
    parser.add_argument(
        "--max-pages",
        help="stop after this many page requests when crawling (default: 200)",
        type=int, default=200, dest='max_pages', metavar='N',
    )
    parser.add_argument(
        "--delay",
        help="seconds to wait between crawl requests, to stay polite over Tor (default: 2.0)",
        type=float, default=2.0, metavar='SECONDS',
    )
    parser.add_argument(
        "--wordlist",
        help=(
            "also probe guessed paths from this wordlist file when crawling, to find pages that are "
            "not linked anywhere (example: /usr/share/wordlists/dirb/common.txt). much slower over Tor."
        ),
        type=str, default=None, metavar='FILE',
    )
    parser.add_argument(
        "--urls-only",
        help=(
            "with --crawl: build the full URL inventory from robots.txt + the whole sitemap tree "
            "(every board, thread and page) without downloading any pages. writes urls.txt and "
            "urls.json under dd_crawl_dump/<host>/. fast — minutes even for thousands of URLs"
        ),
        action='store_true',
    )
    parser.add_argument(
        "--url-list",
        help=(
            "with --crawl: download exactly the URLs listed in this file (one per line, e.g. the "
            "generated urls.txt) instead of following links. combine with --max-pages and --resume "
            "to download a large site in resumable batches"
        ),
        type=str, default=None, metavar='FILE',
    )
    parser.add_argument(
        "--resume",
        help=(
            "with --crawl: skip URLs already downloaded by previous runs (tracked in "
            "dd_crawl_dump/<host>/state.json) and continue the page-file numbering"
        ),
        action='store_true',
    )
    parser.add_argument(
        "--no-rewrite",
        help=(
            "with --crawl: keep sitemap-declared hosts as-is instead of rewriting them onto the "
            "crawl host. by default hosts declared in the site's own sitemaps are rewritten to "
            "the target host"
        ),
        action='store_true',
    )
    parser.add_argument(
        "--max-sitemaps",
        help="with --crawl: maximum number of sitemap files to fetch (default: 300)",
        type=int, default=300, metavar='N',
    )

    args = parser.parse_args()

    if args.version:
        print(Colors.BOLD + Colors.B + f"Darkdump Version: {__version__}\n" + Colors.END)

    if (args.proxy and not args.scrape and not args.breach
            and not args.breach_deep and not args.crawl and not args.live):
        print(Colors.BOLD + Colors.R +
              "Error: Proxy option '-p' must be used with the scraping option '-s' (or --breach/--crawl/--live)." + Colors.END)
        parser.print_help()
        sys.exit(1)

    if args.images and not args.scrape:
        print(Colors.BOLD + Colors.R +
              "Error: Images option '-i' must be used with the scraping option '-s'." + Colors.END)
        parser.print_help()
        sys.exit(1)

    if args.debug:
        print(f"{Colors.R}DEBUG mode is on.{Colors.W}")

    if args.output:
        fmt      = os.path.splitext(args.output)[1].lower() or '.txt'
        fmt_name = {'.json': 'JSON', '.csv': 'CSV'}.get(fmt, 'TXT')
        print(f"{Colors.BOLD + Colors.C}[ Output: {args.output} ({fmt_name}) ]{Colors.END}")

    if args.crawl and (args.query or args.breach or args.breach_deep):
        print(f"{Colors.BOLD + Colors.R}Error: --crawl crawls one site directly; "
              f"it cannot be combined with -q/--query or --breach.{Colors.END}")
        sys.exit(1)

    if (args.urls_only or args.url_list or args.resume) and not args.crawl:
        print(f"{Colors.BOLD + Colors.R}Error: --urls-only, --url-list and --resume "
              f"must be used together with --crawl URL.{Colors.END}")
        sys.exit(1)

    if args.crawl:
        if args.live:
            print(f"{Colors.BOLD + Colors.O}Note: --live applies to search results; "
                  f"--crawl already records whether each page responded.{Colors.END}")
        Darkdump().crawl_site(
            args.crawl,
            depth=args.depth,
            max_pages=args.max_pages,
            delay=args.delay,
            use_proxy=args.proxy,
            wordlist=args.wordlist,
            debug_mode=args.debug,
            output_file=args.output,
            urls_only=args.urls_only,
            url_list=args.url_list,
            resume=args.resume,
            rewrite_host=not args.no_rewrite,
            max_sitemaps=args.max_sitemaps,
        )
    elif args.breach:
        if not args.query:
            print(Colors.BOLD + Colors.R +
                  "Error: --breach requires a target via -q (email, domain, username, or keyword)." + Colors.END)
            sys.exit(1)
        engine = Configuration.SEARCH_ENGINES.get(args.engine, {})
        if args.engine == 'all':
            unfiltered_names = [
                cfg['name'] for cfg in Configuration.SEARCH_ENGINES.values()
                if not cfg.get('filtered', True)
            ]
            if unfiltered_names:
                print(
                    f"\n{Colors.BOLD + Colors.R}[!] WARNING: 'all' also queries unfiltered engines: "
                    f"{', '.join(unfiltered_names)}.{Colors.END}\n"
                    f"{Colors.BOLD + Colors.O}    Results may include illegal or harmful content. "
                    f"Use for legitimate research only.{Colors.END}\n"
                )
                try:
                    confirm = input(f"{Colors.BOLD}    Continue with all engines? [y/N]: {Colors.END}").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    confirm = 'n'
                if confirm != 'y':
                    print(f"{Colors.BOLD + Colors.R}Aborted.{Colors.END}")
                    sys.exit(0)
        elif not engine.get('filtered', True):
            print(
                f"\n{Colors.BOLD + Colors.R}[!] WARNING: {engine.get('name', args.engine)} is an unfiltered engine.{Colors.END}\n"
                f"{Colors.BOLD + Colors.O}    Results may include illegal or harmful content. "
                f"Use for legitimate research only.{Colors.END}\n"
            )
            try:
                confirm = input(f"{Colors.BOLD}    Continue? [y/N]: {Colors.END}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                confirm = 'n'
            if confirm != 'y':
                print(f"{Colors.BOLD + Colors.R}Aborted.{Colors.END}")
                sys.exit(0)
        Darkdump().breach_intel(
            args.query,
            amount=args.amount,
            engine_key=args.engine,
            use_proxy=args.proxy,
            debug_mode=args.debug,
            output_file=args.output,
            deep_scrape=args.breach_deep,
            query_delay=args.breach_delay,
            live_check=args.live,
        )
    elif args.query:
        print(
            f"Searching For: {args.query} | Engine: {args.engine} | "
            f"Showing up to {args.amount} results...\n"
            f"Indexing is viable, skipping dead onions.\n"
        )
        Darkdump().crawl(
            args.query,
            args.amount,
            engine_key=args.engine,
            use_proxy=args.proxy,
            scrape_sites=args.scrape,
            scrape_images=args.images,
            debug_mode=args.debug,
            output_file=args.output,
            dedupe=args.unique,
            live_check=args.live,
        )
    else:
        print("[~] Note: No query arguments were passed. Please supply a query to search.")


if __name__ == "__main__":
    darkdump_main()
