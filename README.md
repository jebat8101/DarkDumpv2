# darkdump

## About

Darkdump is an open-source OSINT tool for deep web investigation. Given a search query it fetches results from multiple dark web search engines, optionally scrapes each result site for emails, metadata, keywords, documents, and images, and streams everything live to either the terminal or a local browser-based interface. All results are automatically filtered against Ahmia's public abuse blacklist regardless of which engine is used.

## Installation

### Quick install (Linux & macOS)

```bash
git clone https://github.com/josh0xA/darkdump
cd darkdump
chmod +x install.sh
./install.sh
darkdump
```
Note: ``./install.sh`` might require ``sudo`` for macOS. 

This installs all dependencies and creates two commands:

| Command        | Description                                     |
|----------------|-------------------------------------------------|
| `darkdump`     | Launch the primary web interface                        |
| `darkdump-cli` | Run the CLI tool                                |

### Manual install

```bash
git clone https://github.com/josh0xA/darkdump
cd darkdump
pip3 install -r requirements.txt
pip3 install -r darkdump-web/requirements.txt
```

To uninstall the launchers: `./uninstall.sh`

### Tor Configuration 
To use Darkdump effectively, you need to configure Tor to allow your script to control it via the Tor control port. Here's how to set up your `torrc` file and verify that Tor is running: <br/>

#### Step 1: Install Tor
If Tor is not already installed on your system, you need to install it. Here's how you can install Tor on various operating systems:

Debian/Kali/Ubuntu: `sudo apt install tor`<br/>
MacOS: `brew install tor`<br/>

#### Step 2: Configure the Tor torrc File<br/>
Locate your torrc file. This file is usually found at `/etc/tor/torrc`on Linux and sometimes Mac. 

Add the following lines to your torrc to enable the control port and set a control port password:
```
ControlPort 9051
HashedControlPassword [YourHashedPasswordHere]
```
Replace `[YourHashedPasswordHere]` with a hashed password which can be generated using the `tor --hash-password` command: `tor --hash-password "my_password"`

#### Step 3: Start Tor Service
Linux: `sudo systemctl start tor.service`<br/>
MacOS: `brew services start tor`<br/>

## Search Engines

Nine engines are available via `-e` / `--engine`:

| Engine       | Filtered | Requires Tor | Notes                                          |
|--------------|----------|--------------|------------------------------------------------|
| `ahmia`      | Yes      | No           | Default. Tor Project-endorsed, strict filtering |
| `notevil`    | Partial  | Yes          | Ahmia fork with broader index                  |
| `tordex`     | **No**   | Yes          | Fully uncensored — confirmation required       |
| `tor66`      | **No**   | Yes          | Crawled index with directory — confirmation required |
| `onionland`  | **No**   | Yes          | Indexes Tor, I2P, and clearnet — confirmation required |
| `excavator`  | **No**   | Yes          | General dark web index — confirmation required |
| `torch`      | **No**   | Yes          | Oldest Tor index, huge but stale — confirmation required |
| `vormweb`    | Yes      | No           | Screens illegal content, badges results by trust level |
| `darksearch` | **No**   | No           | Offline since January 2022 — kept for API compatibility |

All engines have their results checked against Ahmia's blacklist. Unfiltered engines will prompt for confirmation before executing. This strategy is still not perfect, always use extreme caution and judgement when searching and scraping unfiltered engines. 

### Search All Engines

Select **All Engines** in the web UI dropdown, or pass `-e all` on the CLI, to query every
configured engine with a single keyword. `-a/--amount` applies per engine, results are
deduplicated across engines, and every result is labelled with the engine it came from.
Engines that fail or are offline (like DarkSearch) are skipped with a note instead of
aborting the run, and when Tor is not running the Tor-only engines are skipped automatically.
Since this mode includes unfiltered engines, a single confirmation is required before the
search starts. Breach mode (`--breach -e all`, or **All Engines** in the web UI) works the
same way: every generated breach query is run against every engine, each hit is tagged with
its source engine, and the same confirmation and Tor handling apply. Results are labelled
with their source engine and the report ends with a per-engine hit count.

### Site Crawling

`--crawl URL` crawls a single site directly — no search engine involved. It walks same-host
links up to `--depth`, seeds `robots.txt` and `sitemap.xml`, and optionally probes paths from
`--wordlist`. Every page that returns HTML is saved under `dd_crawl_dump/<host>/` together with
a `urls.json` index and a plain `urls.txt` list. Requests are sequential with a `--delay` pause
between them (default 2s) to stay polite over Tor. `.onion` URLs enable the Tor proxy
automatically. A crawl can only find linked, declared, or guessed paths — it cannot enumerate
every path a site may hide.

### Full Site Extraction (URL inventory + resumable download)

Forums and other large sites declare every board, thread and page in their XML sitemaps. The
inventory mode reads the whole sitemap tree (nested indexes included) and lists every URL
without downloading anything — minutes even for tens of thousands of URLs:

```bash
darkdump-cli --crawl http://xxxxxxxxxxxxxxxx.onion --urls-only
```

This writes `dd_crawl_dump/<host>/urls.txt` (one URL per line) and `urls.json` (every URL
tagged with type — thread/board/member/system/file — and section, plus per-type counts).
Hosts declared in the site's own sitemaps that differ from the target (mirrors) are rewritten
onto the target host; use `--no-rewrite` to keep them as declared.

Then download the site in batches. Each run fetches up to `--max-pages` URLs from the list, and
`--resume` skips everything already saved, so the crawl can be stopped and continued any time:

```bash
darkdump-cli --crawl http://xxxxxxxxxxxxxxxx.onion --url-list dd_crawl_dump/<host>/urls.txt \
    --max-pages 500 --delay 2 --resume
```

New links found on downloaded pages (e.g. thread pagination) are appended to `urls.txt`, so
repeating the same command keeps growing and completing the map. Progress lives in
`state.json`; page files are numbered continuously across runs. Pages behind a login are
recorded with their status and a `(login wall)` flag — guest view only, nothing is bypassed.

## Darkdump Web Preview (Recommended) 

<p align="center">
  <img src="https://github.com/josh0xA/darkdump/blob/main/imgs/darkdump_example.png?raw=true" alt="Darkdump example">
</p>


## CLI Usage

```
darkdump-cli [-h] [-v] [-q QUERY] [-a AMOUNT] [-e ENGINE]
             [-p] [-s] [-i] [-d] [-u] [--live] [-o FILE]
             [--breach] [--breach-deep] [--breach-delay SECONDS]
             [--crawl URL] [--depth N] [--max-pages N] [--delay SECONDS]
             [--wordlist FILE] [--urls-only] [--url-list FILE] [--resume]
             [--no-rewrite] [--max-sitemaps N]
```

| Flag | Description |
|------|-------------|
| `-q`, `--query` | Search query |
| `-a`, `--amount` | Number of results to retrieve (default: 10) |
| `-e`, `--engine` | Engine to use (default: `ahmia`) |
| `-p`, `--proxy` | Route requests through Tor |
| `-s`, `--scrape` | Deep scrape each result for metadata, links, emails, documents |
| `-i`, `--images` | Also collect images during scrape (requires `-s`) |
| `-u`, `--unique` | Hide results with duplicate title + description |
| `--live` | Probe every result link over Tor and show only the live ones (dead onions are skipped; proxy enabled automatically) |
| `-d`, `--debug` | Enable debug output |
| `-o FILE`, `--output FILE` | Save results to file — format inferred from extension (`.json`, `.csv`, `.txt`) |
| `--breach` | Run a breach / credential leak intelligence scan for the given target |
| `--breach-deep` | Combine breach scan with deep scraping of each result |
| `--breach-delay` | Seconds between breach queries to avoid rate limits (default: 1.5) |
| `--crawl URL` | Crawl one site directly (no search): follows links, seeds robots/sitemap, saves pages + URL index |
| `--depth N` | Max link depth to follow when crawling (default: 3) |
| `--max-pages N` | Stop after N page requests when crawling (default: 200) |
| `--delay SECONDS` | Pause between crawl requests to stay polite over Tor (default: 2.0) |
| `--wordlist FILE` | Also probe guessed paths from a wordlist while crawling |
| `--urls-only` | With `--crawl`: build the full URL inventory from robots/sitemaps, no pages downloaded |
| `--url-list FILE` | With `--crawl`: download exactly the URLs in this file (one per line) instead of link-following |
| `--resume` | With `--crawl`: skip URLs already downloaded by earlier runs and continue file numbering |
| `--no-rewrite` | With `--crawl`: keep sitemap-declared mirror hosts as-is instead of rewriting them onto the target |
| `--max-sitemaps N` | With `--crawl`: maximum number of sitemap files to fetch (default: 300) |
| `-v`, `--version` | Print version |

### Examples

```bash
# Basic search via Ahmia (no Tor required)
darkdump-cli -q "privacy tools" -a 10

# Search and deep scrape each result via Tor
darkdump-cli -q "hacking" -a 10 -s -p

# Search, scrape, and collect images
darkdump-cli -q "marketplaces" -a 15 -s -p -i

# Use Not Evil engine, deduplicate, save to JSON
darkdump-cli -q "security research" -a 20 -e notevil -p -u -o results.json

# Use OnionLand engine, save to CSV
darkdump-cli -q "crypto" -a 10 -e onionland -p -o results.csv

# Breach intelligence scan for an email address
darkdump-cli --breach -q admin@example.com -e ahmia -p

# Breach scan with deep scraping
darkdump-cli --breach --breach-deep -q example.com -e ahmia

# Search and show only links that are currently live (dead onions are skipped)
darkdump-cli -q "wiki" -a 20 -e ahmia --live

# Same for a breach scan: only live hits are analysed and reported
darkdump-cli --breach -q example.com -e ahmia --live

# Breach scan against every configured engine in one pass (Tor auto-enabled, hits tagged per engine)
darkdump-cli --breach -q example.com -e all

# Crawl an onion site directly and save every reachable path (Tor is enabled automatically)
darkdump-cli --crawl http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion --depth 3 --max-pages 100 -o crawl.json

# Crawl and also probe unlinked paths from a wordlist (slow over Tor)
darkdump-cli --crawl http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion --wordlist /usr/share/wordlists/dirb/common.txt --max-pages 300

# Build the full URL inventory of a forum from its sitemaps (fast, no pages downloaded)
darkdump-cli --crawl http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion --urls-only

# Download the site in resumable batches (repeat until "All inventory URLs have been downloaded")
darkdump-cli --crawl http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion --url-list dd_crawl_dump/<host>/urls.txt --max-pages 500 --delay 2 --resume
```

## Web Interface

Darkdump includes a local browser-based interface.

```bash
# If installed via install.sh
darkdump

# Or run directly
python3 darkdump-web/app.py
```

Then open `http://127.0.0.1:50001` in your browser.

### Features

- Live streaming results as they arrive
- All nine engines plus an All Engines sweep available via dropdown (in search and breach mode)
- Tor proxy toggle with live exit IP display
- Deep scrape with optional image collection
- Metadata-based deduplication
- Breach intelligence scan mode, single engine or all engines
- Export results as JSON, CSV, or TXT


## Ethical Notice

This tool is intended for legitimate security research and OSINT investigations only. The developer, Josh Schiavone, is not responsible for any misuse. Do not use Darkdump to access or investigate sites engaged in illegal activity under the laws and regulations of your jurisdiction. May God bless you all.

## License

MIT License — Copyright (c) Josh Schiavone
