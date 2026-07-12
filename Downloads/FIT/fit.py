#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import click
import csv
import io
import random
import requests
import requests_toolbelt
import socket
import sys
import time
import warnings
import zipfile
from contextlib import contextmanager
from pathlib import Path

# telnetlib is deprecated in Python 3.11 and removed in 3.13
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import telnetlib

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
import platform

BASE_DIR = Path(__file__).parent

# disable warnings in requests for cert bypass
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__version__ = 0.23

# some console colours
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

if platform.system() == "Windows":
	W = ''
	R = ''
	G = ''
	O = ''
	B = ''
	P = ''
	C = ''
	GR = ''


@contextmanager
def _progress(items, verbose):
    """Progressbar in normal mode; plain iteration in verbose mode."""
    if verbose:
        yield items
    else:
        with click.progressbar(items) as bar:
            yield bar


def _print_summary(label, responded, failed):
    total = responded + failed
    print(
        G + "[+] " + W + f"{label} summary: {total} tested — "
        + G + f"{responded} responded" + W + ", "
        + R + f"{failed} blocked/failed" + W
    )


def _fetch_feed(url, label, timeout=10, **kwargs):
    """Fetch a remote feed URL; print a friendly error and return None on failure."""
    try:
        r = requests.get(url, verify=False, timeout=timeout, **kwargs)
        r.raise_for_status()
        return r
    except requests.exceptions.RequestException as e:
        print()  # newline after the trailing "..." on the fetch line
        print(R + "[!] " + W + f"Failed to fetch {label}: {e}")
        return None


def _read_csv(path):
    """Read a local CSV file; print a friendly error and return None on failure."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except OSError as e:
        print(R + "[!] " + W + f"Cannot read {path.name}: {e}")
        return None


def _sample(data, limit):
    """Return a random sample of data when limit > 0 and len(data) exceeds limit."""
    if limit and len(data) > limit:
        return random.sample(data, limit)
    return data


_vt_last_call = 0.0


def _vt_check(indicator, vt_key, is_url=False):
    """
    Query VirusTotal v3 for an IP or URL.
    Paces calls to stay within the free-tier limit (18 s between requests).
    Returns (malicious_count, total_engines) or (None, None) on error.
    """
    global _vt_last_call
    elapsed = time.time() - _vt_last_call
    if _vt_last_call > 0 and elapsed < 18:
        time.sleep(18 - elapsed)
    try:
        if is_url:
            uid = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip('=')
            api_url = f"https://www.virustotal.com/api/v3/urls/{uid}"
        else:
            api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        r = requests.get(api_url, headers={"x-apikey": vt_key}, timeout=10, verify=False)
        _vt_last_call = time.time()
        if r.status_code == 404:
            return 0, 0
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal   = stats.get("malicious", 0)
        total = sum(stats.values())
        return mal, total
    except Exception:
        _vt_last_call = time.time()
        return None, None


def _vt_report(items, vt_key, is_url=False):
    """Run VT enrichment on a list of unblocked items; no-op when vt_key is None."""
    if not items or not vt_key:
        return
    print()
    print(G + "[+] " + W + f"VirusTotal enrichment — {len(items)} unblocked item(s):")
    for item in items:
        mal, total = _vt_check(item, vt_key, is_url=is_url)
        if mal is None:
            print(f"  {O}[VT ERROR  ]{W}  {item}")
        elif mal == 0:
            print(f"  {G}[VT CLEAN  ]{W}  {item}  (0/{total} — likely stale IOC)")
        else:
            print(f"  {R}[VT {mal:>3}/{total:<3}]{W}  {item}  <- active threat, firewall gap!")


# ── Granular HTTP probe ───────────────────────────────────────────────────────

# colour / label / is_network_blocked / payload_reached
_PROBE_VERDICT = {
    'dns_block':   (G, '[DNS BLOCK]   ', True,  False),
    'tcp_block':   (G, '[TCP BLOCK]   ', True,  False),
    'tcp_timeout': (G, '[TCP TIMEOUT] ', True,  False),
    'http_block':  (G, '[HTTP BLOCK]  ', True,  False),
    'read_timeout':(O, '[DISCONNECTED]', False, False),
    'no_data':     (O, '[DISCONNECTED]', False, False),
    'partial':     (O, '[PARTIAL DL]  ', False, True),
    'downloaded':  (R, '[NOT BLOCKED] ', False, True),
    'error':       (O, '[ERROR]       ', False, False),
}

_PROBE_READ_SIZE = 8192  # bytes — enough to carry any PE/ELF magic for AV inspection


def _probe_url(url, srcip=()):
    """
    Send a streaming HTTP GET and read up to 8 KB of the response body.
    Returns (verdict_key, http_status_or_None, bytes_received).

    Verdict semantics
    -----------------
    dns_block   : DNS resolution failed (domain blocked or dead)
    tcp_block   : TCP connect refused / RST received
    tcp_timeout : TCP connect timed out (firewall drop)
    http_block  : HTTP 403/407 received (proxy block page)
    no_data     : HTTP response received but 0 bytes of body
    partial     : 1 – 8191 bytes received (server or proxy cut stream early)
    downloaded  : ≥ 8 KB received (payload flowing past the firewall)
    read_timeout: HTTP headers received but body read timed out
    error       : other unexpected exception
    """
    try:
        if srcip:
            r = setsrcip(srcip).get(url, timeout=(5, 10), stream=True, verify=False)
        else:
            r = requests.get(url, timeout=(5, 10), stream=True, verify=False)

        http_status = r.status_code
        try:
            chunk = r.raw.read(_PROBE_READ_SIZE)
            received = len(chunk)
        except Exception:
            received = 0
        finally:
            r.close()

        if http_status in (403, 407):
            return 'http_block', http_status, received
        if received >= _PROBE_READ_SIZE:
            return 'downloaded', http_status, received
        if received > 0:
            return 'partial', http_status, received
        return 'no_data', http_status, received

    except requests.exceptions.ConnectTimeout:
        return 'tcp_timeout', None, 0

    except requests.exceptions.ReadTimeout:
        return 'read_timeout', None, 0

    except requests.exceptions.ConnectionError as e:
        err = str(e).lower()
        if any(x in err for x in [
            'getaddrinfo', 'name or service not known', 'nodename nor servname',
            'name resolution', 'temporary failure in name', 'errno 8',
        ]):
            return 'dns_block', None, 0
        return 'tcp_block', None, 0

    except (requests.exceptions.RequestException, OSError):
        return 'error', None, 0


def _print_threat_summary(label, blocked, reached, ambiguous):
    total = blocked + reached + ambiguous
    parts = (
        G + "[+] " + W + f"{label} summary: {total} tested — "
        + G + f"{blocked} blocked" + W + ", "
        + R + f"{reached} reached server" + W
    )
    if ambiguous:
        parts += ", " + O + f"{ambiguous} disconnected/ambiguous" + W
    print(parts)


def _update():
    '''Refresh malware URL and good URL lists from public sources.'''
    # ── malware_urls.csv from URLhaus ─────────────────────────────────────
    # Format: plain text, one full URL per line, lines starting with # are comments
    print(G + "[+] " + W + "Updating malware_urls.csv from URLhaus...", end=" ", flush=True)
    r = _fetch_feed("https://urlhaus.abuse.ch/downloads/text/", "URLhaus malware feed")
    if r is not None:
        urls = [l for l in r.text.split("\n") if l.strip() and not l.startswith("#")]
        if urls:
            (BASE_DIR / "malware_urls.csv").write_text("\n".join(urls) + "\n")
            print(f"Done ({len(urls)} URLs)")
        else:
            print()
            print(R + "[!] " + W + "URLhaus returned an empty list — file not updated")

    # ── goodurl.csv from Tranco top 500 ──────────────────────────────────
    # Format: zip containing top-1m.csv with "rank,domain" rows
    print(G + "[+] " + W + "Updating goodurl.csv from Tranco top 500...", end=" ", flush=True)
    r2 = _fetch_feed("https://tranco-list.eu/top-1m.csv.zip", "Tranco list", timeout=30)
    if r2 is not None:
        try:
            z = zipfile.ZipFile(io.BytesIO(r2.content))
            with z.open(z.namelist()[0]) as zf:
                reader = csv.reader(io.TextIOWrapper(zf))
                domains = [row[1] for i, row in enumerate(reader) if i < 500 and len(row) >= 2]
            if domains:
                (BASE_DIR / "goodurl.csv").write_text("\n".join(domains) + "\n")
                print(f"Done ({len(domains)} domains)")
            else:
                print()
                print(R + "[!] " + W + "Tranco list parsed but empty — file not updated")
        except Exception as e:
            print()
            print(R + "[!] " + W + f"Failed to parse Tranco list: {e}")

    # ── manual lists ──────────────────────────────────────────────────────
    print()
    print(O + "[!] " + W + "appctrl.csv and wf.csv are curated lists with no public source.")
    print(O + "[!] " + W + "Update them manually as needed.")


def banner():
    '''Print stylized banner'''
    print(r"""
                          ,----,
                        ,/   .`|
    ,---,.   ,---,    ,`   .'  :
  ,'  .' |,`--.' |  ;    ;     /
,---.'   ||   :  :.'___,/    ,'
|   |   .':   |  '|    :     |
:   :  :  |   :  |;    |.';  ;
:   |  |-,'   '  ;`----'  |  |
|   :  ;/||   |  |    '   :  ;
|   |   .''   :  ;    |   |  '
'   :  '  |   |  '    '   :  |
|   |  |  '   :  |    ;   |.'
|   :  \  ;   |.'     '---'
|   | ,'  '---'
`----'
Firewall Inspection Tester
Author: Alex Harvey, @meshmeld""")
    print("Version: %0.2f\n" % __version__)


def checkconnection():
    '''Check network connection.'''
    try:
        requests.get("https://www.google.ca", verify=False, timeout=5)
    except requests.exceptions.RequestException:
        return False
    return True


def checkips(srcip):
    for ipaddr in srcip:
        try:
            socket.inet_aton(ipaddr)
            print(G + "[+] " + W + "Source IP Address " + ipaddr)
        except socket.error:
            print(R + "[-] " + W + "IP Address " + ipaddr + " is not valid")
            sys.exit(1)


def setsrcip(srcip):
    '''Set a random source ip from a list.'''
    ip = random.choice(srcip)
    s = requests.Session()
    s.mount("http://", requests_toolbelt.adapters.source.SourceAddressAdapter(ip))
    s.mount("https://", requests_toolbelt.adapters.source.SourceAddressAdapter(ip))
    return s


@click.group(chain=True)
def cli():
    banner()
    if checkconnection():
        print(G + "[+] " + W + "Network connection is okay")
    else:
        print(R + "[!] " + W + "Network connection failed")
        print(R + "[!] " + W + "Please verify the network connection")
        sys.exit(1)


@cli.command()
@click.option('--repeat/--no-repeat', default=False)
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
@click.option('--srcip', '-s', multiple=True)
@click.option('--limit', '-l', default=100, help='Max entries per threat test, randomly sampled (0 = all)')
@click.option('--vt-key', envvar='VT_API_KEY', default=None,
              help='VirusTotal API key — enriches unblocked results after the test loop')
def all(repeat, verbose, srcip, limit, vt_key):
    '''Run all tests one after the other'''
    checkips(srcip)
    if repeat:
        print(G + "[+] " + W + "Repeat, repeat, repeat...")

    while True:
        _iprep(srcip, verbose, limit, vt_key)
        _vxvault(srcip, verbose, limit, vt_key)
        _malwareurls(srcip, verbose, limit, vt_key)
        _appctrl(verbose)
        _wf(verbose)
        _webtraffic(verbose)
        if not repeat:
            break


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
@click.option('--srcip', '-s', multiple=True)
@click.option('--limit', '-l', default=100, help='Max entries to test, randomly sampled (0 = all)')
@click.option('--vt-key', envvar='VT_API_KEY', default=None, help='VirusTotal API key')
def iprep(verbose, srcip, limit, vt_key):
    '''IP Reputation test using Feodo Tracker botnet C2 blocklist'''
    checkips(srcip)
    _iprep(srcip, verbose, limit, vt_key)


def _iprep(srcip, verbose=False, limit=100, vt_key=None):
    '''IP Reputation test using Feodo Tracker botnet C2 IP blocklist'''
    # https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    print(G + "[+] " + W + "IP Reputation Test")
    print(G + "[+] " + W + "Fetching bad ip list...", end=" ", flush=True)
    r = _fetch_feed("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "IP blocklist")
    if r is None:
        return
    print("Done")

    data = _sample(
        [line for line in r.text.split("\n") if len(line) > 1 and line[0] != "#"],
        limit
    )
    if not data:
        print(R + "[!] " + W + "IP blocklist is empty — check feed URL or network")
        return

    responded = failed = 0
    not_blocked = []
    with _progress(data, verbose) as ips:
        for ip in ips:
            try:
                telnetlib.Telnet(ip, 443, 1)
                responded += 1
                not_blocked.append(ip)
                if verbose:
                    print(R + "  [NOT BLOCKED] " + W + ip + ":443")
            except (socket.timeout, socket.error, ConnectionRefusedError, EOFError):
                failed += 1
                if verbose:
                    print(G + "  [BLOCKED]     " + W + ip + ":443")
    _print_summary("IP Reputation", responded, failed)
    _vt_report(not_blocked, vt_key, is_url=False)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
@click.option('--srcip', '-s', multiple=True)
@click.option('--limit', '-l', default=100, help='Max entries to test, randomly sampled (0 = all)')
@click.option('--vt-key', envvar='VT_API_KEY', default=None, help='VirusTotal API key')
def vxvault(verbose, srcip, limit, vt_key):
    '''Malware samples download from vxvault'''
    checkips(srcip)
    _vxvault(srcip, verbose, limit, vt_key)


def _vxvault(srcip, verbose=False, limit=100, vt_key=None):
    '''Malware samples download from vxvault'''
    # http://vxvault.net/URL_List.php
    print(G + "[+] " + W + "VX Vault Malware Downloads")
    print(G + "[+] " + W + "Fetching VXVault list...", end=" ", flush=True)
    r = _fetch_feed("http://vxvault.net/URL_List.php", "VXVault list")
    if r is None:
        return
    print("Done")

    if len(srcip) > 0:
        print(G + "[+] " + W + "Multi source IP mode enabled")

    data = _sample(
        [line for line in r.text.split("\r\n") if len(line) > 1 and line[0] == "h"],
        limit
    )
    if not data:
        print(R + "[!] " + W + "VXVault list is empty — check feed URL or network")
        return

    blocked = reached = ambiguous = 0
    not_blocked = []
    with _progress(data, verbose) as urls:
        for url in urls:
            verdict, status, nbytes = _probe_url(url, srcip)
            color, label, is_blocked, is_reached = _PROBE_VERDICT.get(
                verdict, (O, '[UNKNOWN]     ', False, False)
            )
            if is_blocked:
                blocked += 1
            elif is_reached:
                reached += 1
                not_blocked.append(url)
            else:
                ambiguous += 1
            if verbose:
                detail = f"  HTTP {status}" if status else ""
                detail += f"  ({nbytes}B)" if nbytes else ""
                print(f"  {color}{label}{W}  {url}{detail}")
    _print_threat_summary("VX Vault", blocked, reached, ambiguous)
    _vt_report(not_blocked, vt_key, is_url=True)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
@click.option('--srcip', '-s', multiple=True)
@click.option('--limit', '-l', default=100, help='Max entries to test, randomly sampled (0 = all)')
@click.option('--vt-key', envvar='VT_API_KEY', default=None, help='VirusTotal API key')
def malwareurls(verbose, srcip, limit, vt_key):
    '''Malware URL/Domain test'''
    checkips(srcip)
    _malwareurls(srcip, verbose, limit, vt_key)


def _malwareurls(srcip, verbose=False, limit=100, vt_key=None):
    '''Malware URL/Domain test'''
    print(G + "[+] " + W + "Malware URL Downloads")
    print(G + "[+] " + W + "Fetching Malware URL list...", end=" ", flush=True)
    lines = _read_csv(BASE_DIR / "malware_urls.csv")
    if lines is None:
        return
    print("Done")

    if len(srcip) > 0:
        print(G + "[+] " + W + "Multi source IP mode enabled")

    data = _sample([line for line in lines.split("\n") if line.strip()], limit)

    blocked = reached = ambiguous = 0
    not_blocked = []
    with _progress(data, verbose) as urls:
        for url in urls:
            target = url if url.startswith(("http://", "https://")) else "http://" + url
            verdict, status, nbytes = _probe_url(target, srcip)
            color, label, is_blocked, is_reached = _PROBE_VERDICT.get(
                verdict, (O, '[UNKNOWN]     ', False, False)
            )
            if is_blocked:
                blocked += 1
            elif is_reached:
                reached += 1
                not_blocked.append(target)
            else:
                ambiguous += 1
            if verbose:
                detail = f"  HTTP {status}" if status else ""
                detail += f"  ({nbytes}B)" if nbytes else ""
                print(f"  {color}{label}{W}  {target}{detail}")
    _print_threat_summary("Malware URLs", blocked, reached, ambiguous)
    _vt_report(not_blocked, vt_key, is_url=True)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
def appctrl(verbose):
    '''Trigger application control'''
    _appctrl(verbose)


def _appctrl(verbose=False):
    '''Trigger application control'''
    print(G + "[+] " + W + "Application Control")
    print(G + "[+] " + W + "Fetching AppCtrl list...", end=" ", flush=True)
    lines = _read_csv(BASE_DIR / "appctrl.csv")
    if lines is None:
        return
    print("Done")

    data = [line for line in lines.split("\n") if line.strip()]

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            target = url if url.startswith(("http://", "https://")) else "http://" + url
            try:
                requests.get(target, timeout=5, verify=False)
                responded += 1
                if verbose:
                    print(G + "  [SENT]   " + W + target)
            except (requests.exceptions.RequestException, OSError):
                failed += 1
                if verbose:
                    print(O + "  [FAILED] " + W + target)
    _print_summary("App Control", responded, failed)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
def wf(verbose):
    '''URL categorisation trigger'''
    _wf(verbose)


def _wf(verbose=False):
    '''URL categorisation trigger'''
    print(G + "[+] " + W + "WF categorisation trigger")
    print(G + "[+] " + W + "Fetching URL list...", end=" ", flush=True)
    lines = _read_csv(BASE_DIR / "wf.csv")
    if lines is None:
        return
    print("Done")

    data = [line for line in lines.split("\n") if line.strip()]

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            target = url if url.startswith(("http://", "https://")) else "http://" + url
            try:
                requests.get(target, timeout=5, verify=False)
                responded += 1
                if verbose:
                    print(G + "  [SENT]   " + W + target)
            except (requests.exceptions.RequestException, OSError):
                failed += 1
                if verbose:
                    print(O + "  [FAILED] " + W + target)
    _print_summary("URL Filtering", responded, failed)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
def webtraffic(verbose):
    '''Generate good web traffic'''
    _webtraffic(verbose)


def _webtraffic(verbose=False):
    print(G + "[+] " + W + "Web traffic trigger")
    print(G + "[+] " + W + "Fetching traffic list...", end=" ", flush=True)
    lines = _read_csv(BASE_DIR / "goodurl.csv")
    if lines is None:
        return
    print("Done")

    data = [line for line in lines.split("\n") if line.strip()]

    responded = failed = 0
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, ignore_default_args=["--disable-extensions"], args=["--ignore-certificate-errors"])
            page = browser.new_page()
            page.set_default_navigation_timeout(10000)

            with _progress(data, verbose) as urls:
                for url in urls:
                    target = "http://www.%s" % url
                    try:
                        page.goto(target, wait_until="domcontentloaded")
                        responded += 1
                        if verbose:
                            print(G + "  [LOADED]  " + W + target)
                    except PlaywrightTimeoutError:
                        failed += 1
                        if verbose:
                            print(O + "  [TIMEOUT] " + W + target)
                    except Exception:
                        failed += 1
                        if verbose:
                            print(O + "  [FAILED]  " + W + target)

            browser.close()
    except Exception as e:
        print(R + "[!] " + W + f"Browser failed to start: {e}")
        return

    _print_summary("Web Traffic", responded, failed)


@cli.command()
def update():
    '''Refresh malware URL and good URL lists from public sources'''
    _update()


if __name__ == '__main__':
    cli()
