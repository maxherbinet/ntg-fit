#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import requests
import requests_toolbelt
import warnings
import socket
import random
import sys
import csv
import io
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

__version__ = 0.20

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
def all(repeat, verbose, srcip):
    '''Run all test one after the other'''
    checkips(srcip)
    if repeat:
        print(G + "[+] " + W + "Repeat, repeat, repeat...")

    while True:
        _iprep(srcip, verbose)
        _vxvault(srcip, verbose)
        _malwareurls(srcip, verbose)
        _appctrl(verbose)
        _wf(verbose)
        _webtraffic(verbose)
        if not repeat:
            break


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
@click.option('--srcip', '-s', multiple=True)
def iprep(verbose, srcip):
    '''IP Reputation test using Feodo Tracker botnet C2 blocklist'''
    checkips(srcip)
    _iprep(srcip, verbose)


def _iprep(srcip, verbose=False):
    '''IP Reputation test using Feodo Tracker botnet C2 IP blocklist'''
    # https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    print(G + "[+] " + W + "IP Reputation Test")
    print(G + "[+] " + W + "Fetching bad ip list...", end=" ", flush=True)
    r = _fetch_feed("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "IP blocklist")
    if r is None:
        return
    print("Done")

    data = [line for line in r.text.split("\n") if len(line) > 1 and line[0] != "#"]
    if not data:
        print(R + "[!] " + W + "IP blocklist is empty — check feed URL or network")
        return

    responded = failed = 0
    with _progress(data, verbose) as ips:
        for ip in ips:
            try:
                telnetlib.Telnet(ip, 443, 1)
                responded += 1
                if verbose:
                    print(R + "  [NOT BLOCKED] " + W + ip + ":443")
            except (socket.timeout, socket.error, ConnectionRefusedError, EOFError):
                failed += 1
                if verbose:
                    print(G + "  [BLOCKED]     " + W + ip + ":443")
    _print_summary("IP Reputation", responded, failed)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
@click.option('--srcip', '-s', multiple=True)
def vxvault(verbose, srcip):
    '''Malware samples download from vxvault'''
    checkips(srcip)
    _vxvault(srcip, verbose)


def _vxvault(srcip, verbose=False):
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

    data = [line for line in r.text.split("\r\n") if len(line) > 1 and line[0] == "h"]
    if not data:
        print(R + "[!] " + W + "VXVault list is empty — check feed URL or network")
        return

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            try:
                if len(srcip) > 0:
                    setsrcip(srcip).get(url, timeout=1)
                else:
                    requests.get(url, timeout=1)
                responded += 1
                if verbose:
                    print(R + "  [NOT BLOCKED] " + W + url)
            except (requests.exceptions.RequestException, OSError):
                failed += 1
                if verbose:
                    print(G + "  [BLOCKED]     " + W + url)
    _print_summary("VX Vault", responded, failed)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
@click.option('--srcip', '-s', multiple=True)
def malwareurls(verbose, srcip):
    '''Malware URL/Domain test'''
    checkips(srcip)
    _malwareurls(srcip, verbose)


def _malwareurls(srcip, verbose=False):
    '''Malware URL/Domain test'''
    print(G + "[+] " + W + "Malware URL Downloads")
    print(G + "[+] " + W + "Fetching Malware URL list...", end=" ", flush=True)
    lines = _read_csv(BASE_DIR / "malware_urls.csv")
    if lines is None:
        return
    print("Done")

    if len(srcip) > 0:
        print(G + "[+] " + W + "Multi source IP mode enabled")

    data = [line for line in lines.split("\n") if line.strip()]

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            target = url if url.startswith(("http://", "https://")) else "http://" + url
            try:
                if len(srcip) > 0:
                    setsrcip(srcip).get(target, timeout=1)
                else:
                    requests.get(target, timeout=1)
                responded += 1
                if verbose:
                    print(R + "  [NOT BLOCKED] " + W + target)
            except (requests.exceptions.RequestException, OSError):
                failed += 1
                if verbose:
                    print(G + "  [BLOCKED]     " + W + target)
    _print_summary("Malware URLs", responded, failed)


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
            try:
                requests.get(url, timeout=1)
                responded += 1
                if verbose:
                    print(G + "  [SENT]   " + W + url)
            except (requests.exceptions.RequestException, OSError):
                failed += 1
                if verbose:
                    print(O + "  [FAILED] " + W + url)
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
            try:
                requests.get(url, timeout=1)
                responded += 1
                if verbose:
                    print(G + "  [SENT]   " + W + url)
            except (requests.exceptions.RequestException, OSError):
                failed += 1
                if verbose:
                    print(O + "  [FAILED] " + W + url)
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
            browser = p.chromium.launch(headless=True)
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
