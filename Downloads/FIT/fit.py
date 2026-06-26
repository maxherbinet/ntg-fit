#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import requests
import requests_toolbelt
import telnetlib
import socket
import random
from contextlib import contextmanager
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from selenium import webdriver
import selenium
import platform

BASE_DIR = Path(__file__).parent

# disable warnings in requests for cert bypass
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__version__ = 0.17

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
    ''' check network connection '''
    try:
        r = requests.get("https://www.google.ca", verify=False)
    except:
        return False
    else:
        return True


def checkips(srcip):
    for ipaddr in srcip:
        try:
            socket.inet_aton(ipaddr)
            print(G + "[+] " + W + "Source IP Address " + ipaddr)
        except socket.error:
            print(R + "[-] " + W + "IP Address " + ipaddr + " is not valid")
            exit(-1)


def setsrcip(srcip):
    ''' Set a random source ip from a list '''
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
        exit(-1)


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
    '''IP Reputation test using zeustracker uiplist'''
    checkips(srcip)
    _iprep(srcip, verbose)


def _iprep(srcip, verbose=False):
    '''IP Reputation test using zeustracker uiplist'''
    # https://zeustracker.abuse.ch/blocklist.php?download=badips
    print(G + "[+] " + W + "IP Reputation Test")
    print(G + "[+] " + W + "Fetching bad ip list...", end=" ")
    r = requests.get("https://zeustracker.abuse.ch/blocklist.php?download=badips", verify=False)
    print("Done")

    data = [line for line in r.text.split("\n") if len(line) > 1 and line[0] != "#"]

    responded = failed = 0
    with _progress(data, verbose) as ips:
        for ip in ips:
            try:
                tn = telnetlib.Telnet(ip, 443, 1)
                responded += 1
                if verbose:
                    print(R + "  [NOT BLOCKED] " + W + ip + ":443")
            except (socket.timeout, socket.error, ConnectionRefusedError):
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
    print(G + "[+] " + W + "Fetching VXVault list...", end=" ")
    r = requests.get("http://vxvault.net/URL_List.php", timeout=10)
    print("Done")

    if len(srcip) > 0:
        print(G + "[+] " + W + "Multi source IP mode enabled")

    data = [line for line in r.text.split("\r\n") if len(line) > 1 and line[0] == "h"]

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            try:
                if len(srcip) > 0:
                    r = setsrcip(srcip).get(url, timeout=1)
                else:
                    r = requests.get(url, timeout=1)
                responded += 1
                if verbose:
                    print(R + "  [NOT BLOCKED] " + W + url)
            except requests.exceptions.RequestException:
                failed += 1
                if verbose:
                    print(G + "  [BLOCKED]     " + W + url)
    _print_summary("VX Vault", responded, failed)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
@click.option('--srcip', '-s', multiple=True)
def malwareurls(verbose, srcip):
    '''  Malware URl/Domain test '''
    checkips(srcip)
    _malwareurls(srcip, verbose)


def _malwareurls(srcip, verbose=False):
    '''  Malware URl/Domain test '''
    print(G + "[+] " + W + "Malware URL Downloads")
    print(G + "[+] " + W + "Fetching Malware URL list...", end=" ")
    with open(BASE_DIR / "malware_urls.csv", 'r') as f:
        lines = f.read()
    print("Done")

    if len(srcip) > 0:
        print(G + "[+] " + W + "Multi source IP mode enabled")

    data = [line for line in lines.split("\n") if line.strip()]

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            target = "http://" + url
            try:
                if len(srcip) > 0:
                    r = setsrcip(srcip).get(target, timeout=1)
                else:
                    r = requests.get(target, timeout=1)
                responded += 1
                if verbose:
                    print(R + "  [NOT BLOCKED] " + W + target)
            except requests.exceptions.RequestException:
                failed += 1
                if verbose:
                    print(G + "  [BLOCKED]     " + W + target)
    _print_summary("Malware URLs", responded, failed)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
def appctrl(verbose):
    ''' Trigger application control '''
    _appctrl(verbose)


def _appctrl(verbose=False):
    ''' Trigger application control '''
    print(G + "[+] " + W + "Application Control")
    print(G + "[+] " + W + "Fetching AppCtrl list...", end=" ")
    with open(BASE_DIR / "appctrl.csv", 'r') as f:
        lines = f.read()
    print("Done")

    data = [line for line in lines.split("\n") if line.strip()]

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            try:
                r = requests.get(url, timeout=1)
                responded += 1
                if verbose:
                    print(G + "  [SENT]   " + W + url)
            except requests.exceptions.RequestException:
                failed += 1
                if verbose:
                    print(O + "  [FAILED] " + W + url)
    _print_summary("App Control", responded, failed)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
def wf(verbose):
    '''  URL categorisation trigger '''
    _wf(verbose)


def _wf(verbose=False):
    '''  URL categorisation trigger '''
    print(G + "[+] " + W + "WF categorisation trigger")
    print(G + "[+] " + W + "Fetching URL list...", end=" ")
    with open(BASE_DIR / "wf.csv", 'r') as f:
        lines = f.read()
    print("Done")

    data = [line for line in lines.split("\n") if line.strip()]

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            try:
                r = requests.get(url, timeout=1)
                responded += 1
                if verbose:
                    print(G + "  [SENT]   " + W + url)
            except requests.exceptions.RequestException:
                failed += 1
                if verbose:
                    print(O + "  [FAILED] " + W + url)
    _print_summary("URL Filtering", responded, failed)


@cli.command()
@click.option('--verbose', '-v', is_flag=True, default=False, help='Show each request result')
def webtraffic(verbose):
    ''' Generate good web traffic '''
    _webtraffic(verbose)


def _webtraffic(verbose=False):
    driver = webdriver.PhantomJS()
    driver.set_window_size(1920, 1080)
    driver.set_page_load_timeout(10)

    print(G + "[+] " + W + "Web traffic trigger")
    print(G + "[+] " + W + "Fetching traffic list...", end=" ")
    with open(BASE_DIR / "goodurl.csv", 'r') as f:
        lines = f.read()
    print("Done")

    data = [line for line in lines.split("\n") if line.strip()]

    responded = failed = 0
    with _progress(data, verbose) as urls:
        for url in urls:
            target = "http://www.%s" % url
            try:
                driver.get(target)
                responded += 1
                if verbose:
                    print(G + "  [LOADED]  " + W + target)
            except selenium.common.exceptions.TimeoutException:
                failed += 1
                if verbose:
                    print(O + "  [TIMEOUT] " + W + target)

    driver.quit()
    _print_summary("Web Traffic", responded, failed)


if __name__ == '__main__':
    cli()
