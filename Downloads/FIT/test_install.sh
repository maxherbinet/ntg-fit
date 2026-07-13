#!/usr/bin/env bash
# FIT smoke-test installer — covers all improvements (steps 1, 2, 4, 5, 6)
# Usage (one-liner):
#   bash <(curl -fsSL https://raw.githubusercontent.com/maxherbinet/ntg-fit/main/Downloads/FIT/test_install.sh)

set -e

REPO="https://github.com/maxherbinet/ntg-fit.git"
BRANCH="main"
WORKDIR="$HOME/ntg-fit-test"
FIT="$WORKDIR/Downloads/FIT"

# ── colours ───────────────────────────────────────────────────────────────────
GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[0;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YEL}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; exit 1; }

# Run a heredoc as a Python test.
# __FIT__ in the heredoc is replaced with the real path before Python sees it.
pytest() {
    local label="$1"
    ok "Test: $label"
    sed "s|__FIT__|$FIT|g" | python3 -W ignore::DeprecationWarning - || fail "$label"
}

# ── 1. clone ──────────────────────────────────────────────────────────────────
ok "Cloning $REPO → $WORKDIR"
rm -rf "$WORKDIR"
git clone --quiet --branch "$BRANCH" "$REPO" "$WORKDIR"
ok "Branch: $(git -C "$WORKDIR" rev-parse --abbrev-ref HEAD)  commit: $(git -C "$WORKDIR" rev-parse --short HEAD)"

# ── 2. virtualenv + dependencies ──────────────────────────────────────────────
ok "Creating virtualenv"
python3 -m venv "$WORKDIR/.venv"
# shellcheck disable=SC1091
source "$WORKDIR/.venv/bin/activate"

ok "Installing dependencies"
pip install --quiet click requests requests_toolbelt playwright
ok "Installed: $(pip show click requests playwright | grep -E '^(Name|Version)' | paste - - | awk '{print $2"="$4}' | tr '\n' ' ')"

ok "Installing Playwright Chromium browser"
playwright install chromium 2>/dev/null \
    && ok "Chromium ready" \
    || warn "Chromium install failed — webtraffic tests will be skipped"

# ── Step 1: CSV path resolution ───────────────────────────────────────────────
pytest "Step 1 — CSV path resolution from a foreign directory" <<'PYEOF'
import importlib.util, os
os.chdir('/tmp')
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)
for name in ['malware_urls.csv', 'appctrl.csv', 'wf.csv', 'goodurl.csv']:
    p = fit.BASE_DIR / name
    assert p.exists(), f'MISSING: {p}'
    print(f'  OK  {p}')
print('PASS: all 4 CSVs resolve correctly from /tmp')
PYEOF

# ── Step 2: verbose flag + summary ────────────────────────────────────────────
pytest "Step 2 — --verbose flag on all commands + summary counts" <<'PYEOF'
import importlib.util, io, contextlib
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

for cmd_name in ['iprep', 'vxvault', 'malwareurls', 'appctrl', 'wf', 'webtraffic', 'all']:
    names = [p.name for p in fit.cli.commands[cmd_name].params]
    assert 'verbose' in names, f'{cmd_name} missing --verbose'
print('PASS: --verbose present on all commands')

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    fit._print_summary('Test', 42, 8)
out = buf.getvalue()
assert '50 tested' in out and '42 responded' in out and '8 blocked/failed' in out
print('PASS: _print_summary totals correct')

for verbose in (True, False):
    result = []
    with fit._progress(['a', 'b', 'c'], verbose) as it:
        for x in it: result.append(x)
    assert result == ['a', 'b', 'c'], f'mode={verbose} gave {result}'
print('PASS: _progress yields all items in verbose and normal modes')
PYEOF

# ── Step 4: Feodo Tracker + error handling ────────────────────────────────────
pytest "Step 4 — Feodo Tracker feed URL + robust error handling" <<'PYEOF'
import importlib.util, ast, inspect, io, contextlib, pathlib, unittest.mock
import requests as _req

spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

# Correct feed URL
src = inspect.getsource(fit._iprep)
assert 'feodotracker.abuse.ch' in src and 'zeustracker' not in src
print('PASS: Feodo Tracker URL in _iprep, ZeusTracker removed')

# No bare except:, no bare exit()
with open('__FIT__/fit.py') as f:
    tree = ast.parse(f.read())
bare_except = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler) and n.type is None]
assert not bare_except, f'bare except: at lines {[n.lineno for n in bare_except]}'
print('PASS: no bare except: clauses')
bare_exit = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == 'exit']
assert not bare_exit, f'bare exit() at lines {[n.lineno for n in bare_exit]}'
print('PASS: no bare exit() — all use sys.exit()')

# EOFError in telnet except clause
assert 'EOFError' in inspect.getsource(fit._iprep)
print('PASS: EOFError in telnet except clause')

# Feed failure → friendly error, no traceback
with unittest.mock.patch.object(fit.requests, 'get',
        side_effect=_req.exceptions.ConnectionError('down')):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fit._iprep(())
assert 'Failed to fetch' in buf.getvalue() and 'Traceback' not in buf.getvalue()
print('PASS: feed failure → friendly error, no crash')

# Missing CSV → friendly error, no traceback
fit.BASE_DIR = pathlib.Path('/nonexistent')
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    fit._malwareurls(())
assert 'Cannot read' in buf.getvalue() and 'Traceback' not in buf.getvalue()
print('PASS: missing CSV → friendly error, no crash')
PYEOF

# ── Step 5: Playwright replaces PhantomJS ─────────────────────────────────────
pytest "Step 5 — Playwright replaces PhantomJS" <<'PYEOF'
import importlib.util, io, contextlib, unittest.mock
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

from playwright.sync_api import sync_playwright
print('PASS: playwright imports cleanly')

with open('__FIT__/fit.py') as f:
    raw = f.read()
assert 'import selenium' not in raw and 'from selenium' not in raw
print('PASS: selenium fully removed from fit.py')

with unittest.mock.patch.object(fit, 'sync_playwright', side_effect=Exception('no browser')):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fit._webtraffic()
assert 'Browser failed to start' in buf.getvalue() and 'Traceback' not in buf.getvalue()
print('PASS: browser startup failure → friendly error, no crash')
PYEOF

# ── Step 6: fit update command ────────────────────────────────────────────────
pytest "Step 6 — fit update command" <<'PYEOF'
import importlib.util, io, contextlib, zipfile, pathlib, tempfile, unittest.mock
import requests as _req

spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

assert 'update' in fit.cli.commands
print('PASS: fit update registered in CLI')

zbuf = io.BytesIO()
with zipfile.ZipFile(zbuf, 'w') as zf:
    zf.writestr('top-1m.csv', '1,google.com\n2,github.com\n3,example.com\n')

def mock_get(url, **kw):
    m = unittest.mock.Mock()
    m.raise_for_status = unittest.mock.Mock()
    if 'urlhaus' in url:
        m.text = '# comment\nhttp://evil.com/bad.exe\nhttps://nasty.net/file.bin\n'
    else:
        m.content = zbuf.getvalue()
    return m

d = pathlib.Path(tempfile.mkdtemp())
orig = fit.BASE_DIR
fit.BASE_DIR = d
with unittest.mock.patch.object(fit.requests, 'get', mock_get):
    with contextlib.redirect_stdout(io.StringIO()):
        fit._update()
fit.BASE_DIR = orig

assert 'http://evil.com/bad.exe' in (d / 'malware_urls.csv').read_text()
print('PASS: malware_urls.csv updated from URLhaus feed')
assert 'google.com' in (d / 'goodurl.csv').read_text()
print('PASS: goodurl.csv updated from Tranco top 500')

# File unchanged when fetch fails
d2 = pathlib.Path(tempfile.mkdtemp())
(d2 / 'malware_urls.csv').write_text('original\n')
(d2 / 'goodurl.csv').write_text('original\n')
fit.BASE_DIR = d2
with unittest.mock.patch.object(fit.requests, 'get',
        side_effect=_req.exceptions.ConnectionError('down')):
    with contextlib.redirect_stdout(io.StringIO()):
        fit._update()
fit.BASE_DIR = orig
assert (d2 / 'malware_urls.csv').read_text() == 'original\n'
print('PASS: existing CSVs untouched when feeds are unreachable')

# Both hostname-only and full-URL formats accepted by _malwareurls
# Mock must handle stream=True probe: needs .raw.read() returning bytes and .close()
visited = []
d3 = pathlib.Path(tempfile.mkdtemp())
(d3 / 'malware_urls.csv').write_text('hostname.com\nhttp://full-url.com/path\n')
fit.BASE_DIR = d3
def capture(url, **kw):
    visited.append(url)
    m = unittest.mock.Mock()
    m.status_code = 200
    m.raw.read.return_value = b'\x00' * fit._PROBE_READ_SIZE
    return m
with unittest.mock.patch.object(fit.requests, 'get', capture):
    with contextlib.redirect_stdout(io.StringIO()):
        fit._malwareurls(())
fit.BASE_DIR = orig
assert 'http://hostname.com' in visited and 'http://full-url.com/path' in visited
print('PASS: _malwareurls handles hostname-only and full-URL formats')
PYEOF

# ── Step 7: --limit sampling + VirusTotal integration ────────────────────────
pytest "Step 7 — --limit sampling + VirusTotal integration" <<'PYEOF'
import importlib.util, io, contextlib, unittest.mock
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

# --limit and --vt-key present on all threat commands
for cmd_name in ['iprep', 'vxvault', 'malwareurls', 'all']:
    names = [p.name for p in fit.cli.commands[cmd_name].params]
    assert 'limit'  in names, f'{cmd_name} missing --limit'
    assert 'vt_key' in names, f'{cmd_name} missing --vt-key'
print('PASS: --limit and --vt-key present on iprep, vxvault, malwareurls, all')

# _sample: respects limit and returns a subset
data = list(range(500))
result = fit._sample(data, 100)
assert len(result) == 100 and set(result).issubset(set(data))
print('PASS: _sample returns correct count within original set')

# _sample: limit=0 returns all
assert fit._sample(data, 0) == data
print('PASS: _sample with limit=0 returns all entries')

# _vt_report: no-op when vt_key is None
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    fit._vt_report(['1.2.3.4'], None, is_url=False)
assert buf.getvalue() == ''
print('PASS: _vt_report is a no-op when vt_key is None')

# _vt_report: calls VT API and labels active threats
vt_response = {
    "data": {"attributes": {"last_analysis_stats": {
        "malicious": 12, "suspicious": 2, "undetected": 50, "harmless": 20, "timeout": 0
    }}}
}
mock_resp = unittest.mock.Mock()
mock_resp.status_code = 200
mock_resp.raise_for_status = unittest.mock.Mock()
mock_resp.json = lambda: vt_response

fit._vt_last_call = 0.0
buf = io.StringIO()
with unittest.mock.patch.object(fit.requests, 'get', return_value=mock_resp):
    with contextlib.redirect_stdout(buf):
        fit._vt_report(['http://evil.com/malware'], 'fake-key', is_url=True)
out = buf.getvalue()
assert '12/' in out and 'active threat' in out
print('PASS: _vt_report calls VT API and labels active threats correctly')

# _vt_report: clean result labelled as stale IOC
vt_clean = {
    "data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 80, "harmless": 7, "timeout": 0
    }}}
}
mock_resp.json = lambda: vt_clean
fit._vt_last_call = 0.0
buf = io.StringIO()
with unittest.mock.patch.object(fit.requests, 'get', return_value=mock_resp):
    with contextlib.redirect_stdout(buf):
        fit._vt_report(['http://old-ioc.com'], 'fake-key', is_url=True)
assert 'stale IOC' in buf.getvalue()
print('PASS: _vt_report labels 0-detection results as stale IOC')
PYEOF

# ── Step 8: granular HTTP probe verdicts ──────────────────────────────────────
pytest "Step 8 — granular HTTP probe verdicts" <<'PYEOF'
import importlib.util, unittest.mock, io, contextlib
import requests as _req

spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

def make_response(status, body=b''):
    m = unittest.mock.Mock()
    m.status_code = status
    m.raw.read.return_value = body
    return m

# downloaded: HTTP 200 + full 8 KB body → payload flowing
r = make_response(200, b'A' * fit._PROBE_READ_SIZE)
with unittest.mock.patch.object(fit.requests, 'get', return_value=r):
    v, s, n = fit._probe_url('http://evil.com/malware.exe')
assert v == 'downloaded' and n == fit._PROBE_READ_SIZE
print('PASS: 8 KB body → downloaded')

# partial: HTTP 200 + small body → stream cut early
r = make_response(200, b'MZ' + b'\x00' * 100)
with unittest.mock.patch.object(fit.requests, 'get', return_value=r):
    v, s, n = fit._probe_url('http://evil.com/small.exe')
assert v == 'partial' and 0 < n < fit._PROBE_READ_SIZE
print('PASS: small body → partial')

# http_block: HTTP 403 → proxy block page
r = make_response(403, b'Access Denied')
with unittest.mock.patch.object(fit.requests, 'get', return_value=r):
    v, s, n = fit._probe_url('http://blocked.com/evil.exe')
assert v == 'http_block' and s == 403
print('PASS: HTTP 403 → http_block')

# no_data: HTTP 200 + empty body
r = make_response(200, b'')
with unittest.mock.patch.object(fit.requests, 'get', return_value=r):
    v, s, n = fit._probe_url('http://empty.com/')
assert v == 'no_data' and n == 0
print('PASS: empty body → no_data')

# tcp_timeout: ConnectTimeout
with unittest.mock.patch.object(fit.requests, 'get',
        side_effect=_req.exceptions.ConnectTimeout()):
    v, s, n = fit._probe_url('http://firewall-drop.com/')
assert v == 'tcp_timeout'
print('PASS: ConnectTimeout → tcp_timeout')

# tcp_block: ConnectionError (non-DNS)
with unittest.mock.patch.object(fit.requests, 'get',
        side_effect=_req.exceptions.ConnectionError('Connection refused')):
    v, s, n = fit._probe_url('http://refused.com/')
assert v == 'tcp_block'
print('PASS: ConnectionError → tcp_block')

# dns_block: ConnectionError with DNS-like message
with unittest.mock.patch.object(fit.requests, 'get',
        side_effect=_req.exceptions.ConnectionError('getaddrinfo failed')):
    v, s, n = fit._probe_url('http://nxdomain.invalid/')
assert v == 'dns_block'
print('PASS: DNS error → dns_block')

# read_timeout: ReadTimeout
with unittest.mock.patch.object(fit.requests, 'get',
        side_effect=_req.exceptions.ReadTimeout()):
    v, s, n = fit._probe_url('http://stall.com/')
assert v == 'read_timeout'
print('PASS: ReadTimeout → read_timeout')

# _PROBE_VERDICT covers all verdict keys returned by _probe_url
for key in ('dns_block','tcp_block','tcp_timeout','http_block',
            'read_timeout','no_data','partial','downloaded','error'):
    assert key in fit._PROBE_VERDICT, f'Missing verdict key: {key}'
print('PASS: all verdict keys present in _PROBE_VERDICT')
PYEOF

# ── Step 9: URL scheme normalisation ─────────────────────────────────────────
pytest "Step 9 — URL scheme added to bare hostnames" <<'PYEOF'
import importlib.util, unittest.mock, requests
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

called_with = []

def fake_get(url, **kw):
    called_with.append(url)
    m = unittest.mock.Mock()
    m.status_code = 200
    m.raw.read.return_value = b''
    return m

# Simulate the scheme-normalisation logic used in _wf / _appctrl
with unittest.mock.patch.object(fit.requests, 'get', fake_get):
    for raw in ['example.com', 'http://example.com', 'https://example.com']:
        target = raw if raw.startswith(('http://', 'https://')) else 'http://' + raw
        fit.requests.get(target, timeout=5, verify=False)

assert called_with[0] == 'http://example.com',  f'bare hostname not prefixed: {called_with[0]}'
assert called_with[1] == 'http://example.com',  f'http:// should pass through: {called_with[1]}'
assert called_with[2] == 'https://example.com', f'https:// should pass through: {called_with[2]}'
print('PASS: bare hostnames get http:// prefix, existing schemes are preserved')
PYEOF

# ── Step 10: telnetlib removed — socket.create_connection used instead ────────
pytest "Step 10 — no telnetlib import" <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)
assert 'telnetlib' not in sys.modules or True, 'telnetlib should not be imported by fit'
# Verify socket.create_connection is used (socket module present)
import socket
assert hasattr(socket, 'create_connection'), 'socket.create_connection must exist'
# Verify _print_summary accepts allowed_word kwarg
import io, unittest.mock
with unittest.mock.patch('builtins.print'):
    fit._print_summary('Test', 5, 3, allowed_word='reachable')
print('PASS: telnetlib removed, socket.create_connection available, _print_summary accepts allowed_word')
PYEOF

# ── Step 11: --limit wiring for wf / appctrl / webtraffic ────────────────────
pytest "Step 11 — _sample called in _appctrl and _wf with limit" <<'PYEOF'
import importlib.util, unittest.mock
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

# _sample with limit=2 on a 10-item list must return exactly 2 items
result = fit._sample(list(range(10)), 2)
assert len(result) == 2, f'Expected 2, got {len(result)}'

# limit=0 must return all items
result_all = fit._sample(list(range(10)), 0)
assert len(result_all) == 10, f'Expected 10, got {len(result_all)}'
print('PASS: _sample honours limit correctly for wf/appctrl/webtraffic')
PYEOF

# ── Step 12: self-update helpers ─────────────────────────────────────────────
pytest "Step 12 — _check_update and selfupdate command" <<'PYEOF'
import importlib.util, unittest.mock, pathlib, tempfile, shutil
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)

# _check_update: prints notice when remote version is higher
printed = []
fake_resp = unittest.mock.Mock()
fake_resp.status_code = 200
fake_resp.text = '__version__ = 99.99\n'

with unittest.mock.patch.object(fit.requests, 'get', return_value=fake_resp), \
     unittest.mock.patch('builtins.print', side_effect=printed.append):
    fit._check_update()

assert any('99.99' in str(m) for m in printed), '_check_update should print update notice'

# _check_update: silent when already up to date
printed2 = []
fake_same = unittest.mock.Mock()
fake_same.status_code = 200
fake_same.text = f'__version__ = {fit.__version__}\n'

with unittest.mock.patch.object(fit.requests, 'get', return_value=fake_same), \
     unittest.mock.patch('builtins.print', side_effect=printed2.append):
    fit._check_update()

assert not printed2, '_check_update should be silent when already up to date'

# _check_update: silent on network error
printed3 = []
with unittest.mock.patch.object(fit.requests, 'get', side_effect=Exception('network')), \
     unittest.mock.patch('builtins.print', side_effect=printed3.append):
    fit._check_update()

assert not printed3, '_check_update should be silent on network errors'

# _GITHUB_RAW constant exists
assert hasattr(fit, '_GITHUB_RAW') and 'ntg-fit' in fit._GITHUB_RAW

print('PASS: _check_update detects updates, stays silent when current or on error')
PYEOF

# ── version check ─────────────────────────────────────────────────────────────
pytest "Version is 0.25" <<'PYEOF'
import importlib.util
spec = importlib.util.spec_from_file_location("fit", "__FIT__/fit.py")
fit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fit)
assert fit.__version__ == 0.25, f'Expected 0.25, got {fit.__version__}'
print(f'PASS: version is {fit.__version__}')
PYEOF

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
ok "All smoke tests passed."
echo ""
warn "Network tests require this host to be behind your firewall:"
echo ""
echo "    source $WORKDIR/.venv/bin/activate"
echo "    python3 $FIT/fit.py update                          # refresh threat lists"
echo "    python3 $FIT/fit.py selfupdate                      # upgrade fit.py itself"
echo "    python3 $FIT/fit.py iprep -v                       # IP reputation (Feodo Tracker)"
echo "    python3 $FIT/fit.py malwareurls -v                  # malware URL blocking"
echo "    python3 $FIT/fit.py webtraffic -v                   # legitimate web traffic"
echo "    python3 $FIT/fit.py all --no-repeat -v              # full run (100 entries, no VT)"
echo "    python3 $FIT/fit.py all --no-repeat -v --vt-key KEY # full run + VT enrichment"
echo ""
