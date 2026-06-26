#!/usr/bin/env bash
# FIT smoke-test installer
# Clone, set up, and validate the current branch from any test VM.
# Usage: bash test_install.sh

set -e

REPO="https://github.com/maxherbinet/ntg-fit.git"
BRANCH="claude/project-overview-i9dw1p"
WORKDIR="$HOME/ntg-fit-test"

# ── colours ──────────────────────────────────────────────────────────────────
GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[0;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YEL}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; exit 1; }

# ── 1. clone ─────────────────────────────────────────────────────────────────
ok "Cloning $REPO → $WORKDIR"
rm -rf "$WORKDIR"
git clone --quiet --branch "$BRANCH" "$REPO" "$WORKDIR"
cd "$WORKDIR/Downloads/FIT"
ok "Branch: $(git rev-parse --abbrev-ref HEAD)  commit: $(git rev-parse --short HEAD)"

# ── 2. virtualenv ─────────────────────────────────────────────────────────────
ok "Creating virtualenv"
python3 -m venv "$WORKDIR/.venv"
# shellcheck disable=SC1091
source "$WORKDIR/.venv/bin/activate"

ok "Installing dependencies"
# requests_toolbelt is a runtime dependency not listed in requirements.txt;
# selenium omitted here because PhantomJS (webtraffic command) requires
# a separate binary install — skip that command during smoke tests.
pip install --quiet click requests requests_toolbelt selenium
ok "Installed: $(pip show click requests selenium | grep -E 'Name|Version' | paste - - | awk '{print $2"="$4}' | tr '\n' ' ')"

# ── 3. path-fix smoke test ────────────────────────────────────────────────────
# Run from /tmp to prove BASE_DIR resolves CSVs regardless of cwd.
ok "Smoke test 1: CSV path resolution from a different directory"
cd /tmp
python3 -c "
import sys, types, pathlib

# stub selenium so fit.py imports without it
for mod in ['selenium','selenium.webdriver','selenium.common','selenium.common.exceptions']:
    sys.modules[mod] = types.ModuleType(mod)

sys.path.insert(0, str(pathlib.Path('$WORKDIR/Downloads/FIT')))
import fit

for csv in ['malware_urls.csv','appctrl.csv','wf.csv','goodurl.csv']:
    p = fit.BASE_DIR / csv
    assert p.exists(), f'MISSING: {p}'
    print(f'  OK  {p}')
print('PASS: all CSVs found from /tmp')
"
cd "$WORKDIR/Downloads/FIT"

# ── 4. summary helper test ────────────────────────────────────────────────────
ok "Smoke test 2: _print_summary counts"
python3 -c "
import sys, types
for mod in ['selenium','selenium.webdriver','selenium.common','selenium.common.exceptions']:
    sys.modules[mod] = types.ModuleType(mod)

import fit, io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    fit._print_summary('Demo', 37, 13)
out = buf.getvalue()
assert '50 tested' in out
assert '37 responded' in out
assert '13 blocked/failed' in out
print('PASS:', out.strip())
"

# ── 5. _progress helper test ─────────────────────────────────────────────────
ok "Smoke test 3: _progress context manager"
python3 -c "
import sys, types
for mod in ['selenium','selenium.webdriver','selenium.common','selenium.common.exceptions']:
    sys.modules[mod] = types.ModuleType(mod)

import fit
items = ['a','b','c']
for mode in (True, False):
    out = []
    with fit._progress(items, mode) as it:
        for x in it:
            out.append(x)
    assert out == items, f'mode={mode} got {out}'
print('PASS: both verbose and normal modes yield all items')
"

# ── 6. --help sanity check ────────────────────────────────────────────────────
ok "Smoke test 4: CLI --help"
# Suppress the telnetlib deprecation warning (deprecated in 3.11, removed in 3.13)
python3 -W ignore::DeprecationWarning fit.py --help | grep -q "malwareurls" \
    && echo "PASS: commands listed in --help output" \
    || fail "--help output missing expected commands"

python3 -W ignore::DeprecationWarning -c "
import sys, types
for mod in ['selenium','selenium.webdriver','selenium.common','selenium.common.exceptions']:
    sys.modules[mod] = types.ModuleType(mod)
import fit
for cmd_name in ['iprep','vxvault','malwareurls','appctrl','wf','webtraffic','all']:
    cmd = fit.cli.commands[cmd_name]
    param_names = [p.name for p in cmd.params]
    assert 'verbose' in param_names, f'{cmd_name} missing --verbose'
print('PASS: --verbose/-v present on all commands')
"

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
ok "All smoke tests passed."
warn "Network-dependent commands (iprep, vxvault, malwareurls, appctrl, wf) require"
warn "this host to be behind your firewall. Run them manually to validate blocking:"
echo ""
echo "    source $WORKDIR/.venv/bin/activate"
echo "    cd /tmp   # prove path fix works from any directory"
echo "    python3 $WORKDIR/Downloads/FIT/fit.py malwareurls          # normal"
echo "    python3 $WORKDIR/Downloads/FIT/fit.py malwareurls -v       # verbose"
echo "    python3 $WORKDIR/Downloads/FIT/fit.py all --no-repeat -v   # full run"
echo ""
