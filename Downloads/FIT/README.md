# FIT — Firewall Inspection Tester

A command-line tool that generates real network traffic to verify your firewall policies are enforcing correctly.

| Test | What it does |
|---|---|
| `iprep` | Connects to active botnet C2 IPs (Feodo Tracker) to test IP reputation blocking |
| `vxvault` | Fetches live malware URLs from VX Vault to test AV/malware detection |
| `malwareurls` | Requests a curated list of malicious domains to test URL blocking |
| `appctrl` | Hits known application URLs to trigger application control policies |
| `wf` | Requests URLs across categories to trigger web filtering policies |
| `webtraffic` | Simulates legitimate browser traffic using headless Chrome |
| `all` | Runs all of the above in sequence |
| `update` | Refresh `malware_urls.csv` and `goodurl.csv` from public sources |

## Installing

Requires Python 3.7+.

```bash
python3 -m venv env
source env/bin/activate        # Windows: env\Scripts\activate
pip install -r requirements.txt
playwright install chromium
```

## Usage

```bash
fit <command> [options]
```

### Options available on all commands

| Option | Description |
|---|---|
| `-v` / `--verbose` | Print each URL/IP result inline with a per-run summary |
| `-s` / `--srcip <ip>` | Set the source IP for requests (repeatable for multiple IPs) |

### The `all` command

```bash
fit all                    # run all tests once
fit all --repeat           # loop continuously (useful in lab environments)
fit all -v                 # verbose output for all tests
```

### Running individual tests

```bash
fit iprep -v
fit malwareurls -v
fit appctrl
fit wf
```

### Multi source IP mode

Specifying one or more `-s` flags causes FIT to rotate randomly across those source IPs for each request, simulating traffic from multiple clients:

```bash
fit all -s 10.0.0.1 -s 10.0.0.2 -s 10.0.0.3
```

> Each IP must be bound to a local network interface. You will need a unique MAC per IP for results to appear as separate clients to the firewall.

## Reading the output

In verbose mode (`-v`), each request is labelled:

- **Threat tests** (`iprep`, `vxvault`, `malwareurls`):
  - `[BLOCKED]` in green — firewall blocked the connection (desired outcome)
  - `[NOT BLOCKED]` in red — connection reached the destination (firewall missed it)

- **Policy trigger tests** (`appctrl`, `wf`):
  - `[SENT]` in green — request went out successfully
  - `[FAILED]` in orange — request failed (connectivity issue)

A summary line is always printed at the end of each test regardless of verbosity.

## Keeping threat lists current

Run `fit update` periodically to refresh the bundled lists:

```bash
fit update
```

| File | Source | Notes |
|---|---|---|
| `malware_urls.csv` | [URLhaus](https://urlhaus.abuse.ch) (abuse.ch) | Updated automatically |
| `goodurl.csv` | [Tranco](https://tranco-list.eu) top 500 | Updated automatically |
| `appctrl.csv` | Curated manually | No public source — edit by hand |
| `wf.csv` | Curated manually | No public source — edit by hand |

## Known limitations

- `iprep` uses `telnet` on port 443, which some corporate networks block outright — connections may appear as `[BLOCKED]` even without a firewall policy matching the IP.
