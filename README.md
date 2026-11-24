# NetGuard

A Python and Streamlit educational TCP security scanner. Active scans are limited to the exact loopback addresses 127.0.0.1 and ::1, with at most 256 ports and 16 workers. Simulated mode makes no network connections.

## Run locally

Requires Python 3.10 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

On macOS/Linux activate with `source .venv/bin/activate`.

## Test

```bash
python -m pytest -v
```

## Features

TCP connection checks, common port/service associations, configuration review flags, Plotly chart, CSV/JSON export, session-only history, simulated demo, and GitHub Actions tests.

## Limitations

Open ports are not confirmed vulnerabilities. Service labels are guesses based on conventional port numbers. No UDP, network-wide discovery, DNS lookups, version fingerprinting, or exploit checks. Unknown results can reflect timeouts or other errors. Run active scans locally, not on a public hosted service. Never scan systems without authorization or publish sensitive reports. For a public portfolio, use screenshots or a demo-only build.

## Safe local experiment

Run `python -m http.server 8000 --bind 127.0.0.1` from an empty test directory in a second terminal, scan port 8000, then stop the server with Ctrl+C.
