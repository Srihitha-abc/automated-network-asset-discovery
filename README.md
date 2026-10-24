# Automated Network Asset Discovery and Service Inventory Framework

This project discovers devices and open services on **authorized networks only**.
It uses Python/Flask, Nmap, SQLite, HTML, CSS, and JavaScript.

## Safety and authorization

The server refuses every target that is not a subnet of `ASSET_DISCOVERY_NETWORKS`.
Configure only networks that you own or have written permission to test. Nmap is
invoked with an argument list (never a shell command), a five-minute timeout, and
service detection limited to the top 100 ports. Do not expose this development
server directly to the Internet.

## Structure

```text
app.py                 Flask app, authorization, scanner, persistence and API
templates/index.html   Dashboard
static/app.js          Dashboard behavior
static/style.css       Dashboard styling
tests/test_app.py      Unit and integration tests (Nmap is mocked)
requirements.txt       Python dependencies
```

## Setup

1. Install Python 3.11+ and [Nmap](https://nmap.org/download.html), ensuring
   `nmap` is on PATH.
2. Create and activate a virtual environment:
   `python -m venv .venv` then `.venv\Scripts\activate` on Windows.
3. Install packages: `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env` and set a random API key of at least 16
   characters. Set `ASSET_DISCOVERY_NETWORKS` to your approved CIDR(s).
5. Set environment variables in the shell (or use a dotenv runner), then run
   `python app.py`. Browse to http://127.0.0.1:5000 and enter the API key.

Example PowerShell configuration:

```powershell
$env:ASSET_DISCOVERY_API_KEY = "use-a-long-random-secret-here"
$env:ASSET_DISCOVERY_NETWORKS = "192.168.1.0/24"
python app.py
```

## API

All `/api/*` endpoints require `X-API-Key`. `POST /api/scans` accepts
`{"target":"192.168.1.0/24"}` and returns `202` while the scan runs.
`GET /api/assets`, `GET /api/changes`, `GET /api/scans`, and `GET /api/status`
provide inventory and monitoring data. Search uses `q`; service filtering uses
`service`.

Each scan records its status and errors. New devices, newly open services, and
removed services are written to `changes`. Existing assets are updated with
last-seen data and their current service set.

Set `ASSET_DISCOVERY_SCAN_INTERVAL_SECONDS` to a positive value to automatically
scan every configured allowlisted network at that interval. Leave it at `0` to
use only dashboard-triggered scans.

## Testing

Run `pytest`. Tests use a temporary SQLite database and mock Nmap, so they do
not send network traffic. For production use, place Flask behind TLS and an
authenticated reverse proxy, rotate the API key, back up the SQLite database,
and run scans only during approved maintenance windows.
