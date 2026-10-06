# 🔍 Port Inventory

A lightweight, self-hosted web UI for auditing listening ports on your Linux server.

Reads live data from `ss -tulpn`, persists metadata in SQLite, and lets you name, categorize, and annotate every port — so you always know what's running and why.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat-square&logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Features

- **One row per service.** Every bind of the same port/protocol (`0.0.0.0` + `::`, or a wildcard plus a loopback bind) is grouped into one row, with a chip per bind address colored by scope: public, LAN, loopback, Tailscale.
- **Auto-naming.** Well-known ports (SSH, DNS, HTTP(S), PostgreSQL, Redis, WireGuard, …) are named and categorized the first time they're seen. Anything you type yourself is never overwritten.
- **Duplicate-bind detection.** After every scan, the widest bind that is listening becomes the group's primary. Other listening binds are marked as duplicates and shown as faded chips. This is tracked separately from your own *Ignore*: if the primary stops listening, the next listening bind takes over at full opacity.
- **Open web UIs in one click.** Every scan sends `GET /` to each listening TCP port on `localhost` (in parallel, short timeout). Ports that serve something a browser can open (an HTML page, a redirect such as a login page, or an HTTP auth prompt) get an open-in-new-tab button on their row and in the details drawer. APIs that answer with JSON or plain text, and HTTPS-only servers that reject plain HTTP, get no link. The link uses the host you opened Port Inventory on, or `localhost` for loopback-only ports.
- **Categories.** 18 built-in categories plus your own. Create one from the category popover, and delete it again once no port uses it. Each category gets a stable color.
- **Fast editing.** Click a service name to rename it inline (Enter saves, Esc cancels). Click the category chip to change it. Every change saves immediately and shows a toast with **Undo**.
- **Details drawer.** Click a row for notes (saved when you leave the field), the ignore toggle, every bind with its scope and status, the full process string, and the raw `ss` lines with a copy button. The drawer is linked from the URL (`#tcp-22`), so links and reloads reopen it.
- **Bulk actions.** Tick rows, or use the header checkbox to select all visible rows, then set a category, ignore or unignore them all at once.
- **Filtering and sorting.** The stat cards (Total, Unnamed, Public, New, Ignored) double as filters. There is also search, a TCP/UDP switch, a category multi-select and a scope filter, plus sortable column headers. Filters, sort order and theme are remembered in the browser.
- **Keyboard shortcuts.** `/` search · `j`/`k` move · `Enter` details · `e` rename · `i` ignore · `x` select · `Esc` close or clear · `?` show the list.
- **Light and dark themes.** Applied before first paint, so there's no flash on load.
- **Background rescans.** `ss -tulpn` runs at startup and on a configurable interval (default 24h). Opening the UI also triggers a background rescan when the data is older than `PORT_INVENTORY_STALE_SECONDS`. `first_seen` / `last_seen` are tracked per bind: ports first seen in the last 24h are marked **NEW**, and ports that stopped listening are shown as **offline**.
- **Single file, SQLite.** `app.py` plus Flask; the database survives restarts and upgrades migrate it automatically.

---

## Screenshots

_Screenshots of the new UI coming soon._

---

## Quick Start

### Option 1 — Docker Compose (recommended)

```bash
git clone https://github.com/bariscanaslan/port-inventory.git
cd port-inventory
docker compose up -d
```

Then open [http://localhost:8710](http://localhost:8710).

> **Note:** The container runs with `network_mode: host` and `pid: host` so it can read process names and all host ports via `ss -p`. `user: root` is required for process visibility.

---

### Option 2 — Bare metal / venv

**Requirements:** Python 3.10+, `iproute2` (`ss` command)

```bash
git clone https://github.com/bariscanaslan/port-inventory.git
cd port-inventory

python3 -m venv venv
./venv/bin/pip install flask

# Run as root to see process names/PIDs
sudo ./venv/bin/python app.py
```

---

## Configuration

All configuration is done via environment variables. No config files needed.

| Variable | Default | Description |
|---|---|---|
| `PORT_INVENTORY_DIR` | `/DATA/AppData/port-inventory` | Directory for app data |
| `PORT_INVENTORY_DB` | `<DIR>/port_inventory.sqlite3` | SQLite database path |
| `PORT_INVENTORY_HOST` | `127.0.0.1` | Host to bind the web UI to |
| `PORT_INVENTORY_PORT` | `8710` | Port to bind the web UI to |
| `PORT_INVENTORY_RESCAN_INTERVAL` | `86400` | Auto-rescan interval in seconds (default: 24h) |
| `PORT_INVENTORY_STALE_SECONDS` | `300` | Opening the UI triggers a background rescan when the last scan is older than this many seconds |
| `PORT_INVENTORY_HTTP_PROBE_TIMEOUT` | `1.5` | Seconds to wait for each port's HTTP answer during a scan; `0` turns the HTTP check off |

### Bind address guidance

| `PORT_INVENTORY_HOST` | Use case |
|---|---|
| `127.0.0.1` | Loopback only — expose via Cloudflare Tunnel, Tailscale, or reverse proxy |
| `0.0.0.0` | All interfaces — direct LAN or Docker host access |

---

## Docker

### `docker-compose.yml`

```yaml
services:
  port-inventory:
    build:
      context: .
      dockerfile: Dockerfile

    container_name: port-inventory
    restart: unless-stopped

    network_mode: host
    pid: host

    user: root

    environment:
      PORT_INVENTORY_DIR: /data
      PORT_INVENTORY_DB: /data/port_inventory.sqlite3

      # Secure default: only reachable from within the host.
      # Pair with Cloudflare Tunnel, Tailscale, or a reverse proxy to expose externally.
      PORT_INVENTORY_HOST: 0.0.0.0

      PORT_INVENTORY_PORT: 8710

    volumes:
      - ./data:/data

    security_opt:
      - no-new-privileges:true
```

### `Dockerfile`

```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

COPY app.py /app/app.py

RUN mkdir -p /data

ENV PORT_INVENTORY_DIR=/data
ENV PORT_INVENTORY_DB=/data/port_inventory.sqlite3
ENV PORT_INVENTORY_HOST=0.0.0.0
ENV PORT_INVENTORY_PORT=8710

CMD ["python", "/app/app.py"]
```

---

## Systemd Service (bare metal)

```ini
# /etc/systemd/system/port-inventory.service
[Unit]
Description=Port Inventory
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/port-inventory
ExecStart=/opt/port-inventory/venv/bin/python app.py
Restart=on-failure
Environment=PORT_INVENTORY_HOST=127.0.0.1
Environment=PORT_INVENTORY_PORT=8710

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now port-inventory
```

---

## Reverse Proxy (Nginx example)

```nginx
location /port-inventory/ {
    proxy_pass http://127.0.0.1:8710/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

The page calls the API with relative URLs (`api/...`), so it works under a sub-path. Open it with the trailing slash (`/port-inventory/`).

---

## Data

Port metadata is stored in a SQLite database at the configured `PORT_INVENTORY_DB` path. The `./data/` directory (Docker) or `PORT_INVENTORY_DIR` (bare metal) contains:

```
data/
└── port_inventory.sqlite3
```

Tables: `port_metadata` (one row per bind), `custom_categories` and `settings` (last scan time and error). Older databases are migrated on startup. The database is safe to back up while the app is running.

---

## API

All routes are under `/api` and speak JSON. Errors come back as `{"error": "message"}` with a 4xx status. Write requests need `Content-Type: application/json`.

A **key** identifies one bind: `<proto>|<address>|<port>`, e.g. `tcp|0.0.0.0|22` or `udp|127.0.0.53%lo|53`. URL-encode it in paths (`tcp%7C0.0.0.0%7C22`).

| Method | Route | Body | Response |
|---|---|---|---|
| `GET` | `/api/ports` | — | Payload (below). Runs a first scan if none has happened yet |
| `PATCH` | `/api/ports/<key>` | Any of `{name, category, notes, ignored}` | `{"port": {...one bind row...}}` |
| `POST` | `/api/ports/bulk` | `{"keys": [key, ...], "changes": {name?, category?, notes?, ignored?}}` | `{"updated": n, "data": Payload}` |
| `POST` | `/api/rescan` | — | Payload (scan failures are reported in `scan_error`) |
| `GET` | `/api/categories` | — | `{"categories": [Category, ...]}` |
| `POST` | `/api/categories` | `{"name": "Backups"}` | `{"name", "created", "categories"}`: `201` if created, `200` if it already existed (matched case-insensitively) |
| `DELETE` | `/api/categories/<name>` | — | `{"deleted", "categories"}`. `400` for built-ins, `404` if unknown, `409` while any port uses it |

Field rules: `name` ≤ 100 chars, `category` ≤ 48 chars (an unknown category is created on the fly; casing is matched to an existing one), `notes` ≤ 4000 chars, `ignored` must be a boolean. Unknown fields are rejected. A bulk update is all-or-nothing: if any key is unknown, nothing is saved (`404`).

**Payload**

```jsonc
{
  "hostname": "nas",
  "server_time": "2026-10-05T19:55:20.123+00:00",
  "last_scan_at": "2026-10-05T19:55:18.456+00:00",   // null before the first scan
  "scan_error": null,                                // message if the last scan failed
  "rescan_interval_seconds": 86400,
  "stale_after_seconds": 300,
  "stats": {"total": 18, "unnamed": 3, "public": 7, "new": 1, "ignored": 4},  // total/unnamed/public/new exclude ignored groups
  "categories": [{"name": "Web", "builtin": true, "count": 2}],                // count = groups using it
  "groups": [Group, ...]
}
```

**Group** (one per port + protocol)

```jsonc
{
  "id": "tcp-22",                      // also the URL hash for the details drawer
  "port": 22, "proto": "tcp",
  "primary_key": "tcp|0.0.0.0|22",     // best listening bind: wildcard IPv4 > :: > specific, then oldest
  "keys": ["tcp|0.0.0.0|22", "tcp|::|22"],
  "name": "OpenSSH",                   // a user-typed name wins over the auto-filled one
  "auto_name": "SSH",                  // well-known name for this port, or ""
  "other_names": [{"name": "sshd v6", "address": "::"}],  // other user-typed names in the group
  "category": "Remote Access", "notes": "",
  "ignored": false,                    // the user's ignore (taken from the primary)
  "process": "sshd · pid 812",         // summary; "process_full" has the raw ss users:(...) string
  "scopes": ["public"],                // public | tailscale | lan | specific | loopback, of the listening binds
  "has_public": true,                  // listening on a public bind right now
  "first_seen": "...", "last_seen": "...",
  "is_new": false,                     // first seen within the last 24h
  "is_online": true,                   // at least one bind was seen in the latest scan
  "binds": [{
    "key": "tcp|::|22", "address": "::", "scope": "public", "scope_label": "Public",
    "online": true,
    "ignored": false,                  // the user's ignore
    "auto_ignored": true,              // duplicate bind, recomputed on every scan
    "name": "SSH", "auto_name": "SSH", "user_name": "",
    "category": "Remote Access", "notes": "",
    "process": "users:((\"sshd\",pid=812,fd=4))", "raw": "tcp LISTEN 0 128 [::]:22 ...",
    "first_seen": "...", "last_seen": "..."
  }]
}
```

---

## Development

The tests are for development only. The app needs nothing but Flask, and the Dockerfile still copies only `app.py`.

**Backend** (pytest, Flask test client, fake `ss` output, throwaway SQLite DBs):

```bash
./venv/bin/pip install -r requirements-dev.txt
./venv/bin/python -m pytest
```

**UI** (the real page in [jsdom](https://github.com/jsdom/jsdom) against a fake-`ss` server; needs Node 18+ and a Python with Flask, taken from `$PYTHON` or `python3`):

```bash
cd tests/ui && npm install && PYTHON=../../venv/bin/python npm test
```

---

## License

MIT
