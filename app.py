#!/usr/bin/env python3
"""
Port Inventory - self-hosted UI for classifying `ss -tulpn` output.

Features:
- Reads host listening ports via `ss -H -tulpn`
- Shows local address, port, protocol, process info, and bind scope
- New/unclassified ports appear as "Unnamed"
- Lets you assign name, category, notes, owner, exposure, and ignored state
- Stores metadata in SQLite
- Keeps last_seen / first_seen timestamps
- Client-side search & sort
- Ignored ports hidden by default (toggle button)
- Dates displayed as dd/MM/YYYY - HH:mm
- Auto-rescan once per day via background scheduler

Recommended path:
  /DATA/AppData/port-inventory/app.py

Run:
  python3 -m venv venv
  ./venv/bin/pip install flask
  sudo ./venv/bin/python app.py

For a systemd service, run as root if you want process names/PIDs from `ss -p`.
"""

from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from flask import Flask, redirect, render_template_string, request, url_for

APP_DIR = Path(os.environ.get("PORT_INVENTORY_DIR", "/DATA/AppData/port-inventory"))
DB_PATH = Path(os.environ.get("PORT_INVENTORY_DB", APP_DIR / "port_inventory.sqlite3"))
HOST = os.environ.get("PORT_INVENTORY_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT_INVENTORY_PORT", "8710"))

RESCAN_INTERVAL_SECONDS = int(os.environ.get("PORT_INVENTORY_RESCAN_INTERVAL", str(24 * 3600)))  # default: 24h

app = Flask(__name__)


@dataclass(frozen=True)
class PortEntry:
    proto: str
    state: str
    local_address: str
    port: int
    peer: str
    process: str
    raw: str

    @property
    def key(self) -> str:
        return make_key(self.proto, self.local_address, self.port)

    @property
    def scope(self) -> str:
        return classify_scope(self.local_address)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def format_date(iso_str: str) -> str:
    """Convert ISO date string to dd/MM/YYYY - HH:mm format."""
    if not iso_str:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%d/%m/%Y - %H:%M")
    except Exception:
        return iso_str


def make_key(proto: str, local_address: str, port: int) -> str:
    return f"{proto.lower()}|{local_address}|{port}"


def get_db() -> sqlite3.Connection:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS port_metadata (
                key TEXT PRIMARY KEY,
                proto TEXT NOT NULL,
                local_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '',
                owner TEXT NOT NULL DEFAULT '',
                exposure TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                ignored INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_process TEXT NOT NULL DEFAULT '',
                last_raw TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_port_metadata_port
            ON port_metadata(port);

            CREATE INDEX IF NOT EXISTS idx_port_metadata_last_seen
            ON port_metadata(last_seen);
            """
        )


def run_ss() -> str:
    try:
        completed = subprocess.run(
            ["ss", "-H", "-tulpn"],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("`ss` command not found. Install iproute2 package.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("`ss -tulpn` timed out.") from exc

    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "`ss -tulpn` failed.")
    return completed.stdout


def split_address_port(value: str) -> tuple[str, int] | None:
    value = value.strip()
    if value.startswith("["):
        match = re.match(r"^\[(?P<addr>.*)]:(?P<port>\d+)$", value)
        if not match:
            return None
        return match.group("addr"), int(match.group("port"))
    if ":" not in value:
        return None
    addr, port_raw = value.rsplit(":", 1)
    if not port_raw.isdigit():
        return None
    return addr, int(port_raw)


def parse_ss_output(output: str) -> list[PortEntry]:
    entries: list[PortEntry] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = re.split(r"\s+", line, maxsplit=6)
        if len(parts) < 6:
            continue
        proto = parts[0]
        state = parts[1]
        local = parts[4]
        peer = parts[5]
        process = parts[6] if len(parts) >= 7 else ""
        parsed = split_address_port(local)
        if not parsed:
            continue
        local_address, port = parsed
        entries.append(
            PortEntry(
                proto=proto,
                state=state,
                local_address=normalize_address(local_address),
                port=port,
                peer=peer,
                process=process,
                raw=line,
            )
        )
    return sorted(entries, key=lambda e: (e.port, e.proto, e.local_address))


def normalize_address(addr: str) -> str:
    if addr == "*":
        return "*"
    if addr == "::":
        return "::"
    return addr


def classify_scope(addr: str) -> str:
    if addr in {"0.0.0.0", "*", "::"}:
        return "Public bind"
    if addr in {"127.0.0.1", "::1", "localhost"}:
        return "Loopback"
    if addr.startswith("100."):
        return "Tailscale/CGNAT"
    if addr.startswith("10.") or addr.startswith("192.168."):
        return "LAN/private"
    if re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.", addr):
        return "LAN/private"
    return "Specific IP"


def process_hint(process: str) -> str:
    if not process:
        return ""
    match = re.search(r'\("([^"]+)"', process)
    if match:
        return match.group(1)
    return process[:80]


def sync_scan(entries: Iterable[PortEntry]) -> None:
    seen_at = now_iso()
    with get_db() as db:
        for entry in entries:
            row = db.execute("SELECT key FROM port_metadata WHERE key = ?", (entry.key,)).fetchone()
            if row:
                db.execute(
                    """
                    UPDATE port_metadata
                    SET last_seen = ?, last_process = ?, last_raw = ?
                    WHERE key = ?
                    """,
                    (seen_at, entry.process, entry.raw, entry.key),
                )
            else:
                db.execute(
                    """
                    INSERT INTO port_metadata
                    (key, proto, local_address, port, name, category, owner, exposure, notes,
                     ignored, first_seen, last_seen, last_process, last_raw)
                    VALUES (?, ?, ?, ?, '', '', '', '', '', 0, ?, ?, ?, ?)
                    """,
                    (
                        entry.key,
                        entry.proto,
                        entry.local_address,
                        entry.port,
                        seen_at,
                        seen_at,
                        entry.process,
                        entry.raw,
                    ),
                )


def sort_rows(rows: list[sqlite3.Row], sort_by: str, direction: str) -> list[sqlite3.Row]:
    reverse = direction == "desc"

    def text(value: object) -> str:
        return str(value or "").casefold()

    def name_score(row: sqlite3.Row) -> tuple[int, str, int, str, str]:
        # Unnamed rows sort after named rows in ASC mode
        name = str(row["name"] or "").casefold()
        unnamed = 1 if not name else 0
        return (unnamed, name, int(row["port"]), text(row["proto"]), text(row["local_address"]))

    def metadata_score(row: sqlite3.Row) -> tuple[str, str, str, str, int, str, str]:
        return (
            text(row["category"]),
            text(row["owner"]),
            text(row["exposure"]),
            text(row["name"]),
            int(row["port"]),
            text(row["proto"]),
            text(row["local_address"]),
        )

    sorters = {
        "port":     lambda row: (int(row["port"]), text(row["proto"]), text(row["local_address"])),
        "bind":     lambda row: (text(row["local_address"]), int(row["port"]), text(row["proto"])),
        "name":     name_score,
        "metadata": metadata_score,
    }
    sorter = sorters.get(sort_by, sorters["port"])
    return sorted(
        rows,
        key=lambda row: (int(row["ignored"]), sorter(row)),
        reverse=reverse,
    )


def scan_and_sync(sort_by: str = "port", direction: str = "asc") -> tuple[list[sqlite3.Row], str | None]:
    error: str | None = None
    try:
        entries = parse_ss_output(run_ss())
        sync_scan(entries)
    except Exception as exc:
        error = str(exc)
    with get_db() as db:
        rows = db.execute("SELECT * FROM port_metadata").fetchall()
    return sort_rows(list(rows), sort_by, direction), error


# ── Background auto-rescan ──────────────────────────────────────────────────

def _background_rescan_loop() -> None:
    """Runs in a daemon thread; rescans every RESCAN_INTERVAL_SECONDS."""
    while True:
        time.sleep(RESCAN_INTERVAL_SECONDS)
        try:
            scan_and_sync()
        except Exception:
            pass  # errors are non-fatal in background


def start_background_rescan() -> None:
    t = threading.Thread(target=_background_rescan_loop, daemon=True)
    t.start()


# ── Template filters ────────────────────────────────────────────────────────

@app.template_filter("scope")
def scope_filter(addr: str) -> str:
    return classify_scope(addr)


@app.template_filter("hint")
def hint_filter(process: str) -> str:
    return process_hint(process)


@app.template_filter("fmtdate")
def fmtdate_filter(iso_str: str) -> str:
    return format_date(iso_str)


# ── Routes ──────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    sort_by = request.args.get("sort", "port")
    direction = request.args.get("dir", "asc")
    if sort_by not in {"port", "bind", "name", "metadata"}:
        sort_by = "port"
    if direction not in {"asc", "desc"}:
        direction = "asc"

    rows, error = scan_and_sync(sort_by, direction)
    unnamed_count = sum(1 for row in rows if not row["name"] and not row["ignored"])
    public_count = sum(1 for row in rows if classify_scope(row["local_address"]) == "Public bind" and not row["ignored"])
    ignored_count = sum(1 for row in rows if row["ignored"])

    rows_data = []
    for row in rows:
        d = dict(row)
        d["first_seen_fmt"] = format_date(d["first_seen"])
        d["last_seen_fmt"] = format_date(d["last_seen"])
        d["scope"] = classify_scope(d["local_address"])
        d["process_hint"] = process_hint(d["last_process"])
        rows_data.append(d)

    return render_template_string(
        TEMPLATE,
        rows=rows_data,
        error=error,
        unnamed_count=unnamed_count,
        public_count=public_count,
        ignored_count=ignored_count,
        sort_by=sort_by,
        direction=direction,
        rescan_interval_h=RESCAN_INTERVAL_SECONDS // 3600,
    )


@app.post("/update/<path:key>")
def update(key: str):
    with get_db() as db:
        db.execute(
            """
            UPDATE port_metadata
            SET name = ?, category = ?, owner = ?, exposure = ?, notes = ?, ignored = ?
            WHERE key = ?
            """,
            (
                request.form.get("name", "").strip(),
                request.form.get("category", "").strip(),
                request.form.get("owner", "").strip(),
                request.form.get("exposure", "").strip(),
                request.form.get("notes", "").strip(),
                1 if request.form.get("ignored") == "on" else 0,
                key,
            ),
        )
    return redirect(url_for("index"))


@app.post("/update-batch")
def update_batch():
    """Save multiple rows at once. Expects JSON: [{key, name, category, owner, exposure, notes, ignored}, ...]"""
    from flask import jsonify
    payload = request.get_json(force=True, silent=True)
    if not payload or not isinstance(payload, list):
        return jsonify({"error": "invalid payload"}), 400
    with get_db() as db:
        for item in payload:
            key = item.get("key", "").strip()
            if not key:
                continue
            db.execute(
                """
                UPDATE port_metadata
                SET name = ?, category = ?, owner = ?, exposure = ?, notes = ?, ignored = ?
                WHERE key = ?
                """,
                (
                    item.get("name", "").strip(),
                    item.get("category", "").strip(),
                    item.get("owner", "").strip(),
                    item.get("exposure", "").strip(),
                    item.get("notes", "").strip(),
                    1 if item.get("ignored") else 0,
                    key,
                ),
            )
    return jsonify({"saved": len(payload)})


@app.post("/rescan")
def rescan():
    sort_by = request.form.get("sort", "port")
    direction = request.form.get("dir", "asc")
    scan_and_sync(sort_by, direction)
    return redirect(url_for("index", sort=sort_by, dir=direction))


# ── HTML Template ───────────────────────────────────────────────────────────

TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Port Inventory</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMzIgMzIiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNyIgZmlsbD0iIzBkMTUyMSIvPgogIDxyZWN0IHg9IjUiIHk9IjkiIHdpZHRoPSIyMiIgaGVpZ2h0PSIzIiByeD0iMS41IiBmaWxsPSIjNGZhY2RlIi8+CiAgPHJlY3QgeD0iNSIgeT0iMTQuNSIgd2lkdGg9IjE0IiBoZWlnaHQ9IjMiIHJ4PSIxLjUiIGZpbGw9IiMzZGQ2OGMiLz4KICA8cmVjdCB4PSI1IiB5PSIyMCIgd2lkdGg9IjE4IiBoZWlnaHQ9IjMiIHJ4PSIxLjUiIGZpbGw9IiM0ZmFjZGUiIG9wYWNpdHk9IjAuNSIvPgogIDxjaXJjbGUgY3g9IjI0IiBjeT0iMjMiIHI9IjUiIGZpbGw9IiMwZDE1MjEiIHN0cm9rZT0iIzRmYWNkZSIgc3Ryb2tlLXdpZHRoPSIxLjUiLz4KICA8Y2lyY2xlIGN4PSIyNCIgY3k9IjIzIiByPSIyLjUiIGZpbGw9IiM0ZmFjZGUiLz4KPC9zdmc+">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      color-scheme: dark;
      --bg:       #080d16;
      --surface:  #0d1521;
      --panel:    #111e2e;
      --border:   #1e3048;
      --border2:  #243a55;
      --text:     #cdd6e8;
      --muted:    #5c7a9e;
      --accent:   #4facde;
      --accent2:  #1e88c8;
      --danger:   #f06880;
      --warn:     #f5a623;
      --ok:       #3dd68c;
      --purple:   #9b6dff;
      --mono: 'JetBrains Mono', monospace;
      --sans: 'DM Sans', sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--sans);
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      font-size: 14px;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

    /* ── Header ── */
    header {
      padding: 20px 28px;
      border-bottom: 1px solid var(--border);
      background: rgba(8,13,22,.9);
      position: sticky; top: 0; z-index: 50;
      backdrop-filter: blur(14px);
      display: flex; flex-wrap: wrap; gap: 16px; align-items: center; justify-content: space-between;
    }
    .header-left h1 {
      font-family: var(--mono);
      font-size: 18px; font-weight: 800; letter-spacing: -.3px;
      color: #fff;
      display: flex; align-items: center; gap: 8px;
    }
    .header-left h1 .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--ok);
      box-shadow: 0 0 8px var(--ok);
      animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }
    .header-left .sub { font-size: 12px; color: var(--muted); margin-top: 3px; font-family: var(--mono); }
    .stats { display: flex; gap: 10px; flex-wrap: wrap; }
    .stat {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 8px 14px; min-width: 90px; text-align: center;
    }
    .stat strong { font-family: var(--mono); font-size: 20px; font-weight: 800; display: block; color: #fff; line-height: 1.1; }
    .stat .label { font-size: 11px; color: var(--muted); margin-top: 2px; }
    .stat.warn strong { color: var(--warn); }
    .stat.danger strong { color: var(--danger); }
    .stat.purple strong { color: var(--purple); }

    /* ── Toolbar ── */
    .toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; padding: 16px 28px 0; }
    .search-wrap { position: relative; flex: 1; min-width: 200px; max-width: 360px; }
    .search-wrap svg { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); color: var(--muted); pointer-events: none; }
    #search {
      width: 100%; background: var(--surface); border: 1px solid var(--border2);
      border-radius: 10px; color: var(--text); font-family: var(--mono); font-size: 13px;
      padding: 9px 12px 9px 34px; outline: none; transition: border-color .15s;
    }
    #search:focus { border-color: var(--accent); }
    #search::placeholder { color: var(--muted); }

    .btn {
      display: inline-flex; align-items: center; gap: 6px;
      font-family: var(--sans); font-size: 13px; font-weight: 600;
      border: 1px solid var(--border2); border-radius: 10px;
      padding: 8px 14px; cursor: pointer; transition: all .15s; white-space: nowrap;
    }
    .btn-primary { background: var(--accent); color: #001828; border-color: var(--accent); }
    .btn-primary:hover { background: #6cc5ee; }
    .btn-ghost { background: var(--surface); color: var(--text); }
    .btn-ghost:hover { background: var(--panel); border-color: var(--accent); color: var(--accent); }
    .btn-ghost.active { background: rgba(155,109,255,.15); border-color: var(--purple); color: var(--purple); }
    .btn svg { flex-shrink: 0; }

    /* ── Sort bar ── */
    .sort-bar { padding: 12px 28px 0; display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
    .sort-label { font-size: 11px; color: var(--muted); font-family: var(--mono); margin-right: 4px; }
    .sort-link {
      font-size: 12px; font-weight: 600; font-family: var(--mono); color: var(--muted);
      background: var(--surface); border: 1px solid var(--border); border-radius: 7px;
      padding: 5px 10px; text-decoration: none;
      display: inline-flex; align-items: center; gap: 4px; transition: all .15s;
    }
    .sort-link:hover { color: var(--text); border-color: var(--border2); }
    .sort-link.active { color: var(--accent); border-color: var(--accent2); background: rgba(79,172,222,.08); }

    /* ── Main ── */
    main { padding: 18px 28px 40px; }
    .error {
      border: 1px solid rgba(240,104,128,.35); background: rgba(240,104,128,.08);
      color: #fca5b4; padding: 12px 16px; border-radius: 12px; margin-bottom: 14px;
      font-family: var(--mono); font-size: 13px;
    }

    /* ── Table ── */
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: separate; border-spacing: 0 6px; }
    thead th {
      color: var(--muted); font-size: 11px; font-weight: 600;
      font-family: var(--mono); text-transform: uppercase; letter-spacing: .8px;
      padding: 4px 12px; text-align: left;
    }
    tbody tr { transition: opacity .2s; }
    tbody tr td {
      background: var(--panel); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border);
      padding: 14px 12px; vertical-align: top;
    }
    tbody tr td:first-child { border-left: 1px solid var(--border); border-radius: 12px 0 0 12px; }
    tbody tr td:last-child  { border-right: 1px solid var(--border); border-radius: 0 12px 12px 0; }
    tbody tr:hover td { background: #152030; border-color: var(--border2); }
    tbody tr.ignored-row { opacity: .35; }

    /* ── Port cell ── */
    .port-num { font-family: var(--mono); font-size: 26px; font-weight: 800; color: var(--accent); letter-spacing: -.5px; line-height: 1; }
    .proto-badge {
      display: inline-block; font-family: var(--mono); font-size: 10px; font-weight: 600;
      color: var(--muted); background: var(--surface); border: 1px solid var(--border);
      border-radius: 5px; padding: 2px 6px; margin-top: 5px; text-transform: uppercase;
    }

    /* ── Scope badges ── */
    .badge {
      display: inline-flex; align-items: center; gap: 5px; border-radius: 99px; padding: 4px 10px;
      font-size: 11px; font-weight: 700; font-family: var(--mono); border: 1px solid var(--border); color: var(--muted);
    }
    .badge::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; opacity: .6; }
    .badge.public    { color: var(--danger); border-color: rgba(240,104,128,.35); background: rgba(240,104,128,.07); }
    .badge.loopback  { color: var(--ok);     border-color: rgba(61,214,140,.3);   background: rgba(61,214,140,.07); }
    .badge.tailscale { color: var(--purple); border-color: rgba(155,109,255,.3);  background: rgba(155,109,255,.07); }
    .badge.lan       { color: var(--accent); border-color: rgba(79,172,222,.3);   background: rgba(79,172,222,.07); }

    /* ── Name cell ── */
    .port-name    { font-size: 15px; font-weight: 600; color: #fff; }
    .port-unnamed { font-family: var(--mono); font-size: 13px; font-weight: 700; color: var(--warn); }
    .process-hint { font-family: var(--mono); font-size: 11px; color: var(--muted); margin-top: 5px; }
    .addr-mono    { font-family: var(--mono); font-size: 12px; color: var(--text); }

    /* ── Meta cell ── */
    .meta-row  { display: flex; gap: 6px; align-items: baseline; font-size: 12px; margin-top: 3px; }
    .meta-key  { color: var(--muted); font-family: var(--mono); font-size: 11px; }
    .meta-val  { color: var(--text); font-weight: 500; }
    .meta-date { font-family: var(--mono); font-size: 11px; color: var(--muted); }

    /* ── Form ── */
    .edit-form {
      display: grid; grid-template-columns: repeat(2, minmax(120px, 1fr)); gap: 7px; min-width: 380px;
    }
    .edit-form input, .edit-form select, .edit-form textarea {
      width: 100%; background: #0a111d; color: var(--text); border: 1px solid var(--border2);
      border-radius: 8px; padding: 7px 10px; font-family: var(--sans); font-size: 12px;
      outline: none; transition: border-color .15s;
    }
    .edit-form input:focus, .edit-form select:focus, .edit-form textarea:focus { border-color: var(--accent); }
    .edit-form input::placeholder, .edit-form textarea::placeholder { color: var(--muted); }
    .edit-form textarea { grid-column: 1 / -1; min-height: 52px; resize: vertical; }
    .form-actions { grid-column: 1 / -1; display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .ignore-label { display: flex; align-items: center; gap: 7px; font-size: 12px; font-weight: 600; color: var(--muted); cursor: pointer; }
    .ignore-label input[type=checkbox] { accent-color: var(--purple); width: 14px; height: 14px; }

    /* ── Proto filters ── */
    .proto-filters { display: flex; gap: 4px; }
    .proto-filters .btn { padding: 7px 12px; font-family: var(--mono); font-size: 12px; font-weight: 700; letter-spacing: .4px; }
    .proto-filters .btn.active { background: rgba(79,172,222,.12); border-color: var(--accent2); color: var(--accent); }

    /* ── No results ── */
    #no-results { display: none; text-align: center; padding: 60px 0; color: var(--muted); font-family: var(--mono); font-size: 14px; }

    /* ── Responsive ── */
    @media (max-width: 900px) {
      header { padding: 14px 16px; }
      .toolbar, .sort-bar, main { padding-left: 16px; padding-right: 16px; }
      .table-wrap { overflow-x: auto; }
      .edit-form { min-width: 280px; grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>

<header>
  <div class="header-left">
    <h1><span class="dot"></span> Port Inventory</h1>
    <div class="sub">ss -tulpn · auto-rescan every {{ rescan_interval_h }}h</div>
  </div>
  <div class="stats">
    <div class="stat"><strong>{{ rows|length }}</strong><div class="label">Tracked</div></div>
    <div class="stat warn"><strong>{{ unnamed_count }}</strong><div class="label">Unnamed</div></div>
    <div class="stat danger"><strong>{{ public_count }}</strong><div class="label">Public</div></div>
    <div class="stat purple"><strong>{{ ignored_count }}</strong><div class="label">Ignored</div></div>
  </div>
</header>

<div class="toolbar">
  <div class="search-wrap">
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
      <circle cx="6.5" cy="6.5" r="5" stroke="currentColor" stroke-width="1.5"/>
      <path d="M10 10L14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    </svg>
    <input id="search" type="search" placeholder="Search ports, names, processes…" autocomplete="off">
  </div>

  <div class="proto-filters">
    <button class="btn btn-ghost active" id="filter-all" onclick="setProtoFilter('all')">All</button>
    <button class="btn btn-ghost"        id="filter-tcp" onclick="setProtoFilter('tcp')">TCP</button>
    <button class="btn btn-ghost"        id="filter-udp" onclick="setProtoFilter('udp')">UDP</button>
  </div>

  <button id="toggle-ignored" class="btn btn-ghost" onclick="toggleIgnored()">
    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 3C4 3 1 8 1 8s3 5 7 5 7-5 7-5-3-5-7-5zm0 8a3 3 0 1 1 0-6 3 3 0 0 1 0 6z"/><circle cx="8" cy="8" r="1.5"/></svg>
    Show Ignored
    <span id="ignored-badge" style="background:rgba(155,109,255,.2);color:var(--purple);border-radius:99px;padding:1px 7px;font-size:11px;font-weight:700;">{{ ignored_count }}</span>
  </button>

  <button id="save-all-btn" class="btn btn-primary" onclick="saveAll()" disabled style="opacity:.4;">
    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M2 2h9l3 3v9a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1zm7 0v4H4V2m5 9a2 2 0 1 1-4 0 2 2 0 0 1 4 0z"/></svg>
    Save All
    <span id="dirty-badge" style="display:none;background:rgba(0,0,0,.3);border-radius:99px;padding:1px 7px;font-size:11px;font-weight:700;margin-left:2px;">0</span>
  </button>

  <form action="/rescan" method="post" style="display:contents">
    <input type="hidden" name="sort" value="{{ sort_by }}">
    <input type="hidden" name="dir" value="{{ direction }}">
    <button type="submit" class="btn btn-ghost">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M13.65 2.35A8 8 0 1 0 15 8h-2a6 6 0 1 1-1.05-3.35L10 7h5V2l-1.35.35z"/></svg>
      Rescan
    </button>
  </form>
</div>

<div class="sort-bar">
  <span class="sort-label">Sort:</span>
  {% macro sort_link(label, key) -%}
    {% set next_dir = 'desc' if sort_by == key and direction == 'asc' else 'asc' %}
    <a class="sort-link {{ 'active' if sort_by == key else '' }}" href="{{ url_for('index', sort=key, dir=next_dir) }}">
      {{ label }}{% if sort_by == key %} {{ '▲' if direction == 'asc' else '▼' }}{% endif %}
    </a>
  {%- endmacro %}
  {{ sort_link('Port', 'port') }}
  {{ sort_link('Bind address', 'bind') }}
  {{ sort_link('Service name', 'name') }}
  {{ sort_link('Metadata', 'metadata') }}
</div>

<main>
  {% if error %}<div class="error">⚠ {{ error }}</div>{% endif %}

  <div class="table-wrap">
    <table id="port-table">
      <thead>
        <tr>
          <th>Port</th>
          <th>Bind / Scope</th>
          <th>Service</th>
          <th>Metadata</th>
          <th>Edit</th>
        </tr>
      </thead>
      <tbody>
        {% for row in rows %}
        {% set scope = row.scope %}
        <tr
          class="{{ 'ignored-row' if row.ignored else '' }}"
          data-ignored="{{ '1' if row.ignored else '0' }}"
          data-proto="{{ row.proto | lower }}"
          data-search="{{ (row.port | string + ' ' + row.proto + ' ' + row.local_address + ' ' + (row.name or '') + ' ' + (row.category or '') + ' ' + (row.owner or '') + ' ' + (row.process_hint or '') + ' ' + (row.notes or '')) | lower }}"
        >
          <td>
            <div class="port-num">{{ row.port }}</div>
            <span class="proto-badge">{{ row.proto }}</span>
          </td>
          <td>
            <div class="addr-mono" style="margin-bottom:8px;">{{ row.local_address }}</div>
            <span class="badge
              {{ 'public'    if scope == 'Public bind'
                 else 'loopback'  if scope == 'Loopback'
                 else 'tailscale' if scope == 'Tailscale/CGNAT'
                 else 'lan'       if scope == 'LAN/private'
                 else '' }}">{{ scope }}</span>
          </td>
          <td>
            {% if row.name %}<div class="port-name">{{ row.name }}</div>
            {% else %}<div class="port-unnamed">Unnamed</div>{% endif %}
            <div class="process-hint">{{ row.process_hint or 'Process hidden / unknown' }}</div>
          </td>
          <td>
            <div class="meta-row"><span class="meta-key">category</span><span class="meta-val">{{ row.category or '—' }}</span></div>
            <div class="meta-row"><span class="meta-key">owner</span><span class="meta-val">{{ row.owner or '—' }}</span></div>
            <div class="meta-row"><span class="meta-key">exposure</span><span class="meta-val">{{ row.exposure or '—' }}</span></div>
            <div class="meta-row" style="margin-top:8px;"><span class="meta-key">first</span><span class="meta-date">{{ row.first_seen_fmt }}</span></div>
            <div class="meta-row"><span class="meta-key">last</span><span class="meta-date">{{ row.last_seen_fmt }}</span></div>
            {% if row.notes %}<div style="margin-top:8px;font-size:12px;color:var(--text);">{{ row.notes }}</div>{% endif %}
          </td>
          <td>
            <form class="edit-form" method="post" action="{{ url_for('update', key=row.key) }}" data-key="{{ row.key }}">
              <input name="name" value="{{ row.name }}" placeholder="Name (e.g. Nginx)">
              <input name="category" value="{{ row.category }}" placeholder="Category (e.g. Web)">
              <input name="owner" value="{{ row.owner }}" placeholder="Owner (e.g. Docker)">
              <select name="exposure">
                {% for val in ['', 'Public', 'LAN only', 'Loopback only', 'Tunnel only', 'Unknown'] %}
                  <option value="{{ val }}" {% if row.exposure == val %}selected{% endif %}>{{ val or 'Exposure…' }}</option>
                {% endfor %}
              </select>
              <textarea name="notes" placeholder="Notes…">{{ row.notes }}</textarea>
              <div class="form-actions">
                <label class="ignore-label">
                  <input type="checkbox" name="ignored" {% if row.ignored %}checked{% endif %}>
                  Ignore
                </label>
                <button type="submit" class="btn btn-primary row-save-btn" style="padding:7px 14px;font-size:12px;">Save</button>
              </div>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <div id="no-results">No ports match your search.</div>
  </div>
</main>

<script>
  var showIgnored = false;
  var protoFilter = 'all';
  var dirtyKeys = new Set();

  // ── Helpers ───────────────────────────────────────────────────────────────
  function findFormByKey(key) {
    var forms = document.querySelectorAll('.edit-form');
    for (var i = 0; i < forms.length; i++) {
      if (forms[i].dataset.key === key) return forms[i];
    }
    return null;
  }

  function getSnapshot(form) {
    var fd = new FormData(form);
    return JSON.stringify({
      name:     fd.get('name') || '',
      category: fd.get('category') || '',
      owner:    fd.get('owner') || '',
      exposure: fd.get('exposure') || '',
      notes:    fd.get('notes') || '',
      ignored:  form.querySelector('input[name="ignored"]').checked,
    });
  }

  // ── Dirty tracking ────────────────────────────────────────────────────────
  function initDirtyTracking() {
    document.querySelectorAll('.edit-form').forEach(function(form) {
      form._snapshot = getSnapshot(form);
      form.querySelectorAll('input,select,textarea').forEach(function(field) {
        field.addEventListener('input',  function() { markDirty(form); });
        field.addEventListener('change', function() { markDirty(form); });
      });
    });
  }

  function markDirty(form) {
    var key = form.dataset.key;
    var isDirty = getSnapshot(form) !== form._snapshot;
    var saveBtn = form.querySelector('.row-save-btn');
    if (isDirty) {
      dirtyKeys.add(key);
      if (saveBtn) { saveBtn.textContent = 'Save *'; saveBtn.style.background = 'var(--warn)'; saveBtn.style.color = '#1a0e00'; saveBtn.style.borderColor = 'var(--warn)'; }
    } else {
      dirtyKeys.delete(key);
      if (saveBtn) { saveBtn.textContent = 'Save'; saveBtn.style.background = ''; saveBtn.style.color = ''; saveBtn.style.borderColor = ''; }
    }
    updateSaveAllBtn();
  }

  function updateSaveAllBtn() {
    var btn   = document.getElementById('save-all-btn');
    var badge = document.getElementById('dirty-badge');
    var count = dirtyKeys.size;
    if (count > 0) {
      btn.disabled = false; btn.style.opacity = '1';
      badge.style.display = 'inline'; badge.textContent = count;
    } else {
      btn.disabled = true; btn.style.opacity = '.4';
      badge.style.display = 'none';
    }
  }

  // ── Save All ──────────────────────────────────────────────────────────────
  function saveAll() {
    if (dirtyKeys.size === 0) return;
    var btn = document.getElementById('save-all-btn');
    btn.disabled = true; btn.style.opacity = '.6';

    var payload = [];
    dirtyKeys.forEach(function(key) {
      var form = findFormByKey(key);
      if (!form) return;
      var fd = new FormData(form);
      payload.push({
        key:      key,
        name:     (fd.get('name') || '').trim(),
        category: (fd.get('category') || '').trim(),
        owner:    (fd.get('owner') || '').trim(),
        exposure: (fd.get('exposure') || '').trim(),
        notes:    (fd.get('notes') || '').trim(),
        ignored:  form.querySelector('input[name="ignored"]').checked,
      });
    });

    fetch('/update-batch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.saved !== undefined) {
        dirtyKeys.forEach(function(key) {
          var form = findFormByKey(key);
          if (!form) return;
          form._snapshot = getSnapshot(form);
          var saveBtn = form.querySelector('.row-save-btn');
          if (saveBtn) { saveBtn.textContent = 'Save'; saveBtn.style.background = ''; saveBtn.style.color = ''; saveBtn.style.borderColor = ''; }
        });
        dirtyKeys.clear();
        updateSaveAllBtn();
        flashSaved(btn);
      }
    })
    .catch(function() {
      btn.disabled = false; btn.style.opacity = '1';
      alert('Save failed — check console.');
    });
  }

  function flashSaved(btn) {
    var orig = btn.innerHTML;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M2 8l4 4 8-8" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round"/></svg> Saved!';
    btn.style.opacity = '1';
    setTimeout(function() { btn.innerHTML = orig; updateSaveAllBtn(); }, 1800);
  }

  // ── Filters ───────────────────────────────────────────────────────────────
  function setProtoFilter(proto) {
    protoFilter = proto;
    ['all','tcp','udp'].forEach(function(p) {
      document.getElementById('filter-' + p).classList.toggle('active', p === proto);
    });
    applyFilter();
  }

  function toggleIgnored() {
    showIgnored = !showIgnored;
    var btn = document.getElementById('toggle-ignored');
    if (showIgnored) {
      btn.classList.add('active');
      btn.childNodes[2].nodeValue = ' Hide Ignored ';
    } else {
      btn.classList.remove('active');
      btn.childNodes[2].nodeValue = ' Show Ignored ';
    }
    applyFilter();
  }

  function applyFilter() {
    var q = document.getElementById('search').value.toLowerCase().trim();
    var rows = document.querySelectorAll('#port-table tbody tr');
    var visible = 0;
    rows.forEach(function(row) {
      var ignored = row.dataset.ignored === '1';
      var proto   = row.dataset.proto || '';
      if (ignored && !showIgnored)                                          { row.style.display = 'none'; return; }
      if (protoFilter !== 'all' && proto !== protoFilter)                   { row.style.display = 'none'; return; }
      if (q && (row.dataset.search || '').indexOf(q) === -1)               { row.style.display = 'none'; return; }
      row.style.display = '';
      visible++;
    });
    document.getElementById('no-results').style.display =
      (visible === 0 && (q || protoFilter !== 'all')) ? 'block' : 'none';
  }

  document.getElementById('search').addEventListener('input', applyFilter);
  applyFilter();
  initDirtyTracking();
</script>

</body>
</html>
"""


if __name__ == "__main__":
    init_db()
    start_background_rescan()
    app.run(host=HOST, port=PORT)