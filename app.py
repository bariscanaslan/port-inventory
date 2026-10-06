#!/usr/bin/env python3
"""
Port Inventory - self-hosted UI for classifying `ss -tulpn` output.

Answers one question: "which application is behind this port?"

Features:
- Reads host listening ports via `ss -H -tulpn`
- Groups binds of the same port/proto into one row (0.0.0.0 + :: = one service)
- Well-known ports are auto-named on first sight
- Duplicate binds of the same port/proto are marked auto_ignored (wildcard bind wins),
  separately from the user's own ignore flag
- TCP ports serving a web page on localhost get an "open in new tab" link
- Inline rename, category popover, details drawer, bulk actions, undo
- JSON API (/api/...) + client-side rendering, filtering and sorting
- Stores metadata in SQLite, keeps first_seen / last_seen timestamps
- Auto-rescan via background thread
- Light / dark theme (persisted in localStorage)

Recommended path:
  /DATA/AppData/port-inventory/app.py

Run:
  python3 -m venv venv
  ./venv/bin/pip install flask
  sudo ./venv/bin/python app.py

For a systemd service, run as root if you want process names/PIDs from `ss -p`.
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from typing import Any, Iterable, Iterator

from flask import Flask, Response, jsonify, request
from werkzeug.exceptions import HTTPException

APP_DIR = Path(os.environ.get("PORT_INVENTORY_DIR", "/DATA/AppData/port-inventory"))
DB_PATH = Path(os.environ.get("PORT_INVENTORY_DB", APP_DIR / "port_inventory.sqlite3"))
HOST = os.environ.get("PORT_INVENTORY_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT_INVENTORY_PORT", "8710"))

RESCAN_INTERVAL_SECONDS = int(os.environ.get("PORT_INVENTORY_RESCAN_INTERVAL", str(24 * 3600)))  # default: 24h
# Opening the UI triggers a background rescan when the last scan is older than this.
STALE_SECONDS = int(os.environ.get("PORT_INVENTORY_STALE_SECONDS", "300"))
# Every scan sends `GET /` to each listening TCP port on localhost; 0 turns this off.
HTTP_PROBE_TIMEOUT = float(os.environ.get("PORT_INVENTORY_HTTP_PROBE_TIMEOUT", "1.5"))
HTTP_PROBE_HOST = "localhost"
HTTP_PROBE_WORKERS = 32

NEW_WINDOW = timedelta(hours=24)

MAX_NAME_LEN = 100
MAX_CATEGORY_LEN = 48
MAX_NOTES_LEN = 4000
MAX_BULK_KEYS = 2000

EDITABLE_FIELDS = ("name", "category", "notes", "ignored")

app = Flask(__name__)

CATEGORIES: list[str] = [
    "Web",
    "Database",
    "Proxy / Load Balancer",
    "Message Queue",
    "Monitoring",
    "VPN / Tunnel",
    "Remote Access",
    "Mail",
    "File Transfer",
    "DNS",
    "DHCP",
    "Container / Orchestration",
    "Development",
    "Security",
    "Media",
    "IoT",
    "System",
    "Other",
]

WELL_KNOWN_PORTS: dict[int, dict[str, str]] = {
    20:    {"name": "FTP Data",               "category": "File Transfer"},
    21:    {"name": "FTP",                    "category": "File Transfer"},
    22:    {"name": "SSH",                    "category": "Remote Access"},
    23:    {"name": "Telnet",                 "category": "Remote Access"},
    25:    {"name": "SMTP",                   "category": "Mail"},
    53:    {"name": "DNS",                    "category": "DNS"},
    67:    {"name": "DHCP Server",            "category": "DHCP"},
    68:    {"name": "DHCP Client",            "category": "DHCP"},
    80:    {"name": "HTTP",                   "category": "Web"},
    110:   {"name": "POP3",                   "category": "Mail"},
    111:   {"name": "RPCBind",                "category": "System"},
    123:   {"name": "NTP",                    "category": "System"},
    143:   {"name": "IMAP",                   "category": "Mail"},
    443:   {"name": "HTTPS",                  "category": "Web"},
    445:   {"name": "SMB",                    "category": "File Transfer"},
    465:   {"name": "SMTPS",                  "category": "Mail"},
    587:   {"name": "SMTP Submission",        "category": "Mail"},
    631:   {"name": "CUPS",                   "category": "System"},
    993:   {"name": "IMAPS",                  "category": "Mail"},
    995:   {"name": "POP3S",                  "category": "Mail"},
    1194:  {"name": "OpenVPN",                "category": "VPN / Tunnel"},
    1433:  {"name": "MSSQL",                  "category": "Database"},
    1883:  {"name": "MQTT",                   "category": "Message Queue"},
    2375:  {"name": "Docker API",             "category": "Container / Orchestration"},
    2376:  {"name": "Docker API (TLS)",       "category": "Container / Orchestration"},
    3000:  {"name": "Dev Server",             "category": "Development"},
    3306:  {"name": "MySQL",                  "category": "Database"},
    3389:  {"name": "RDP",                    "category": "Remote Access"},
    5000:  {"name": "Dev Server",             "category": "Development"},
    5353:  {"name": "mDNS",                   "category": "DNS"},
    5432:  {"name": "PostgreSQL",             "category": "Database"},
    5900:  {"name": "VNC",                    "category": "Remote Access"},
    6379:  {"name": "Redis",                  "category": "Database"},
    8080:  {"name": "HTTP Alt",               "category": "Web"},
    8443:  {"name": "HTTPS Alt",              "category": "Web"},
    8888:  {"name": "Jupyter",                "category": "Development"},
    9000:  {"name": "Portainer / PHP-FPM",    "category": "Container / Orchestration"},
    9090:  {"name": "Prometheus",             "category": "Monitoring"},
    9100:  {"name": "Node Exporter",          "category": "Monitoring"},
    27017: {"name": "MongoDB",                "category": "Database"},
    41641: {"name": "Tailscale",              "category": "VPN / Tunnel"},
    51820: {"name": "WireGuard",              "category": "VPN / Tunnel"},
}

# Columns removed from the schema; dropped on startup if still present.
LEGACY_COLUMNS = ("owner", "exposure")

PORT_METADATA_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
    key TEXT PRIMARY KEY,
    proto TEXT NOT NULL,
    local_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    ignored INTEGER NOT NULL DEFAULT 0,
    auto_ignored INTEGER NOT NULL DEFAULT 0,
    http INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_process TEXT NOT NULL DEFAULT '',
    last_raw TEXT NOT NULL DEFAULT ''
)
"""

PORT_METADATA_COLUMNS = (
    "key", "proto", "local_address", "port", "name", "category", "notes",
    "ignored", "auto_ignored", "http", "first_seen", "last_seen", "last_process", "last_raw",
)

# Scope ids, most exposed first (also the client's "Binds" sort order).
SCOPE_ORDER = ("public", "tailscale", "lan", "specific", "loopback")
SCOPE_LABELS = {
    "public": "Public",
    "tailscale": "Tailscale",
    "lan": "LAN",
    "specific": "Specific IP",
    "loopback": "Loopback",
}
TAILSCALE_NETS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
)

PROCESS_RE = re.compile(r'\("([^"]+)",pid=(\d+)')

_scan_lock = threading.Lock()


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


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


def now_iso() -> str:
    # Millisecond precision: two scans in the same second must still get distinct
    # timestamps, since "online" means last_seen == the latest scan's timestamp.
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_iso(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def make_key(proto: str, local_address: str, port: int) -> str:
    return f"{proto.lower()}|{local_address}|{port}"


def auto_name_for(port: int) -> str:
    return WELL_KNOWN_PORTS.get(int(port), {}).get("name", "")


def user_name_of(row: sqlite3.Row) -> str:
    """The row's name if the user typed it; '' if empty or the auto-filled name."""
    name = row["name"]
    return name if name and name != auto_name_for(row["port"]) else ""


# ── Database ────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    """One transaction: commits on success, rolls back on error, always closes."""
    conn = get_db()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}


def drop_legacy_columns(db: sqlite3.Connection) -> None:
    """Remove owner/exposure. Uses ALTER TABLE DROP COLUMN (SQLite >= 3.35),
    falling back to a table rebuild on older SQLite versions."""
    present = [col for col in LEGACY_COLUMNS if col in table_columns(db, "port_metadata")]
    if not present:
        return
    try:
        for col in present:
            db.execute(f"ALTER TABLE port_metadata DROP COLUMN {col}")
    except sqlite3.OperationalError:
        existing = table_columns(db, "port_metadata")
        cols = ", ".join(col for col in PORT_METADATA_COLUMNS if col in existing)
        db.execute("DROP TABLE IF EXISTS port_metadata_new")
        db.execute(PORT_METADATA_DDL.format(table="port_metadata_new"))
        db.execute(
            f"INSERT INTO port_metadata_new ({cols}) SELECT {cols} FROM port_metadata ORDER BY rowid"
        )
        db.execute("DROP TABLE port_metadata")
        db.execute("ALTER TABLE port_metadata_new RENAME TO port_metadata")


def add_auto_ignored_column(db: sqlite3.Connection) -> None:
    """One-time split of dedup's auto-ignore out of the user's `ignored` flag.

    Before this column existed, dedup wrote `ignored` directly. A currently ignored,
    unnamed or auto-named duplicate bind becomes auto_ignored=1; it also stays
    user-ignored only when its whole group was ignored (the user ignored the group).
    Any other ignored row is a user ignore. The next scan recomputes auto_ignored.
    """
    if "auto_ignored" in table_columns(db, "port_metadata"):
        return
    db.execute("ALTER TABLE port_metadata ADD COLUMN auto_ignored INTEGER NOT NULL DEFAULT 0")
    rows = db.execute(
        "SELECT rowid, key, port, proto, local_address, name, ignored FROM port_metadata"
    ).fetchall()
    for group in group_rows(rows).values():
        if len(group) < 2:
            continue
        visible = [r for r in group if not r["ignored"]]
        keeper = min(visible or group, key=lambda r: (bind_priority(r["local_address"]), r["rowid"]))
        for row in group:
            if row["rowid"] == keeper["rowid"] or not row["ignored"] or user_name_of(row):
                continue
            db.execute(
                "UPDATE port_metadata SET auto_ignored = 1, ignored = ? WHERE key = ?",
                (0 if visible else 1, row["key"]),
            )


def add_http_column(db: sqlite3.Connection) -> None:
    """`http` = the port answered HTTP on localhost in the last scan; filled by the next scan."""
    if "http" not in table_columns(db, "port_metadata"):
        db.execute("ALTER TABLE port_metadata ADD COLUMN http INTEGER NOT NULL DEFAULT 0")


def migrate_categories(db: sqlite3.Connection) -> None:
    """Normalize category casing and register every in-use custom category."""
    canonical = {name.casefold(): name for name in CATEGORIES}
    canonical.update(
        {row["name"].casefold(): row["name"] for row in db.execute("SELECT name FROM custom_categories")}
    )
    rows = db.execute(
        "SELECT category, MIN(rowid) AS first FROM port_metadata WHERE category <> '' GROUP BY category ORDER BY first"
    ).fetchall()
    for row in rows:
        category = row["category"]
        target = canonical.setdefault(category.casefold(), category)
        if target != category:
            db.execute("UPDATE port_metadata SET category = ? WHERE category = ?", (target, category))
        elif target not in CATEGORIES:
            db.execute("INSERT OR IGNORE INTO custom_categories (name) VALUES (?)", (target,))


def init_db() -> None:
    with db_session() as db:
        db.execute(PORT_METADATA_DDL.format(table="port_metadata"))
        add_auto_ignored_column(db)  # before the legacy rebuild, which copies existing columns only
        add_http_column(db)
        drop_legacy_columns(db)
        db.execute("CREATE INDEX IF NOT EXISTS idx_port_metadata_port ON port_metadata(port)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_port_metadata_last_seen ON port_metadata(last_seen)")
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS custom_categories (name TEXT PRIMARY KEY)")
        migrate_categories(db)


def get_setting(db: sqlite3.Connection, key: str) -> str:
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else ""


def set_setting(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


# ── Scanning ────────────────────────────────────────────────────────────────

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
        parsed = split_address_port(parts[4])
        if not parsed:
            continue
        local_address, port = parsed
        entries.append(
            PortEntry(
                proto=parts[0],
                state=parts[1],
                local_address=local_address,
                port=port,
                peer=parts[5],
                process=parts[6] if len(parts) >= 7 else "",
                raw=line,
            )
        )
    return sorted(entries, key=lambda e: (e.port, e.proto, e.local_address))


def classify_scope(addr: str) -> str:
    host = addr.split("%", 1)[0]
    if host in {"0.0.0.0", "*", "::", ""}:
        return "public"
    if host == "localhost":
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "specific"
    if ip.is_loopback:
        return "loopback"
    if any(ip in net for net in TAILSCALE_NETS):
        return "tailscale"
    if ip.is_private or ip.is_link_local:
        return "lan"
    return "specific"


def process_summary(process: str) -> str:
    """'users:(("nginx",pid=10,fd=6),("nginx",pid=11,fd=6))' -> 'nginx · pid 10, 11'."""
    found = PROCESS_RE.findall(process or "")
    if not found:
        return ""
    names = list(dict.fromkeys(name for name, _ in found))
    pids = list(dict.fromkeys(pid for _, pid in found))
    pid_text = ", ".join(pids[:3]) + (f" +{len(pids) - 3}" if len(pids) > 3 else "")
    return f"{', '.join(names)} · pid {pid_text}"


def is_browsable(status: int, headers: Message) -> bool:
    """Would a browser show something useful? An HTML page, a redirect (e.g. to a login
    page) or an HTTP auth prompt. APIs (JSON / plain-text answers, 404s on /) and
    HTTPS-only servers rejecting plain HTTP with a 400 don't count."""
    if 300 <= status < 400:
        return bool(headers.get("Location"))
    if status == 401:
        return bool(headers.get("WWW-Authenticate"))
    content_type = (headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    return 200 <= status < 300 and content_type in ("text/html", "application/xhtml+xml")


def probe_http(port: int) -> bool:
    """True if http://localhost:<port>/ answers with something a browser can open."""
    conn = http.client.HTTPConnection(HTTP_PROBE_HOST, port, timeout=HTTP_PROBE_TIMEOUT)
    try:
        conn.request("GET", "/", headers={
            "User-Agent": "port-inventory", "Accept": "text/html,*/*;q=0.8", "Connection": "close",
        })
        response = conn.getresponse()
        return is_browsable(response.status, response.headers)
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


def probe_http_ports(entries: Iterable[PortEntry]) -> set[int]:
    """Probe every listening TCP port in parallel; returns the ones that speak HTTP."""
    ports = sorted({e.port for e in entries if e.proto.lower() == "tcp"})
    if not ports or HTTP_PROBE_TIMEOUT <= 0:
        return set()
    with ThreadPoolExecutor(max_workers=min(HTTP_PROBE_WORKERS, len(ports))) as pool:
        return {port for port, ok in zip(ports, pool.map(probe_http, ports)) if ok}


def sync_scan(entries: Iterable[PortEntry], http_ports: set[int] = frozenset()) -> None:
    seen_at = now_iso()
    with db_session() as db:
        for entry in entries:
            is_http = int(entry.proto.lower() == "tcp" and entry.port in http_ports)
            row = db.execute("SELECT key FROM port_metadata WHERE key = ?", (entry.key,)).fetchone()
            if row:
                db.execute(
                    """
                    UPDATE port_metadata
                    SET last_seen = ?, last_process = ?, last_raw = ?, http = ?
                    WHERE key = ?
                    """,
                    (seen_at, entry.process, entry.raw, is_http, entry.key),
                )
            else:
                known = WELL_KNOWN_PORTS.get(entry.port, {})
                db.execute(
                    """
                    INSERT INTO port_metadata
                    (key, proto, local_address, port, name, category, notes,
                     ignored, http, first_seen, last_seen, last_process, last_raw)
                    VALUES (?, ?, ?, ?, ?, ?, '', 0, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.key,
                        entry.proto,
                        entry.local_address,
                        entry.port,
                        known.get("name", ""),
                        known.get("category", ""),
                        is_http,
                        seen_at,
                        seen_at,
                        entry.process,
                        entry.raw,
                    ),
                )
        dedupe_binds(db, seen_at)
        set_setting(db, "last_scan_at", seen_at)
        set_setting(db, "last_scan_error", "")


def bind_priority(addr: str) -> int:
    """Lower is better: wildcard IPv4 > wildcard IPv6 > anything else."""
    if addr in {"0.0.0.0", "*"}:
        return 0
    if addr == "::":
        return 1
    if addr == ":::":
        return 2
    return 3


def primary_rank(row: sqlite3.Row, online: bool) -> tuple[bool, int, int]:
    """Sort key for picking a group's primary bind: online first, then the widest
    bind, then the first inserted. Shared by dedup and the API grouping."""
    return (not online, bind_priority(row["local_address"]), row["rowid"])


def group_rows(rows: Iterable[sqlite3.Row]) -> dict[tuple[int, str], list[sqlite3.Row]]:
    groups: dict[tuple[int, str], list[sqlite3.Row]] = {}
    for row in rows:
        groups.setdefault((int(row["port"]), row["proto"].lower()), []).append(row)
    return groups


def dedupe_binds(db: sqlite3.Connection, seen_at: str) -> None:
    """Recompute auto_ignored from scratch after a scan.

    Within each (port, proto) group the primary is the best-priority bind online
    in this scan; every other online bind is a duplicate (auto_ignored=1) and
    offline binds get auto_ignored=0. The user's `ignored` flag is never touched.
    """
    rows = db.execute(
        "SELECT rowid, key, port, proto, local_address, last_seen, auto_ignored FROM port_metadata"
    ).fetchall()
    updates = []
    for group in group_rows(rows).values():
        online = [r for r in group if r["last_seen"] == seen_at]
        primary = min(online, key=lambda r: primary_rank(r, True)) if online else None
        for row in group:
            auto = int(row["last_seen"] == seen_at and row["rowid"] != primary["rowid"])
            if auto != row["auto_ignored"]:
                updates.append((auto, row["key"]))
    db.executemany("UPDATE port_metadata SET auto_ignored = ? WHERE key = ?", updates)


def run_scan() -> str | None:
    """Scan once and sync the DB. Returns an error message, or None on success."""
    with _scan_lock:
        try:
            entries = parse_ss_output(run_ss())
        except Exception as exc:
            with db_session() as db:
                set_setting(db, "last_scan_error", str(exc))
            return str(exc)
        sync_scan(entries, probe_http_ports(entries))
        return None


# ── Grouping / payload ──────────────────────────────────────────────────────

def build_group(rows: list[sqlite3.Row], last_scan_at: str, now: datetime) -> dict[str, Any]:
    def online(row: sqlite3.Row) -> bool:
        return bool(last_scan_at) and row["last_seen"] == last_scan_at

    # Same primary dedup picked: the best online bind (or the best bind, if offline).
    ordered = sorted(rows, key=lambda r: primary_rank(r, online(r)))
    primary = ordered[0]
    port = int(primary["port"])
    proto = primary["proto"].lower()

    # Shown name: a user-supplied name beats an auto-filled one, the primary's first.
    user_names = [user_name_of(r) for r in ordered]
    name = next((n for n in user_names if n), "") or next((r["name"] for r in ordered if r["name"]), "")
    other_names = []
    for row, user_name in zip(ordered, user_names):
        if user_name and user_name != name:
            other_names.append({"name": user_name, "address": row["local_address"]})

    is_online = any(online(r) for r in rows)
    live = [r for r in ordered if online(r)] if is_online else ordered
    scopes = sorted({classify_scope(r["local_address"]) for r in live}, key=SCOPE_ORDER.index)
    process_row = next((r for r in live if process_summary(r["last_process"])), primary)

    first_seen = min(r["first_seen"] for r in rows)
    last_seen = max(r["last_seen"] for r in rows)
    first_dt = parse_iso(first_seen)

    binds = []
    for row in ordered:
        scope = classify_scope(row["local_address"])
        binds.append({
            "key": row["key"],
            "address": row["local_address"],
            "scope": scope,
            "scope_label": SCOPE_LABELS[scope],
            "ignored": bool(row["ignored"]),
            "auto_ignored": bool(row["auto_ignored"]),
            "online": online(row),
            "name": row["name"],
            "auto_name": row["name"] if row["name"] and not user_name_of(row) else "",
            "user_name": user_name_of(row),
            "category": row["category"],
            "notes": row["notes"],
            "process": row["last_process"],
            "raw": row["last_raw"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        })

    return {
        "id": f"{proto}-{port}",
        "port": port,
        "proto": proto,
        "primary_key": primary["key"],
        "keys": [r["key"] for r in ordered],
        "name": name,
        "auto_name": auto_name_for(port),
        "other_names": other_names,
        "category": next((r["category"] for r in ordered if r["category"]), ""),
        "notes": next((r["notes"] for r in ordered if r["notes"]), ""),
        "ignored": bool(primary["ignored"]),  # Ignore/Unignore act on every bind; the primary represents the group
        "process": process_summary(process_row["last_process"]),
        "process_full": process_row["last_process"],
        "binds": binds,
        "scopes": scopes,
        "has_public": is_online and "public" in scopes,  # only currently listening ports count as exposed
        "first_seen": first_seen,
        "last_seen": last_seen,
        "is_new": bool(first_dt and first_dt >= now - NEW_WINDOW),
        "is_online": is_online,
        "http": any(online(r) and r["http"] for r in rows),  # answered HTTP on localhost in the last scan
    }


def list_categories(db: sqlite3.Connection) -> list[dict[str, Any]]:
    counts = {
        row["category"]: row["n"]
        for row in db.execute(
            """
            SELECT category, COUNT(DISTINCT port || '/' || lower(proto)) AS n
            FROM port_metadata WHERE category <> '' GROUP BY category
            """
        )
    }
    custom = [row["name"] for row in db.execute("SELECT name FROM custom_categories")]
    names = CATEGORIES + sorted((c for c in custom if c not in CATEGORIES), key=str.casefold)
    names += sorted((c for c in counts if c not in names), key=str.casefold)
    return [{"name": n, "builtin": n in CATEGORIES, "count": counts.get(n, 0)} for n in names]


def build_payload(db: sqlite3.Connection) -> dict[str, Any]:
    last_scan_at = get_setting(db, "last_scan_at")
    rows = db.execute("SELECT rowid, * FROM port_metadata ORDER BY port, lower(proto), rowid").fetchall()
    grouped = group_rows(rows)

    now = datetime.now(timezone.utc)
    groups = [build_group(group_rows, last_scan_at, now) for group_rows in grouped.values()]
    active = [g for g in groups if not g["ignored"]]
    return {
        "hostname": socket.gethostname(),
        "server_time": now.isoformat(timespec="milliseconds"),
        "last_scan_at": last_scan_at or None,
        "scan_error": get_setting(db, "last_scan_error") or None,
        "rescan_interval_seconds": RESCAN_INTERVAL_SECONDS,
        "stale_after_seconds": STALE_SECONDS,
        "stats": {
            "total": len(active),
            "unnamed": sum(1 for g in active if not g["name"]),
            "public": sum(1 for g in active if g["has_public"]),
            "new": sum(1 for g in active if g["is_new"]),
            "ignored": len(groups) - len(active),
        },
        "categories": list_categories(db),
        "groups": groups,
    }


# ── Mutations ───────────────────────────────────────────────────────────────

def canonical_category(db: sqlite3.Connection, name: str) -> tuple[str, bool]:
    """Return (existing name with its casing, False) or register it: (name, True)."""
    folded = name.casefold()
    for builtin in CATEGORIES:
        if builtin.casefold() == folded:
            return builtin, False
    for row in db.execute("SELECT name FROM custom_categories"):
        if row["name"].casefold() == folded:
            return row["name"], False
    db.execute("INSERT INTO custom_categories (name) VALUES (?)", (name,))
    return name, True


def validate_text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ApiError(f"'{field}' must be a string")
    value = value.strip()
    if len(value) > limit:
        raise ApiError(f"'{field}' is longer than {limit} characters")
    return value


def parse_changes(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not data:
        raise ApiError("Expected an object with at least one of: " + ", ".join(EDITABLE_FIELDS))
    unknown = sorted(set(data) - set(EDITABLE_FIELDS))
    if unknown:
        raise ApiError("Unknown field(s): " + ", ".join(unknown))
    changes: dict[str, Any] = {}
    for field, limit in (("name", MAX_NAME_LEN), ("category", MAX_CATEGORY_LEN), ("notes", MAX_NOTES_LEN)):
        if field in data:
            changes[field] = validate_text(data[field], field, limit)
    if "ignored" in data:
        if not isinstance(data["ignored"], bool):
            raise ApiError("'ignored' must be true or false")
        changes["ignored"] = int(data["ignored"])
    return changes


def apply_changes(db: sqlite3.Connection, keys: list[str], changes: dict[str, Any]) -> int:
    existing = {row["key"] for row in db.execute("SELECT key FROM port_metadata")}
    missing = [k for k in keys if k not in existing]
    if missing:
        raise ApiError("Unknown port key(s): " + ", ".join(missing[:5]), 404)
    if changes.get("category"):
        changes["category"], _ = canonical_category(db, changes["category"])
    fields = list(changes)
    assignments = ", ".join(f"{field} = ?" for field in fields)
    values = [changes[field] for field in fields]
    db.executemany(
        f"UPDATE port_metadata SET {assignments} WHERE key = ?",
        [(*values, key) for key in keys],
    )
    return len(keys)


# ── Background auto-rescan ──────────────────────────────────────────────────

def _background_rescan_loop() -> None:
    """Runs in a daemon thread; rescans every RESCAN_INTERVAL_SECONDS."""
    while True:
        time.sleep(RESCAN_INTERVAL_SECONDS)
        try:
            run_scan()
        except Exception:
            pass  # errors are non-fatal in background


def start_background_rescan() -> None:
    t = threading.Thread(target=_background_rescan_loop, daemon=True)
    t.start()


# ── Routes ──────────────────────────────────────────────────────────────────

@app.errorhandler(ApiError)
def handle_api_error(exc: ApiError):
    return jsonify({"error": exc.message}), exc.status


@app.errorhandler(HTTPException)
def handle_http_error(exc: HTTPException):
    if request.path.startswith("/api/"):
        return jsonify({"error": exc.description}), exc.code
    return exc


def json_body() -> Any:
    data = request.get_json(silent=True)
    if data is None:
        raise ApiError("Request body must be JSON (Content-Type: application/json)")
    return data


@app.get("/")
def index():
    return Response(TEMPLATE, mimetype="text/html")


@app.get("/api/ports")
def api_ports():
    with db_session() as db:
        scanned = get_setting(db, "last_scan_at")
    if not scanned:
        run_scan()
    with db_session() as db:
        return jsonify(build_payload(db))


@app.patch("/api/ports/<path:key>")
def api_update_port(key: str):
    changes = parse_changes(json_body())
    with db_session() as db:
        apply_changes(db, [key], changes)
        row = db.execute("SELECT * FROM port_metadata WHERE key = ?", (key,)).fetchone()
        result = {field: row[field] for field in PORT_METADATA_COLUMNS}
    result["ignored"] = bool(result["ignored"])
    result["auto_ignored"] = bool(result["auto_ignored"])
    return jsonify({"port": result})


@app.post("/api/ports/bulk")
def api_bulk_update():
    data = json_body()
    if not isinstance(data, dict):
        raise ApiError("Expected {keys: [...], changes: {...}}")
    keys = data.get("keys")
    if not isinstance(keys, list) or not keys or not all(isinstance(k, str) and k for k in keys):
        raise ApiError("'keys' must be a non-empty list of port keys")
    if len(keys) > MAX_BULK_KEYS:
        raise ApiError(f"At most {MAX_BULK_KEYS} keys per request")
    changes = parse_changes(data.get("changes"))
    with db_session() as db:
        updated = apply_changes(db, list(dict.fromkeys(keys)), changes)
        payload = build_payload(db)
    return jsonify({"updated": updated, "data": payload})


@app.post("/api/rescan")
def api_rescan():
    run_scan()
    with db_session() as db:
        return jsonify(build_payload(db))


@app.get("/api/categories")
def api_categories():
    with db_session() as db:
        return jsonify({"categories": list_categories(db)})


@app.post("/api/categories")
def api_add_category():
    data = json_body()
    if not isinstance(data, dict) or "name" not in data:
        raise ApiError("Expected {name: \"...\"}")
    name = validate_text(data["name"], "name", MAX_CATEGORY_LEN)
    if not name:
        raise ApiError("Category name can't be empty")
    with db_session() as db:
        canonical, created = canonical_category(db, name)
        categories = list_categories(db)
    return jsonify({"name": canonical, "created": created, "categories": categories}), 201 if created else 200


@app.delete("/api/categories/<path:name>")
def api_delete_category(name: str):
    if any(name.casefold() == builtin.casefold() for builtin in CATEGORIES):
        raise ApiError("Built-in categories can't be deleted")
    with db_session() as db:
        if not db.execute("SELECT 1 FROM custom_categories WHERE name = ?", (name,)).fetchone():
            raise ApiError(f"No custom category named '{name}'", 404)
        in_use = db.execute(
            "SELECT COUNT(DISTINCT port || '/' || lower(proto)) FROM port_metadata WHERE category = ?",
            (name,),
        ).fetchone()[0]
        if in_use:
            raise ApiError(f"'{name}' is still used by {in_use} port{'s' if in_use != 1 else ''}", 409)
        db.execute("DELETE FROM custom_categories WHERE name = ?", (name,))
        categories = list_categories(db)
    return jsonify({"deleted": name, "categories": categories})


# ── HTML shell (data comes from /api) ───────────────────────────────────────

TEMPLATE = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script>
    // Apply saved theme before first paint to avoid a flash
    (function () {
      try {
        var t = localStorage.getItem('pi-theme');
        if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
      } catch (e) {}
    })();
  </script>
  <title>Port Inventory</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMzIgMzIiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNyIgZmlsbD0iIzBkMTUyMSIvPgogIDxyZWN0IHg9IjUiIHk9IjkiIHdpZHRoPSIyMiIgaGVpZ2h0PSIzIiByeD0iMS41IiBmaWxsPSIjNGZhY2RlIi8+CiAgPHJlY3QgeD0iNSIgeT0iMTQuNSIgd2lkdGg9IjE0IiBoZWlnaHQ9IjMiIHJ4PSIxLjUiIGZpbGw9IiMzZGQ2OGMiLz4KICA8cmVjdCB4PSI1IiB5PSIyMCIgd2lkdGg9IjE4IiBoZWlnaHQ9IjMiIHJ4PSIxLjUiIGZpbGw9IiM0ZmFjZGUiIG9wYWNpdHk9IjAuNSIvPgogIDxjaXJjbGUgY3g9IjI0IiBjeT0iMjMiIHI9IjUiIGZpbGw9IiMwZDE1MjEiIHN0cm9rZT0iIzRmYWNkZSIgc3Ryb2tlLXdpZHRoPSIxLjUiLz4KICA8Y2lyY2xlIGN4PSIyNCIgY3k9IjIzIiByPSIyLjUiIGZpbGw9IiM0ZmFjZGUiLz4KPC9zdmc+">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      color-scheme: dark;
      --bg:       #080d16;
      --surface:  #0d1521;
      --panel:    #111e2e;
      --border:   #1e3048;
      --border2:  #243a55;
      --text:     #cdd6e8;
      --muted:    #8299b8;
      --accent:   #4facde;
      --accent2:  #1e88c8;
      --danger:   #f06880;
      --warn:     #f5a623;
      --ok:       #3dd68c;
      --purple:   #9b6dff;
      --accent-text: #4facde;
      --danger-text: #f06880;
      --warn-text:   #f5a623;
      --ok-text:     #3dd68c;
      --purple-text: #b18cff;
      --field-border: #52739b;
      --header-bg:    rgba(8,13,22,.88);
      --heading:      #ffffff;
      --row-hover:    #132032;
      --row-selected: #12253a;
      --input-bg:     #0a111d;
      --code-bg:      #0a111d;
      --on-accent:    #001828;
      --btn-primary:  #4facde;
      --btn-primary-hover: #6cc5ee;
      --shadow:   0 16px 48px rgba(0,0,0,.55);
      --backdrop: rgba(2,6,12,.6);
      --cat0-fg: #7dd3fc; --cat0-bg: #0c2a3d;
      --cat1-fg: #6ee7b7; --cat1-bg: #0b2e26;
      --cat2-fg: #fcd34d; --cat2-bg: #33280a;
      --cat3-fg: #fda4af; --cat3-bg: #3a1720;
      --cat4-fg: #c4b5fd; --cat4-bg: #241c45;
      --cat5-fg: #5eead4; --cat5-bg: #0a2e2d;
      --cat6-fg: #fdba74; --cat6-bg: #36200c;
      --cat7-fg: #bef264; --cat7-bg: #233010;
      --cat8-fg: #f9a8d4; --cat8-bg: #3a1530;
      --cat9-fg: #a5b4fc; --cat9-bg: #1c2245;
      --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: 'DM Sans', system-ui, -apple-system, 'Segoe UI', sans-serif;
    }
    :root[data-theme="light"] {
      color-scheme: light;
      --bg:       #f0f4f8;
      --surface:  #ffffff;
      --panel:    #f8fafc;
      --border:   #cbd5e1;
      --border2:  #94a3b8;
      --text:     #0f172a;
      --muted:    #526175;
      --accent:   #0284c7;
      --accent2:  #0369a1;
      --danger:   #dc2626;
      --warn:     #d97706;
      --ok:       #16a34a;
      --purple:   #7c3aed;
      --accent-text: #0369a1;
      --danger-text: #b91c1c;
      --warn-text:   #a14a06;
      --ok-text:     #15703a;
      --purple-text: #6d28d9;
      --field-border: #7b8aa0;
      --header-bg:    rgba(240,244,248,.88);
      --heading:      #0f172a;
      --row-hover:    #f1f5f9;
      --row-selected: #e6f1fa;
      --input-bg:     #ffffff;
      --code-bg:      #f1f5f9;
      --on-accent:    #ffffff;
      --btn-primary:  #0369a1;
      --btn-primary-hover: #075985;
      --shadow:   0 16px 48px rgba(15,23,42,.18);
      --backdrop: rgba(15,23,42,.35);
      --cat0-fg: #075985; --cat0-bg: #e0f2fe;
      --cat1-fg: #065f46; --cat1-bg: #d1fae5;
      --cat2-fg: #92400e; --cat2-bg: #fef3c7;
      --cat3-fg: #9f1239; --cat3-bg: #ffe4e6;
      --cat4-fg: #5b21b6; --cat4-bg: #ede9fe;
      --cat5-fg: #115e59; --cat5-bg: #ccfbf1;
      --cat6-fg: #9a3412; --cat6-bg: #ffedd5;
      --cat7-fg: #3f6212; --cat7-bg: #ecfccb;
      --cat8-fg: #9d174d; --cat8-bg: #fce7f3;
      --cat9-fg: #3730a3; --cat9-bg: #e0e7ff;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    [hidden] { display: none !important; }
    html { -webkit-text-size-adjust: 100%; }
    body {
      font-family: var(--sans); font-size: 14px; line-height: 1.4;
      background: var(--bg); color: var(--text); min-height: 100vh;
    }
    body.has-bulk { padding-bottom: 80px; }
    button, input, select, textarea { font: inherit; color: inherit; }
    button { cursor: pointer; }
    .mono { font-family: var(--mono); }
    .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
    :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }
    ::-webkit-scrollbar-track { background: transparent; }

    /* ── Buttons ── */
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 8px;
      min-height: 32px; padding: 0 12px; border-radius: 8px;
      border: 1px solid var(--border2); background: var(--surface); color: var(--text);
      font-size: 13px; font-weight: 600; white-space: nowrap; transition: background .12s, border-color .12s, color .12s;
    }
    .btn:hover { border-color: var(--accent); color: var(--accent-text); }
    .btn:disabled { opacity: .6; cursor: default; }
    .btn-primary { background: var(--btn-primary); border-color: var(--btn-primary); color: var(--on-accent); }
    .btn-primary:hover { background: var(--btn-primary-hover); border-color: var(--btn-primary-hover); color: var(--on-accent); }
    .btn-link { background: transparent; border-color: transparent; color: var(--accent-text); padding: 0 8px; }
    .btn-link:hover { text-decoration: underline; border-color: transparent; }
    .btn-sm { min-height: 32px; padding: 0 10px; font-size: 12px; }
    .icon-btn {
      display: inline-flex; align-items: center; justify-content: center;
      width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0;
      border: 1px solid var(--border2); background: var(--surface); color: var(--text);
      font-weight: 700; font-size: 14px;
    }
    .icon-btn:hover { border-color: var(--accent); color: var(--accent-text); }
    .icon-btn.ghost { border-color: transparent; background: transparent; color: var(--muted); }
    .icon-btn.ghost:hover { color: var(--text); background: var(--row-hover); }

    /* ── Header ── */
    .topbar {
      position: sticky; top: 0; z-index: 30;
      display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;
      padding: 12px 24px; background: var(--header-bg); backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
    }
    .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
    .brand svg { width: 32px; height: 32px; flex-shrink: 0; }
    .brand h1 { font-size: 16px; font-weight: 700; color: var(--heading); letter-spacing: -.2px; }
    .brand-sub { display: flex; flex-wrap: wrap; gap: 0 8px; font-size: 12px; color: var(--muted); }
    .brand-sub .mono { color: var(--text); }
    .top-actions { display: flex; align-items: center; gap: 8px; }
    .spinner {
      width: 14px; height: 14px; border-radius: 50%;
      border: 2px solid currentColor; border-right-color: transparent;
      animation: spin .8s linear infinite; display: none;
    }
    #rescan-btn.is-loading .spinner { display: inline-block; }
    #rescan-btn.is-loading .rescan-icon { display: none; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .theme-icon-moon { display: none; }
    :root[data-theme="light"] .theme-icon-sun { display: none; }
    :root[data-theme="light"] .theme-icon-moon { display: block; }

    main { padding: 16px 24px 32px; max-width: 1480px; margin: 0 auto; }

    .banner {
      display: flex; gap: 8px; align-items: flex-start;
      padding: 8px 16px; margin-bottom: 16px; border-radius: 8px;
      border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent);
      background: color-mix(in srgb, var(--danger) 10%, var(--surface));
      color: var(--danger-text); font-family: var(--mono); font-size: 12px;
    }

    /* ── Stat cards (filters) ── */
    .stats { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 8px; margin-bottom: 16px; }
    .stat {
      display: flex; flex-direction: column; align-items: flex-start; gap: 0;
      padding: 8px 16px; min-height: 56px; border-radius: 8px; text-align: left;
      border: 1px solid var(--border); background: var(--surface); color: var(--text);
      transition: border-color .12s, background .12s;
    }
    .stat:hover { border-color: var(--border2); }
    .stat-value { font-family: var(--mono); font-size: 20px; font-weight: 800; color: var(--heading); line-height: 1.2; }
    .stat-label { font-size: 12px; color: var(--muted); font-weight: 600; }
    .stat[data-card="unnamed"] .stat-value { color: var(--warn-text); }
    .stat[data-card="public"] .stat-value { color: var(--danger-text); }
    .stat[data-card="new"] .stat-value { color: var(--accent-text); }
    .stat[data-card="ignored"] .stat-value { color: var(--purple-text); }
    .stat[aria-pressed="true"] {
      border-color: var(--accent); background: color-mix(in srgb, var(--accent) 10%, var(--surface));
      box-shadow: inset 0 0 0 1px var(--accent);
    }

    /* ── Toolbar ── */
    .toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
    .search { position: relative; flex: 1 1 240px; max-width: 360px; }
    .search svg { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--muted); pointer-events: none; }
    .search input {
      width: 100%; height: 32px; padding: 0 32px 0 32px; border-radius: 8px;
      border: 1px solid var(--field-border); background: var(--input-bg); color: var(--text); font-size: 13px;
    }
    .search input::placeholder { color: var(--muted); }
    .search kbd {
      position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
      font-family: var(--mono); font-size: 11px; color: var(--muted);
      border: 1px solid var(--border2); border-radius: 4px; padding: 0 4px; pointer-events: none;
    }
    .search input:focus + kbd, .search input:not(:placeholder-shown) + kbd { display: none; }
    .result-count { font-size: 12px; color: var(--muted); white-space: nowrap; margin-right: 8px; }
    .segmented { display: inline-flex; border: 1px solid var(--border2); border-radius: 8px; overflow: hidden; }
    .segmented button {
      min-height: 30px; padding: 0 12px; border: 0; background: var(--surface); color: var(--muted);
      font-family: var(--mono); font-size: 12px; font-weight: 700;
    }
    .segmented button + button { border-left: 1px solid var(--border2); }
    .segmented button[aria-pressed="true"] { background: color-mix(in srgb, var(--accent) 14%, var(--surface)); color: var(--accent-text); }
    .segmented button:focus-visible { outline-offset: -2px; }
    .select {
      height: 32px; padding: 0 8px; border-radius: 8px; border: 1px solid var(--field-border);
      background: var(--surface); color: var(--text); font-size: 13px; font-weight: 600;
    }
    .dropdown { position: relative; }
    .count-badge {
      font-family: var(--mono); font-size: 11px; padding: 0 6px; border-radius: 99px;
      background: var(--btn-primary); color: var(--on-accent);
    }
    .menu {
      position: absolute; top: calc(100% + 4px); left: 0; z-index: 40; min-width: 240px; max-height: 360px; overflow: auto;
      padding: 8px; border-radius: 8px; border: 1px solid var(--border2); background: var(--surface); box-shadow: var(--shadow);
    }
    .menu label {
      display: flex; align-items: center; gap: 8px; min-height: 32px; padding: 0 8px; border-radius: 6px;
      font-size: 13px; cursor: pointer;
    }
    .menu label:hover { background: var(--row-hover); }
    .menu .menu-count { margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--muted); }
    .menu-foot { display: flex; justify-content: flex-end; border-top: 1px solid var(--border); margin-top: 8px; padding-top: 8px; }
    input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }

    /* ── Table ── */
    .table-card { border: 1px solid var(--border); border-radius: 12px; background: var(--surface); overflow: hidden; }
    .table-scroll { overflow-x: auto; }
    table.ports { width: 100%; border-collapse: collapse; font-size: 13px; }
    .ports thead th {
      background: var(--panel); text-align: left;
      font-size: 11px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: .6px;
      border-bottom: 1px solid var(--border); padding: 0 8px; height: 40px; white-space: nowrap;
    }
    .ports th .sort-btn {
      display: inline-flex; align-items: center; gap: 4px; min-height: 32px; padding: 0 4px;
      border: 0; background: transparent; color: inherit; font: inherit; text-transform: inherit; letter-spacing: inherit;
    }
    .ports th .sort-btn:hover { color: var(--text); }
    .ports th[aria-sort="ascending"] .sort-btn, .ports th[aria-sort="descending"] .sort-btn { color: var(--accent-text); }
    .sort-arrow { font-size: 10px; width: 10px; }
    .ports td { padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: middle; height: 48px; }
    .ports tbody tr:last-child td { border-bottom: 0; }
    .ports tbody tr { cursor: pointer; }
    .ports tbody tr:hover td { background: var(--row-hover); }
    .ports tbody tr.is-selected td { background: var(--row-selected); }
    .ports tbody tr:focus { outline: none; }
    .ports tbody tr:focus-visible td, .ports tbody tr.is-focused td { box-shadow: inset 0 1px 0 var(--accent), inset 0 -1px 0 var(--accent); }
    .ports tbody tr:focus-visible td:first-child, .ports tbody tr.is-focused td:first-child { box-shadow: inset 2px 0 0 var(--accent), inset 0 1px 0 var(--accent), inset 0 -1px 0 var(--accent); }
    .ports tbody tr.is-offline td > * { opacity: .6; }
    .col-check { width: 40px; text-align: center; padding-left: 16px !important; }
    .col-port { width: 80px; }
    .col-proto { width: 64px; }
    .col-cat { width: 200px; }
    .col-seen { width: 112px; white-space: nowrap; }
    .col-more { width: 88px; text-align: right; white-space: nowrap; padding-right: 12px !important; }
    .port-num { font-family: var(--mono); font-size: 15px; font-weight: 800; color: var(--accent-text); }
    .proto-tag {
      display: inline-block; font-family: var(--mono); font-size: 11px; font-weight: 700; color: var(--muted);
      border: 1px solid var(--border2); border-radius: 4px; padding: 0 4px; text-transform: uppercase;
    }
    .svc-line { display: flex; align-items: center; gap: 8px; min-width: 0; }
    .name-btn {
      border: 0; background: transparent; padding: 2px 4px; margin-left: -4px; border-radius: 4px;
      font-size: 13px; font-weight: 600; color: var(--heading); text-align: left;
      max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: text;
    }
    .name-btn:hover { background: var(--panel); box-shadow: inset 0 0 0 1px var(--border2); }
    .name-btn.is-unnamed { color: var(--warn-text); font-weight: 500; font-style: italic; }
    .name-input {
      width: 100%; max-width: 320px; height: 28px; padding: 0 8px; border-radius: 6px;
      border: 1px solid var(--accent); background: var(--input-bg); color: var(--text); font-size: 13px; font-weight: 600;
    }
    .svc-proc { font-family: var(--mono); font-size: 11px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 420px; }
    .pill {
      flex-shrink: 0; font-family: var(--mono); font-size: 10px; font-weight: 800; letter-spacing: .4px; text-transform: uppercase;
      border-radius: 99px; padding: 1px 6px; border: 1px solid currentColor;
    }
    .pill-new { color: var(--accent-text); }
    .pill-offline { color: var(--muted); }
    .pill-ignored { color: var(--purple-text); }

    .chip {
      display: inline-flex; align-items: center; gap: 4px; max-width: 100%;
      height: 22px; padding: 0 8px; border-radius: 99px; font-size: 12px; font-weight: 600;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis; border: 1px solid transparent;
    }
    .cat-btn {
      display: inline-flex; align-items: center; min-height: 32px; max-width: 100%;
      border: 0; background: transparent; padding: 0; border-radius: 99px;
    }
    .cat-btn:hover .chip { box-shadow: 0 0 0 1px currentColor; }
    .chip-empty { color: var(--muted); border: 1px dashed var(--border2); font-weight: 500; }
    .cat-c0 { color: var(--cat0-fg); background: var(--cat0-bg); }
    .cat-c1 { color: var(--cat1-fg); background: var(--cat1-bg); }
    .cat-c2 { color: var(--cat2-fg); background: var(--cat2-bg); }
    .cat-c3 { color: var(--cat3-fg); background: var(--cat3-bg); }
    .cat-c4 { color: var(--cat4-fg); background: var(--cat4-bg); }
    .cat-c5 { color: var(--cat5-fg); background: var(--cat5-bg); }
    .cat-c6 { color: var(--cat6-fg); background: var(--cat6-bg); }
    .cat-c7 { color: var(--cat7-fg); background: var(--cat7-bg); }
    .cat-c8 { color: var(--cat8-fg); background: var(--cat8-bg); }
    .cat-c9 { color: var(--cat9-fg); background: var(--cat9-bg); }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; flex-shrink: 0; }

    .bind-chips { display: flex; flex-wrap: wrap; gap: 4px; }
    .bind {
      height: 20px; padding: 0 6px; border-radius: 4px; font-family: var(--mono); font-size: 11px; font-weight: 600;
      max-width: 180px; color: var(--muted); border-color: var(--border2);
    }
    .scope-public    { color: var(--danger-text); background: color-mix(in srgb, var(--danger) 10%, var(--surface)); border-color: color-mix(in srgb, var(--danger) 40%, transparent); }
    .scope-lan       { color: var(--accent-text); background: color-mix(in srgb, var(--accent) 10%, var(--surface)); border-color: color-mix(in srgb, var(--accent) 40%, transparent); }
    .scope-loopback  { color: var(--ok-text);     background: color-mix(in srgb, var(--ok) 10%, var(--surface));     border-color: color-mix(in srgb, var(--ok) 40%, transparent); }
    .scope-tailscale { color: var(--purple-text); background: color-mix(in srgb, var(--purple) 10%, var(--surface)); border-color: color-mix(in srgb, var(--purple) 40%, transparent); }
    .bind.is-faded { opacity: .5; }
    .bind.is-offline { border-style: dashed; }
    .seen { color: var(--muted); font-size: 12px; }
    .more-btn { font-size: 16px; letter-spacing: 1px; }
    .open-btn { text-decoration: none; }
    .open-btn.ghost { color: var(--accent-text); }
    .col-more .open-btn { margin-right: 4px; }

    .empty { padding: 48px 16px; text-align: center; color: var(--muted); }
    .empty-title { font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 4px; }
    .empty .btn { margin-top: 16px; }

    /* ── Bulk bar ── */
    .bulk-bar {
      position: fixed; left: 50%; transform: translateX(-50%); z-index: 35;
      bottom: calc(16px + env(safe-area-inset-bottom, 0px));
      display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: center;
      padding: 8px 8px 8px 16px; border-radius: 12px; max-width: calc(100vw - 32px);
      border: 1px solid var(--border2); background: var(--surface); box-shadow: var(--shadow);
    }
    .bulk-count { font-weight: 700; font-size: 13px; margin-right: 8px; }

    /* ── Drawer ── */
    .backdrop {
      position: fixed; inset: 0; z-index: 50; background: var(--backdrop);
      opacity: 0; visibility: hidden; transition: opacity .18s, visibility .18s;
    }
    .backdrop.open { opacity: 1; visibility: visible; }
    .drawer {
      position: fixed; top: 0; right: 0; bottom: 0; z-index: 60; width: 420px; max-width: 100vw;
      display: flex; flex-direction: column; background: var(--surface); border-left: 1px solid var(--border2);
      box-shadow: var(--shadow); transform: translateX(100%); visibility: hidden;
      transition: transform .2s ease, visibility .2s;
    }
    .drawer.open { transform: none; visibility: visible; }
    .drawer:focus { outline: none; }
    .drawer-head {
      display: flex; align-items: flex-start; justify-content: space-between; gap: 16px;
      padding: 16px 16px 16px 24px; border-bottom: 1px solid var(--border);
      padding-top: calc(16px + env(safe-area-inset-top, 0px));
    }
    .drawer-port { display: flex; align-items: center; gap: 8px; }
    .drawer-port .port-num { font-size: 20px; }
    .drawer-actions { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
    .drawer-head h2 { font-size: 16px; font-weight: 700; color: var(--heading); margin-top: 4px; word-break: break-word; }
    .drawer-body { flex: 1; overflow-y: auto; padding: 16px 24px 32px; display: flex; flex-direction: column; gap: 16px; }
    .field { display: flex; flex-direction: column; gap: 4px; }
    .field-label, .drawer-body h3 { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); }
    .field input[type="text"], .field textarea {
      width: 100%; padding: 8px; border-radius: 8px; border: 1px solid var(--field-border);
      background: var(--input-bg); color: var(--text); font-size: 13px;
    }
    .field input[type="text"] { height: 36px; }
    .field textarea { min-height: 96px; resize: vertical; line-height: 1.5; }
    .field-hint { font-size: 11px; color: var(--muted); }
    .field .cat-btn { align-self: flex-start; }
    .switch-row { display: flex; align-items: center; gap: 8px; min-height: 32px; font-size: 13px; font-weight: 600; cursor: pointer; }
    .callout {
      font-size: 12px; padding: 8px 12px; border-radius: 8px;
      border: 1px solid color-mix(in srgb, var(--warn) 45%, transparent);
      background: color-mix(in srgb, var(--warn) 8%, var(--surface));
    }
    .callout strong { color: var(--warn-text); }
    .section-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
    .drawer-body section h3 { margin-bottom: 8px; }
    .drawer-body section .section-head h3 { margin-bottom: 0; }
    .bind-list { list-style: none; display: flex; flex-direction: column; gap: 4px; }
    .bind-list li {
      display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
      padding: 8px; border-radius: 8px; background: var(--panel); border: 1px solid var(--border);
    }
    .bind-addr { font-family: var(--mono); font-size: 12px; font-weight: 600; word-break: break-all; }
    .bind-note { font-size: 11px; color: var(--muted); margin-left: auto; }
    pre.code {
      font-family: var(--mono); font-size: 11px; line-height: 1.6; color: var(--text);
      background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px;
      padding: 8px 12px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow: auto;
    }
    dl.seen-list { display: grid; grid-template-columns: auto 1fr; gap: 4px 16px; font-size: 13px; }
    dl.seen-list dt { color: var(--muted); }
    dl.seen-list dd { font-family: var(--mono); font-size: 12px; }

    /* ── Popover ── */
    .popover {
      position: fixed; z-index: 70; width: 264px; max-height: 360px; overflow: auto;
      padding: 4px; border-radius: 8px; border: 1px solid var(--border2); background: var(--surface); box-shadow: var(--shadow);
    }
    .pop-row { display: flex; align-items: center; gap: 4px; }
    .pop-item {
      flex: 1; display: flex; align-items: center; gap: 8px; min-height: 32px; padding: 0 8px;
      border: 0; border-radius: 6px; background: transparent; color: var(--text); font-size: 13px; text-align: left; min-width: 0;
    }
    .pop-item:hover, .pop-item:focus-visible { background: var(--row-hover); }
    .pop-item .pop-label { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .pop-item .pop-check { color: var(--accent-text); font-weight: 800; }
    .pop-item.pop-new { color: var(--accent-text); font-weight: 600; }
    .pop-del { width: 28px; height: 28px; font-size: 14px; }
    .pop-sep { height: 1px; background: var(--border); margin: 4px 0; }
    .pop-input {
      width: 100%; height: 32px; padding: 0 8px; border-radius: 6px;
      border: 1px solid var(--accent); background: var(--input-bg); color: var(--text); font-size: 13px;
    }
    .pop-hint { font-size: 11px; color: var(--muted); padding: 4px 8px 0; }

    /* ── Help modal ── */
    .modal-wrap { position: fixed; inset: 0; z-index: 80; display: flex; align-items: center; justify-content: center; padding: 16px; background: var(--backdrop); }
    .modal { width: 100%; max-width: 400px; border-radius: 12px; border: 1px solid var(--border2); background: var(--surface); box-shadow: var(--shadow); padding: 16px 24px 24px; }
    .modal-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
    .modal h2 { font-size: 15px; color: var(--heading); }
    .keys { display: grid; grid-template-columns: auto 1fr; gap: 8px 16px; font-size: 13px; align-items: center; }
    kbd.key {
      display: inline-block; min-width: 24px; text-align: center; font-family: var(--mono); font-size: 12px; font-weight: 700;
      padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border2); background: var(--panel);
    }

    /* ── Toasts ── */
    .toasts {
      position: fixed; right: 16px; z-index: 90; display: flex; flex-direction: column; gap: 8px; align-items: flex-end;
      bottom: calc(16px + env(safe-area-inset-bottom, 0px)); pointer-events: none;
    }
    body.has-bulk .toasts { bottom: calc(80px + env(safe-area-inset-bottom, 0px)); }
    .toast {
      pointer-events: auto; display: flex; align-items: center; gap: 8px; max-width: min(420px, calc(100vw - 32px));
      padding: 8px 8px 8px 16px; border-radius: 8px; font-size: 13px;
      border: 1px solid var(--border2); background: var(--surface); box-shadow: var(--shadow);
      animation: toast-in .18s ease;
    }
    .toast-msg { flex: 1; word-break: break-word; }
    .toast-error { border-color: var(--danger); }
    .toast-error .toast-msg { color: var(--danger-text); }
    @keyframes toast-in { from { opacity: 0; transform: translateY(8px); } }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { transition: none !important; animation-duration: .01ms !important; }
    }

    /* ── Mobile ── */
    @media (max-width: 767px) {
      .topbar { padding: 8px 16px; padding-top: calc(8px + env(safe-area-inset-top, 0px)); }
      .rescan-label { display: none; }
      main { padding: 16px 16px 32px; }
      .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .stat { padding: 8px; min-height: 48px; }
      .stat-value { font-size: 17px; }
      .search { flex-basis: 100%; max-width: none; }
      .result-count { flex-basis: 100%; order: 10; }
      .table-card { border: 0; background: transparent; border-radius: 0; overflow: visible; }
      .table-scroll { overflow: visible; }
      table.ports, .ports tbody { display: block; }
      .ports thead { display: none; }
      .ports tbody tr {
        display: grid; grid-template-columns: 44px auto minmax(0, 1fr) auto;
        grid-template-areas: "check port svc more" "check proto cat cat" ". . binds binds";
        gap: 4px 8px; align-items: center; padding: 8px; margin-bottom: 8px;
        border: 1px solid var(--border); border-radius: 12px; background: var(--surface);
      }
      .ports tbody tr.is-selected { background: var(--row-selected); }
      .ports td { display: block; height: auto; padding: 0 !important; border: 0; background: transparent !important; box-shadow: none !important; width: auto; }
      .ports tbody tr.is-focused, .ports tbody tr:focus-visible { box-shadow: 0 0 0 2px var(--accent); }
      .ports .col-check { grid-area: check; align-self: start; }
      .ports .col-port { grid-area: port; }
      .ports .col-proto { grid-area: proto; }
      .ports .col-service { grid-area: svc; }
      .ports .col-cat { grid-area: cat; }
      .ports .col-binds { grid-area: binds; }
      .ports .col-seen { display: none; }
      .ports .col-more { grid-area: more; align-self: start; }
      .svc-proc { max-width: none; }
      .drawer { width: 100vw; border-left: 0; }
      .drawer-body { padding: 16px; }
      .bulk-bar { left: 8px; right: 8px; transform: none; max-width: none; bottom: calc(8px + env(safe-area-inset-bottom, 0px)); padding: 8px; }
      .bulk-count { flex-basis: 100%; text-align: center; margin: 0; }
      body.has-bulk { padding-bottom: 128px; }
      body.has-bulk .toasts { bottom: calc(128px + env(safe-area-inset-bottom, 0px)); }
      .toasts { left: 16px; align-items: stretch; }
      .toast { max-width: none; }

      /* Touch targets: at least 44px on phones (WCAG 2.5.5); desktop stays compact */
      .ports td.col-check { display: flex; align-items: center; justify-content: center; width: 44px; height: 44px; cursor: pointer; }
      .ports td.col-check input[type="checkbox"], #d-ignored { width: 20px; height: 20px; }
      .name-btn { display: inline-flex; align-items: center; min-height: 44px; padding: 0 4px; }
      .cat-btn { min-height: 44px; }
      .more-btn, .icon-btn { width: 44px; height: 44px; }
      .bulk-bar .btn { min-height: 44px; }
      .btn, .select, .search input { min-height: 44px; }
      .segmented button { min-height: 42px; }
      .pop-item { min-height: 44px; }
      .pop-del { width: 44px; height: 44px; }
      .switch-row { min-height: 44px; }
      .menu label { min-height: 44px; }
    }
  </style>
</head>
<body>

<header class="topbar">
  <div class="brand">
    <svg viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="#0d1521"/>
      <rect x="5" y="9" width="22" height="3" rx="1.5" fill="#4facde"/>
      <rect x="5" y="14.5" width="14" height="3" rx="1.5" fill="#3dd68c"/>
      <rect x="5" y="20" width="18" height="3" rx="1.5" fill="#4facde" opacity="0.5"/>
      <circle cx="24" cy="23" r="5" fill="#0d1521" stroke="#4facde" stroke-width="1.5"/>
      <circle cx="24" cy="23" r="2.5" fill="#4facde"/>
    </svg>
    <div>
      <h1>Port Inventory</h1>
      <div class="brand-sub">
        <span id="hostname" class="mono">…</span>
        <span aria-hidden="true">·</span>
        <span id="scanned-at">Loading…</span>
      </div>
    </div>
  </div>
  <div class="top-actions">
    <button type="button" id="rescan-btn" class="btn btn-primary" title="Run ss -tulpn now">
      <span class="spinner" aria-hidden="true"></span>
      <svg class="rescan-icon" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M13.65 2.35A8 8 0 1 0 15 8h-2a6 6 0 1 1-1.05-3.35L10 7h5V2l-1.35.35z"/></svg>
      <span class="rescan-label">Rescan</span>
    </button>
    <button type="button" id="help-btn" class="icon-btn" title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts">?</button>
    <button type="button" id="theme-btn" class="icon-btn" title="Toggle light / dark theme" aria-label="Toggle light / dark theme">
      <svg class="theme-icon-sun" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
        <circle cx="12" cy="12" r="4.5"/>
        <path d="M12 1.5v2.5M12 20v2.5M1.5 12H4M20 12h2.5M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M4.6 19.4l1.8-1.8M17.6 6.4l1.8-1.8"/>
      </svg>
      <svg class="theme-icon-moon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>
      </svg>
    </button>
  </div>
</header>

<main>
  <div id="scan-error" class="banner" role="alert" hidden></div>

  <section class="stats" aria-label="Quick filters">
    <button type="button" class="stat" data-card="total" aria-pressed="true"><span class="stat-value" id="stat-total">–</span><span class="stat-label">Total</span></button>
    <button type="button" class="stat" data-card="unnamed" aria-pressed="false"><span class="stat-value" id="stat-unnamed">–</span><span class="stat-label">Unnamed</span></button>
    <button type="button" class="stat" data-card="public" aria-pressed="false"><span class="stat-value" id="stat-public">–</span><span class="stat-label">Public</span></button>
    <button type="button" class="stat" data-card="new" aria-pressed="false"><span class="stat-value" id="stat-new">–</span><span class="stat-label">New (24h)</span></button>
    <button type="button" class="stat" data-card="ignored" aria-pressed="false"><span class="stat-value" id="stat-ignored">–</span><span class="stat-label">Ignored</span></button>
  </section>

  <div class="toolbar">
    <div class="search">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="6.5" cy="6.5" r="5" stroke="currentColor" stroke-width="1.5"/>
        <path d="M10 10L14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <input id="search" type="search" placeholder="Search ports, names, processes…" autocomplete="off" spellcheck="false" aria-label="Search ports">
      <kbd>/</kbd>
    </div>
    <span id="result-count" class="result-count" aria-live="polite"></span>
    <div class="segmented" role="group" aria-label="Protocol">
      <button type="button" data-proto="all" aria-pressed="true">All</button>
      <button type="button" data-proto="tcp" aria-pressed="false">TCP</button>
      <button type="button" data-proto="udp" aria-pressed="false">UDP</button>
    </div>
    <div class="dropdown">
      <button type="button" id="cat-filter-btn" class="btn" aria-haspopup="true" aria-expanded="false" aria-controls="cat-filter-menu">
        Category <span id="cat-filter-count" class="count-badge" hidden></span> <span aria-hidden="true">▾</span>
      </button>
      <div id="cat-filter-menu" class="menu" hidden></div>
    </div>
    <select id="scope-filter" class="select" aria-label="Bind scope">
      <option value="">Any scope</option>
      <option value="public">Public</option>
      <option value="lan">LAN</option>
      <option value="loopback">Loopback</option>
      <option value="tailscale">Tailscale</option>
    </select>
    <button type="button" id="reset-filters" class="btn btn-link" hidden>Reset filters</button>
  </div>

  <div class="table-card">
    <div class="table-scroll">
      <table class="ports" id="ports">
        <thead>
          <tr>
            <th class="col-check"><input type="checkbox" id="select-all" aria-label="Select all visible ports"></th>
            <th class="col-port" data-sort="port"><button type="button" class="sort-btn">Port <span class="sort-arrow" aria-hidden="true"></span></button></th>
            <th class="col-proto" data-sort="proto"><button type="button" class="sort-btn">Proto <span class="sort-arrow" aria-hidden="true"></span></button></th>
            <th class="col-service" data-sort="name"><button type="button" class="sort-btn">Service <span class="sort-arrow" aria-hidden="true"></span></button></th>
            <th class="col-cat" data-sort="category"><button type="button" class="sort-btn">Category <span class="sort-arrow" aria-hidden="true"></span></button></th>
            <th class="col-binds" data-sort="binds"><button type="button" class="sort-btn">Binds <span class="sort-arrow" aria-hidden="true"></span></button></th>
            <th class="col-seen" data-sort="last_seen"><button type="button" class="sort-btn">Last seen <span class="sort-arrow" aria-hidden="true"></span></button></th>
            <th class="col-more"><span class="sr-only">Details</span></th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <div id="loading" class="empty">Loading ports…</div>
    <div id="empty" class="empty" hidden>
      <p class="empty-title" id="empty-title">No ports match these filters</p>
      <p id="empty-sub">Try another search, or clear the filters to see everything.</p>
      <button type="button" id="empty-clear" class="btn">Clear filters</button>
    </div>
  </div>
</main>

<div id="bulk-bar" class="bulk-bar" role="region" aria-label="Bulk actions" hidden>
  <span id="bulk-count" class="bulk-count">0 selected</span>
  <button type="button" id="bulk-category" class="btn">Set category <span aria-hidden="true">▾</span></button>
  <button type="button" id="bulk-ignore" class="btn">Ignore</button>
  <button type="button" id="bulk-unignore" class="btn">Unignore</button>
  <button type="button" id="bulk-clear" class="btn btn-link">Clear selection</button>
</div>

<div id="drawer-backdrop" class="backdrop"></div>
<aside id="drawer" class="drawer" role="dialog" aria-modal="true" aria-labelledby="d-title" tabindex="-1">
  <div class="drawer-head">
    <div>
      <div class="drawer-port"><span id="d-port" class="port-num"></span><span id="d-proto" class="proto-tag"></span><span id="d-pills"></span></div>
      <h2 id="d-title"></h2>
    </div>
    <div class="drawer-actions">
      <a id="d-open" class="icon-btn ghost open-btn" target="_blank" rel="noopener noreferrer" hidden></a>
      <button type="button" id="drawer-close" class="icon-btn ghost" aria-label="Close details">✕</button>
    </div>
  </div>
  <div class="drawer-body">
    <label class="field">
      <span class="field-label">Name</span>
      <input type="text" id="d-name" maxlength="100" autocomplete="off">
    </label>
    <div class="field">
      <span class="field-label">Category</span>
      <button type="button" id="d-cat-btn" class="cat-btn"></button>
    </div>
    <label class="field">
      <span class="field-label">Notes</span>
      <textarea id="d-notes" maxlength="4000" placeholder="What is this, who owns it, why is it exposed…"></textarea>
      <span class="field-hint">Saved when you leave the field</span>
    </label>
    <label class="switch-row"><input type="checkbox" id="d-ignored"> Ignore this port</label>
    <div id="d-other-names" class="callout" hidden></div>
    <section>
      <h3>Binds</h3>
      <ul id="d-binds" class="bind-list"></ul>
    </section>
    <section>
      <h3>Process</h3>
      <pre id="d-process" class="code"></pre>
    </section>
    <section>
      <div class="section-head"><h3>Raw ss output</h3><button type="button" id="d-copy" class="btn btn-sm">Copy</button></div>
      <pre id="d-raw" class="code"></pre>
    </section>
    <section>
      <h3>Seen</h3>
      <dl class="seen-list">
        <dt>First seen</dt><dd id="d-first"></dd>
        <dt>Last seen</dt><dd id="d-last"></dd>
      </dl>
    </section>
  </div>
</aside>

<div id="popover" class="popover" role="dialog" aria-label="Choose category" hidden></div>

<div id="help" class="modal-wrap" hidden>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="help-title">
    <div class="modal-head">
      <h2 id="help-title">Keyboard shortcuts</h2>
      <button type="button" id="help-close" class="icon-btn ghost" aria-label="Close">✕</button>
    </div>
    <div class="keys">
      <kbd class="key">/</kbd><span>Focus search</span>
      <kbd class="key">j</kbd><span>Next row</span>
      <kbd class="key">k</kbd><span>Previous row</span>
      <kbd class="key">Enter</kbd><span>Open details</span>
      <kbd class="key">e</kbd><span>Rename focused row</span>
      <kbd class="key">i</kbd><span>Ignore / unignore focused row</span>
      <kbd class="key">x</kbd><span>Select focused row</span>
      <kbd class="key">Esc</kbd><span>Close panel, then clear search</span>
      <kbd class="key">?</kbd><span>Show this list</span>
    </div>
  </div>
</div>

<div id="toasts" class="toasts" aria-live="polite"></div>

<script>
(function () {
  'use strict';

  // ── State ─────────────────────────────────────────────────────────────────
  const STORE_KEY = 'pi-state';
  const CARDS = ['total', 'unnamed', 'public', 'new', 'ignored'];
  const SCOPE_RANK = { public: 0, tailscale: 1, lan: 2, specific: 3, loopback: 4 };
  const SORT_KEYS = ['port', 'proto', 'name', 'category', 'binds', 'last_seen'];
  const DEFAULT_FILTERS = { card: 'total', proto: 'all', cats: [], scope: '' };

  const state = {
    data: null,
    groups: new Map(),      // primary_key -> group
    byId: new Map(),        // 'tcp-22' -> primary_key
    categories: [],
    filters: Object.assign({}, DEFAULT_FILTERS, { cats: [] }),
    query: '',
    sort: { key: 'port', dir: 'asc' },
    selected: new Set(),    // primary keys
    focusedKey: null,
    visible: [],            // primary keys in display order
    rowEls: new Map(),      // primary_key -> <tr>
    relEls: [],             // [element, iso] pairs refreshed every minute
    drawerKey: null,
    editing: false,
    pendingRender: false,
    scanning: false,
    clockSkew: 0,
    popover: null,          // { anchor, onClose }
    lastFocus: null,
  };

  const $ = (id) => document.getElementById(id);
  const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

  // ── Persistence ───────────────────────────────────────────────────────────
  function loadPrefs() {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(STORE_KEY) || 'null'); } catch (e) { saved = null; }
    if (!saved || typeof saved !== 'object') return;
    const f = saved.filters || {};
    if (CARDS.includes(f.card)) state.filters.card = f.card;
    if (['all', 'tcp', 'udp'].includes(f.proto)) state.filters.proto = f.proto;
    if (Array.isArray(f.cats)) state.filters.cats = f.cats.filter((c) => typeof c === 'string');
    if (['', 'public', 'lan', 'loopback', 'tailscale'].includes(f.scope)) state.filters.scope = f.scope;
    const s = saved.sort || {};
    if (SORT_KEYS.includes(s.key)) state.sort.key = s.key;
    if (s.dir === 'asc' || s.dir === 'desc') state.sort.dir = s.dir;
  }

  function savePrefs() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify({ filters: state.filters, sort: state.sort })); } catch (e) {}
  }

  // ── DOM helpers (user data only ever goes through textContent) ────────────
  function h(tag, props, children) {
    const node = document.createElement(tag);
    if (props) {
      for (const k of Object.keys(props)) {
        const v = props[k];
        if (v === undefined || v === null || v === false) continue;
        if (k === 'text') node.textContent = v;
        else if (k === 'className') node.className = v;
        else if (k === 'dataset') Object.assign(node.dataset, v);
        else if (k in node && typeof v !== 'string') node[k] = v;
        else node.setAttribute(k, v === true ? '' : v);
      }
    }
    if (children) for (const c of children) if (c) node.append(c);
    return node;
  }

  const OPEN_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg>';

  // The server probed http://localhost:<port>; open it on the host this page was loaded
  // from, so the link also works from another machine. Loopback-only ports stay on localhost.
  function httpUrl(g) {
    const loopbackOnly = g.scopes.length > 0 && g.scopes.every((s) => s === 'loopback');
    let host = loopbackOnly ? 'localhost' : (location.hostname || 'localhost');
    if (host.includes(':') && !host.startsWith('[')) host = '[' + host + ']';
    return 'http://' + host + ':' + g.port + '/';
  }

  function fillOpenLink(a, g) {
    const url = httpUrl(g);
    a.href = url;
    a.title = 'Open ' + url + ' in a new tab';
    a.setAttribute('aria-label', 'Open port ' + g.port + ' in a new tab');
    a.innerHTML = OPEN_ICON;
    return a;
  }

  function hashString(s) {
    let x = 5381;
    for (let i = 0; i < s.length; i++) x = ((x << 5) + x + s.charCodeAt(i)) | 0;
    return Math.abs(x);
  }

  function categoryChip(name, extraClass) {
    if (!name) return h('span', { className: 'chip chip-empty ' + (extraClass || ''), text: '+ Category' });
    return h('span', { className: 'chip cat-c' + (hashString(name) % 10) + ' ' + (extraClass || ''), text: name });
  }

  // ── Time ──────────────────────────────────────────────────────────────────
  function nowMs() { return Date.now() + state.clockSkew; }

  function relTime(iso) {
    const t = Date.parse(iso);
    if (!iso || isNaN(t)) return '—';
    const s = Math.max(0, Math.floor((nowMs() - t) / 1000));
    if (s < 45) return 'just now';
    const m = Math.floor(s / 60);
    if (m < 60) return Math.max(1, m) + ' min ago';
    const hrs = Math.floor(m / 60);
    if (hrs < 24) return hrs + 'h ago';
    const d = Math.floor(hrs / 24);
    if (d < 30) return d + 'd ago';
    const mo = Math.floor(d / 30);
    if (mo < 12) return mo + ' mo ago';
    return Math.floor(d / 365) + 'y ago';
  }

  function absTime(iso) {
    const d = new Date(iso);
    if (!iso || isNaN(d.getTime())) return '—';
    const p = (n) => String(n).padStart(2, '0');
    return p(d.getDate()) + '/' + p(d.getMonth() + 1) + '/' + d.getFullYear() + ' - ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function relNode(tag, iso, className) {
    const node = h(tag, { className: className, text: relTime(iso), title: absTime(iso) });
    state.relEls.push([node, iso]);
    return node;
  }

  function tickTimes() {
    state.relEls = state.relEls.filter(([node]) => node.isConnected);
    for (const [node, iso] of state.relEls) node.textContent = relTime(iso);
    renderScanned();
  }

  // ── API ───────────────────────────────────────────────────────────────────
  async function api(method, url, body) {
    const opts = { method: method, headers: { 'Accept': 'application/json' } };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    let res;
    try { res = await fetch(url, opts); }
    catch (e) { throw new Error('Network error: the server could not be reached'); }
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (e) { json = null; }
    if (!res.ok) throw new Error((json && json.error) || ('Request failed (HTTP ' + res.status + ')'));
    return json;
  }

  // ── Toasts ────────────────────────────────────────────────────────────────
  function toast(message, opts) {
    opts = opts || {};
    const box = $('toasts');
    const node = h('div', { className: 'toast' + (opts.error ? ' toast-error' : ''), role: opts.error ? 'alert' : 'status' });
    node.append(h('span', { className: 'toast-msg', text: message }));
    let timer = null;
    const dismiss = () => { clearTimeout(timer); node.remove(); };
    if (opts.undo) {
      node.append(h('button', { type: 'button', className: 'btn btn-sm', text: 'Undo', onclick: () => { dismiss(); opts.undo(); } }));
    }
    node.append(h('button', { type: 'button', className: 'icon-btn ghost', text: '✕', 'aria-label': 'Dismiss', onclick: dismiss }));
    box.append(node);
    while (box.children.length > 4) box.firstElementChild.remove();
    timer = setTimeout(dismiss, opts.duration || (opts.error ? 8000 : 5000));
  }
  const toastError = (msg) => toast(msg, { error: true });

  // ── Data ──────────────────────────────────────────────────────────────────
  function applyPayload(p) {
    const oldIds = new Map();
    for (const [key, g] of state.groups) oldIds.set(key, g.id);

    state.data = p;
    state.categories = p.categories || [];
    state.groups = new Map();
    state.byId = new Map();
    for (const g of p.groups) {
      g._search = [
        g.port, g.proto, g.name, g.auto_name, g.category, g.notes, g.process, g.process_full,
        g.binds.map((b) => b.address + ' ' + b.scope_label).join(' '),
        g.other_names.map((o) => o.name).join(' '),
      ].join(' ').toLowerCase();
      state.groups.set(g.primary_key, g);
      state.byId.set(g.id, g.primary_key);
    }
    const srv = Date.parse(p.server_time);
    if (!isNaN(srv)) state.clockSkew = srv - Date.now();

    // Primary keys can change between scans; follow groups by their stable id.
    const remap = (key) => {
      if (!key) return null;
      if (state.groups.has(key)) return key;
      const id = oldIds.get(key);
      return (id && state.byId.get(id)) || null;
    };
    state.selected = new Set([...state.selected].map(remap).filter(Boolean));
    state.focusedKey = remap(state.focusedKey);
    if (state.drawerKey) {
      state.drawerKey = remap(state.drawerKey);
      if (!state.drawerKey) closeDrawer();
    }
    $('loading').hidden = true;
    renderAll();
  }

  async function loadPorts() {
    try {
      const p = await api('GET', 'api/ports');
      applyPayload(p);
      openFromHash();
      const last = Date.parse(p.last_scan_at);
      if (!p.scan_error && (isNaN(last) || nowMs() - last > p.stale_after_seconds * 1000)) rescan(true);
    } catch (e) {
      $('loading').textContent = 'Could not load ports: ' + e.message;
      toastError(e.message);
    }
  }

  async function rescan(silent) {
    if (state.scanning) return;
    state.scanning = true;
    const btn = $('rescan-btn');
    btn.classList.add('is-loading');
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.querySelector('.rescan-label').textContent = 'Scanning…';
    try {
      const p = await api('POST', 'api/rescan');
      applyPayload(p);
      if (p.scan_error) toastError('Scan failed: ' + p.scan_error);
      else if (!silent) toast('Scan complete · ' + p.groups.length + ' ports');
    } catch (e) {
      toastError(e.message);
    } finally {
      state.scanning = false;
      btn.classList.remove('is-loading');
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
      btn.querySelector('.rescan-label').textContent = 'Rescan';
    }
  }

  // ── Saving + undo ─────────────────────────────────────────────────────────
  const fieldOfBind = (b, f) => (f === 'ignored' ? !!b.ignored : (b[f] || ''));

  async function save(groups, changes, opts) {
    opts = opts || {};
    const fields = Object.keys(changes);
    const keys = [];
    const before = [];
    for (const g of groups) {
      for (const b of g.binds) {
        keys.push(b.key);
        const prev = {};
        for (const f of fields) prev[f] = fieldOfBind(b, f);
        before.push({ key: b.key, values: prev });
      }
    }
    if (!keys.length) return;
    // Optimistic update so the row reflects the change immediately
    for (const g of groups) {
      for (const f of fields) g[f] = changes[f];
    }
    renderAll();
    try {
      const res = await api('POST', 'api/ports/bulk', { keys: keys, changes: changes });
      applyPayload(res.data);
      toast(opts.message || 'Saved', { undo: () => undo(before) });
    } catch (e) {
      toastError('Not saved: ' + e.message);
      refresh();
    }
  }

  async function undo(before) {
    const buckets = new Map();
    for (const item of before) {
      const sig = JSON.stringify(item.values);
      if (!buckets.has(sig)) buckets.set(sig, { changes: item.values, keys: [] });
      buckets.get(sig).keys.push(item.key);
    }
    try {
      let last = null;
      for (const b of buckets.values()) last = await api('POST', 'api/ports/bulk', b);
      if (last) applyPayload(last.data);
      toast('Change undone');
    } catch (e) {
      toastError('Undo failed: ' + e.message);
      refresh();
    }
  }

  async function refresh() {
    try { applyPayload(await api('GET', 'api/ports')); } catch (e) { /* already reported */ }
  }

  const label = (g) => g.port + '/' + g.proto;

  function setName(g, name) {
    name = name.trim();
    if (name === g.name) return;
    save([g], { name: name }, { message: name ? 'Renamed ' + label(g) + ' to ' + name : 'Name cleared on ' + label(g) });
  }

  function setNotes(g, notes) {
    if (notes.trim() === (g.notes || '')) return;
    save([g], { notes: notes }, { message: 'Notes saved' });
  }

  function setCategory(groups, category) {
    const msg = category ? 'Category set to ' + category : 'Category cleared';
    save(groups, { category: category }, { message: groups.length > 1 ? msg + ' on ' + groups.length + ' ports' : msg });
  }

  function setIgnored(groups, ignored) {
    const what = groups.length > 1 ? groups.length + ' ports' : label(groups[0]);
    save(groups, { ignored: ignored }, { message: (ignored ? 'Ignored ' : 'Unignored ') + what });
  }

  // ── Filtering + sorting ───────────────────────────────────────────────────
  function matchesCard(g, card) {
    if (card === 'ignored') return g.ignored;
    if (g.ignored) return false;
    if (card === 'unnamed') return !g.name;
    if (card === 'public') return g.has_public;
    if (card === 'new') return g.is_new;
    return true;
  }

  function passes(g, terms) {
    const f = state.filters;
    if (!matchesCard(g, f.card)) return false;
    if (f.proto !== 'all' && g.proto !== f.proto) return false;
    if (f.cats.length && !f.cats.includes(g.category || '')) return false;
    if (f.scope && !g.scopes.includes(f.scope)) return false;
    for (const t of terms) if (!g._search.includes(t)) return false;
    return true;
  }

  function scopeRank(g) {
    return g.scopes.length ? Math.min(...g.scopes.map((s) => SCOPE_RANK[s])) : 9;
  }

  function compare(a, b) {
    const { key, dir } = state.sort;
    const m = dir === 'asc' ? 1 : -1;
    let r = 0;
    if (key === 'name' || key === 'category') {
      // Empty values always go last, whatever the direction
      if (!a[key] !== !b[key]) return a[key] ? -1 : 1;
      r = collator.compare(a[key] || '', b[key] || '');
    } else if (key === 'port') r = a.port - b.port;
    else if (key === 'proto') r = collator.compare(a.proto, b.proto);
    else if (key === 'binds') r = scopeRank(a) - scopeRank(b) || b.binds.length - a.binds.length;
    else if (key === 'last_seen') r = Date.parse(a.last_seen) - Date.parse(b.last_seen);
    return (r * m) || (a.port - b.port) || collator.compare(a.proto, b.proto);
  }

  function filtersActive() {
    const f = state.filters;
    return !!(state.query || f.card !== 'total' || f.proto !== 'all' || f.cats.length || f.scope);
  }

  function resetFilters() {
    state.filters = Object.assign({}, DEFAULT_FILTERS, { cats: [] });
    state.query = '';
    $('search').value = '';
    savePrefs();
    renderAll();
  }

  // ── Rendering ─────────────────────────────────────────────────────────────
  function renderAll() {
    if (!state.data) return;
    renderHeader();
    renderStats();
    renderToolbar();
    renderTable();
    renderBulkBar();
    if (state.drawerKey) fillDrawer();
    if (state.popover && !state.popover.anchor.isConnected) closePopover();
  }

  function renderScanned() {
    const node = $('scanned-at');
    const last = state.data && state.data.last_scan_at;
    node.textContent = last ? 'Scanned ' + relTime(last) : 'Not scanned yet';
    const every = state.data ? Math.round(state.data.rescan_interval_seconds / 3600) : 0;
    node.title = (last ? absTime(last) + ' · ' : '') + (every ? 'auto-rescan every ' + every + 'h' : '');
  }

  function renderHeader() {
    $('hostname').textContent = state.data.hostname || '';
    renderScanned();
    const err = $('scan-error');
    err.hidden = !state.data.scan_error;
    err.textContent = state.data.scan_error ? 'Last scan failed: ' + state.data.scan_error : '';
  }

  function renderStats() {
    const s = state.data.stats;
    for (const card of CARDS) {
      $('stat-' + card).textContent = s[card];
    }
    document.querySelectorAll('.stat').forEach((btn) => {
      btn.setAttribute('aria-pressed', String(btn.dataset.card === state.filters.card));
    });
  }

  function renderToolbar() {
    const f = state.filters;
    document.querySelectorAll('.segmented button').forEach((btn) => {
      btn.setAttribute('aria-pressed', String(btn.dataset.proto === f.proto));
    });
    $('scope-filter').value = f.scope;
    const countBadge = $('cat-filter-count');
    countBadge.hidden = !f.cats.length;
    countBadge.textContent = f.cats.length;
    $('reset-filters').hidden = !filtersActive();
    document.querySelectorAll('.ports th[data-sort]').forEach((th) => {
      const active = th.dataset.sort === state.sort.key;
      if (active) th.setAttribute('aria-sort', state.sort.dir === 'asc' ? 'ascending' : 'descending');
      else th.removeAttribute('aria-sort');
      th.querySelector('.sort-arrow').textContent = active ? (state.sort.dir === 'asc' ? '▲' : '▼') : '';
    });
  }

  function renderTable() {
    if (state.editing) { state.pendingRender = true; return; }
    state.pendingRender = false;
    const terms = state.query.toLowerCase().split(/\s+/).filter(Boolean);
    const all = [...state.groups.values()];
    const visible = all.filter((g) => passes(g, terms)).sort(compare);
    state.visible = visible.map((g) => g.primary_key);

    // Selection only ever covers visible rows
    const visibleSet = new Set(state.visible);
    for (const key of [...state.selected]) if (!visibleSet.has(key)) state.selected.delete(key);
    if (state.focusedKey && !visibleSet.has(state.focusedKey)) state.focusedKey = null;

    state.relEls = state.relEls.filter(([node]) => !node.closest || !node.closest('#rows'));
    state.rowEls = new Map();
    const frag = document.createDocumentFragment();
    for (const g of visible) {
      const tr = renderRow(g);
      state.rowEls.set(g.primary_key, tr);
      frag.append(tr);
    }
    const tbody = $('rows');
    tbody.replaceChildren(frag);

    // Result count + empty state
    const cardTotal = all.filter((g) => matchesCard(g, state.filters.card)).length;
    const cardName = state.filters.card === 'total' ? '' : ' ' + state.filters.card;
    $('result-count').textContent = visible.length + ' of ' + cardTotal + cardName + ' port' + (cardTotal === 1 ? '' : 's');
    const empty = $('empty');
    empty.hidden = visible.length > 0;
    if (!visible.length) {
      const nothing = all.length === 0;
      $('empty-title').textContent = nothing ? 'No listening ports recorded yet' : 'No ports match these filters';
      $('empty-sub').textContent = nothing ? 'Run a scan to read ss -tulpn.' : 'Try another search, or clear the filters to see everything.';
      $('empty-clear').hidden = nothing || !filtersActive();
    }
    renderSelectAll();
    if (state.popover && !state.popover.anchor.isConnected) closePopover();
  }

  function renderRow(g) {
    const selected = state.selected.has(g.primary_key);
    const tr = h('tr', {
      className: [
        g.is_online ? '' : 'is-offline',
        selected ? 'is-selected' : '',
        state.focusedKey === g.primary_key ? 'is-focused' : '',
      ].join(' ').trim(),
      tabIndex: state.focusedKey === g.primary_key ? 0 : -1,
      'aria-label': 'Port ' + label(g) + (g.name ? ', ' + g.name : ', unnamed'),
    });
    tr._key = g.primary_key;

    const cb = h('input', { type: 'checkbox', className: 'row-check', 'aria-label': 'Select port ' + label(g) });
    cb.checked = selected;
    tr.append(h('td', { className: 'col-check' }, [cb]));
    tr.append(h('td', { className: 'col-port' }, [h('span', { className: 'port-num', text: String(g.port) })]));
    tr.append(h('td', { className: 'col-proto' }, [h('span', { className: 'proto-tag', text: g.proto })]));

    const nameBtn = h('button', {
      type: 'button',
      className: 'name-btn' + (g.name ? '' : ' is-unnamed'),
      text: g.name || 'Unnamed: click to name',
      title: g.name ? 'Click to rename' : 'Click to name this service',
    });
    const line = h('div', { className: 'svc-line' }, [nameBtn]);
    if (g.is_new && !g.ignored) line.append(h('span', { className: 'pill pill-new', text: 'new' }));
    if (!g.is_online) line.append(h('span', { className: 'pill pill-offline', text: 'offline' }));
    if (g.ignored) line.append(h('span', { className: 'pill pill-ignored', text: 'ignored' }));
    const proc = h('div', { className: 'svc-proc', text: g.process || 'process hidden', title: g.process_full || 'Run as root to see process names' });
    tr.append(h('td', { className: 'col-service' }, [line, proc]));

    const catBtn = h('button', { type: 'button', className: 'cat-btn', 'aria-label': 'Category: ' + (g.category || 'none') + '. Change category' }, [categoryChip(g.category)]);
    tr.append(h('td', { className: 'col-cat' }, [catBtn]));

    const chips = h('div', { className: 'bind-chips' });
    for (const b of g.binds) chips.append(bindChip(b));
    tr.append(h('td', { className: 'col-binds' }, [chips]));

    tr.append(h('td', { className: 'col-seen' }, [relNode('span', g.last_seen, 'seen')]));
    tr.append(h('td', { className: 'col-more' }, [
      g.http && fillOpenLink(h('a', { className: 'icon-btn ghost open-btn', target: '_blank', rel: 'noopener noreferrer' }), g),
      h('button', { type: 'button', className: 'icon-btn ghost more-btn', text: '⋯', 'aria-label': 'Details for port ' + label(g) }),
    ]));
    return tr;
  }

  // auto_ignored = dedup's duplicate marker; ignored = the user's choice
  function bindStatus(b) {
    const notes = [];
    if (b.auto_ignored) notes.push('duplicate bind');
    if (b.ignored) notes.push('ignored');
    return notes;
  }

  function bindTitle(b) {
    const notes = [b.address, b.scope_label].concat(bindStatus(b));
    if (!b.online) notes.push('offline');
    return notes.join(' · ');
  }

  function bindChip(b) {
    return h('span', {
      className: 'chip bind scope-' + b.scope + (b.ignored || b.auto_ignored ? ' is-faded' : '') + (b.online ? '' : ' is-offline'),
      text: b.address,
      title: bindTitle(b),
    });
  }

  function renderSelectAll() {
    const all = $('select-all');
    const n = state.visible.filter((k) => state.selected.has(k)).length;
    all.checked = n > 0 && n === state.visible.length;
    all.indeterminate = n > 0 && n < state.visible.length;
  }

  function renderBulkBar() {
    const n = state.selected.size;
    $('bulk-bar').hidden = n === 0;
    document.body.classList.toggle('has-bulk', n > 0);
    $('bulk-count').textContent = n + ' selected';
  }

  function updateRowSelection(key) {
    const tr = state.rowEls.get(key);
    if (tr) {
      const on = state.selected.has(key);
      tr.classList.toggle('is-selected', on);
      tr.querySelector('.row-check').checked = on;
    }
    renderSelectAll();
    renderBulkBar();
  }

  function toggleSelected(key, on) {
    if (on === undefined) on = !state.selected.has(key);
    if (on) state.selected.add(key); else state.selected.delete(key);
    updateRowSelection(key);
  }

  // ── Focus (j/k) ───────────────────────────────────────────────────────────
  function setFocus(key, opts) {
    const prev = state.rowEls.get(state.focusedKey);
    if (prev) { prev.classList.remove('is-focused'); prev.tabIndex = -1; }
    state.focusedKey = key;
    const tr = state.rowEls.get(key);
    if (!tr) return;
    tr.classList.add('is-focused');
    tr.tabIndex = 0;
    if (!opts || opts.focus !== false) {
      tr.focus({ preventScroll: true });
      tr.scrollIntoView({ block: 'nearest' });
    }
  }

  function moveFocus(delta) {
    if (!state.visible.length) return;
    const i = state.visible.indexOf(state.focusedKey);
    const next = i === -1 ? (delta > 0 ? 0 : state.visible.length - 1) : Math.min(state.visible.length - 1, Math.max(0, i + delta));
    setFocus(state.visible[next]);
  }

  function focusRowElement(key) {
    const tr = state.rowEls.get(key);
    if (tr) tr.focus({ preventScroll: true });
  }

  // ── Inline name edit ──────────────────────────────────────────────────────
  function startNameEdit(key) {
    const g = state.groups.get(key);
    const tr = state.rowEls.get(key);
    if (!g || !tr || state.editing) return;
    setFocus(key, { focus: false });
    const btn = tr.querySelector('.name-btn');
    const input = h('input', {
      type: 'text', className: 'name-input', maxLength: 100, value: g.name,
      placeholder: g.auto_name || 'Service name', 'aria-label': 'Name for port ' + label(g),
    });
    btn.replaceWith(input);
    state.editing = true;
    input.focus();
    input.select();
    let done = false;
    const finish = (commit) => {
      if (done) return;
      done = true;
      state.editing = false;
      const value = input.value;
      if (commit) setName(g, value);
      renderTable();
      focusRowElement(key);
    };
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); finish(true); }
      else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); finish(false); }
    });
    input.addEventListener('blur', () => finish(true));
  }

  // ── Category popover ──────────────────────────────────────────────────────
  function openCategoryPopover(anchor, groups) {
    if (state.popover && state.popover.anchor === anchor) { closePopover(); return; }
    closePopover();
    const pop = $('popover');
    state.popover = { anchor: anchor, groups: groups };
    anchor.setAttribute('aria-expanded', 'true');
    buildCategoryPopover(groups);
    pop.hidden = false;
    positionPopover();
    const current = pop.querySelector('.pop-item.is-current') || pop.querySelector('.pop-item');
    if (current) current.focus();
  }

  function buildCategoryPopover(groups) {
    const pop = $('popover');
    const current = new Set(groups.map((g) => g.category || ''));
    const single = current.size === 1 ? [...current][0] : null;
    const items = [];

    const item = (labelText, chipClass, onPick, isCurrent) => {
      const btn = h('button', { type: 'button', className: 'pop-item' + (isCurrent ? ' is-current' : '') }, [
        chipClass ? h('span', { className: 'dot ' + chipClass }) : null,
        h('span', { className: 'pop-label', text: labelText }),
        isCurrent ? h('span', { className: 'pop-check', text: '✓', 'aria-hidden': 'true' }) : null,
      ]);
      btn.addEventListener('click', onPick);
      return btn;
    };

    for (const c of state.categories) {
      const row = h('div', { className: 'pop-row' }, [
        item(c.name, 'cat-c' + (hashString(c.name) % 10), () => { closePopover(); setCategory(groups, c.name); }, single === c.name),
      ]);
      if (!c.builtin && c.count === 0) {
        row.append(h('button', {
          type: 'button', className: 'icon-btn ghost pop-del', text: '✕', title: 'Delete unused category',
          'aria-label': 'Delete category ' + c.name, onclick: (e) => { e.stopPropagation(); deleteCategory(c.name); },
        }));
      }
      items.push(row);
    }
    if (!current.has('') || current.size > 1) {
      items.push(h('div', { className: 'pop-row' }, [item('No category', null, () => { closePopover(); setCategory(groups, ''); }, false)]));
    }
    items.push(h('div', { className: 'pop-sep' }));
    const newBtn = h('button', { type: 'button', className: 'pop-item pop-new', text: '＋ New category' });
    newBtn.addEventListener('click', () => {
      const input = h('input', { type: 'text', className: 'pop-input', maxLength: 48, placeholder: 'Category name', 'aria-label': 'New category name' });
      const hint = h('div', { className: 'pop-hint', text: 'Enter to create and assign · Esc to cancel' });
      newBtn.replaceWith(input, hint);
      input.focus();
      input.addEventListener('keydown', async (e) => {
        if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closePopover(); return; }
        if (e.key !== 'Enter') return;
        e.preventDefault();
        const name = input.value.trim();
        if (!name) return;
        input.disabled = true;
        try {
          const res = await api('POST', 'api/categories', { name: name });
          state.categories = res.categories;
          closePopover();
          setCategory(groups, res.name);
        } catch (err) {
          input.disabled = false;
          input.focus();
          toastError(err.message);
        }
      });
    });
    items.push(newBtn);
    $('popover').replaceChildren(...items);
  }

  function positionPopover() {
    const pop = $('popover');
    const r = state.popover.anchor.getBoundingClientRect();
    const w = pop.offsetWidth;
    const hgt = pop.offsetHeight;
    let left = Math.min(r.left, window.innerWidth - w - 8);
    let top = r.bottom + 4;
    if (top + hgt > window.innerHeight - 8 && r.top - hgt - 4 > 8) top = r.top - hgt - 4;
    pop.style.left = Math.max(8, left) + 'px';
    pop.style.top = Math.max(8, top) + 'px';
  }

  function closePopover() {
    if (!state.popover) return;
    const anchor = state.popover.anchor;
    state.popover = null;
    const pop = $('popover');
    const hadFocus = pop.contains(document.activeElement);
    pop.hidden = true;
    pop.replaceChildren();
    anchor.removeAttribute('aria-expanded');
    if (hadFocus && anchor.isConnected) anchor.focus();
  }

  async function deleteCategory(name) {
    try {
      const res = await api('DELETE', 'api/categories/' + encodeURIComponent(name));
      state.categories = res.categories;
      state.filters.cats = state.filters.cats.filter((c) => c !== name);
      if (state.popover) { buildCategoryPopover(state.popover.groups); positionPopover(); }
      if (!$('cat-filter-menu').hidden) renderCategoryFilterMenu();
      renderToolbar();
      toast('Deleted category ' + name);
    } catch (e) {
      toastError(e.message);
    }
  }

  // ── Category filter menu ──────────────────────────────────────────────────
  function renderCategoryFilterMenu() {
    const menu = $('cat-filter-menu');
    const counts = new Map();
    for (const g of state.groups.values()) {
      if (!matchesCard(g, state.filters.card)) continue;
      counts.set(g.category || '', (counts.get(g.category || '') || 0) + 1);
    }
    const entries = state.categories.map((c) => c.name).filter((n) => counts.has(n) || state.filters.cats.includes(n));
    entries.push('');
    const rows = entries.map((name) => {
      const cb = h('input', { type: 'checkbox' });
      cb.checked = state.filters.cats.includes(name);
      cb.addEventListener('change', () => {
        const set = new Set(state.filters.cats);
        if (cb.checked) set.add(name); else set.delete(name);
        state.filters.cats = [...set];
        savePrefs();
        renderToolbar();
        renderTable();
        renderBulkBar();
      });
      return h('label', null, [
        cb,
        name ? h('span', { className: 'dot cat-c' + (hashString(name) % 10) }) : h('span', { className: 'dot', style: 'color: var(--muted)' }),
        h('span', { text: name || 'Uncategorized' }),
        h('span', { className: 'menu-count', text: String(counts.get(name) || 0) }),
      ]);
    });
    const clear = h('button', { type: 'button', className: 'btn btn-link btn-sm', text: 'Clear', onclick: () => {
      state.filters.cats = []; savePrefs(); renderAll(); renderCategoryFilterMenu();
    } });
    menu.replaceChildren(...rows, h('div', { className: 'menu-foot' }, [clear]));
  }

  function toggleCategoryMenu(open) {
    const menu = $('cat-filter-menu');
    const btn = $('cat-filter-btn');
    if (open === undefined) open = menu.hidden;
    if (open) renderCategoryFilterMenu();
    menu.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    if (open) { const first = menu.querySelector('input'); if (first) first.focus(); }
  }

  // ── Drawer ────────────────────────────────────────────────────────────────
  function openDrawer(key) {
    const g = state.groups.get(key);
    if (!g) return;
    closePopover();
    if (!state.drawerKey) state.lastFocus = document.activeElement;
    state.drawerKey = key;
    fillDrawer();
    $('drawer').classList.add('open');
    $('drawer-backdrop').classList.add('open');
    history.replaceState(null, '', '#' + g.id);
    $('drawer').focus();
  }

  function closeDrawer() {
    if (!$('drawer').classList.contains('open')) { state.drawerKey = null; return; }
    // Blur first so autosave-on-blur fires while the group is still known
    if ($('drawer').contains(document.activeElement)) document.activeElement.blur();
    closePopover();
    const key = state.drawerKey;
    state.drawerKey = null;
    $('drawer').classList.remove('open');
    $('drawer-backdrop').classList.remove('open');
    history.replaceState(null, '', location.pathname + location.search);
    if (key && state.rowEls.has(key)) setFocus(key);
    else if (state.lastFocus && state.lastFocus.isConnected) state.lastFocus.focus();
  }

  function openFromHash() {
    const id = decodeURIComponent(location.hash.replace(/^#/, ''));
    const key = id && state.byId.get(id);
    if (key) openDrawer(key);
    else if (state.drawerKey) closeDrawer();
  }

  function fillDrawer() {
    const g = state.groups.get(state.drawerKey);
    if (!g) return;
    $('d-port').textContent = g.port;
    $('d-proto').textContent = g.proto;
    const pills = $('d-pills');
    pills.replaceChildren();
    if (g.is_new) pills.append(h('span', { className: 'pill pill-new', text: 'new' }));
    if (!g.is_online) pills.append(h('span', { className: 'pill pill-offline', text: 'offline' }));
    if (g.ignored) pills.append(h('span', { className: 'pill pill-ignored', text: 'ignored' }));
    $('d-title').textContent = g.name || 'Unnamed service';
    const open = $('d-open');
    open.hidden = !g.http;
    if (g.http) fillOpenLink(open, g);

    const name = $('d-name');
    if (document.activeElement !== name) name.value = g.name;
    name.placeholder = g.auto_name || 'e.g. Nginx, Home Assistant';
    const notes = $('d-notes');
    if (document.activeElement !== notes) notes.value = g.notes || '';
    $('d-ignored').checked = g.ignored;

    const catBtn = $('d-cat-btn');
    catBtn.replaceChildren(categoryChip(g.category));
    catBtn.setAttribute('aria-label', 'Category: ' + (g.category || 'none') + '. Change category');

    const other = $('d-other-names');
    other.hidden = !g.other_names.length;
    other.replaceChildren();
    if (g.other_names.length) {
      other.append(h('strong', { text: 'Binds have different names. ' }), document.createTextNode('Showing "' + g.name + '". Also: '));
      g.other_names.forEach((o, i) => {
        if (i) other.append(document.createTextNode(', '));
        other.append(h('span', { text: '"' + o.name + '"' }), h('span', { className: 'mono', text: ' on ' + o.address }));
      });
      other.append(document.createTextNode('. Saving the name here applies it to every bind.'));
    }

    const list = $('d-binds');
    list.replaceChildren(...g.binds.map((b) => {
      const note = [];
      if (b.key === g.primary_key) note.push('primary');
      note.push(...bindStatus(b));
      note.push(b.online ? 'online' : 'offline · last ' + relTime(b.last_seen));
      return h('li', null, [
        h('span', { className: 'chip bind scope-' + b.scope + (b.ignored || b.auto_ignored ? ' is-faded' : ''), text: b.scope_label }),
        h('span', { className: 'bind-addr', text: b.address }),
        h('span', { className: 'bind-note', text: note.join(' · ') }),
      ]);
    }));

    const processes = [...new Set(g.binds.map((b) => b.process).filter(Boolean))];
    $('d-process').textContent = processes.length ? processes.join('\n') : 'Process hidden: run Port Inventory as root to see process names and PIDs.';
    $('d-raw').textContent = g.binds.map((b) => b.raw).filter(Boolean).join('\n') || '—';
    $('d-first').textContent = absTime(g.first_seen) + '  (' + relTime(g.first_seen) + ')';
    $('d-last').textContent = absTime(g.last_seen) + '  (' + relTime(g.last_seen) + ')';
  }

  // navigator.clipboard only exists in secure contexts (https, localhost); over
  // plain-http LAN access fall back to a hidden textarea + execCommand('copy').
  function copyWithTextarea(text) {
    const back = document.activeElement;
    const ta = h('textarea', { readonly: true, tabindex: '-1', 'aria-hidden': 'true', style: 'position:fixed;top:0;left:0;width:1px;height:1px;opacity:0' });
    ta.value = text;
    document.body.append(ta);
    ta.focus();
    ta.select();
    let ok = false;
    try { ok = typeof document.execCommand === 'function' && document.execCommand('copy') === true; }
    catch (e) { ok = false; }
    ta.remove();
    if (back && back.focus) back.focus();
    return ok;
  }

  async function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try { await navigator.clipboard.writeText(text); return; }
      catch (e) { /* denied or insecure context: try the fallback */ }
    }
    if (!copyWithTextarea(text)) throw new Error('Copy failed: select the text and copy it manually');
  }

  // ── Help ──────────────────────────────────────────────────────────────────
  function toggleHelp(open) {
    const help = $('help');
    if (open === undefined) open = help.hidden;
    help.hidden = !open;
    if (open) $('help-close').focus();
    else $('help-btn').focus();
  }

  // ── Events ────────────────────────────────────────────────────────────────
  function isTyping(el) {
    if (!el || el === document.body) return false;
    const tag = el.tagName;
    return tag === 'INPUT' && !['checkbox', 'radio', 'button'].includes(el.type) || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
  }

  function bindEvents() {
    $('rows').addEventListener('click', (e) => {
      const tr = e.target.closest('tr');
      if (!tr || !tr._key) return;
      const key = tr._key;
      const g = state.groups.get(key);
      if (e.target.closest('.name-input, .open-btn')) return;
      if (e.target.closest('.col-check')) {
        const cb = tr.querySelector('.row-check');
        if (e.target !== cb) cb.checked = !cb.checked;
        toggleSelected(key, cb.checked);
        setFocus(key, { focus: false });
        return;
      }
      if (e.target.closest('.name-btn')) { startNameEdit(key); return; }
      const cat = e.target.closest('.cat-btn');
      if (cat) { setFocus(key, { focus: false }); openCategoryPopover(cat, [g]); return; }
      if (window.getSelection && String(window.getSelection()).length) return;  // let people select text
      setFocus(key, { focus: false });
      openDrawer(key);
    });
    $('rows').addEventListener('focusin', (e) => {
      const tr = e.target.closest('tr');
      if (tr && tr._key && tr._key !== state.focusedKey) setFocus(tr._key, { focus: false });
    });

    $('select-all').addEventListener('change', (e) => {
      const on = e.target.checked;
      for (const key of state.visible) { if (on) state.selected.add(key); else state.selected.delete(key); }
      renderTable();
      renderBulkBar();
    });

    document.querySelectorAll('.ports th[data-sort] .sort-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const key = btn.closest('th').dataset.sort;
        if (state.sort.key === key) state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
        else state.sort = { key: key, dir: key === 'last_seen' ? 'desc' : 'asc' };
        savePrefs();
        renderToolbar();
        renderTable();
      });
    });

    document.querySelectorAll('.stat').forEach((btn) => {
      btn.addEventListener('click', () => {
        const card = btn.dataset.card;
        state.filters.card = state.filters.card === card ? 'total' : card;
        savePrefs();
        renderAll();
      });
    });
    document.querySelectorAll('.segmented button').forEach((btn) => {
      btn.addEventListener('click', () => { state.filters.proto = btn.dataset.proto; savePrefs(); renderAll(); });
    });
    $('scope-filter').addEventListener('change', (e) => { state.filters.scope = e.target.value; savePrefs(); renderAll(); });
    $('search').addEventListener('input', (e) => { state.query = e.target.value.trim(); renderToolbar(); renderTable(); renderBulkBar(); });
    $('reset-filters').addEventListener('click', resetFilters);
    $('empty-clear').addEventListener('click', resetFilters);
    $('cat-filter-btn').addEventListener('click', () => toggleCategoryMenu());

    $('rescan-btn').addEventListener('click', () => rescan(false));
    $('theme-btn').addEventListener('click', () => {
      const root = document.documentElement;
      const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('pi-theme', next); } catch (e) {}
    });
    $('help-btn').addEventListener('click', () => toggleHelp(true));
    $('help-close').addEventListener('click', () => toggleHelp(false));
    $('help').addEventListener('click', (e) => { if (e.target === $('help')) toggleHelp(false); });

    // Bulk bar
    const selectedGroups = () => [...state.selected].map((k) => state.groups.get(k)).filter(Boolean);
    $('bulk-category').addEventListener('click', (e) => openCategoryPopover(e.currentTarget, selectedGroups()));
    $('bulk-ignore').addEventListener('click', () => { const gs = selectedGroups(); if (gs.length) setIgnored(gs, true); });
    $('bulk-unignore').addEventListener('click', () => { const gs = selectedGroups(); if (gs.length) setIgnored(gs, false); });
    $('bulk-clear').addEventListener('click', () => { state.selected.clear(); renderTable(); renderBulkBar(); });

    // Drawer
    $('drawer-close').addEventListener('click', closeDrawer);
    $('drawer-backdrop').addEventListener('click', closeDrawer);
    let fieldKey = null;  // the group a drawer field was focused for
    for (const id of ['d-name', 'd-notes']) {
      $(id).addEventListener('focus', () => { fieldKey = state.drawerKey; });
    }
    $('d-name').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); e.target.blur(); } });
    $('d-name').addEventListener('blur', (e) => {
      const g = state.groups.get(fieldKey);
      if (g) setName(g, e.target.value);
    });
    $('d-notes').addEventListener('blur', (e) => {
      const g = state.groups.get(fieldKey);
      if (g) setNotes(g, e.target.value);
    });
    $('d-ignored').addEventListener('change', (e) => {
      const g = state.groups.get(state.drawerKey);
      if (g) setIgnored([g], e.target.checked);
    });
    $('d-cat-btn').addEventListener('click', (e) => {
      const g = state.groups.get(state.drawerKey);
      if (g) openCategoryPopover(e.currentTarget, [g]);
    });
    $('d-copy').addEventListener('click', async () => {
      try { await copyText($('d-raw').textContent); toast('Copied raw ss output'); }
      catch (e) { toastError(e.message); }
    });
    window.addEventListener('hashchange', openFromHash);

    // Outside clicks close menus
    document.addEventListener('mousedown', (e) => {
      if (state.popover && !$('popover').contains(e.target) && !state.popover.anchor.contains(e.target)) closePopover();
      const menu = $('cat-filter-menu');
      if (!menu.hidden && !menu.contains(e.target) && !$('cat-filter-btn').contains(e.target)) toggleCategoryMenu(false);
    });
    window.addEventListener('resize', () => { if (state.popover) positionPopover(); });
    document.querySelector('.table-scroll').addEventListener('scroll', closePopover, { passive: true });
    window.addEventListener('scroll', () => { if (state.popover && !$('drawer').contains(state.popover.anchor)) closePopover(); }, { passive: true });

    $('popover').addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      const items = [...$('popover').querySelectorAll('.pop-item')];
      const i = items.indexOf(document.activeElement);
      const next = items[Math.min(items.length - 1, Math.max(0, i + (e.key === 'ArrowDown' ? 1 : -1)))];
      if (next) { e.preventDefault(); next.focus(); }
    });

    document.addEventListener('keydown', onKeydown);
  }

  function trapFocus(e, container) {
    const items = [...container.querySelectorAll('a[href], button, input, textarea, select, [tabindex="0"]')]
      .filter((el) => !el.disabled && el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === container)) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  function onKeydown(e) {
    if (e.key === 'Tab') {
      if (!$('help').hidden) trapFocus(e, $('help'));
      else if (state.drawerKey && !state.popover) trapFocus(e, $('drawer'));
      return;
    }
    if (e.key === 'Escape') {
      if (!$('help').hidden) { toggleHelp(false); return; }
      if (state.popover) { closePopover(); return; }
      if (!$('cat-filter-menu').hidden) { toggleCategoryMenu(false); $('cat-filter-btn').focus(); return; }
      if (state.drawerKey) { closeDrawer(); return; }
      const search = $('search');
      if (search.value) { search.value = ''; state.query = ''; renderAll(); return; }
      if (document.activeElement === search) search.blur();
      return;
    }
    if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
    if (!$('help').hidden || state.popover) return;

    if (e.key === '?') { e.preventDefault(); toggleHelp(true); return; }
    if (e.key === '/') { e.preventDefault(); $('search').focus(); $('search').select(); return; }
    if (state.drawerKey) return;  // row shortcuts are off while the drawer is open

    const key = state.focusedKey;
    const onRow = e.target === document.body || (e.target.tagName === 'TR');
    switch (e.key) {
      case 'j': e.preventDefault(); moveFocus(1); break;
      case 'k': e.preventDefault(); moveFocus(-1); break;
      case 'Enter': if (key && onRow) { e.preventDefault(); openDrawer(key); } break;
      case 'e': if (key) { e.preventDefault(); startNameEdit(key); } break;
      case 'x': if (key) { e.preventDefault(); toggleSelected(key); } break;
      case 'i': {
        const g = key && state.groups.get(key);
        if (!g) break;
        e.preventDefault();
        // Keep focus moving forward when the row is about to disappear
        const i = state.visible.indexOf(key);
        const after = state.visible[i + 1] || state.visible[i - 1] || null;
        setIgnored([g], !g.ignored);
        if (!state.visible.includes(key)) setFocus(after);
        else setFocus(key);
        break;
      }
    }
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  loadPrefs();
  bindEvents();
  renderToolbar();
  loadPorts();
  setInterval(tickTimes, 60 * 1000);
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    init_db()
    run_scan()
    start_background_rescan()
    app.run(host=HOST, port=PORT)
