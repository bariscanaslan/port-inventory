"""Backend tests: migrations, scanning/dedup/grouping and every /api route.

Run from the repo root:  python -m pytest
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

import pytest

from conftest import LEGACY_DDL, PRE_AUTO_DDL, ROOT, SS_OUTPUT, make_db, read_rows, real_probe_http


def groups(payload: dict) -> dict[str, dict]:
    return {g["id"]: g for g in payload["groups"]}


def get(client) -> dict:
    r = client.get("/api/ports")
    assert r.status_code == 200
    return r.get_json()


def rescan(client) -> dict:
    r = client.post("/api/rescan")
    assert r.status_code == 200
    return r.get_json()


def bulk(client, keys, changes, status=200):
    r = client.post("/api/ports/bulk", json={"keys": keys, "changes": changes})
    assert r.status_code == status, r.get_json()
    return r.get_json()


def port_url(key: str) -> str:
    return "/api/ports/" + quote(key, safe="")


def bind(group: dict, address: str) -> dict:
    return next(b for b in group["binds"] if b["address"] == address)


# ── Shell ────────────────────────────────────────────────────────────────────

def test_shell_is_served_with_inline_favicon(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.mimetype == "text/html"
    assert b"Port Inventory" in r.data
    assert b"data:image/svg+xml;base64,PHN2Zy" in r.data


def test_mobile_touch_targets_are_44px(app):
    css = app.TEMPLATE.split("@media (max-width: 767px) {", 1)[1].split("</style>", 1)[0]
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    rules = re.findall(r"([^{}]+)\{([^{}]*)\}", css)

    def rule_for(selector: str) -> str:
        return " ".join(body for sel, body in rules if selector in [s.strip() for s in sel.split(",")])

    for selector in (".name-btn", ".cat-btn", ".bulk-bar .btn", ".ports td.col-check", ".more-btn", ".pop-item"):
        assert "44px" in rule_for(selector), selector


# ── Scanning, grouping, dedup ────────────────────────────────────────────────

def test_first_get_scans_and_groups(client):
    p = get(client)
    assert p["last_scan_at"] and p["scan_error"] is None
    assert p["hostname"] and p["server_time"]
    assert p["stale_after_seconds"] == 300
    G = groups(p)
    assert set(G) == {"tcp-22", "udp-53", "tcp-631", "tcp-7777", "tcp-8710"}

    ssh = G["tcp-22"]
    assert ssh["primary_key"] == "tcp|0.0.0.0|22"
    assert ssh["keys"] == ["tcp|0.0.0.0|22", "tcp|::|22"]
    assert ssh["name"] == "SSH" and ssh["category"] == "Remote Access"
    assert ssh["process"] == "sshd · pid 812"
    assert ssh["is_online"] and ssh["is_new"] and not ssh["ignored"]
    dup = bind(ssh, "::")
    assert dup["auto_ignored"] and not dup["ignored"]
    assert dup["auto_name"] == "SSH" and dup["user_name"] == ""
    assert not bind(ssh, "0.0.0.0")["auto_ignored"]

    dns = G["udp-53"]
    assert dns["primary_key"] == "udp|0.0.0.0|53"
    assert dns["scopes"] == ["public", "loopback"]  # 127.0.0.53%lo is loopback
    assert dns["process"] == "dnsmasq · pid 600"
    assert bind(dns, "127.0.0.53%lo")["auto_ignored"]

    g7 = G["tcp-7777"]
    # equal priority: the first inserted (ss output is sorted by address) wins
    assert g7["primary_key"] == "tcp|100.101.1.2|7777"
    assert g7["scopes"] == ["tailscale", "lan"]
    assert g7["process"] == "foo · pid 1, 2"  # primary has none; first live bind with one
    assert G["tcp-631"]["name"] == "CUPS" and G["tcp-631"]["scopes"] == ["loopback"]
    assert p["stats"] == {"total": 5, "unnamed": 2, "public": 2, "new": 5, "ignored": 0}


def test_primary_going_offline_promotes_listening_duplicate(client, fake_ss):
    get(client)
    fake_ss.remove("0.0.0.0:22 ")
    ssh = groups(rescan(client))["tcp-22"]  # same second as the first scan: ms timestamps matter
    assert ssh["primary_key"] == "tcp|::|22"
    assert ssh["is_online"] and ssh["has_public"]
    v6, v4 = ssh["binds"]
    assert (v6["address"], v6["online"], v6["auto_ignored"], v6["ignored"]) == ("::", True, False, False)
    assert (v4["address"], v4["online"], v4["auto_ignored"]) == ("0.0.0.0", False, False)


def test_duplicate_coming_back_is_auto_ignored_again(client, fake_ss):
    get(client)
    fake_ss.remove("0.0.0.0:22 ")
    rescan(client)
    fake_ss.output = SS_OUTPUT
    ssh = groups(rescan(client))["tcp-22"]
    assert ssh["primary_key"] == "tcp|0.0.0.0|22"
    assert bind(ssh, "::")["auto_ignored"] and bind(ssh, "::")["online"]
    assert not bind(ssh, "0.0.0.0")["auto_ignored"]


def test_ignore_unignore_round_trip(client):
    ssh = groups(get(client))["tcp-22"]
    d = bulk(client, ssh["keys"], {"ignored": True})["data"]
    ssh = groups(d)["tcp-22"]
    assert ssh["ignored"] and all(b["ignored"] for b in ssh["binds"])
    assert bind(ssh, "::")["auto_ignored"]  # dedup flag independent of the user's
    assert d["stats"]["ignored"] == 1 and d["stats"]["total"] == 4

    ssh = groups(rescan(client))["tcp-22"]
    assert ssh["ignored"], "a rescan must not undo a user ignore"

    ssh = groups(bulk(client, ssh["keys"], {"ignored": False})["data"])["tcp-22"]
    assert not ssh["ignored"] and not any(b["ignored"] for b in ssh["binds"])
    assert bind(ssh, "::")["auto_ignored"], "duplicate stays faded through auto_ignored"


def test_dedup_never_touches_user_ignored(client, fake_ss):
    get(client)
    assert client.patch(port_url("tcp|::|22"), json={"ignored": True}).status_code == 200
    fake_ss.remove("0.0.0.0:22 ")
    v6 = bind(groups(rescan(client))["tcp-22"], "::")
    assert v6["ignored"] and not v6["auto_ignored"]
    fake_ss.output = SS_OUTPUT
    v6 = bind(groups(rescan(client))["tcp-22"], "::")
    assert v6["ignored"] and v6["auto_ignored"]


def test_new_port_is_auto_named_and_new(client, fake_ss):
    get(client)
    fake_ss.add("tcp LISTEN 0 128 0.0.0.0:3000 0.0.0.0:*")
    g = groups(rescan(client))["tcp-3000"]
    assert g["name"] == "Dev Server" and g["category"] == "Development" and g["is_new"]


def test_conflicting_user_names_listed(client):
    get(client)
    client.patch(port_url("tcp|0.0.0.0|22"), json={"name": "OpenSSH"})
    client.patch(port_url("tcp|::|22"), json={"name": "sshd v6"})
    ssh = groups(get(client))["tcp-22"]
    assert ssh["name"] == "OpenSSH"
    assert ssh["other_names"] == [{"name": "sshd v6", "address": "::"}]


def test_user_name_on_duplicate_beats_auto_name(client):
    get(client)
    client.patch(port_url("tcp|::|22"), json={"name": "OpenSSH"})
    assert groups(get(client))["tcp-22"]["name"] == "OpenSSH"


def test_scan_error_is_reported_and_cleared(client, fake_ss):
    get(client)
    fake_ss.error = "`ss` command not found. Install iproute2 package."
    p = rescan(client)
    assert "ss" in p["scan_error"] and p["groups"], "error reported, previous data kept"
    fake_ss.error = None
    assert rescan(client)["scan_error"] is None


def test_stale_seconds_from_environment():
    env = dict(os.environ, PORT_INVENTORY_STALE_SECONDS="42")
    out = subprocess.run(
        [sys.executable, "-c", "import app; print(app.STALE_SECONDS)"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == "42"


def test_stale_seconds_in_payload(client, app, monkeypatch):
    monkeypatch.setattr(app, "STALE_SECONDS", 60)
    assert get(client)["stale_after_seconds"] == 60


# ── HTTP probe ───────────────────────────────────────────────────────────────

def test_http_ports_are_flagged(client, db_path, fake_http):
    G = groups(get(client))
    assert sorted(fake_http.probed) == [22, 631, 7777, 8710], "each TCP port once, never UDP"
    assert G["tcp-8710"]["http"]
    assert not any(G[g]["http"] for g in ("tcp-22", "udp-53", "tcp-631", "tcp-7777"))
    assert read_rows(db_path)["tcp|127.0.0.1|8710"]["http"] == 1


def test_http_flag_follows_rescans(client, fake_ss, fake_http):
    get(client)
    fake_http.ports = {22}
    G = groups(rescan(client))
    assert G["tcp-22"]["http"] and not G["tcp-8710"]["http"]

    fake_ss.remove("0.0.0.0:22 ")
    fake_ss.remove("[::]:22 ")
    assert not groups(rescan(client))["tcp-22"]["http"], "offline ports have no link"


def test_udp_port_never_flagged_even_if_tcp_twin_speaks_http(client, fake_ss, fake_http):
    fake_ss.add('udp UNCONN 0 0 0.0.0.0:8710 0.0.0.0:*')
    G = groups(get(client))
    assert G["tcp-8710"]["http"] and not G["udp-8710"]["http"]


def test_http_probe_disabled_by_zero_timeout(client, app, fake_http, monkeypatch):
    monkeypatch.setattr(app, "HTTP_PROBE_TIMEOUT", 0)
    assert not any(g["http"] for g in get(client)["groups"])
    assert fake_http.probed == []


def test_http_probe_timeout_from_environment():
    env = dict(os.environ, PORT_INVENTORY_HTTP_PROBE_TIMEOUT="0.25")
    out = subprocess.run(
        [sys.executable, "-c", "import app; print(app.HTTP_PROBE_TIMEOUT)"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == "0.25"


# (status, headers, body) served on GET / -> is it a web page a browser can open?
PROBE_CASES = {
    "html page": ((200, {"Content-Type": "text/html; charset=utf-8"}, b"<!doctype html>"), True),
    "xhtml page": ((200, {"Content-Type": "application/xhtml+xml"}, b"<html/>"), True),
    "redirect to login": ((302, {"Location": "/login"}, b""), True),
    "basic auth prompt": ((401, {"WWW-Authenticate": 'Basic realm="x"'}, b""), True),
    # llama.cpp / ollama runner: an API, nothing to see in a browser
    "json 404 api": ((404, {"Content-Type": "application/json"}, b'{"error":"File Not Found"}'), False),
    "plain-text api": ((200, {"Content-Type": "text/plain"}, b"Ollama is running"), False),
    "json 200 api": ((200, {"Content-Type": "application/json"}, b"{}"), False),
    "html 404": ((404, {"Content-Type": "text/html"}, b"<h1>Not Found</h1>"), False),
    "redirect without location": ((302, {}, b""), False),
    "401 without auth prompt": ((401, {"Content-Type": "application/json"}, b"{}"), False),
    # what Go's TLS server says to plain HTTP: an http:// link would break
    "https-only server": ((400, {"Content-Type": "text/plain"}, b"Client sent an HTTP request to an HTTPS server."), False),
}


@pytest.fixture
def web_servers():
    """One local HTTP server per PROBE_CASES entry; yields {case: port}."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, headers, body = self.server.reply
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    servers = {}
    for case, (reply, _) in PROBE_CASES.items():
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.reply = reply
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers[case] = server
    yield {case: server.server_address[1] for case, server in servers.items()}
    for server in servers.values():
        server.shutdown()
        server.server_close()


def test_real_probe_only_counts_web_pages(app, monkeypatch, web_servers):
    monkeypatch.setattr(app, "HTTP_PROBE_HOST", "127.0.0.1")
    monkeypatch.setattr(app, "HTTP_PROBE_TIMEOUT", 1.0)
    got = {case: real_probe_http(port) for case, port in web_servers.items()}
    assert got == {case: expected for case, (_, expected) in PROBE_CASES.items()}


def test_real_probe_ignores_non_http_and_closed_ports(app, monkeypatch):
    monkeypatch.setattr(app, "HTTP_PROBE_HOST", "127.0.0.1")
    monkeypatch.setattr(app, "HTTP_PROBE_TIMEOUT", 1.0)

    # A non-HTTP service that greets first, like SSH
    banner = socket.socket()
    banner.bind(("127.0.0.1", 0))
    banner.listen()

    def greet():
        while True:
            try:
                conn, _ = banner.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            conn.close()

    threading.Thread(target=greet, daemon=True).start()

    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()

    try:
        assert real_probe_http(banner.getsockname()[1]) is False
        assert real_probe_http(closed_port) is False
    finally:
        banner.close()


@pytest.mark.parametrize("addr,scope", [
    ("0.0.0.0", "public"), ("*", "public"), ("::", "public"),
    ("127.0.0.1", "loopback"), ("127.0.0.53%lo", "loopback"), ("::1", "loopback"),
    ("100.101.1.2", "tailscale"), ("fd7a:115c:a1e0::1", "tailscale"),
    ("192.168.1.5", "lan"), ("10.0.0.1", "lan"), ("172.17.0.1", "lan"), ("fe80::1%eth0", "lan"),
    ("8.8.8.8", "specific"),
])
def test_classify_scope(app, addr, scope):
    assert app.classify_scope(addr) == scope


@pytest.mark.parametrize("process,summary", [
    ('users:(("sshd",pid=812,fd=3))', "sshd · pid 812"),
    ('users:(("nginx",pid=1,fd=6),("nginx",pid=2,fd=6),("nginx",pid=3,fd=6),("nginx",pid=4,fd=6))', "nginx · pid 1, 2, 3 +1"),
    ("", ""),
])
def test_process_summary(app, process, summary):
    assert app.process_summary(process) == summary


# ── Migrations ───────────────────────────────────────────────────────────────

LEGACY_ROWS = [
    {"key": "tcp|127.0.0.1|8710", "name": "Port Inventory", "category": "Home Lab",
     "owner": "me", "exposure": "LAN", "notes": "the app itself"},
    {"key": "tcp|0.0.0.0|22", "name": "OpenSSH", "category": "remote access"},
    {"key": "tcp|0.0.0.0|9999", "name": "Gone"},
]


def test_migrate_legacy_schema(db_path, fake_ss, app):
    make_db(db_path, LEGACY_DDL, LEGACY_ROWS)
    app.init_db()
    with app.db_session() as db:
        cols = app.table_columns(db, "port_metadata")
        custom = [r["name"] for r in db.execute("SELECT name FROM custom_categories")]
    assert "owner" not in cols and "exposure" not in cols and {"auto_ignored", "http"} <= cols
    assert custom == ["Home Lab"]
    rows = read_rows(db_path)
    assert rows["tcp|0.0.0.0|22"]["category"] == "Remote Access"  # casing normalized
    assert rows["tcp|127.0.0.1|8710"]["notes"] == "the app itself"

    G = groups(get(app.app.test_client()))
    assert not G["tcp-9999"]["is_online"] and not G["tcp-9999"]["is_new"]
    assert not G["tcp-9999"]["has_public"], "offline ports don't count as exposed"
    assert G["tcp-8710"]["category"] == "Home Lab"


def test_legacy_rebuild_fallback_for_old_sqlite(db_path, app):
    """SQLite < 3.35 has no DROP COLUMN: the table is rebuilt instead."""
    make_db(db_path, LEGACY_DDL, LEGACY_ROWS)

    class NoDropColumn:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, *args):
            if "DROP COLUMN" in sql:
                raise app.sqlite3.OperationalError("near DROP: syntax error")
            return self.conn.execute(sql, *args)

    with app.db_session() as db:
        app.add_auto_ignored_column(db)
        app.drop_legacy_columns(NoDropColumn(db))
        assert app.table_columns(db, "port_metadata") == set(app.PORT_METADATA_COLUMNS)
    rows = read_rows(db_path)
    assert len(rows) == 3 and rows["tcp|127.0.0.1|8710"]["name"] == "Port Inventory"


def test_migrate_auto_ignored(db_path, fake_ss, app):
    make_db(db_path, PRE_AUTO_DDL, [
        # auto-named duplicate that dedup ignored -> auto_ignored, no longer user-ignored
        {"key": "tcp|0.0.0.0|22", "name": "SSH"},
        {"key": "tcp|::|22", "name": "SSH", "ignored": 1},
        # user-named row can't have been ignored by dedup -> stays a user ignore
        {"key": "udp|0.0.0.0|53", "name": "DNS"},
        {"key": "udp|127.0.0.53%lo|53", "name": "My resolver", "ignored": 1},
        # a single ignored bind is a user ignore
        {"key": "tcp|0.0.0.0|4000", "ignored": 1},
        # whole group ignored by the user: stays ignored, duplicate also flagged auto
        {"key": "tcp|0.0.0.0|5000", "name": "Dev Server", "ignored": 1},
        {"key": "tcp|::|5000", "name": "Dev Server", "ignored": 1},
        # unnamed duplicate of equal priority
        {"key": "tcp|10.0.0.1|6000"},
        {"key": "tcp|10.0.0.2|6000", "ignored": 1},
    ])
    app.init_db()
    expected = {
        "tcp|0.0.0.0|22": (0, 0), "tcp|::|22": (0, 1),
        "udp|0.0.0.0|53": (0, 0), "udp|127.0.0.53%lo|53": (1, 0),
        "tcp|0.0.0.0|4000": (1, 0),
        "tcp|0.0.0.0|5000": (1, 0), "tcp|::|5000": (1, 1),
        "tcp|10.0.0.1|6000": (0, 0), "tcp|10.0.0.2|6000": (0, 1),
    }
    rows = read_rows(db_path)
    assert {k: (r["ignored"], r["auto_ignored"]) for k, r in rows.items()} == expected

    app.init_db()  # second start: migration must not run again
    rows = read_rows(db_path)
    assert {k: (r["ignored"], r["auto_ignored"]) for k, r in rows.items()} == expected

    # First scan (fake ss: 22 and 53 online, the rest offline) recomputes auto_ignored
    G = groups(get(app.app.test_client()))
    assert not G["tcp-22"]["ignored"] and bind(G["tcp-22"], "::")["auto_ignored"]
    assert bind(G["udp-53"], "127.0.0.53%lo")["ignored"]
    assert G["tcp-5000"]["ignored"] and not G["tcp-5000"]["is_online"]
    assert not any(b["auto_ignored"] for b in G["tcp-5000"]["binds"]), "offline binds are never duplicates"
    assert G["tcp-4000"]["ignored"]


# ── PATCH /api/ports/<key> ───────────────────────────────────────────────────

def test_patch_updates_one_bind(client):
    get(client)
    r = client.patch(port_url("udp|127.0.0.53%lo|53"), json={"notes": "  stub resolver  ", "ignored": True})
    assert r.status_code == 200
    port = r.get_json()["port"]
    assert port["notes"] == "stub resolver" and port["ignored"] is True and port["auto_ignored"] is True


@pytest.mark.parametrize("body,status,message", [
    ({"owner": "x"}, 400, "Unknown field"),
    ({"ignored": "yes"}, 400, "true or false"),
    ({"name": "x" * 101}, 400, "longer than"),
    ({"name": 5}, 400, "must be a string"),
    ({}, 400, "at least one"),
])
def test_patch_validation(client, body, status, message):
    get(client)
    r = client.patch(port_url("tcp|0.0.0.0|22"), json=body)
    assert r.status_code == status and message in r.get_json()["error"]


def test_patch_rejects_non_json_and_unknown_keys(client):
    get(client)
    r = client.patch(port_url("tcp|0.0.0.0|22"), data="name=x", content_type="application/x-www-form-urlencoded")
    assert r.status_code == 400
    r = client.patch(port_url("tcp|nope|1"), json={"name": "x"})
    assert r.status_code == 404 and "error" in r.get_json()


# ── POST /api/ports/bulk ─────────────────────────────────────────────────────

def test_bulk_updates_whole_group(client):
    g7 = groups(get(client))["tcp-7777"]
    j = bulk(client, g7["keys"], {"name": "Foo Service", "category": "home lab"})
    assert j["updated"] == 2
    g7 = groups(j["data"])["tcp-7777"]
    assert g7["name"] == "Foo Service"
    assert all(b["user_name"] == "Foo Service" for b in g7["binds"])
    cats = {c["name"]: c for c in j["data"]["categories"]}
    assert g7["category"] == "home lab" and cats["home lab"]["count"] == 1 and not cats["home lab"]["builtin"]
    assert j["data"]["stats"]["unnamed"] == 1


def test_bulk_category_is_canonicalized(client):
    get(client)
    client.post("/api/categories", json={"name": "Home Lab"})
    j = bulk(client, ["tcp|127.0.0.1|8710"], {"category": "HOME LAB"})
    assert groups(j["data"])["tcp-8710"]["category"] == "Home Lab"
    j = bulk(client, ["tcp|127.0.0.1|8710"], {"category": "web"})
    assert groups(j["data"])["tcp-8710"]["category"] == "Web"


def test_bulk_is_all_or_nothing(client):
    get(client)
    bulk(client, ["tcp|0.0.0.0|22", "nope"], {"ignored": True}, status=404)
    assert not groups(get(client))["tcp-22"]["ignored"]


@pytest.mark.parametrize("body", [
    {"keys": [], "changes": {"ignored": True}},
    {"keys": ["tcp|0.0.0.0|22"], "changes": {}},
    {"keys": [1], "changes": {"ignored": True}},
    ["tcp|0.0.0.0|22"],
])
def test_bulk_validation(client, body):
    get(client)
    assert client.post("/api/ports/bulk", json=body).status_code == 400


# ── Categories ───────────────────────────────────────────────────────────────

def test_categories_list(client):
    cats = client.get("/api/categories").get_json()["categories"]
    assert [c["name"] for c in cats[:2]] == ["Web", "Database"]
    assert all(c["builtin"] for c in cats)


def test_category_create_dedupes_case_insensitively(client):
    r = client.post("/api/categories", json={"name": "Backups"})
    assert r.status_code == 201 and r.get_json()["created"]
    r = client.post("/api/categories", json={"name": "backups"})
    assert r.status_code == 200 and r.get_json() | {"categories": None} == {"name": "Backups", "created": False, "categories": None}
    assert client.post("/api/categories", json={"name": "web"}).get_json()["name"] == "Web"


@pytest.mark.parametrize("body", [{"name": "  "}, {"name": "x" * 49}, {"nom": "x"}, ["x"]])
def test_category_create_validation(client, body):
    assert client.post("/api/categories", json=body).status_code == 400


def test_category_delete_rules(client):
    get(client)
    assert client.delete("/api/categories/Web").status_code == 400
    assert client.delete("/api/categories/" + quote("Proxy / Load Balancer", safe="")).status_code == 400
    assert client.delete("/api/categories/Nope").status_code == 404

    client.post("/api/categories", json={"name": "Home Lab"})
    bulk(client, ["tcp|127.0.0.1|8710"], {"category": "Home Lab"})
    r = client.delete("/api/categories/Home%20Lab")
    assert r.status_code == 409 and "used by 1 port" in r.get_json()["error"]

    assert client.post("/api/categories", json={"name": "A/B"}).status_code == 201
    r = client.delete("/api/categories/" + quote("A/B", safe=""))
    assert r.status_code == 200 and all(c["name"] != "A/B" for c in r.get_json()["categories"])


# ── Routing ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", ["/update/x", "/update-batch", "/rescan"])
def test_old_routes_removed(client, url):
    assert client.post(url).status_code == 404


def test_api_errors_are_json(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.get_json()["error"]
    r = client.get("/api/rescan")
    assert r.status_code == 405 and r.get_json()["error"]
