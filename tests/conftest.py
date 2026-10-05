"""Shared fixtures: a throwaway SQLite DB per test and a scriptable fake `ss`."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app as app_module  # noqa: E402

SS_OUTPUT = """\
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=812,fd=4))
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=13))
udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=600,fd=4))
tcp LISTEN 0 128 127.0.0.1:8710 0.0.0.0:* users:(("python",pid=900,fd=5))
tcp LISTEN 0 128 192.168.1.5:7777 0.0.0.0:* users:(("foo",pid=1,fd=3),("foo",pid=2,fd=3))
tcp LISTEN 0 128 100.101.1.2:7777 0.0.0.0:*
tcp LISTEN 0 128 [::1]:631 [::]:*
"""

# Schema of the very first release: owner/exposure, no auto_ignored.
LEGACY_DDL = """
CREATE TABLE port_metadata (
    key TEXT PRIMARY KEY, proto TEXT NOT NULL, local_address TEXT NOT NULL, port INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '', exposure TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '', ignored INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    last_process TEXT NOT NULL DEFAULT '', last_raw TEXT NOT NULL DEFAULT ''
)
"""

# Schema after owner/exposure were dropped but before auto_ignored existed.
PRE_AUTO_DDL = """
CREATE TABLE port_metadata (
    key TEXT PRIMARY KEY, proto TEXT NOT NULL, local_address TEXT NOT NULL, port INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
    ignored INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    last_process TEXT NOT NULL DEFAULT '', last_raw TEXT NOT NULL DEFAULT ''
)
"""


class FakeSS:
    """Stands in for app.run_ss. Edit `.output` or set `.error` between scans."""

    def __init__(self) -> None:
        self.output = SS_OUTPUT
        self.error: str | None = None

    def __call__(self) -> str:
        if self.error:
            raise RuntimeError(self.error)
        return self.output

    def remove(self, fragment: str) -> None:
        lines = self.output.splitlines()
        kept = [line for line in lines if fragment not in line]
        assert len(kept) == len(lines) - 1, f"expected exactly one line containing {fragment!r}"
        self.output = "\n".join(kept) + "\n"

    def add(self, line: str) -> None:
        self.output += line.rstrip("\n") + "\n"


@pytest.fixture
def app():
    return app_module


@pytest.fixture
def fake_ss(monkeypatch):
    ss = FakeSS()
    monkeypatch.setattr(app_module, "run_ss", ss)
    return ss


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    path = tmp_path / "port_inventory.sqlite3"
    monkeypatch.setattr(app_module, "APP_DIR", tmp_path)
    monkeypatch.setattr(app_module, "DB_PATH", path)
    return path


@pytest.fixture
def client(db_path, fake_ss):
    app_module.init_db()
    return app_module.app.test_client()


def make_db(path: Path, ddl: str, rows: list[dict]) -> None:
    """Create a DB with an older schema and the given rows (missing fields default)."""
    conn = sqlite3.connect(path)
    conn.execute(ddl)
    columns = [r[1] for r in conn.execute("PRAGMA table_info(port_metadata)")]
    for row in rows:
        proto, addr, port = row["key"].split("|")
        values = {
            "proto": proto, "local_address": addr, "port": int(port),
            "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T00:00:00+00:00",
            **row,
        }
        cols = [c for c in columns if c in values]
        conn.execute(
            f"INSERT INTO port_metadata ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
            [values[c] for c in cols],
        )
    conn.commit()
    conn.close()


def read_rows(path: Path) -> dict[str, dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = {r["key"]: dict(r) for r in conn.execute("SELECT * FROM port_metadata")}
    conn.close()
    return rows
