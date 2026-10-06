"""Serve app.py on 127.0.0.1:<port> with a fake `ss` and a throwaway DB (UI tests only)."""

import os
import shutil
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import app  # noqa: E402

SS_OUTPUT = """\
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=812,fd=4))
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=13))
udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*
tcp LISTEN 0 128 127.0.0.1:8710 0.0.0.0:* users:(("python",pid=900,fd=5))
tcp LISTEN 0 128 192.168.1.5:7777 0.0.0.0:*
tcp LISTEN 0 128 0.0.0.0:4000 0.0.0.0:*
tcp LISTEN 0 128 0.0.0.0:4001 0.0.0.0:*
tcp LISTEN 0 128 [::1]:631 [::]:*
"""

if __name__ == "__main__":
    port = int(sys.argv[1])
    data_dir = Path(tempfile.mkdtemp(prefix="port-inventory-ui-"))
    # run.js stops the server with SIGTERM; clean up the throwaway DB on the way out
    signal.signal(signal.SIGTERM, lambda *_: (shutil.rmtree(data_dir, ignore_errors=True), sys.exit(0)))

    # If run.js dies without stopping us (Ctrl+C, timeout, crash), don't linger as an orphan
    parent = os.getppid()

    def exit_with_parent():
        while os.getppid() == parent:
            time.sleep(0.5)
        shutil.rmtree(data_dir, ignore_errors=True)
        os._exit(0)

    threading.Thread(target=exit_with_parent, daemon=True).start()
    app.APP_DIR = data_dir
    app.DB_PATH = data_dir / "ui.sqlite3"
    app.run_ss = lambda: SS_OUTPUT
    app.probe_http = lambda port: port in (631, 4001)  # never probe real local ports
    app.init_db()
    app.run_scan()
    app.app.run(host="127.0.0.1", port=port)
