// Starts tests/ui/fake_server.py on a free port, runs ui.test.js against it, stops it.
// Python with Flask installed: $PYTHON, else `python3` on PATH.
const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const runChecks = require('./ui.test.js');

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  });
}

async function waitUntilUp(base, server, log) {
  for (let i = 0; i < 100; i++) {
    if (server.exitCode !== null) throw new Error('fake server exited:\n' + log.join(''));
    try {
      const res = await fetch(base);
      await res.text();  // always drain the body, or undici trips over the closed socket
      if (res.ok) return;
    } catch (e) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error('fake server did not start:\n' + log.join(''));
}

(async () => {
  const port = await freePort();
  const base = 'http://127.0.0.1:' + port + '/';
  const log = [];
  const server = spawn(process.env.PYTHON || 'python3', [path.join(__dirname, 'fake_server.py'), String(port)], { stdio: ['ignore', 'pipe', 'pipe'] });
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { server.kill(); process.exit(130); });
  server.stdout.on('data', (d) => log.push(String(d)));
  server.stderr.on('data', (d) => log.push(String(d)));
  let code = 0;
  try {
    await waitUntilUp(base, server, log);
    const passed = await runChecks(base);
    console.log('all ' + passed + ' UI checks passed');
  } catch (e) {
    console.error(e.message);
    code = 1;
  } finally {
    server.kill();
  }
  process.exit(code);
})();
