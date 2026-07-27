import { readFileSync } from 'node:fs';
import { WebSocketServer, WebSocket } from 'ws';
import dgram from 'node:dgram';
import net from 'node:net';

// --- Config ---
interface Config {
  port: number;
  upstream: { host: string; port: number };
  dns_ip: string;
}

function loadConfig(): Config {
  const raw = readFileSync('config.yml', 'utf-8');
  const m: Record<string, string> = {};
  for (const line of raw.split('\n')) {
    const kv = line.match(/^(\w[\w_]*):\s*(.+)$/);
    if (kv) m[kv[1]] = kv[2].trim();
  }
  const [host, portStr] = (m.upstream || '127.0.0.1:30000').split(':');
  return {
    port: parseInt(m.port || '8888', 10),
    upstream: { host, port: parseInt(portStr, 10) },
    dns_ip: m.dns_ip || '1.1.1.1',
  };
}

const config = loadConfig();

// --- State ---
type Session =
  | { kind: 'handshake'; addr: string }
  | { kind: 'relay_udp'; addr: string; socket: dgram.Socket }
  | { kind: 'relay_dns'; addr: string }
  | { kind: 'sink'; addr: string }
  | { kind: 'dead' };

const sessions = new Map<WebSocket, Session>();

function log(level: string, msg: string): void {
  const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
  console.log(`[${ts}] ${level.padEnd(5)} ${msg}`);
}

// --- Server ---
const wss = new WebSocketServer({ host: '0.0.0.0', port: config.port });

wss.on('listening', () => {
  console.log(`minetest-wasm-proxy ws://0.0.0.0:${config.port}`);
  console.log(`upstream: ${config.upstream.host}:${config.upstream.port}`);
});

wss.on('connection', (ws, req) => {
  const addr = (req.socket.remoteAddress ?? '?') +
    (req.headers['x-forwarded-for'] ? ` xff=${req.headers['x-forwarded-for']}` : '');
  log('INFO', `[${addr}] connected`);
  sessions.set(ws, { kind: 'handshake', addr });

  ws.on('message', (data, isBinary) => {
    const s = sessions.get(ws);
    if (!s || s.kind === 'dead') return;

    // --- Handshake ---
    if (s.kind === 'handshake') {
      if (isBinary) { ws.close(); return; }
      const text = typeof data === 'string' ? data : data.toString('utf-8');
      const m = text.match(/^PROXY\s+IPV[46]\s+(UDP|TCP)\s+(\S+)\s+(\d+)$/i);
      if (!m) { ws.send('UNSUPPORTED'); return; }

      const proto = m[1].toUpperCase();
      const clientIp = m[2];
      const clientPort = parseInt(m[3], 10);

      // UDP — relay to upstream
      if (proto === 'UDP') {
        log('INFO', `[${s.addr}] UDP (client asked ${clientIp}:${clientPort}) -> upstream ${config.upstream.host}:${config.upstream.port}`);

        const udpType = net.isIPv6(config.upstream.host) ? 'udp6' : 'udp4';
        const udp = dgram.createSocket(udpType);

        udp.on('message', (msg) => {
          log('DEBUG', `[${s.addr}] UDP <- upstream ${msg.length}B`);
          if (ws.readyState === WebSocket.OPEN) ws.send(msg, { binary: true });
        });
        udp.on('error', (err) => {
          log('WARN', `[${s.addr}] UDP err: ${err.message}`);
          try { ws.close(); } catch { /* */ }
        });

        sessions.set(ws, { kind: 'relay_udp', addr: s.addr, socket: udp });
        ws.send('PROXY OK');
        return;
      }

      // TCP DNS — fake resolver, always 127.0.0.1
      if (proto === 'TCP' && clientIp === '10.0.0.1' && clientPort === 53) {
        log('INFO', `[${s.addr}] DNS (fake)`);
        sessions.set(ws, { kind: 'relay_dns', addr: s.addr });
        ws.send('PROXY OK');
        return;
      }

      // TCP other (server list, content, etc.) — accept but discard
      if (proto === 'TCP') {
        log('INFO', `[${s.addr}] TCP sink ${clientIp}:${clientPort}`);
        sessions.set(ws, { kind: 'sink', addr: s.addr });
        ws.send('PROXY OK');
        return;
      }
      return;
    }

    // --- Relay ---
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);

    if (s.kind === 'relay_udp') {
      log('DEBUG', `[${s.addr}] WS -> upstream ${buf.length}B`);
      s.socket.send(buf, 0, buf.length, config.upstream.port, config.upstream.host, (err) => {
        if (err) log('WARN', `[${s.addr}] UDP send err: ${err.message}`);
      });
      return;
    }
    if (s.kind === 'relay_dns') {
      // Always respond with the configured DNS IP (must NOT be loopback or LAN —
      // those internally, bypassing the proxy entirely)
      const hostname = buf.toString('utf-8').trim();
      log('INFO', `[${s.addr}] DNS: ${hostname || '(empty)'} -> ${config.dns_ip}`);
      ws.send(Buffer.from(config.dns_ip.split('.').map(Number)), { binary: true });
      return;
    }

    // sink: silently discard
  });

  ws.on('close', () => {
    const s = sessions.get(ws);
    if (s?.kind === 'relay_udp') try { s.socket.close(); } catch { /* */ }
    sessions.set(ws, { kind: 'dead' });
    log('INFO', `[${addr}] disconnected`);
  });

  ws.on('error', () => {
    const s = sessions.get(ws);
    if (s?.kind === 'relay_udp') try { s.socket.close(); } catch { /* */ }
    sessions.set(ws, { kind: 'dead' });
  });
});

process.on('SIGINT', () => { wss.close(); process.exit(0); });
process.on('SIGTERM', () => { wss.close(); process.exit(0); });
