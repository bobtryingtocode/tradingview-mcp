/**
 * Inbound webhook receiver for TradingView alerts.
 *
 * Runs an HTTP server in the same process as the MCP server. TradingView alerts
 * configured with "Webhook URL" POST to it; received bodies are buffered in
 * memory (ring buffer) and surfaced via MCP tools.
 *
 * Auth: required shared-secret header. The server refuses to start without a
 * secret of >= 8 chars, and rejects requests whose `X-Webhook-Secret` (or
 * `Authorization: Bearer <secret>`) does not match.
 *
 * Defaults bind to 127.0.0.1 so the port is not reachable from the network
 * without an explicit tunnel.
 */
import http from 'node:http';
import { randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';

const DEFAULT_PORT = 9223;
const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_MAX_ALERTS = 500;
const MAX_BODY_BYTES = 64 * 1024;
const MIN_SECRET_LEN = 8;

const state = {
  server: null,
  port: null,
  host: null,
  secret: null,
  alerts: [],
  maxAlerts: DEFAULT_MAX_ALERTS,
  startedAt: null,
  totalReceived: 0,
  totalRejected: 0,
};

export function _getState() { return state; }

export function _resetState() {
  state.server = null;
  state.port = null;
  state.host = null;
  state.secret = null;
  state.alerts = [];
  state.maxAlerts = DEFAULT_MAX_ALERTS;
  state.startedAt = null;
  state.totalReceived = 0;
  state.totalRejected = 0;
}

function pushAlert(entry) {
  state.alerts.push(entry);
  if (state.alerts.length > state.maxAlerts) {
    state.alerts.splice(0, state.alerts.length - state.maxAlerts);
  }
  state.totalReceived++;
}

function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  // Hash both to fixed-length digests so timingSafeEqual gets equal-length
  // inputs and we don't leak secret length via early length check.
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

function extractSecret(req) {
  const header = req.headers['x-webhook-secret'];
  if (typeof header === 'string' && header.length) return header;
  const auth = req.headers['authorization'];
  if (typeof auth === 'string') {
    const m = auth.match(/^Bearer\s+(.+)$/i);
    if (m) return m[1];
  }
  return null;
}

export function handleRequest(req, res) {
  if (req.method === 'GET' && (req.url === '/health' || req.url === '/healthz')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, received: state.totalReceived }));
    return;
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { 'Allow': 'POST', 'Content-Length': '0', 'Connection': 'close' });
    res.end();
    return;
  }

  const provided = extractSecret(req);
  if (!state.secret || !constantTimeEqual(provided || '', state.secret)) {
    state.totalRejected++;
    res.writeHead(401, { 'Content-Length': '0', 'Connection': 'close' });
    res.end();
    return;
  }

  let received = 0;
  const chunks = [];
  let aborted = false;

  req.on('data', (chunk) => {
    if (aborted) return;
    received += chunk.length;
    if (received > MAX_BODY_BYTES) {
      aborted = true;
      state.totalRejected++;
      res.writeHead(413, { 'Content-Length': '0', 'Connection': 'close' });
      res.end();
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', () => {
    if (aborted) return;
    const raw = Buffer.concat(chunks).toString('utf8');
    let parsed = null;
    if (raw.length) {
      try { parsed = JSON.parse(raw); } catch { /* leave as null, keep raw */ }
    }
    const entry = {
      id: randomUUID(),
      receivedAt: new Date().toISOString(),
      ip: req.socket?.remoteAddress || null,
      contentType: req.headers['content-type'] || null,
      userAgent: req.headers['user-agent'] || null,
      body: parsed,
      raw: parsed === null ? raw : undefined,
    };
    pushAlert(entry);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, id: entry.id }));
  });

  req.on('error', () => { /* swallow; client gone */ });
}

export async function start({ port, host, secret, max_alerts } = {}, deps = {}) {
  const requestedSecret = (typeof secret === 'string' && secret.length)
    ? secret
    : process.env.TV_WEBHOOK_SECRET || null;

  if (state.server) {
    const conflicts = [];
    // port 0 means "any free port" — don't treat as a conflict
    if (Number.isFinite(port) && port !== 0 && port !== state.port) {
      conflicts.push(`port (running=${state.port}, requested=${port})`);
    }
    if (host && host !== state.host) {
      conflicts.push(`host (running=${state.host}, requested=${host})`);
    }
    if (requestedSecret && requestedSecret !== state.secret) {
      conflicts.push('secret (differs from running)');
    }
    if (Number.isFinite(max_alerts) && Math.floor(max_alerts) !== state.maxAlerts) {
      conflicts.push(`max_alerts (running=${state.maxAlerts}, requested=${Math.floor(max_alerts)})`);
    }
    if (conflicts.length) {
      throw new Error(
        `Webhook already running on ${state.host}:${state.port}. Call webhook_stop first to change: ${conflicts.join(', ')}`
      );
    }
    return {
      success: true,
      already_running: true,
      port: state.port,
      host: state.host,
      max_alerts: state.maxAlerts,
    };
  }

  const useSecret = requestedSecret;
  if (!useSecret || useSecret.length < MIN_SECRET_LEN) {
    throw new Error(
      `Webhook secret required (>= ${MIN_SECRET_LEN} chars). Pass \`secret\` or set TV_WEBHOOK_SECRET env var.`
    );
  }

  const usePort = Number.isFinite(port) ? port : DEFAULT_PORT;
  const useHost = host || DEFAULT_HOST;
  const useMax = Number.isFinite(max_alerts) ? Math.max(1, Math.floor(max_alerts)) : DEFAULT_MAX_ALERTS;

  const createServer = deps.createServer || ((handler) => http.createServer(handler));
  const server = createServer(handleRequest);

  await new Promise((resolve, reject) => {
    const onError = (err) => {
      server.removeListener('listening', onListening);
      reject(err);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(usePort, useHost);
  });

  const addr = server.address();
  const actualPort = (addr && typeof addr === 'object') ? addr.port : usePort;

  state.server = server;
  state.port = actualPort;
  state.host = useHost;
  state.secret = useSecret;
  state.maxAlerts = useMax;
  state.startedAt = new Date().toISOString();

  return {
    success: true,
    port: actualPort,
    host: useHost,
    max_alerts: useMax,
    auth: 'shared-secret',
    started_at: state.startedAt,
    hint: `POST alerts to http://${useHost}:${actualPort}/ with header "X-Webhook-Secret: <your secret>"`,
  };
}

export async function stop() {
  if (!state.server) {
    return { success: true, running: false };
  }
  const server = state.server;
  const port = state.port;
  state.server = null;
  state.port = null;
  state.host = null;
  state.secret = null;
  state.startedAt = null;
  state.alerts = [];
  state.totalReceived = 0;
  state.totalRejected = 0;
  await new Promise((resolve) => server.close(() => resolve()));
  return { success: true, stopped_port: port };
}

export function status() {
  return {
    success: true,
    running: !!state.server,
    port: state.port,
    host: state.host,
    auth_enabled: !!state.secret,
    started_at: state.startedAt,
    total_received: state.totalReceived,
    total_rejected: state.totalRejected,
    buffered_count: state.alerts.length,
    max_alerts: state.maxAlerts,
  };
}

export function list({ limit, since } = {}) {
  let items = state.alerts;
  if (since) {
    items = items.filter((a) => a.receivedAt >= since);
  }
  if (Number.isFinite(limit) && limit > 0) {
    items = items.slice(-Math.floor(limit));
  }
  return {
    success: true,
    count: items.length,
    total_received: state.totalReceived,
    alerts: items,
  };
}

export function clear() {
  const cleared = state.alerts.length;
  state.alerts = [];
  return { success: true, cleared };
}
