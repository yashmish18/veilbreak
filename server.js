#!/usr/bin/env node
/**
 * Browser Vigilant — Standalone Vault API Server
 * ================================================
 * A zero-dependency Node.js HTTP server implementing all 4 vault API routes.
 * Drop-in replacement for `next dev` with identical logic, security, and SQLite persistence.
 *
 * Routes:
 *   POST /api/vault/register   — Register a client (ECDSA P-256 public key)
 *   POST /api/vault/submit     — Submit a signed threat report
 *   GET  /api/vault/sync       — Poll distributable threat hashes
 *   GET  /api/vault/stats      — Aggregated vault statistics
 *
 * Usage:
 *   node --experimental-strip-types server.js [port]
 *
 * Requires Node >= 22.5 (DatabaseSync + type stripping).
 */

// ─── Imports ──────────────────────────────────────────────────────────────────
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Resolve web lib paths (must be file:// URLs for Windows ESM compatibility)
const WEB_LIB = path.join(__dirname, 'web', 'lib');
const toFileUrl = (p) => new URL(`file:///${p.replace(/\\/g, '/')}`).href;

// Dynamic imports (with type-stripping via --experimental-strip-types)
const { clientRepo, threatRepo } = await import(toFileUrl(path.join(WEB_LIB, 'db.ts')));
const { authenticateSignedRequest } = await import(toFileUrl(path.join(WEB_LIB, 'crypto.ts')));
const { evaluateThreatTrust } = await import(toFileUrl(path.join(WEB_LIB, 'trust_model.ts')));


// ─── Helpers ──────────────────────────────────────────────────────────────────
const PORT = parseInt(process.argv[2] || process.env.PORT || '3000', 10);

function json(res, status, data) {
    const body = JSON.stringify(data);
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, x-phantom-client, x-phantom-timestamp, x-phantom-nonce, x-phantom-signature',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    res.end(body);
}

async function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => { data += chunk; });
        req.on('end', () => resolve(data));
        req.on('error', reject);
    });
}

/**
 * Adapts a Node.js IncomingMessage into a minimal Web Request-compatible object
 * so we can reuse authenticateSignedRequest() from crypto.ts unchanged.
 */
function makeWebRequest(req, rawBody, port) {
    const url = `http://localhost:${port}${req.url}`;
    const headers = new Headers();
    for (const [key, val] of Object.entries(req.headers)) {
        if (typeof val === 'string') headers.set(key, val);
        else if (Array.isArray(val)) val.forEach(v => headers.append(key, v));
    }
    return {
        method: req.method,
        url,
        headers,
        text: async () => rawBody,
        json: async () => JSON.parse(rawBody),
    };
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

async function handleRegister(req, res, rawBody) {
    let body;
    try { body = JSON.parse(rawBody); }
    catch { return json(res, 400, { error: 'Malformed JSON body' }); }

    const { clientId, publicKeyJwk } = body;

    if (!clientId || typeof clientId !== 'string' || clientId.length < 8) {
        return json(res, 400, { error: 'Invalid clientId (must be at least 8 chars)' });
    }
    if (!publicKeyJwk || typeof publicKeyJwk !== 'object' || publicKeyJwk.kty !== 'EC' || publicKeyJwk.crv !== 'P-256') {
        return json(res, 400, { error: 'Invalid publicKeyJwk (must be ECDSA P-256 JWK)' });
    }

    try {
        const registered = clientRepo.register(clientId, publicKeyJwk);
        return json(res, 201, { success: true, message: 'Client registered successfully', client: registered });
    } catch (e) {
        console.error('[register] Error:', e);
        return json(res, 500, { error: 'Internal Server Error' });
    }
}

async function handleSubmitPOST(req, res, rawBody) {
    let body;
    try { body = JSON.parse(rawBody); }
    catch { return json(res, 400, { error: 'Malformed JSON body' }); }

    const webReq = makeWebRequest(req, rawBody, PORT);

    const auth = await authenticateSignedRequest(webReq, body);
    if (!auth.ok) {
        return json(res, auth.status || 401, { error: auth.error });
    }

    const { clientId } = auth;
    const { hash, threatType, confidence, evidence } = body;

    if (!hash || typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash)) {
        return json(res, 400, { error: 'Invalid SHA-256 hash parameter' });
    }

    let result;
    try {
        result = evaluateThreatTrust({
            hash,
            threatType: threatType || 'MALICIOUS_DOMAIN',
            confidence: typeof confidence === 'number' ? confidence : 0.85,
            clientId,
            evidence
        });
    } catch (trustError) {
        return json(res, 403, { error: trustError.message });
    }

    const syncId = threatRepo.recordSync(clientId, 1, hash);

    return json(res, 201, {
        success: true,
        threat: result.record,
        isDistributable: result.isDistributable,
        trustEvaluation: result.reason,
        syncId
    });
}

async function handleSubmitGET(req, res) {
    const parsedUrl = new URL(`http://localhost:${PORT}${req.url}`);
    const hash = parsedUrl.searchParams.get('hash');

    if (!hash) {
        return json(res, 400, { error: 'Hash parameter required' });
    }

    const threat = threatRepo.get(hash);
    if (!threat) {
        return json(res, 404, { error: 'Threat not found' });
    }

    return json(res, 200, { threat });
}

async function handleSync(req, res) {
    const parsedUrl = new URL(`http://localhost:${PORT}${req.url}`);
    const sinceStr = parsedUrl.searchParams.get('since') || '0';
    const since = parseInt(sinceStr, 10) || 0;
    const clientId = parsedUrl.searchParams.get('clientId') || 'anonymous';

    const hashes = threatRepo.getDistributableHashes(since);

    if (hashes.length > 0) {
        threatRepo.recordSync(clientId, hashes.length);
    }

    return json(res, 200, { hashes, timestamp: Date.now(), count: hashes.length });
}

async function handleStats(_req, res) {
    try {
        const stats = threatRepo.getStats();
        return json(res, 200, stats);
    } catch (e) {
        console.error('[stats] Error:', e);
        return json(res, 500, { error: 'Internal Server Error' });
    }
}

// ─── Router ───────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
    const rawUrl = req.url.split('?')[0];
    const method = req.method.toUpperCase();

    // CORS preflight
    if (method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type, x-phantom-client, x-phantom-timestamp, x-phantom-nonce, x-phantom-signature',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
        });
        return res.end();
    }

    const rawBody = (method === 'POST' || method === 'PUT') ? await readBody(req) : '';

    console.log(`[${new Date().toISOString()}] ${method} ${req.url}`);

    try {
        if (rawUrl === '/api/vault/register' && method === 'POST') {
            return await handleRegister(req, res, rawBody);
        }
        if (rawUrl === '/api/vault/submit' && method === 'POST') {
            return await handleSubmitPOST(req, res, rawBody);
        }
        if (rawUrl === '/api/vault/submit' && method === 'GET') {
            return await handleSubmitGET(req, res);
        }
        if (rawUrl === '/api/vault/sync' && method === 'GET') {
            return await handleSync(req, res);
        }
        if (rawUrl === '/api/vault/stats' && method === 'GET') {
            return await handleStats(req, res);
        }

        // Health check
        if (rawUrl === '/health' || rawUrl === '/') {
            return json(res, 200, { status: 'ok', server: 'Browser Vigilant Vault API', version: '2.0.0' });
        }

        return json(res, 404, { error: `Route not found: ${method} ${rawUrl}` });

    } catch (e) {
        console.error('[server] Unhandled error:', e);
        return json(res, 500, { error: 'Internal Server Error' });
    }
});

server.listen(PORT, '127.0.0.1', () => {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`  Browser Vigilant — Vault API Server`);
    console.log(`  Listening on http://localhost:${PORT}`);
    console.log(`  Node ${process.version} | SQLite (node:sqlite)`);
    console.log(`${'='.repeat(60)}\n`);
    console.log('  Routes:');
    console.log(`    POST http://localhost:${PORT}/api/vault/register`);
    console.log(`    POST http://localhost:${PORT}/api/vault/submit`);
    console.log(`    GET  http://localhost:${PORT}/api/vault/sync`);
    console.log(`    GET  http://localhost:${PORT}/api/vault/stats`);
    console.log(`    GET  http://localhost:${PORT}/health`);
    console.log('');
});

server.on('error', err => {
    console.error('[server] Fatal:', err);
    process.exit(1);
});

// Graceful shutdown
function shutdown(signal) {
    console.log(`\n[server] Received ${signal} — shutting down gracefully...`);
    server.close(() => {
        import(toFileUrl(path.join(WEB_LIB, 'db.ts'))).then(({ closeDb }) => {
            closeDb();
            console.log('[server] Closed. Bye.');
            process.exit(0);
        }).catch(() => process.exit(0));
    });
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));


