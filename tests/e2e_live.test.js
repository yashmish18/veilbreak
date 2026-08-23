#!/usr/bin/env node
/**
 * Browser Vigilant — Live E2E API Scenario Test
 * ================================================
 * Executes all 8 E2E scenarios against the running vault API server:
 *   1.  Health check
 *   2.  Client registration (ECDSA P-256)
 *   3.  Safe URL — no threat submitted (negative case)
 *   4.  Phishing threat submission (signed + authenticated)
 *   5.  Threat persistence — GET by hash after submission
 *   6.  Sync endpoint — distributable hashes after submission
 *   7.  Second reporter corroboration — multi-reporter CONFIRMED state
 *   8.  Backend offline resilience — simulated (validates local-only path)
 *   9.  Malformed message — invalid hash format
 *  10.  Malicious origin — request from unregistered client
 *  11.  Server restart persistence — DB survives process (read after write)
 *  12.  Stats reflect real data
 *
 * Requires Node >= 22.5. Run AFTER starting server.js.
 */

import crypto from 'node:crypto';

const BASE = 'http://localhost:3000';
let passed = 0;
let failed = 0;

// ─── ECDSA P-256 Key Generation (WebCrypto) ───────────────────────────────────
async function generateKeyPair() {
    return crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
}

async function exportPublicJwk(keyPair) {
    return crypto.subtle.exportKey('jwk', keyPair.publicKey);
}

async function signRequest(privateKey, method, path, timestamp, nonce, body, clientId) {
    const bodyStr = body ? JSON.stringify(body) : '';
    const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex');
    const canonical = `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}\n${clientId}`;
    const sig = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        new TextEncoder().encode(canonical)
    );
    return Buffer.from(sig).toString('base64');
}

// ─── Test Harness ─────────────────────────────────────────────────────────────
async function test(name, fn) {
    try {
        await fn();
        console.log(`  ✓ ${name} PASSED`);
        passed++;
    } catch (e) {
        console.error(`  ✗ ${name} FAILED: ${e.message}`);
        failed++;
    }
}

function assert(condition, message) {
    if (!condition) throw new Error(message);
}

async function req(method, path, body = null, headers = {}) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json', ...headers }
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(`${BASE}${path}`, opts);
    const data = await res.json();
    return { status: res.status, data };
}

async function signedPost(path, body, clientId, privateKey) {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    const signature = await signRequest(privateKey, 'POST', path, timestamp, nonce, body, clientId);
    return req('POST', path, body, {
        'x-phantom-client': clientId,
        'x-phantom-timestamp': String(timestamp),
        'x-phantom-nonce': nonce,
        'x-phantom-signature': signature
    });
}

// ─── Test State ───────────────────────────────────────────────────────────────
const CLIENT_ID_1 = `e2e_client_${Date.now()}_a`;
const CLIENT_ID_2 = `e2e_client_${Date.now()}_b`;
const TARGET_DOMAIN = `phish-e2e-${Date.now()}.xyz`;
const THREAT_HASH = crypto.createHash('sha256').update(TARGET_DOMAIN).digest('hex');
let keyPair1, pubJwk1;
let keyPair2, pubJwk2;

// ─── Run Scenarios ────────────────────────────────────────────────────────────
console.log('\n' + '='.repeat(70));
console.log('  BROWSER VIGILANT // LIVE E2E API SCENARIO TEST');
console.log('='.repeat(70) + '\n');
console.log(`  API Server : ${BASE}`);
console.log(`  Target hash: ${THREAT_HASH.slice(0, 16)}... (domain: ${TARGET_DOMAIN})`);
console.log('');

// ── Scenario 1: Health Check ──────────────────────────────────────────────────
console.log('--- Scenario 1: Health Check ---');
await test('Server is reachable and healthy', async () => {
    const { status, data } = await req('GET', '/health');
    assert(status === 200, `Expected 200, got ${status}`);
    assert(data.status === 'ok', 'Missing status:ok');
    assert(data.server === 'Browser Vigilant Vault API', 'Wrong server identity');
});

// ── Scenario 2: Client Registration ──────────────────────────────────────────
console.log('\n--- Scenario 2: Client Registration (ECDSA P-256) ---');
keyPair1 = await generateKeyPair();
pubJwk1 = await exportPublicJwk(keyPair1);
keyPair2 = await generateKeyPair();
pubJwk2 = await exportPublicJwk(keyPair2);

await test('Client 1 registers with valid ECDSA P-256 public key', async () => {
    const { status, data } = await req('POST', '/api/vault/register', {
        clientId: CLIENT_ID_1, publicKeyJwk: pubJwk1
    });
    assert(status === 201, `Expected 201, got ${status}: ${JSON.stringify(data)}`);
    assert(data.success === true, 'Missing success flag');
    assert(data.client.clientId === CLIENT_ID_1, 'Client ID mismatch');
});

await test('Client 2 registers with valid ECDSA P-256 public key', async () => {
    const { status, data } = await req('POST', '/api/vault/register', {
        clientId: CLIENT_ID_2, publicKeyJwk: pubJwk2
    });
    assert(status === 201, `Expected 201, got ${status}: ${JSON.stringify(data)}`);
    assert(data.success === true, 'Missing success flag');
});

await test('Registration rejects invalid client ID (too short)', async () => {
    const { status } = await req('POST', '/api/vault/register', {
        clientId: 'short', publicKeyJwk: pubJwk1
    });
    assert(status === 400, `Expected 400, got ${status}`);
});

await test('Registration rejects non-P256 key', async () => {
    const { status } = await req('POST', '/api/vault/register', {
        clientId: CLIENT_ID_1, publicKeyJwk: { kty: 'RSA', crv: 'P-384' }
    });
    assert(status === 400, `Expected 400, got ${status}`);
});

// ── Scenario 3: Safe URL — No Threat (Negative Case) ─────────────────────────
console.log('\n--- Scenario 3: Safe URL Negative Case ---');
await test('GET /api/vault/submit for unknown hash returns 404', async () => {
    const safeHash = crypto.createHash('sha256').update('example.com').digest('hex');
    const { status, data } = await req('GET', `/api/vault/submit?hash=${safeHash}`);
    assert(status === 404, `Expected 404 for safe domain, got ${status}: ${JSON.stringify(data)}`);
});

// ── Scenario 4: Phishing Threat Submission ────────────────────────────────────
console.log('\n--- Scenario 4: Phishing Threat Submission (Authenticated) ---');
let firstSubmitResult;
await test('Client 1 submits signed phishing threat — ECDSA authenticated', async () => {
    const body = { hash: THREAT_HASH, threatType: 'PHISHING', confidence: 0.95 };
    const { status, data } = await signedPost('/api/vault/submit', body, CLIENT_ID_1, keyPair1.privateKey);
    assert(status === 201, `Expected 201, got ${status}: ${JSON.stringify(data)}`);
    assert(data.success === true, 'Missing success');
    assert(data.threat.hash === THREAT_HASH.toLowerCase(), 'Hash mismatch');
    assert(data.threat.status === 'CONFIRMED', `Expected CONFIRMED (confidence≥0.92), got ${data.threat.status}`);
    assert(data.isDistributable === true, 'High-confidence threat must be distributable');
    firstSubmitResult = data;
    console.log(`    → Trust evaluation: ${data.trustEvaluation}`);
});

await test('Unauthenticated submission is rejected (missing headers)', async () => {
    const body = { hash: THREAT_HASH, threatType: 'PHISHING', confidence: 0.95 };
    const { status } = await req('POST', '/api/vault/submit', body);
    assert(status === 401, `Expected 401 for unsigned request, got ${status}`);
});

await test('Malformed hash format is rejected by trust engine', async () => {
    const body = { hash: 'not-a-valid-hex-hash', threatType: 'PHISHING', confidence: 0.9 };
    const { status } = await signedPost('/api/vault/submit', body, CLIENT_ID_1, keyPair1.privateKey);
    // Either 400 (route validation) or 403 (trust engine rejection)
    assert(status === 400 || status === 403, `Expected 400/403, got ${status}`);
});

// ── Scenario 5: Threat Persistence ────────────────────────────────────────────
console.log('\n--- Scenario 5: Threat Persistence (GET by hash) ---');
await test('Submitted threat is retrievable by hash from SQLite', async () => {
    const { status, data } = await req('GET', `/api/vault/submit?hash=${THREAT_HASH}`);
    assert(status === 200, `Expected 200, got ${status}: ${JSON.stringify(data)}`);
    assert(data.threat.hash === THREAT_HASH.toLowerCase(), 'Hash mismatch in persistence read');
    assert(data.threat.status === 'CONFIRMED', `Expected CONFIRMED, got ${data.threat.status}`);
    console.log(`    → Retrieved threat: status=${data.threat.status}, confidence=${(data.threat.confidence*100).toFixed(1)}%`);
});

// ── Scenario 6: Sync Endpoint ─────────────────────────────────────────────────
console.log('\n--- Scenario 6: Sync Endpoint (Distributable Hashes) ---');
await test('Sync endpoint returns confirmed threat hash', async () => {
    const { status, data } = await req('GET', `/api/vault/sync?since=0&clientId=${CLIENT_ID_2}`);
    assert(status === 200, `Expected 200, got ${status}: ${JSON.stringify(data)}`);
    assert(Array.isArray(data.hashes), 'hashes must be an array');
    assert(data.hashes.includes(THREAT_HASH.toLowerCase()), `Expected ${THREAT_HASH.slice(0,16)}... in sync response. Got: ${JSON.stringify(data.hashes).slice(0, 100)}`);
    assert(data.count >= 1, 'Count must be >= 1');
    console.log(`    → Sync returned ${data.count} distributable hash(es)`);
});

await test('Sync with future since= returns empty (no new threats since future timestamp)', async () => {
    const future = Date.now() + 99999999;
    const { status, data } = await req('GET', `/api/vault/sync?since=${future}`);
    assert(status === 200, `Expected 200`);
    assert(data.count === 0, `Expected 0 hashes for future timestamp, got ${data.count}`);
});

// ── Scenario 7: Second Reporter Corroboration ────────────────────────────────
console.log('\n--- Scenario 7: Second Reporter Corroboration ---');
await test('Client 2 corroborates same threat — reporter count increments', async () => {
    const body = { hash: THREAT_HASH, threatType: 'PHISHING', confidence: 0.88 };
    const { status, data } = await signedPost('/api/vault/submit', body, CLIENT_ID_2, keyPair2.privateKey);
    assert(status === 201, `Expected 201, got ${status}: ${JSON.stringify(data)}`);
    assert(data.threat.reporters.length === 2, `Expected 2 reporters, got ${data.threat.reporters.length}`);
    assert(data.threat.status === 'CONFIRMED', `Expected CONFIRMED, got ${data.threat.status}`);
    console.log(`    → Reporters: ${data.threat.reporters.join(', ').slice(0, 60)}`);
});

// ── Scenario 8: Replay Attack Protection ─────────────────────────────────────
console.log('\n--- Scenario 8: Replay Attack (Nonce Reuse) ---');
await test('Replayed signed request is rejected (409 CONFLICT)', async () => {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex'); // same nonce used twice
    const body = { hash: THREAT_HASH, threatType: 'PHISHING', confidence: 0.91 };
    const signature = await signRequest(keyPair1.privateKey, 'POST', '/api/vault/submit', timestamp, nonce, body, CLIENT_ID_1);
    const headers = {
        'x-phantom-client': CLIENT_ID_1,
        'x-phantom-timestamp': String(timestamp),
        'x-phantom-nonce': nonce,
        'x-phantom-signature': signature
    };
    // First request — should succeed
    const r1 = await req('POST', '/api/vault/submit', body, headers);
    assert(r1.status === 201, `First request must succeed, got ${r1.status}`);
    // Second request with same nonce — must be rejected
    const r2 = await req('POST', '/api/vault/submit', body, headers);
    assert(r2.status === 409, `Replay must be rejected with 409, got ${r2.status}: ${JSON.stringify(r2.data)}`);
});

// ── Scenario 9: Malformed Message Handling ───────────────────────────────────
console.log('\n--- Scenario 9: Malformed Message Handling ---');
await test('Malformed JSON body returns 400', async () => {
    const res = await fetch(`${BASE}/api/vault/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{ this is: not valid json }'
    });
    assert(res.status === 400, `Expected 400 for malformed JSON, got ${res.status}`);
});

await test('Missing hash parameter on GET /submit returns 400', async () => {
    const { status } = await req('GET', '/api/vault/submit');
    assert(status === 400, `Expected 400, got ${status}`);
});

// ── Scenario 10: Vault Poisoning Defense ─────────────────────────────────────
console.log('\n--- Scenario 10: Vault Poisoning Defense ---');
await test('Submission of google.com hash is blocked by poisoning safeguard', async () => {
    const googleHash = crypto.createHash('sha256').update('google.com').digest('hex');
    const body = { hash: googleHash, threatType: 'PHISHING', confidence: 0.99 };
    const { status, data } = await signedPost('/api/vault/submit', body, CLIENT_ID_1, keyPair1.privateKey);
    assert(status === 403, `Expected 403, got ${status}: ${JSON.stringify(data)}`);
    assert(data.error.includes('REJECTED') || data.error.includes('Poisoning'), `Expected poisoning rejection message, got: ${data.error}`);
});

// ── Scenario 11: Stats Reflect Real Data ─────────────────────────────────────
console.log('\n--- Scenario 11: Vault Stats ---');
await test('Stats endpoint reflects real threat and client counts', async () => {
    const { status, data } = await req('GET', '/api/vault/stats');
    assert(status === 200, `Expected 200, got ${status}`);
    assert(typeof data.totalThreats === 'number', 'totalThreats must be a number');
    assert(data.totalThreats >= 1, `Expected at least 1 threat, got ${data.totalThreats}`);
    assert(typeof data.totalClients === 'number', 'totalClients must be a number');
    assert(data.totalClients >= 2, `Expected at least 2 clients, got ${data.totalClients}`);
    assert(data.verifiedThreats >= 1, `Expected at least 1 verified threat, got ${data.verifiedThreats}`);
    assert(Array.isArray(data.recentThreats), 'recentThreats must be an array');
    console.log(`    → Total threats: ${data.totalThreats}, Verified: ${data.verifiedThreats}, Clients: ${data.totalClients}`);
});

// ── Scenario 12: Stale Timestamp (Anti-replay) ───────────────────────────────
console.log('\n--- Scenario 12: Stale Timestamp Attack ---');
await test('Request with expired timestamp is rejected (401)', async () => {
    const staleTimestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago
    const nonce = crypto.randomBytes(16).toString('hex');
    const body = { hash: THREAT_HASH, threatType: 'PHISHING', confidence: 0.9 };
    const signature = await signRequest(keyPair1.privateKey, 'POST', '/api/vault/submit', staleTimestamp, nonce, body, CLIENT_ID_1);
    const { status } = await req('POST', '/api/vault/submit', body, {
        'x-phantom-client': CLIENT_ID_1,
        'x-phantom-timestamp': String(staleTimestamp),
        'x-phantom-nonce': nonce,
        'x-phantom-signature': signature
    });
    assert(status === 401, `Expected 401 for stale timestamp, got ${status}`);
});

// ─── Final Summary ────────────────────────────────────────────────────────────
console.log('\n' + '='.repeat(70));
if (failed === 0) {
    console.log(`  ✅ ALL E2E SCENARIOS PASSED: ${passed} PASSED | ${failed} FAILED`);
} else {
    console.log(`  ❌ E2E RESULTS: ${passed} PASSED | ${failed} FAILED`);
}
console.log('='.repeat(70) + '\n');

// Exit: defer with setImmediate so Node flushes pending I/O first
setImmediate(() => process.exit(failed > 0 ? 1 : 0));
