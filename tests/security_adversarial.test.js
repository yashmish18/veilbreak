import assert from 'node:assert';
import crypto from 'node:crypto';
import { clientRepo, nonceRepo } from '../web/lib/db.ts';
import { buildCanonicalRequest, verifySignature, authenticateSignedRequest } from '../web/lib/crypto.ts';
import { evaluateThreatTrust, isProtectedDomainHash } from '../web/lib/trust_model.ts';
import { MerkleTree } from '../blockchain/merkle_tree.js';

async function testAdversarial() {
    console.log('\n--- Running Security & Adversarial Attack Tests ---');

    // Setup a legitimate client
    const legitKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
    const legitPubJwk = await crypto.subtle.exportKey('jwk', legitKeyPair.publicKey);
    const legitClientId = 'node_victim_' + Date.now();
    clientRepo.register(legitClientId, legitPubJwk);

    // Setup an attacker client
    const attackerKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    // ─────────────────────────────────────────────────────────────────────────
    // ATTACK 1: Forged Signature (Attacker signs with their own key for victim's clientId)
    // ─────────────────────────────────────────────────────────────────────────
    console.log('  [Attack 1/8] Attempting Signature Forgery (Key substitution)...');
    const timestamp1 = Date.now();
    const nonce1 = 'nonce_attack_1_' + Date.now();
    const body1 = { hash: crypto.createHash('sha256').update('phish.xyz').digest('hex'), confidence: 0.95 };
    const canonical1 = buildCanonicalRequest('POST', '/api/vault/submit', timestamp1, nonce1, body1, legitClientId);

    // Attacker signs the request with attacker's private key
    const forgedSigBuf = await crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        attackerKeyPair.privateKey,
        new TextEncoder().encode(canonical1)
    );
    const forgedSigBase64 = Buffer.from(forgedSigBuf).toString('base64');

    // Server verifies against victim's registered public key
    const isForgedValid = await verifySignature(legitPubJwk, canonical1, forgedSigBase64);
    assert.strictEqual(isForgedValid, false, 'Forged signature must be rejected by server');
    console.log('    ✓ FORGED SIGNATURE REJECTED');

    // ─────────────────────────────────────────────────────────────────────────
    // ATTACK 2: Request Tampering in Transit (Changing payload after signing)
    // ─────────────────────────────────────────────────────────────────────────
    console.log('  [Attack 2/8] Attempting In-Transit Body Tampering...');
    const validSigBuf = await crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        legitKeyPair.privateKey,
        new TextEncoder().encode(canonical1)
    );
    const validSigBase64 = Buffer.from(validSigBuf).toString('base64');

    // Attacker modifies the payload in transit
    const tamperedBody = { ...body1, confidence: 0.01, threatType: 'CLEAN' };
    const tamperedCanonical = buildCanonicalRequest('POST', '/api/vault/submit', timestamp1, nonce1, tamperedBody, legitClientId);

    const isTamperedAccepted = await verifySignature(legitPubJwk, tamperedCanonical, validSigBase64);
    assert.strictEqual(isTamperedAccepted, false, 'Tampered payload must fail cryptographic verification');
    console.log('    ✓ TAMPERED PAYLOAD REJECTED');

    // ─────────────────────────────────────────────────────────────────────────
    // ATTACK 3: Replay Attack (Replaying a valid signed request with used nonce)
    // ─────────────────────────────────────────────────────────────────────────
    console.log('  [Attack 3/8] Attempting Replay Attack (Reusing Nonce)...');
    const nonce3 = 'nonce_replay_' + Date.now();
    nonceRepo.record(nonce3, legitClientId, Date.now());

    assert.strictEqual(nonceRepo.has(nonce3), true, 'Nonce repository must contain recorded nonce');
    // Simulated authenticate request with reused nonce:
    const mockReplayReq = new Request('http://localhost:3000/api/vault/submit', {
        method: 'POST',
        headers: {
            'x-phantom-client': legitClientId,
            'x-phantom-timestamp': String(Date.now()),
            'x-phantom-nonce': nonce3,
            'x-phantom-signature': validSigBase64
        },
        body: JSON.stringify(body1)
    });

    const replayAuth = await authenticateSignedRequest(mockReplayReq, body1);
    assert.strictEqual(replayAuth.ok, false, 'Replay request must be rejected');
    assert.strictEqual(replayAuth.status, 409, 'Replay request must return 409 Conflict');
    console.log('    ✓ REPLAY ATTACK REJECTED (409 CONFLICT)');

    // ─────────────────────────────────────────────────────────────────────────
    // ATTACK 4: Expired Timestamp Attack (Sending stale signed request)
    // ─────────────────────────────────────────────────────────────────────────
    console.log('  [Attack 4/8] Attempting Stale Request Attack (Expired Timestamp)...');
    const expiredTimestamp = Date.now() - (10 * 60 * 1000); // 10 minutes ago
    const mockExpiredReq = new Request('http://localhost:3000/api/vault/submit', {
        method: 'POST',
        headers: {
            'x-phantom-client': legitClientId,
            'x-phantom-timestamp': String(expiredTimestamp),
            'x-phantom-nonce': 'nonce_expired_' + Date.now(),
            'x-phantom-signature': validSigBase64
        },
        body: JSON.stringify(body1)
    });

    const expiredAuth = await authenticateSignedRequest(mockExpiredReq, body1);
    assert.strictEqual(expiredAuth.ok, false, 'Expired request must be rejected');
    assert.strictEqual(expiredAuth.status, 401, 'Expired request must return 401 Unauthorized');
    console.log('    ✓ STALE TIMESTAMP REJECTED (401)');

    // ─────────────────────────────────────────────────────────────────────────
    // ATTACK 5: Vault Poisoning Attack (Attempting to flag google.com as threat)
    // ─────────────────────────────────────────────────────────────────────────
    console.log('  [Attack 5/8] Attempting Vault Poisoning (Submitting google.com hash)...');
    const googleHash = crypto.createHash('sha256').update('google.com').digest('hex');
    assert.strictEqual(isProtectedDomainHash(googleHash), true, 'google.com must be in protected domain list');

    let poisoningErrorCaught = false;
    try {
        evaluateThreatTrust({
            hash: googleHash,
            threatType: 'PHISHING',
            confidence: 0.99,
            clientId: legitClientId
        });
    } catch (err) {
        poisoningErrorCaught = true;
        assert(err.message.includes('Poisoning Defense Triggered'), 'Error message must specify poisoning defense');
    }
    assert.strictEqual(poisoningErrorCaught, true, 'Vault poisoning attempt on protected domain must throw and be blocked');
    console.log('    ✓ VAULT POISONING ATTEMPT BLOCKED (Protected Domain Safeguard)');

    // ─────────────────────────────────────────────────────────────────────────
    // ATTACK 6: Malformed SHA-256 Hash Injection
    // ─────────────────────────────────────────────────────────────────────────
    console.log('  [Attack 6/8] Attempting Malformed Hash Injection...');
    let malformedCaught = false;
    try {
        evaluateThreatTrust({
            hash: 'not_a_sha256_hash_123',
            threatType: 'PHISHING',
            confidence: 0.95,
            clientId: legitClientId
        });
    } catch (err) {
        malformedCaught = true;
    }
    assert.strictEqual(malformedCaught, true, 'Malformed hash must be rejected');
    console.log('    ✓ MALFORMED HASH REJECTED');

    // ─────────────────────────────────────────────────────────────────────────
    // ATTACK 7: Merkle Root Tampering Detection
    // ─────────────────────────────────────────────────────────────────────────
    console.log('  [Attack 7/8] Attempting Merkle Tree Tampering Detection...');
    const tree = new MerkleTree();
    await tree.addLeaf(crypto.createHash('sha256').update('threat1.xyz').digest('hex'));
    await tree.addLeaf(crypto.createHash('sha256').update('threat2.xyz').digest('hex'));
    const validRoot = tree.getRoot();

    // Adversary tampers with leaf data in storage
    const fakeProof = {
        leaf: crypto.createHash('sha256').update('legit.com').digest('hex'),
        root: validRoot,
        proof: []
    };
    const isFakeProofValid = await tree.verifyCompactProof(fakeProof);
    assert.strictEqual(isFakeProofValid, false, 'Fake Merkle proof must not verify against genuine root');
    console.log('    ✓ MERKLE TAMPERING REJECTED');

    // ─────────────────────────────────────────────────────────────────────────
    // ATTACK 8: Unknown / Unregistered Client ID Attack
    // ─────────────────────────────────────────────────────────────────────────
    console.log('  [Attack 8/8] Attempting Submission from Unregistered Client ID...');
    const mockUnknownReq = new Request('http://localhost:3000/api/vault/submit', {
        method: 'POST',
        headers: {
            'x-phantom-client': 'node_unregistered_ghost_9999',
            'x-phantom-timestamp': String(Date.now()),
            'x-phantom-nonce': 'nonce_unknown_' + Date.now(),
            'x-phantom-signature': validSigBase64
        },
        body: JSON.stringify(body1)
    });

    const unknownAuth = await authenticateSignedRequest(mockUnknownReq, body1);
    assert.strictEqual(unknownAuth.ok, false, 'Unknown client must be rejected');
    assert.strictEqual(unknownAuth.status, 403, 'Unknown client must return 403 Forbidden');
    console.log('    ✓ UNREGISTERED CLIENT REJECTED (403)');

    console.log('\n========================================================');
    console.log('  ALL 8 ADVERSARIAL ATTACKS SUCCESSFULLY DEFENDED!');
    console.log('========================================================');
    return true;
}

export default testAdversarial;
