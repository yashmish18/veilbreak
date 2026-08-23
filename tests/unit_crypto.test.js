import assert from 'node:assert';
import crypto from 'node:crypto';
import { buildCanonicalRequest, verifySignature } from '../web/lib/crypto.ts';

async function testCrypto() {
    console.log('\n--- Running Unit Tests: Cryptographic Identity & Request Signing ---');

    // 1. Generate Web Crypto ECDSA P-256 Keypair
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    assert(keyPair.privateKey, 'Private key must be generated');
    assert(keyPair.publicKey, 'Public key must be generated');

    const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    assert.strictEqual(pubJwk.kty, 'EC', 'Key type must be EC');
    assert.strictEqual(pubJwk.crv, 'P-256', 'Curve must be P-256');

    // 2. Canonical Request Construction
    const clientId = 'node_test_12345678';
    const timestamp = Date.now();
    const nonce = 'a1b2c3d4e5f67890';
    const body = { hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', confidence: 0.95 };

    const canonical = buildCanonicalRequest('POST', '/api/vault/submit', timestamp, nonce, body, clientId);
    assert(canonical.includes('POST'), 'Canonical must include method');
    assert(canonical.includes('/api/vault/submit'), 'Canonical must include path');
    assert(canonical.includes(clientId), 'Canonical must include clientId');

    // 3. Asymmetric Request Signing
    const canonicalBytes = new TextEncoder().encode(canonical);
    const signatureBuf = await crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        keyPair.privateKey,
        canonicalBytes
    );
    const signatureBase64 = Buffer.from(signatureBuf).toString('base64');
    assert(signatureBase64.length > 0, 'Signature must not be empty');

    // 4. Server-Side Verification of Valid Signature
    const isValid = await verifySignature(pubJwk, canonical, signatureBase64);
    assert.strictEqual(isValid, true, 'Valid signature must verify successfully');

    // 5. Tampered Body Detection
    const tamperedCanonical = buildCanonicalRequest('POST', '/api/vault/submit', timestamp, nonce, { ...body, confidence: 0.1 }, clientId);
    const isTamperedValid = await verifySignature(pubJwk, tamperedCanonical, signatureBase64);
    assert.strictEqual(isTamperedValid, false, 'Tampered request body must be rejected');

    // 6. Wrong Client Detection
    const wrongClientCanonical = buildCanonicalRequest('POST', '/api/vault/submit', timestamp, nonce, body, 'node_attacker');
    const isWrongClientValid = await verifySignature(pubJwk, wrongClientCanonical, signatureBase64);
    assert.strictEqual(isWrongClientValid, false, 'Signature with wrong client ID must be rejected');

    console.log('  ✓ ECDSA P-256 Keypair generation & export PASSED');
    console.log('  ✓ Deterministic Canonical Request construction PASSED');
    console.log('  ✓ Web Crypto P-256 signing & server verification PASSED');
    console.log('  ✓ Tampered payload detection PASSED');
    console.log('  ✓ Client spoofing rejection PASSED');
    return true;
}

export default testCrypto;
