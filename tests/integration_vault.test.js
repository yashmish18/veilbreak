import assert from 'node:assert';
import crypto from 'node:crypto';
import { clientRepo, threatRepo } from '../web/lib/db.ts';
import { evaluateThreatTrust } from '../web/lib/trust_model.ts';

async function testIntegration() {
    console.log('\n--- Running Integration Tests: SQLite Persistence & Threat Trust Engine ---');

    // 1. Register Client Keypair in SQLite
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
    const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const clientId = 'node_integ_test_' + Date.now();

    clientRepo.register(clientId, pubJwk);
    const retrievedClient = clientRepo.get(clientId);
    assert(retrievedClient, 'Client must be persisted in SQLite');
    assert.strictEqual(retrievedClient.clientId, clientId, 'Client ID must match');
    assert.strictEqual(retrievedClient.publicKeyJwk.crv, 'P-256', 'Public key curve must be P-256');

    // 2. Submit Threat through Trust Engine — unique domain per run to ensure isolation
    const uniqueDomain = `malicious-integ-test-${Date.now()}-${Math.random().toString(36).slice(2)}.xyz`;
    const threatHash = crypto.createHash('sha256').update(uniqueDomain).digest('hex');
    const result1 = evaluateThreatTrust({
        hash: threatHash,
        threatType: 'PHISHING',
        confidence: 0.95,
        clientId
    });

    assert.strictEqual(result1.record.status, 'CONFIRMED', 'High confidence threat must reach CONFIRMED state');
    assert.strictEqual(result1.isDistributable, true, 'Confirmed threat must be distributable');

    // 3. Multi-Reporter Corroboration
    const secondClientId = 'node_second_client_' + Date.now();
    clientRepo.register(secondClientId, pubJwk);

    const result2 = evaluateThreatTrust({
        hash: threatHash,
        threatType: 'PHISHING',
        confidence: 0.99,
        clientId: secondClientId
    });

    assert.strictEqual(result2.record.observationCount, 2, 'Observation count must increment');
    assert.strictEqual(result2.record.reporters.length, 2, 'Both reporters must be recorded');

    // 4. Query Distributable Hashes from SQLite
    const distributable = threatRepo.getDistributableHashes(0);
    assert(distributable.includes(threatHash), 'Distributable list must contain confirmed threat hash');

    // 5. Query Aggregated Stats
    const stats = threatRepo.getStats();
    assert(stats.totalThreats >= 1, 'Total threats must be at least 1');
    assert(stats.verifiedThreats >= 1, 'Verified threats must be at least 1');
    assert(stats.totalClients >= 2, 'Total registered clients must be at least 2');

    console.log('  ✓ Client ECDSA registration & SQLite retrieval PASSED');
    console.log('  ✓ Deterministic Trust Engine state transitions PASSED');
    console.log('  ✓ Multi-reporter threat corroboration PASSED');
    console.log('  ✓ Distributable delta query from SQLite PASSED');
    console.log('  ✓ Aggregated system statistics query PASSED');
    return true;
}

export default testIntegration;
