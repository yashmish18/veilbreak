/**
 * run_all_tests.js — Unified Test & Verification Runner for Browser Vigilant
 */

import testCrypto from './unit_crypto.test.js';
import testMerkle from './unit_merkle.test.js';
import testMLParity from './unit_ml_parity.test.js';
import testIntegration from './integration_vault.test.js';
import testAdversarial from './security_adversarial.test.js';

async function main() {
    console.log('======================================================================');
    console.log('  BROWSER VIGILANT // AUTOMATED TEST & SECURITY VERIFICATION SUITE   ');
    console.log('======================================================================');

    const startTime = performance.now();
    let passed = 0;
    let failed = 0;

    const testSuites = [
        { name: 'Cryptographic Identity & Request Signing', fn: testCrypto },
        { name: 'Cryptographic Merkle Threat Ledger', fn: testMerkle },
        { name: '56-Feature Mathematical Parity Contract', fn: testMLParity },
        { name: 'SQLite Persistence & Threat Trust Engine', fn: testIntegration },
        { name: 'Adversarial Security Attack Pass (8 Attack Vectors)', fn: testAdversarial }
    ];

    for (const suite of testSuites) {
        try {
            await suite.fn();
            passed++;
        } catch (error) {
            console.error(`\n  [FAIL] Test Suite "${suite.name}" FAILED:`, error);
            failed++;
        }
    }

    const elapsed = (performance.now() - startTime).toFixed(2);

    console.log('\n======================================================================');
    console.log(`  FINAL TEST RESULTS: ${passed} PASSED | ${failed} FAILED in ${elapsed}ms`);
    console.log('======================================================================');

    if (failed > 0) {
        process.exit(1);
    }
}

main().catch(err => {
    console.error('Fatal test runner error:', err);
    process.exit(1);
});
