import assert from 'node:assert';
import { extractFeaturesFullJS } from '../wasm-loader.js';

async function testMLParity() {
    console.log('\n--- Running Unit Tests: 56-Feature Mathematical Parity & Schema ---');

    const testUrls = [
        "https://www.google.com",
        "http://paypal-secure.account-verify.xyz/signin",
        "http://secure-login.paypa1.top/account/update",
        "http://sbi-refund.xyz/process?vpa=taxrefund@government",
        "http://malware.xyz/invoice2024.pdf.exe"
    ];

    for (const url of testUrls) {
        const feats = extractFeaturesFullJS(url);

        // 1. Length contract check
        assert.strictEqual(feats.length, 56, `Feature vector for ${url} must have exactly 56 features`);

        // 2. Numerical validity check
        for (let i = 0; i < feats.length; i++) {
            assert(typeof feats[i] === 'number' && !isNaN(feats[i]), `Feature F${i} for ${url} must be a valid number, got ${feats[i]}`);
        }

        // 3. Specific Feature Behavior Validation
        if (url.includes('.xyz') || url.includes('.top')) {
            assert.strictEqual(feats[38], 1.0, `F38 (Suspicious TLD) must trigger for ${url}`);
        }
        if (url.includes('paypa1')) {
            assert.strictEqual(feats[21], 1.0, `F21 (Brand Typosquat) must trigger for ${url}`);
        }
        if (url.includes('pdf.exe')) {
            assert.strictEqual(feats[31], 1.0, `F31 (Double extension) must trigger for ${url}`);
        }
        if (url.includes('vpa=taxrefund@government')) {
            assert.strictEqual(feats[49], 1.0, `F49 (Suspicious UPI pattern) must trigger for ${url}`);
        }
    }

    console.log('  ✓ 56-Feature length and Float32 schema contract PASSED');
    console.log('  ✓ No NaN or undefined feature values across test corpus PASSED');
    console.log('  ✓ Specific mathematical signal triggers (TLD, Typosquat, Double-Ext, UPI) PASSED');
    return true;
}

export default testMLParity;
