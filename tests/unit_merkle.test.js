import assert from 'node:assert';
import crypto from 'node:crypto';
import { MerkleTree } from '../blockchain/merkle_tree.js';

async function testMerkle() {
    console.log('\n--- Running Unit Tests: Client-Side Cryptographic Merkle Ledger ---');

    const tree = new MerkleTree();

    const hash1 = crypto.createHash('sha256').update('evil-phish.xyz').digest('hex');
    const hash2 = crypto.createHash('sha256').update('paypal-fake.top').digest('hex');
    const hash3 = crypto.createHash('sha256').update('sbi-scam.xyz').digest('hex');
    const hash4 = crypto.createHash('sha256').update('gpay-fraud.site').digest('hex');

    // 1. Add leaves & compute root
    await tree.addLeaf(hash1);
    await tree.addLeaf(hash2);
    await tree.addLeaf(hash3);
    await tree.addLeaf(hash4);

    const root = tree.getRoot();
    assert(root && root.length === 64, 'Merkle root must be a 64-char SHA-256 hash');
    assert.strictEqual(tree.getLeafCount(), 4, 'Tree must contain 4 leaves');

    // 2. Contains check
    assert.strictEqual(await tree.contains(hash1), true, 'Tree must contain added hash');
    const cleanHash = crypto.createHash('sha256').update('google.com').digest('hex');
    assert.strictEqual(await tree.contains(cleanHash), false, 'Tree must not contain clean hash');

    // 3. Compact Proof Generation & Verification
    const proof = await tree.getCompactProof(hash2);
    assert(proof && proof.leaf === hash2, 'Proof leaf must match queried hash');
    assert.strictEqual(proof.root, root, 'Proof root must match tree root');

    const isProofValid = await tree.verifyCompactProof(proof);
    assert.strictEqual(isProofValid, true, 'Valid compact Merkle proof must verify');

    // 4. Tampered Proof Detection
    const tamperedProof = { ...proof, leaf: cleanHash };
    const isTamperedValid = await tree.verifyCompactProof(tamperedProof);
    assert.strictEqual(isTamperedValid, false, 'Tampered proof leaf must be rejected');

    // 5. Serialization / Deserialization
    const serialized = tree.serialize();
    const newTree = new MerkleTree();
    await newTree.deserialize(serialized);
    assert.strictEqual(newTree.getRoot(), root, 'Deserialized tree root must match original root');
    assert.strictEqual(newTree.getLeafCount(), 4, 'Deserialized leaf count must match original');

    console.log('  ✓ Merkle leaf insertion & root calculation PASSED');
    console.log('  ✓ Inclusion verification PASSED');
    console.log('  ✓ Compact proof generation & verification PASSED');
    console.log('  ✓ Tampered leaf proof rejection PASSED');
    console.log('  ✓ Deterministic Serialization & Deserialization PASSED');
    return true;
}

export default testMerkle;
