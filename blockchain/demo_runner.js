const fs = require('fs');
const path = require('path');

// Simple demo runner for Node.js environment
async function runDemo() {
    console.log('🚀 Blockchain Demo Runner Starting');
    console.log('==================================');
    
    // Simulate the blockchain components
    console.log('📦 Initializing blockchain components...');
    
    // Mock implementations for demo
    class MockMerkleTree {
        constructor() {
            this.leaves = [];
        }
        
        async addLeaf(hash) {
            if (!this.leaves.includes(hash)) {
                this.leaves.push(hash);
                console.log(`Added leaf: ${hash}`);
            }
        }
        
        async contains(hash) {
            return this.leaves.includes(hash);
        }
        
        getRoot() {
            return 'merkle_root_' + this.leaves.length;
        }
    }
    
    class MockThreatRegistry {
        constructor() {
            this.threats = new Map();
        }
        
        async registerThreat(hash, reporter, confidence, type, evidence) {
            const threat = {
                domainHash: hash,
                reporter: reporter,
                confidence: confidence,
                threatType: type,
                evidence: evidence,
                status: 'pending',
                timestamp: Date.now()
            };
            
            this.threats.set(hash, threat);
            console.log(`Registered threat: ${hash} (${confidence})`);
            return threat;
        }
        
        getStatistics() {
            const threats = Array.from(this.threats.values());
            return {
                totalThreats: threats.length,
                verifiedThreats: threats.filter(t => t.status === 'verified').length,
                pendingThreats: threats.filter(t => t.status === 'pending').length
            };
        }
    }
    
    // Demo data
    const demoThreats = [
        {
            domain: 'phishing-bank-login.xyz',
            confidence: 0.95,
            type: 'PHISHING',
            evidence: { entropy: 4.8, signals: ['password form', 'suspicious TLD'] }
        },
        {
            domain: 'crypto-scam-wallet.top',
            confidence: 0.88,
            type: 'CRYPTO_SCAM',
            evidence: { entropy: 4.1, signals: ['fake metamask', 'phishing overlay'] }
        },
        {
            domain: 'legitimate-banking.com',
            confidence: 0.1,
            type: 'LEGITIMATE',
            evidence: { entropy: 3.2, signals: ['secure connection', 'official domain'] }
        }
    ];
    
    // Initialize components
    const merkleTree = new MockMerkleTree();
    const registry = new MockThreatRegistry();
    
    console.log('✅ Components initialized');
    console.log('==================================');
    
    // Demonstrate threat registration
    console.log('🔍 Registering demo threats...');
    
    for (const threat of demoThreats) {
        // Simple hash function for demo
        const hash = require('crypto')
            .createHash('sha256')
            .update(threat.domain)
            .digest('hex');
        
        await registry.registerThreat(
            hash,
            'demo_validator',
            threat.confidence,
            threat.type,
            threat.evidence
        );
        
        if (threat.confidence > 0.5) {
            await merkleTree.addLeaf(hash);
        }
    }
    
    console.log('✅ Threats registered');
    console.log('==================================');
    
    // Demonstrate threat lookup
    console.log('🔍 Looking up demo threats...');
    
    for (const threat of demoThreats) {
        const hash = require('crypto')
            .createHash('sha256')
            .update(threat.domain)
            .digest('hex');
            
        const inMerkle = await merkleTree.contains(hash);
        const threatRecord = registry.threats.get(hash);
        
        console.log(`Domain: ${threat.domain}`);
        console.log(`Hash: ${hash}`);
        console.log(`In Merkle Tree: ${inMerkle}`);
        console.log(`Threat Record: ${JSON.stringify(threatRecord)}`);
        console.log('----------------------------------');
    }
    
    // Show statistics
    console.log('📊 Showing registry statistics...');
    const stats = registry.getStatistics();
    console.log(`Total Threats: ${stats.totalThreats}`);
    console.log(`Verified Threats: ${stats.verifiedThreats}`);
    console.log(`Pending Threats: ${stats.pendingThreats}`);
    console.log('==================================');
    
    // Performance demonstration
    console.log('⏱️ Performance demonstration...');
    
    const startTime = Date.now();
    const testDomains = Array.from({length: 100}, (_, i) => `test-domain-${i}.xyz`);
    
    // Register 100 test domains
    for (const domain of testDomains) {
        const hash = require('crypto')
            .createHash('sha256')
            .update(domain)
            .digest('hex');
            
        await registry.registerThreat(hash, 'performance_test', 0.9, 'TEST', {});
        await merkleTree.addLeaf(hash);
    }
    
    const registerTime = Date.now() - startTime;
    
    // Lookup all domains
    const lookupStart = Date.now();
    let foundCount = 0;
    for (const domain of testDomains) {
        const hash = require('crypto')
            .createHash('sha256')
            .update(domain)
            .digest('hex');
            
        if (await merkleTree.contains(hash)) {
            foundCount++;
        }
    }
    const lookupTime = Date.now() - lookupStart;
    
    console.log(`Registering 100 domains took ${registerTime}ms`);
    console.log(`Looking up 100 domains took ${lookupTime}ms`);
    console.log(`Lookup success rate: ${(foundCount / testDomains.length * 100).toFixed(2)}%`);
    
    console.log('==================================');
    console.log('🎉 Demo completed successfully!');
    console.log('==================================');

}

// Run the demo
runDemo().catch(console.error);
