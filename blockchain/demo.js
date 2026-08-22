/**
 * Blockchain Threat Vault Demonstration
 * Shows the system in action with sample threats and validations
 */

class BlockchainDemo {
    constructor() {
        this.vault = new BlockchainThreatVault();
        this.demoData = [
            {
                domain: "phishing-bank-login.xyz",
                confidence: 0.95,
                type: "PHISHING",
                evidence: {
                    url: "https://phishing-bank-login.xyz/secure/login",
                    features: {
                        entropy: 4.8,
                        brandDistance: 1,
                        suspiciousTld: true
                    },
                    domSignals: ["password form", "credential harvesting"]
                }
            },
            {
                domain: "legitimate-banking.com",
                confidence: 0.1,
                type: "LEGITIMATE",
                evidence: {
                    url: "https://legitimate-banking.com/dashboard",
                    features: {
                        entropy: 3.2,
                        brandDistance: 0,
                        suspiciousTld: false
                    },
                    domSignals: ["secure connection", "official domain"]
                }
            },
            {
                domain: "crypto-wallet-scam.top",
                confidence: 0.88,
                type: "CRYPTO_SCAM",
                evidence: {
                    url: "https://crypto-wallet-scam.top/connect-wallet",
                    features: {
                        entropy: 4.1,
                        brandDistance: 2,
                        suspiciousTld: true
                    },
                    domSignals: ["fake metamask", "phishing overlay"]
                }
            }
        ];
    }

    async runDemo() {
        console.log('🚀 Starting Blockchain Threat Vault Demo');
        console.log('=====================================');

        try {
            // Initialize the system
            await this.initializeSystem();
            
            // Run demonstration scenarios
            await this.demonstrateThreatRegistration();
            await this.demonstrateThreatVerification();
            await this.demonstrateMerkleProofs();
            await this.showStatistics();
            
            console.log('✅ Demo completed successfully');
            
        } catch (error) {
            console.error('Demo failed:', error);
        }
    }

    async initializeSystem() {
        console.log('🔄 Initializing Blockchain System');
        await this.vault.initialize();
        console.log('✅ System initialized');
        console.log('📦 Merkle Tree Root:', this.vault.merkleTree.getRoot());
        console.log('🔐 Node ID:', this.vault.consensus.nodeId);
        console.log('📊 Registry Status:', this.vault.registry.getStatistics());
    }

    async demonstrateThreatRegistration() {
        console.log('\n📋 Threat Registration Demo');
        console.log('==========================');
        
        for (const threat of this.demoData) {
            console.log('🔍 Processing:', threat.domain);
            
            try {
                const result = await this.vault.submitThreat(
                    threat.domain,
                    threat.confidence,
                    threat.type,
                    threat.evidence
                );
                
                console.log('✅ Threat registered:', threat.domain, '(confidence: ' + threat.confidence + ')');
                
            } catch (error) {
                console.error('❌ Registration failed for', threat.domain, ':', error.message);
            }
        }
    }

    async demonstrateThreatVerification() {
        console.log('\n✅ Threat Verification Demo');
        console.log('==========================');
        
        // Simulate verification from multiple validators
        const validators = ['validator_1', 'validator_2', 'validator_3'];
        
        for (const threat of this.demoData) {
            console.log('🔍 Verifying:', threat.domain);
            
            const domainHash = await this.vault.hashDomain(threat.domain);
            
            // Simulate multiple validator votes
            for (const validator of validators) {
                const isValid = threat.confidence > 0.5; // Simple rule for demo
                const confidence = 0.7 + Math.random() * 0.3; // 0.7-1.0
                
                try {
                    await this.vault.verifyThreat(domainHash, isValid, confidence);
                    console.log('✅ Validator ' + validator + ' verified threat (confidence: ' + confidence.toFixed(2) + ')');
                } catch (error) {
                    console.error('❌ Validator ' + validator + ' failed:', error.message);
                }
            }
            
            // Check final status
            const finalThreat = this.vault.registry.getThreat(domainHash);
            console.log('📊 Final status: ' + threat.domain + ' - ' + (finalThreat ? finalThreat.status : 'N/A'));
        }
    }

    async demonstrateMerkleProofs() {
        console.log('Demonstrating Merkle proofs...');
        
        for (const threat of this.demoData) {
            if (threat.confidence <= 0.5) continue; // Skip legitimate sites
            
            console.log(`Generating Merkle proof for: ${threat.domain}`);
            
            try {
                const proof = await this.vault.getMerkleProof(threat.domain);
                console.log(`Merkle proof generated: ${proof}`);
                
                // Verify the proof
                const isValid = await this.vault.verifyMerkleProof(proof);
                console.log(`Merkle proof is valid: ${isValid}`);
                
            } catch (error) {
                console.error('Error generating or verifying Merkle proof:', error);
            }
        }
    }

    async showStatistics() {
        console.log('Showing statistics...');
        
        const stats = await this.vault.getStatistics();
        
        console.log(`Total threats registered: ${stats.totalThreats}`);
        console.log(`Total verified threats: ${stats.totalVerified}`);
        console.log(`Total unverified threats: ${stats.totalUnverified}`);
        console.log(`Total legitimate sites: ${stats.totalLegitimate}`);
        console.log(`Total phishing sites: ${stats.totalPhishing}`);
        console.log(`Total crypto scams: ${stats.totalCryptoScams}`);
        console.log(`Total other threats: ${stats.totalOther}`);
    }

    async runPerformanceTest() {
        console.log('Running performance test...');
        
        const testDomains = [];
        const startTime = Date.now();
        
        // Generate 1000 test domains
        for (let i = 0; i < 1000; i++) {
            testDomains.push(`test-domain-${i}.xyz`);
        }
        
        // Test threat registration
        const registerStart = Date.now();
        for (const domain of testDomains) {
            try {
                await this.vault.submitThreat(
                    domain,
                    0.8,
                    "TEST_THREAT",
                    { features: { entropy: 4.5 } }
                );
            } catch (error) {
                // Ignore errors for performance test
            }
        }
        const registerTime = Date.now() - registerStart;
        
        // Test threat lookup
        const lookupStart = Date.now();
        let foundCount = 0;
        for (const domain of testDomains) {
            const result = await this.vault.isThreat(domain);
            if (result.isThreat) foundCount++;
        }
        const lookupTime = Date.now() - lookupStart;
        
        console.log(`Total registration time: ${registerTime}ms`);
        console.log(`Average registration time per domain: ${(registerTime / 1000).toFixed(2)}ms per domain`);
        console.log(`Total lookup time: ${lookupTime}ms`);
        console.log(`Average lookup time per domain: ${(lookupTime / 1000).toFixed(2)}ms per domain`);
        console.log(`Lookup success rate: ${(foundCount / 1000 * 100).toFixed(1)}%`);
        console.log(`Total test time: ${Date.now() - startTime}ms`);
    }

    async demonstratePrivacyFeatures() {
        console.log('Demonstrating privacy features...');
        
        console.log('Hashing a sample domain...');
        console.log('=========================');
        
        // Show hash example
        const sampleDomain = "suspicious-bank.xyz";
        const hash = await this.vault.hashDomain(sampleDomain);
        console.log(`Sample domain: ${sampleDomain}`);
        console.log(`Hashed domain: ${hash}`);
    }
}

// Run the demo when script is executed
if (typeof window !== 'undefined') {
    // Browser environment
    window.runBlockchainDemo = async function() {
        const demo = new BlockchainDemo();
        await demo.runDemo();
        await demo.runPerformanceTest();
        await demo.demonstratePrivacyFeatures();
    };
    
    console.log('Type runBlockchainDemo() to start.');
} else if (typeof module !== 'undefined' && module.exports) {
    // Node.js environment
    module.exports = BlockchainDemo;
}

// Example usage:
/*
// In browser console:
runBlockchainDemo();

// Or programmatically:
const demo = new BlockchainDemo();
await demo.runDemo();
*/
