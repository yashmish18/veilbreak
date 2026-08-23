/**
 * blockchain_vault.js — Client-Side Cryptographic Merkle Threat Ledger
 * 
 * Responsibilities:
 *  1. Maintain local cryptographic Merkle tree of confirmed threat hashes
 *  2. O(1) in-memory lookup for pre-navigation checks
 *  3. Cryptographic inclusion proofs (compact proofs)
 *  4. Tamper detection via Merkle root validation
 *  5. Asymmetric signed communication with backend threat vault API
 */

import { MerkleTree } from './merkle_tree.js';
import { identity } from './identity.js';

class BlockchainThreatVault {
    constructor(merkleTree = null) {
        this.merkleTree = merkleTree || new MerkleTree();
        this.identity = identity;
        this.isInitialized = false;
        this.syncInterval = null;
        this.localThreats = new Set(); // In-memory Set of verified domain SHA-256 hashes
        this.apiBaseUrl = 'http://localhost:3000/api/vault';
    }

    /**
     * Initialize the cryptographic vault & ECDSA identity
     */
    async initialize() {
        if (this.isInitialized) return;

        try {
            await this.identity.initialize();
            await this.loadThreatData();
            
            // Try registering public key with backend
            this.identity.ensureRegistered(this.apiBaseUrl).catch(() => {});

            this.isInitialized = true;
            console.log(`[Cryptographic Vault] Initialized. Node ID: ${this.identity.clientId}`);
        } catch (error) {
            console.error('[Cryptographic Vault] Initialization error:', error);
            throw error;
        }
    }

    /**
     * Load threat ledger from local storage
     */
    async loadThreatData() {
        try {
            if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                const data = await chrome.storage.local.get(['bv_threat_vault', 'bv_merkle_tree']);

                if (data.bv_merkle_tree) {
                    await this.merkleTree.deserialize(data.bv_merkle_tree);
                }

                if (data.bv_threat_vault && Array.isArray(data.bv_threat_vault.blocks)) {
                    for (const block of data.bv_threat_vault.blocks) {
                        if (block.domainHash) {
                            this.localThreats.add(block.domainHash);
                            await this.merkleTree.addLeaf(block.domainHash);
                        }
                    }
                }
            }
        } catch (error) {
            console.warn('[Cryptographic Vault] Load warning:', error);
        }
    }

    /**
     * Persist threat ledger to local storage
     */
    async saveThreatData() {
        try {
            if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                await chrome.storage.local.set({
                    bv_merkle_tree: this.merkleTree.serialize(),
                    bv_local_threats_count: this.localThreats.size
                });
            }
        } catch (error) {
            console.warn('[Cryptographic Vault] Save error:', error);
        }
    }

    /**
     * Hash a domain/hostname using SHA-256
     */
    async hashDomain(domain) {
        let hostname = domain.trim().toLowerCase();
        try {
            if (hostname.includes('://')) {
                hostname = new URL(hostname).hostname;
            } else if (hostname.includes('/')) {
                hostname = hostname.split('/')[0];
            }
            if (hostname.startsWith('www.')) {
                hostname = hostname.slice(4);
            }
            if (hostname.includes(':')) {
                hostname = hostname.split(':')[0];
            }
        } catch {}
        return await this.identity.sha256(hostname);
    }

    /**
     * O(1) Fast Threat Verification against Merkle Vault
     */
    async isThreat(domain) {
        if (!this.isInitialized) await this.initialize();

        try {
            const domainHash = await this.hashDomain(domain);

            if (this.localThreats.has(domainHash)) {
                return { isThreat: true, source: 'local_merkle_ledger', hash: domainHash };
            }

            const inTree = await this.merkleTree.contains(domainHash);
            if (inTree) {
                this.localThreats.add(domainHash);
                return { isThreat: true, source: 'merkle_tree', hash: domainHash };
            }

            return { isThreat: false, source: 'clean', hash: domainHash };
        } catch (error) {
            return { isThreat: false, source: 'error', error: error.message };
        }
    }

    /**
     * Submit a threat detection to the community vault using ECDSA request signing
     */
    async submitThreat(domain, confidence = 0.95, threatType = 'MALICIOUS_DOMAIN', evidence = null) {
        if (!this.isInitialized) await this.initialize();

        const domainHash = await this.hashDomain(domain);

        // Add to local Merkle tree immediately
        await this.merkleTree.addLeaf(domainHash);
        this.localThreats.add(domainHash);
        await this.saveThreatData();

        // Asymmetrically signed request to backend API
        try {
            const payload = {
                hash: domainHash,
                threatType,
                confidence,
                evidence: {
                    source: 'extension_engine',
                    timestamp: Date.now(),
                    signals: evidence?.signals || []
                }
            };

            const signedHeaders = await this.identity.signRequest('POST', '/api/vault/submit', payload);

            const res = await fetch(`${this.apiBaseUrl}/submit`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...signedHeaders
                },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                const data = await res.json();
                console.log(`[Cryptographic Vault] Threat successfully submitted & verified: ${domainHash.slice(0, 10)}...`);
                return data;
            }
        } catch (apiError) {
            // Local detection continues unaffected even if network is unreachable
            console.warn('[Cryptographic Vault] API submission deferred (offline):', apiError.message);
        }

        return { hash: domainHash, status: 'saved_locally' };
    }

    /**
     * Synchronize verified threat hashes from global network
     */
    async syncWithNetwork() {
        if (!this.isInitialized) await this.initialize();

        try {
            let lastSync = 0;
            if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                const stored = await chrome.storage.local.get('bv_last_sync');
                lastSync = stored.bv_last_sync || 0;
            }

            const res = await fetch(`${this.apiBaseUrl}/sync?since=${lastSync}&clientId=${this.identity.clientId}`);
            if (!res.ok) return;

            const data = await res.json();
            if (data && data.hashes && Array.isArray(data.hashes)) {
                let addedCount = 0;
                for (const hash of data.hashes) {
                    if (!this.localThreats.has(hash)) {
                        this.localThreats.add(hash);
                        await this.merkleTree.addLeaf(hash);
                        addedCount++;
                    }
                }

                if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                    await chrome.storage.local.set({ bv_last_sync: Date.now() });
                }

                await this.saveThreatData();
                if (addedCount > 0) {
                    console.log(`[Cryptographic Vault] Synced ${addedCount} verified threat hashes from community vault.`);
                }
            }
        } catch (error) {
            // Soft fail if offline
        }
    }

    /**
     * Get inclusion proof for a domain
     */
    async getMerkleProof(domain) {
        if (!this.isInitialized) await this.initialize();
        const domainHash = await this.hashDomain(domain);
        return await this.merkleTree.getCompactProof(domainHash);
    }

    /**
     * Verify inclusion proof
     */
    async verifyMerkleProof(proof) {
        if (!this.isInitialized) await this.initialize();
        return await this.merkleTree.verifyCompactProof(proof);
    }

    /**
     * Get statistics
     */
    async getStatistics() {
        if (!this.isInitialized) await this.initialize();
        return {
            merkleRoot: this.merkleTree.getRoot() || '0'.repeat(64),
            treeHeight: this.merkleTree.getHeight(),
            totalLeaves: this.merkleTree.getLeafCount(),
            localThreatsCount: this.localThreats.size,
            nodeId: this.identity.clientId
        };
    }
}

export { BlockchainThreatVault };
