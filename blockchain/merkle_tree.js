/**
 * Merkle Tree Implementation for Threat Vault
 * Provides O(log n) inclusion proofs and tamper detection
 */

class MerkleTree {
    constructor() {
        this.leaves = [];
        this.levels = [];
        this.crypto = window.crypto || window.msCrypto;
    }

    // SHA-256 hash function using Web Crypto API
    async sha256(data) {
        const encoder = new TextEncoder();
        const hashBuffer = await this.crypto.subtle.digest('SHA-256', encoder.encode(data));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Add a threat hash to the tree
    async addLeaf(domainHash) {
        if (!this.leaves.includes(domainHash)) {
            this.leaves.push(domainHash);
            await this.rebuildTree();
        }
    }

    // Remove a threat hash from the tree
    async removeLeaf(domainHash) {
        const index = this.leaves.indexOf(domainHash);
        if (index > -1) {
            this.leaves.splice(index, 1);
            await this.rebuildTree();
        }
    }

    // Check if a domain hash exists in the tree
    async contains(domainHash) {
        return this.leaves.includes(domainHash);
    }

    // Get Merkle proof for inclusion verification
    async getProof(domainHash) {
        const index = this.leaves.indexOf(domainHash);
        if (index === -1) return null;

        const proof = [];
        let currentIndex = index;
        let currentLevel = 0;

        while (currentLevel < this.levels.length - 1) {
            const level = this.levels[currentLevel];
            const isLeft = currentIndex % 2 === 0;
            const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;

            if (siblingIndex < level.length) {
                proof.push({
                    index: siblingIndex,
                    hash: level[siblingIndex],
                    side: isLeft ? 'right' : 'left'
                });
            }

            currentIndex = Math.floor(currentIndex / 2);
            currentLevel++;
        }

        return {
            leaf: domainHash,
            index: index,
            proof: proof,
            root: this.getRoot()
        };
    }

    // Verify Merkle proof
    async verifyProof(proof) {
        if (!proof || !proof.leaf || !proof.root || !proof.proof) {
            return false;
        }

        let currentHash = proof.leaf;

        for (const sibling of proof.proof) {
            if (sibling.side === 'left') {
                currentHash = await this.sha256(sibling.hash + currentHash);
            } else {
                currentHash = await this.sha256(currentHash + sibling.hash);
            }
        }

        return currentHash === proof.root;
    }

    // Rebuild the entire tree
    async rebuildTree() {
        if (this.leaves.length === 0) {
            this.levels = [[]];
            return;
        }

        // Start with leaf level
        let currentLevel = [...this.leaves];
        this.levels = [currentLevel];

        // Build tree level by level
        while (currentLevel.length > 1) {
            const nextLevel = [];
            
            for (let i = 0; i < currentLevel.length; i += 2) {
                if (i + 1 < currentLevel.length) {
                    // Hash pair of nodes
                    const combined = await this.sha256(currentLevel[i] + currentLevel[i + 1]);
                    nextLevel.push(combined);
                } else {
                    // Odd number of nodes - duplicate last node
                    nextLevel.push(currentLevel[i]);
                }
            }
            
            this.levels.push(nextLevel);
            currentLevel = nextLevel;
        }
    }

    // Get root hash
    getRoot() {
        if (this.levels.length === 0 || this.levels[this.levels.length - 1].length === 0) {
            return null;
        }
        return this.levels[this.levels.length - 1][0];
    }

    // Get tree height
    getHeight() {
        return this.levels.length;
    }

    // Get total number of leaves
    getLeafCount() {
        return this.leaves.length;
    }

    // Serialize tree for storage
    serialize() {
        return {
            leaves: this.leaves,
            root: this.getRoot(),
            height: this.getHeight()
        };
    }

    // Deserialize tree from storage
    async deserialize(data) {
        if (data && data.leaves) {
            this.leaves = data.leaves;
            await this.rebuildTree();
        }
    }

    // Generate compact proof for bandwidth efficiency
    async getCompactProof(domainHash) {
        const fullProof = await this.getProof(domainHash);
        if (!fullProof) return null;

        // Only include necessary sibling hashes
        const compactProof = {
            leaf: fullProof.leaf,
            indexes: fullProof.proof.map(p => p.index),
            hashes: fullProof.proof.map(p => p.hash),
            root: fullProof.root
        };

        return compactProof;
    }

    // Verify compact proof
    async verifyCompactProof(compactProof) {
        if (!compactProof || !compactProof.leaf || !compactProof.root) {
            return false;
        }

        let currentHash = compactProof.leaf;
        let currentIndex = this.leaves.indexOf(compactProof.leaf);

        if (currentIndex === -1) return false;

        for (let i = 0; i < compactProof.hashes.length; i++) {
            const siblingHash = compactProof.hashes[i];
            const isLeft = currentIndex % 2 === 0;
            
            if (isLeft) {
                currentHash = await this.sha256(currentHash + siblingHash);
            } else {
                currentHash = await this.sha256(siblingHash + currentHash);
            }
            
            currentIndex = Math.floor(currentIndex / 2);
        }

        return currentHash === compactProof.root;
    }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MerkleTree;
} else {
    window.MerkleTree = MerkleTree;
}

export { MerkleTree };
