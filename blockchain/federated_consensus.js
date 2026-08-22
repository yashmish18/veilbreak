/**
 * Federated Byzantine Agreement (FBA) Consensus for Threat Validation
 * Enables decentralized threat verification without a central authority
 */

class FederatedConsensus {
    constructor(nodeId, trustedValidators = []) {
        this.nodeId = nodeId;
        this.trustedValidators = new Set(trustedValidators);
        this.quorumSlices = this.generateQuorumSlices();
        this.threatVotes = new Map(); // threatHash -> Map(validator -> vote)
        this.validatorReputation = new Map(); // validator -> reputation score
        this.minimumReputation = 500;
    }

    // Generate quorum slices based on trust relationships
    generateQuorumSlices() {
        const slices = new Map();
        
        // Each node trusts itself and a subset of other validators
        const allValidators = [this.nodeId, ...this.trustedValidators];
        
        for (const validator of allValidators) {
            const slice = new Set([validator]); // Always include self
            
            // Add 70% of other validators that this node trusts
            const otherValidators = allValidators.filter(v => v !== validator);
            const trustCount = Math.floor(otherValidators.length * 0.7);
            
            // Shuffle and select trusted validators
            const shuffled = this.shuffleArray(otherValidators);
            for (let i = 0; i < Math.min(trustCount, shuffled.length); i++) {
                slice.add(shuffled[i]);
            }
            
            slices.set(validator, slice);
        }
        
        return slices;
    }

    // Fisher-Yates shuffle algorithm
    shuffleArray(array) {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    }

    // Submit a threat for validation
    async submitThreat(threatHash, evidence, confidence) {
        const threatData = {
            hash: threatHash,
            evidence: evidence,
            confidence: confidence,
            timestamp: Date.now(),
            submitter: this.nodeId
        };

        // Store locally
        this.threatVotes.set(threatHash, new Map([[this.nodeId, {
            vote: true,
            confidence: confidence,
            timestamp: Date.now()
        }]]));

        // Broadcast to quorum slice for validation
        await this.broadcastToQuorum(threatHash, threatData);
        
        return threatData;
    }

    // Validate threat using local ML model
    async validateThreat(threatData) {
        try {
            // Simulate ML validation (in real implementation, this would call the ONNX model)
            const mlConfidence = await this.simulateMLValidation(threatData.evidence);
            
            // Combine ML confidence with submitter confidence
            const combinedConfidence = (mlConfidence + threatData.confidence) / 2;
            
            return {
                isValid: combinedConfidence > 0.7,
                confidence: combinedConfidence,
                validator: this.nodeId,
                timestamp: Date.now()
            };
        } catch (error) {
            console.warn('Threat validation failed:', error.message);
            return {
                isValid: false,
                confidence: 0,
                validator: this.nodeId,
                timestamp: Date.now(),
                error: error.message
            };
        }
    }

    // Simulate ML validation (replace with actual ONNX inference)
    async simulateMLValidation(evidence) {
        // This is a placeholder - in real implementation:
        // 1. Extract features from evidence
        // 2. Run through ONNX model
        // 3. Return probability score
        
        // Simulate based on evidence characteristics
        let score = 0.5; // Base score
        
        if (evidence.url && evidence.url.includes('phish')) score += 0.3;
        if (evidence.features && evidence.features.entropy > 4.5) score += 0.2;
        if (evidence.domSignals && evidence.domSignals.length > 3) score += 0.15;
        
        return Math.min(0.99, Math.max(0.01, score));
    }

    // Receive threat validation from other validators
    async receiveValidation(threatHash, validation) {
        if (!this.threatVotes.has(threatHash)) {
            this.threatVotes.set(threatHash, new Map());
        }

        const votes = this.threatVotes.get(threatHash);
        votes.set(validation.validator, validation);

        // Check if quorum is reached
        const quorumResult = await this.checkQuorum(threatHash);
        return quorumResult;
    }

    // Check if sufficient quorum has been reached
    async checkQuorum(threatHash) {
        const votes = this.threatVotes.get(threatHash);
        if (!votes || votes.size < 2) return null; // Need at least 2 votes

        // Calculate weighted votes based on reputation
        let totalWeight = 0;
        let positiveWeight = 0;
        let avgConfidence = 0;
        let validatorCount = 0;

        for (const [validator, vote] of votes) {
            const reputation = this.validatorReputation.get(validator) || 1000;
            
            // Only count validators with sufficient reputation
            if (reputation >= this.minimumReputation) {
                const weight = reputation / 1000; // Normalize to 0-1
                totalWeight += weight;
                
                if (vote.isValid) {
                    positiveWeight += weight;
                }
                
                avgConfidence += vote.confidence;
                validatorCount++;
            }
        }

        if (validatorCount === 0) return null;

        avgConfidence /= validatorCount;
        const consensusThreshold = 0.6; // 60% agreement needed
        const positiveRatio = positiveWeight / totalWeight;

        return {
            threatHash: threatHash,
            consensus: positiveRatio >= consensusThreshold,
            confidence: avgConfidence,
            validatorCount: validatorCount,
            positiveRatio: positiveRatio,
            timestamp: Date.now()
        };
    }

    // Broadcast threat to quorum slice
    async broadcastToQuorum(threatHash, threatData) {
        const mySlice = this.quorumSlices.get(this.nodeId);
        if (!mySlice) return;

        // In real implementation, this would send messages to other validators
        console.log('Broadcasting threat to quorum slice: ' + Array.from(mySlice).join(', '));
        
        // Simulate receiving validations from quorum members
        for (const validator of mySlice) {
            if (validator !== this.nodeId) {
                // Simulate network delay
                setTimeout(async () => {
                    const validation = await this.simulateValidatorResponse(threatData, validator);
                    await this.receiveValidation(threatHash, validation);
                }, Math.random() * 1000);
            }
        }
    }

    // Simulate validator response
    async simulateValidatorResponse(threatData, validatorId) {
        // Simulate different validator behaviors
        const isValid = Math.random() > 0.2; // 80% accuracy
        const confidence = 0.5 + Math.random() * 0.5; // 0.5-1.0 confidence
        
        return {
            threatHash: threatData.hash,
            isValid: isValid,
            confidence: confidence,
            validator: validatorId,
            timestamp: Date.now()
        };
    }

    // Update validator reputation based on performance
    updateReputation(validator, accuracy, timeliness) {
        const currentReputation = this.validatorReputation.get(validator) || 1000;
        
        // Calculate reputation change
        const accuracyBonus = accuracy * 50; // 0-50 points for accuracy
        const timelinessBonus = timeliness * 20; // 0-20 points for timeliness
        const baseDecay = -5; // Small decay to prevent stagnation
        
        const newReputation = Math.max(0, currentReputation + accuracyBonus + timelinessBonus + baseDecay);
        
        this.validatorReputation.set(validator, newReputation);
        return newReputation;
    }

    // Get validator reputation
    getReputation(validator) {
        return this.validatorReputation.get(validator) || 1000;
    }

    // Check if validator can participate in consensus
    canValidate(validator) {
        return (this.validatorReputation.get(validator) || 1000) >= this.minimumReputation;
    }

    // Add trusted validator
    addTrustedValidator(validatorId) {
        this.trustedValidators.add(validatorId);
        this.quorumSlices = this.generateQuorumSlices(); // Regenerate slices
    }

    // Remove trusted validator
    removeTrustedValidator(validatorId) {
        this.trustedValidators.delete(validatorId);
        this.quorumSlices = this.generateQuorumSlices(); // Regenerate slices
    }

    // Get current quorum slice for this node
    getMyQuorumSlice() {
        return this.quorumSlices.get(this.nodeId) || new Set([this.nodeId]);
    }

    // Get all trusted validators
    getTrustedValidators() {
        return Array.from(this.trustedValidators);
    }

    // Get threat validation status
    getThreatStatus(threatHash) {
        return this.threatVotes.get(threatHash) || new Map();
    }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FederatedConsensus;
} else {
    window.FederatedConsensus = FederatedConsensus;
}

export { FederatedConsensus };
