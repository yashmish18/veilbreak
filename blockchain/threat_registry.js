/**
 * Threat Registry - Blockchain-like Threat Management System
 * Implements smart contract logic for threat registration and verification
 */

class ThreatRegistry {
    constructor() {
        this.threats = new Map();           // domainHash -> ThreatRecord
        this.validators = new Map();        // validatorId -> ValidatorRecord
        this.stakes = new Map();            // validatorId -> stakedAmount
        this.reputation = new Map();        // validatorId -> reputationScore
        this.threatHistory = [];            // Historical threat records
        this.minimumStake = 100;            // Minimum tokens required to validate
        this.minimumReputation = 500;       // Minimum reputation to participate
    }

    // Threat record structure
    createThreatRecord(domainHash, reporter, confidence, threatType, evidence) {
        return {
            domainHash: domainHash,
            reporter: reporter,
            confidence: confidence,
            threatType: threatType,
            evidence: evidence,
            timestamp: Date.now(),
            status: 'pending',                  // pending, verified, rejected, disputed
            verifications: [],                  // List of validator verifications
            verificationCount: 0,
            totalConfidence: 0,
            createdAt: Date.now(),
            updatedAt: Date.now()
        };
    }

    // Validator record structure
    createValidatorRecord(validatorId, publicKey) {
        return {
            id: validatorId,
            publicKey: publicKey,
            registeredAt: Date.now(),
            lastActive: Date.now(),
            totalReports: 0,
            successfulVerifications: 0,
            failedVerifications: 0,
            reputation: 1000,                   // Starting reputation
            stakedAmount: 0,
            isActive: true
        };
    }

    // Register a new threat
    async registerThreat(domainHash, reporter, confidence, threatType, evidence) {
        // Validate inputs
        if (!domainHash || !reporter || confidence < 0 || confidence > 1) {
            throw new Error('Invalid threat registration parameters');
        }

        // Check if threat already exists
        if (this.threats.has(domainHash)) {
            const existing = this.threats.get(domainHash);
            // Update confidence if new report is more confident
            if (confidence > existing.confidence) {
                existing.confidence = confidence;
                existing.evidence = evidence;
                existing.updatedAt = Date.now();
                return existing;
            }
            return existing;
        }

        // Create new threat record
        const threatRecord = this.createThreatRecord(
            domainHash, reporter, confidence, threatType, evidence
        );

        // Store the threat
        this.threats.set(domainHash, threatRecord);
        this.threatHistory.push(threatRecord);

        // Update reporter statistics
        if (this.validators.has(reporter)) {
            const validator = this.validators.get(reporter);
            validator.totalReports++;
            validator.lastActive = Date.now();
        }

        ;
        return threatRecord;
    }

    // Submit verification for a threat
    async submitVerification(domainHash, validatorId, isValid, confidence, signature) {
        // Check if threat exists
        if (!this.threats.has(domainHash)) {
            throw new Error('Threat not found');
        }

        // Check validator eligibility
        if (!this.canValidate(validatorId)) {
            throw new Error('Validator not eligible to verify threats');
        }

        const threat = this.threats.get(domainHash);
        const validator = this.validators.get(validatorId);

        // Create verification record
        const verification = {
            validator: validatorId,
            isValid: isValid,
            confidence: confidence,
            signature: signature,
            timestamp: Date.now(),
            reputation: validator.reputation
        };

        // Add verification to threat record
        threat.verifications.push(verification);
        threat.verificationCount++;
        threat.totalConfidence += confidence;
        threat.updatedAt = Date.now();

        // Update validator statistics
        validator.lastActive = Date.now();
        if (isValid) {
            validator.successfulVerifications++;
        } else {
            validator.failedVerifications++;
        }

        // Update threat status based on consensus
        await this.updateThreatStatus(domainHash);

        // Update validator reputation
        this.updateValidatorReputation(validatorId, isValid, confidence);

        ;
        return verification;
    }

    // Update threat status based on verification consensus
    async updateThreatStatus(domainHash) {
        const threat = this.threats.get(domainHash);
        if (!threat || threat.verificationCount === 0) return;

        // Calculate weighted consensus
        let totalWeight = 0;
        let positiveWeight = 0;
        let avgConfidence = 0;

        for (const verification of threat.verifications) {
            const weight = verification.reputation / 1000; // Normalize reputation
            totalWeight += weight;
            
            if (verification.isValid) {
                positiveWeight += weight;
            }
            
            avgConfidence += verification.confidence;
        }

        avgConfidence /= threat.verifications.length;
        const positiveRatio = positiveWeight / totalWeight;
        const consensusThreshold = 0.6; // 60% agreement needed

        // Update threat status
        if (positiveRatio >= consensusThreshold) {
            threat.status = 'verified';
            threat.finalConfidence = avgConfidence;
        } else if (positiveRatio <= 0.4) {
            threat.status = 'rejected';
            threat.finalConfidence = avgConfidence;
        } else {
            threat.status = 'disputed';
            threat.finalConfidence = avgConfidence;
        }
    }

    // Register a new validator
    async registerValidator(validatorId, publicKey, stakeAmount = 0) {
        // Check if validator already exists
        if (this.validators.has(validatorId)) {
            throw new Error('Validator already registered');
        }

        // Validate stake amount
        if (stakeAmount < this.minimumStake) {
            throw new Error(`Minimum stake required: ' +  + '`);
        }

        // Create validator record
        const validator = this.createValidatorRecord(validatorId, publicKey);
        validator.stakedAmount = stakeAmount;

        // Register validator
        this.validators.set(validatorId, validator);
        this.stakes.set(validatorId, stakeAmount);
        this.reputation.set(validatorId, validator.reputation);

        ;
        return validator;
    }

    // Update validator reputation
    updateValidatorReputation(validatorId, isValid, confidence) {
        const validator = this.validators.get(validatorId);
        if (!validator) return;

        // Calculate reputation change
        const baseChange = isValid ? 10 : -15; // Positive for correct, negative for incorrect
        const confidenceBonus = confidence * 20; // 0-20 bonus based on confidence
        const timeDecay = -1; // Small decay over time

        const reputationChange = baseChange + confidenceBonus + timeDecay;
        validator.reputation = Math.max(0, validator.reputation + reputationChange);
        
        this.reputation.set(validatorId, validator.reputation);
    }

    // Check if validator can participate in verification
    canValidate(validatorId) {
        const validator = this.validators.get(validatorId);
        if (!validator) return false;
        
        const hasMinimumStake = (this.stakes.get(validatorId) || 0) >= this.minimumStake;
        const hasMinimumReputation = (this.reputation.get(validatorId) || 0) >= this.minimumReputation;
        const isActive = validator.isActive;
        
        return hasMinimumStake && hasMinimumReputation && isActive;
    }

    // Get threat information
    getThreat(domainHash) {
        return this.threats.get(domainHash) || null;
    }

    // Get all threats
    getAllThreats() {
        return Array.from(this.threats.values());
    }

    // Get threats by status
    getThreatsByStatus(status) {
        return Array.from(this.threats.values()).filter(t => t.status === status);
    }

    // Get validator information
    getValidator(validatorId) {
        return this.validators.get(validatorId) || null;
    }

    // Get all validators
    getAllValidators() {
        return Array.from(this.validators.values());
    }

    // Get active validators
    getActiveValidators() {
        return Array.from(this.validators.values()).filter(v => v.isActive);
    }

    // Get validator reputation
    getValidatorReputation(validatorId) {
        return this.reputation.get(validatorId) || 0;
    }

    // Get threat statistics
    getStatistics() {
        const threats = Array.from(this.threats.values());
        const validators = Array.from(this.validators.values());
        
        return {
            totalThreats: threats.length,
            verifiedThreats: threats.filter(t => t.status === 'verified').length,
            rejectedThreats: threats.filter(t => t.status === 'rejected').length,
            disputedThreats: threats.filter(t => t.status === 'disputed').length,
            pendingThreats: threats.filter(t => t.status === 'pending').length,
            totalValidators: validators.length,
            activeValidators: validators.filter(v => v.isActive).length,
            totalStaked: Array.from(this.stakes.values()).reduce((a, b) => a + b, 0),
            averageReputation: validators.length > 0 ? 
                validators.reduce((sum, v) => sum + v.reputation, 0) / validators.length : 0
        };
    }

    // Get recent threats
    getRecentThreats(limit = 50) {
        return this.threatHistory
            .slice(-limit)
            .sort((a, b) => b.createdAt - a.createdAt);
    }

    // Search threats by various criteria
    searchThreats(criteria) {
        let results = Array.from(this.threats.values());
        
        if (criteria.status) {
            results = results.filter(t => t.status === criteria.status);
        }
        
        if (criteria.threatType) {
            results = results.filter(t => t.threatType === criteria.threatType);
        }
        
        if (criteria.dateFrom) {
            results = results.filter(t => t.createdAt >= criteria.dateFrom);
        }
        
        if (criteria.dateTo) {
            results = results.filter(t => t.createdAt <= criteria.dateTo);
        }
        
        if (criteria.minConfidence) {
            results = results.filter(t => t.confidence >= criteria.minConfidence);
        }
        
        return results.sort((a, b) => b.updatedAt - a.updatedAt);
    }

    // Export registry data (for backup/sync)
    exportData() {
        return {
            threats: Object.fromEntries(this.threats),
            validators: Object.fromEntries(this.validators),
            stakes: Object.fromEntries(this.stakes),
            reputation: Object.fromEntries(this.reputation),
            threatHistory: this.threatHistory,
            metadata: {
                minimumStake: this.minimumStake,
                minimumReputation: this.minimumReputation,
                exportTimestamp: Date.now()
            }
        };
    }

    // Import registry data (for restore/sync)
    importData(data) {
        if (data.threats) {
            this.threats = new Map(Object.entries(data.threats));
        }
        
        if (data.validators) {
            this.validators = new Map(Object.entries(data.validators));
        }
        
        if (data.stakes) {
            this.stakes = new Map(Object.entries(data.stakes));
        }
        
        if (data.reputation) {
            this.reputation = new Map(Object.entries(data.reputation));
        }
        
        if (data.threatHistory) {
            this.threatHistory = data.threatHistory;
        }
        
        if (data.metadata) {
            this.minimumStake = data.metadata.minimumStake || this.minimumStake;
            this.minimumReputation = data.metadata.minimumReputation || this.minimumReputation;
        }
        
        ;
    }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThreatRegistry;
} else {
    window.ThreatRegistry = ThreatRegistry;
}

export { ThreatRegistry };
