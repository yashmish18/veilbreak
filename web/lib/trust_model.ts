import crypto from 'node:crypto';
import type { ThreatRecord } from './db.ts';
import { threatRepo } from './db.ts';

// Known critical domains that must never be flagged as threats (Vault Poisoning Safeguard)
const PROTECTED_DOMAINS = [
    'google.com', 'www.google.com', 'accounts.google.com',
    'github.com', 'www.github.com', 'api.github.com',
    'microsoft.com', 'login.microsoftonline.com', 'live.com',
    'apple.com', 'icloud.com', 'idmsa.apple.com',
    'amazon.com', 'aws.amazon.com',
    'paypal.com', 'www.paypal.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'wikipedia.org', 'cloudflare.com', 'mozilla.org',
    'bankofamerica.com', 'chase.com', 'wellsfargo.com',
    'localhost', '127.0.0.1'
];

// Pre-compute SHA-256 hashes of protected domains
const PROTECTED_HASHES = new Set<string>(
    PROTECTED_DOMAINS.map(d => crypto.createHash('sha256').update(d.toLowerCase()).digest('hex'))
);

export function isProtectedDomainHash(hash: string): boolean {
    return PROTECTED_HASHES.has(hash.toLowerCase());
}

export interface ThreatSubmissionInput {
    hash: string;
    threatType: string;
    confidence: number;
    clientId: string;
    evidence?: any;
}

/**
 * Deterministic Threat Trust State Machine
 * Evaluates submissions and transitions state appropriately:
 * OBSERVED -> AUTHENTICATED -> VALIDATED -> CONFIRMED -> DISTRIBUTABLE
 */
export function evaluateThreatTrust(input: ThreatSubmissionInput): {
    record: ThreatRecord;
    isDistributable: boolean;
    reason: string;
} {
    const { hash, threatType, confidence, clientId, evidence } = input;
    const now = Date.now();

    // 1. Poisoning Safeguard Check
    if (isProtectedDomainHash(hash)) {
        throw new Error('REJECTED: Target hash corresponds to a protected core domain (Poisoning Defense Triggered)');
    }

    // 2. Format validation
    if (!/^[a-f0-9]{64}$/i.test(hash)) {
        throw new Error('REJECTED: Invalid SHA-256 domain hash format');
    }

    const clampedConfidence = Math.max(0.0, Math.min(1.0, confidence));

    // Retrieve existing record if present
    const existing = threatRepo.get(hash);

    let record: ThreatRecord;

    if (existing) {
        // Multi-reporter corroboration logic
        const reporters = new Set(existing.reporters);
        reporters.add(clientId);

        const newObservationCount = existing.observationCount + 1;
        const newConfidence = Math.max(existing.confidence, clampedConfidence);

        // State Transition Logic
        let newStatus: ThreatRecord['status'] = existing.status;

        if (reporters.size >= 2 || newConfidence >= 0.90) {
            newStatus = 'CONFIRMED';
        } else if (newConfidence >= 0.70) {
            newStatus = 'VALIDATED';
        } else {
            newStatus = 'AUTHENTICATED';
        }

        record = {
            ...existing,
            confidence: newConfidence,
            threatType: threatType || existing.threatType,
            status: newStatus,
            updatedAt: now,
            observationCount: newObservationCount,
            reporters: Array.from(reporters),
            evidence: evidence || existing.evidence
        };
    } else {
        // Initial submission
        let initialStatus: ThreatRecord['status'] = 'AUTHENTICATED';

        if (clampedConfidence >= 0.92) {
            // Very high confidence single observation (e.g. verified IDN homograph / strong ML)
            initialStatus = 'CONFIRMED';
        } else if (clampedConfidence >= 0.75) {
            initialStatus = 'VALIDATED';
        } else {
            initialStatus = 'OBSERVED';
        }

        record = {
            hash: hash.toLowerCase(),
            threatType: threatType || 'UNCLASSIFIED',
            confidence: clampedConfidence,
            status: initialStatus,
            firstSeenAt: now,
            updatedAt: now,
            observationCount: 1,
            reporters: [clientId],
            evidence
        };
    }

    // Save state to SQLite
    threatRepo.save(record);

    const isDistributable = record.status === 'CONFIRMED' || record.status === 'DISTRIBUTABLE';

    return {
        record,
        isDistributable,
        reason: `Threat state evaluated to ${record.status} (reporters: ${record.reporters.length}, confidence: ${(record.confidence * 100).toFixed(1)}%)`
    };
}
