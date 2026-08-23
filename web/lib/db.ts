import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';

// Initialize SQLite database
const dataDir = path.join(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'threat_vault.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode for high concurrency
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA synchronous = NORMAL;');

// Create tables
db.exec(`
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    public_key_jwk TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    last_active INTEGER NOT NULL,
    reputation REAL DEFAULT 100.0,
    submissions_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS threats (
    hash TEXT PRIMARY KEY,
    threat_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'OBSERVED',
    first_seen_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    observation_count INTEGER DEFAULT 1,
    reporters TEXT NOT NULL,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS sync_logs (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    synced_at INTEGER NOT NULL,
    hash_count INTEGER NOT NULL,
    threat_hash TEXT
);

CREATE TABLE IF NOT EXISTS used_nonces (
    nonce TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_updated ON threats(updated_at);
CREATE INDEX IF NOT EXISTS idx_nonces_timestamp ON used_nonces(timestamp);
`);

// Clean old nonces (older than 15 minutes) periodically
export function cleanOldNonces() {
    const fifteenMinutesAgo = Date.now() - 15 * 60 * 1000;
    db.prepare('DELETE FROM used_nonces WHERE timestamp < ?').run(fifteenMinutesAgo);
}

// ── Client Repository ────────────────────────────────────────────────────────
export const clientRepo = {
    register(clientId: string, publicKeyJwk: any) {
        const jwkStr = typeof publicKeyJwk === 'string' ? publicKeyJwk : JSON.stringify(publicKeyJwk);
        const now = Date.now();
        db.prepare(`
            INSERT INTO clients (client_id, public_key_jwk, registered_at, last_active, reputation, submissions_count, is_active)
            VALUES (?, ?, ?, ?, 100.0, 0, 1)
            ON CONFLICT(client_id) DO UPDATE SET
                public_key_jwk = excluded.public_key_jwk,
                last_active = excluded.last_active
        `).run(clientId, jwkStr, now, now);
        return { clientId, publicKeyJwk, registeredAt: now };
    },

    get(clientId: string) {
        const row: any = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);
        if (!row) return null;
        return {
            clientId: row.client_id,
            publicKeyJwk: JSON.parse(row.public_key_jwk),
            registeredAt: row.registered_at,
            lastActive: row.last_active,
            reputation: row.reputation,
            submissionsCount: row.submissions_count,
            isActive: Boolean(row.is_active)
        };
    },

    updateActivity(clientId: string) {
        db.prepare('UPDATE clients SET last_active = ?, submissions_count = submissions_count + 1 WHERE client_id = ?').run(Date.now(), clientId);
    }
};

// ── Nonce Repository ─────────────────────────────────────────────────────────
export const nonceRepo = {
    has(nonce: string): boolean {
        const row = db.prepare('SELECT 1 FROM used_nonces WHERE nonce = ?').get(nonce);
        return Boolean(row);
    },

    record(nonce: string, clientId: string, timestamp: number) {
        db.prepare('INSERT INTO used_nonces (nonce, client_id, timestamp) VALUES (?, ?, ?)').run(nonce, clientId, timestamp);
    }
};

// ── Threat Repository ────────────────────────────────────────────────────────
export interface ThreatRecord {
    hash: string;
    threatType: string;
    confidence: number;
    status: 'OBSERVED' | 'AUTHENTICATED' | 'VALIDATED' | 'PENDING' | 'CONFIRMED' | 'DISTRIBUTABLE';
    firstSeenAt: number;
    updatedAt: number;
    observationCount: number;
    reporters: string[];
    evidence?: any;
}

export const threatRepo = {
    get(hash: string): ThreatRecord | null {
        const row: any = db.prepare('SELECT * FROM threats WHERE hash = ?').get(hash);
        if (!row) return null;
        return {
            hash: row.hash,
            threatType: row.threat_type,
            confidence: row.confidence,
            status: row.status,
            firstSeenAt: row.first_seen_at,
            updatedAt: row.updated_at,
            observationCount: row.observation_count,
            reporters: JSON.parse(row.reporters),
            evidence: row.evidence ? JSON.parse(row.evidence) : undefined
        };
    },

    save(threat: ThreatRecord) {
        const reportersStr = JSON.stringify(threat.reporters);
        const evidenceStr = threat.evidence ? JSON.stringify(threat.evidence) : null;
        db.prepare(`
            INSERT INTO threats (hash, threat_type, confidence, status, first_seen_at, updated_at, observation_count, reporters, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                threat_type = excluded.threat_type,
                confidence = excluded.confidence,
                status = excluded.status,
                updated_at = excluded.updated_at,
                observation_count = excluded.observation_count,
                reporters = excluded.reporters,
                evidence = excluded.evidence
        `).run(
            threat.hash,
            threat.threatType,
            threat.confidence,
            threat.status,
            threat.firstSeenAt,
            threat.updatedAt,
            threat.observationCount,
            reportersStr,
            evidenceStr
        );
    },

    getDistributableHashes(sinceTimestamp: number = 0): string[] {
        const rows: any[] = db.prepare(`
            SELECT hash FROM threats
            WHERE status IN ('CONFIRMED', 'DISTRIBUTABLE')
              AND updated_at > ?
            ORDER BY updated_at ASC
        `).all(sinceTimestamp);
        return rows.map(r => r.hash);
    },

    getAll(limit: number = 100): ThreatRecord[] {
        const rows: any[] = db.prepare(`
            SELECT * FROM threats
            ORDER BY updated_at DESC
            LIMIT ?
        `).all(limit);
        return rows.map(row => ({
            hash: row.hash,
            threatType: row.threat_type,
            confidence: row.confidence,
            status: row.status,
            firstSeenAt: row.first_seen_at,
            updatedAt: row.updated_at,
            observationCount: row.observation_count,
            reporters: JSON.parse(row.reporters),
            evidence: row.evidence ? JSON.parse(row.evidence) : undefined
        }));
    },

    getStats() {
        const totalThreats = (db.prepare('SELECT COUNT(*) as count FROM threats').get() as any).count;
        const distributableThreats = (db.prepare("SELECT COUNT(*) as count FROM threats WHERE status IN ('CONFIRMED', 'DISTRIBUTABLE')").get() as any).count;
        const totalClients = (db.prepare('SELECT COUNT(*) as count FROM clients').get() as any).count;
        const totalSyncs = (db.prepare('SELECT COUNT(*) as count FROM sync_logs').get() as any).count;

        const recentThreats = db.prepare('SELECT * FROM threats ORDER BY updated_at DESC LIMIT 10').all().map((row: any) => ({
            hash: row.hash,
            threatType: row.threat_type,
            confidence: row.confidence,
            status: row.status,
            createdAt: new Date(row.first_seen_at).toISOString(),
            updatedAt: new Date(row.updated_at).toISOString(),
            observationCount: row.observation_count,
            source: JSON.parse(row.reporters)[0] || 'extension'
        }));

        const breakdown = db.prepare('SELECT threat_type as source, COUNT(*) as count FROM threats GROUP BY threat_type').all();

        return {
            totalThreats,
            verifiedThreats: distributableThreats,
            distributableThreats,
            totalClients,
            totalSyncs,
            recentThreats,
            sourceBreakdown: breakdown,
            lastUpdated: new Date().toISOString()
        };
    },

    recordSync(clientId: string, count: number, threatHash?: string) {
        const id = `sync_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
        db.prepare('INSERT INTO sync_logs (id, client_id, synced_at, hash_count, threat_hash) VALUES (?, ?, ?, ?, ?)').run(
            id, clientId, Date.now(), count, threatHash || null
        );
        return id;
    }
};

/** Cleanly close the SQLite connection (call before process.exit). */
export function closeDb() {
    try { db.close(); } catch (_) { /* already closed */ }
}

// Graceful shutdown — ensures libuv handle is released on Windows
for (const sig of ['SIGINT', 'SIGTERM', 'beforeExit']) {
    process.on(sig as any, () => { closeDb(); });
}

export default db;
