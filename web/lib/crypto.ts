import crypto from 'node:crypto';
import { clientRepo, nonceRepo, cleanOldNonces } from './db.ts';

// Freshness window for signed requests (5 minutes)
export const MAX_TIMESTAMP_DRIFT_MS = 5 * 60 * 1000;

export interface SignedRequestHeaders {
    clientId: string;
    timestamp: number;
    nonce: string;
    signature: string;
}

/**
 * Creates the canonical string to be signed or verified.
 * Canonical format:
 * METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256\nCLIENT_ID
 */
export function buildCanonicalRequest(
    method: string,
    path: string,
    timestamp: number,
    nonce: string,
    body: any,
    clientId: string
): string {
    const bodyStr = typeof body === 'string' ? body : (body ? JSON.stringify(body) : '');
    const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex');
    const normalizedMethod = method.toUpperCase().trim();
    const normalizedPath = path.split('?')[0].trim();
    return `${normalizedMethod}\n${normalizedPath}\n${timestamp}\n${nonce}\n${bodyHash}\n${clientId}`;
}

/**
 * Verify ECDSA P-256 signature using Node.js crypto module.
 */
export async function verifySignature(
    publicKeyJwk: any,
    canonicalData: string,
    signatureBase64: string
): Promise<boolean> {
    try {
        const keyObject = crypto.createPublicKey({
            key: publicKeyJwk,
            format: 'jwk'
        });

        // Convert base64 or hex signature to buffer
        const signatureBuf = Buffer.from(signatureBase64, 'base64');
        const verifier = crypto.createVerify('SHA256');
        verifier.update(Buffer.from(canonicalData, 'utf-8'));
        verifier.end();

        // WebCrypto ECDSA outputs IEEE P1363 format (64 bytes: r + s).
        // Node crypto.createVerify supports dsaEncoding 'ieee-p1363'
        return verifier.verify(
            {
                key: keyObject,
                dsaEncoding: 'ieee-p1363'
            },
            signatureBuf
        );
    } catch (error) {
        // Fallback for standard DER encoding if IEEE P1363 fails
        try {
            const keyObject = crypto.createPublicKey({
                key: publicKeyJwk,
                format: 'jwk'
            });
            const signatureBuf = Buffer.from(signatureBase64, 'base64');
            const verifier = crypto.createVerify('SHA256');
            verifier.update(Buffer.from(canonicalData, 'utf-8'));
            verifier.end();
            return verifier.verify(keyObject, signatureBuf);
        } catch (e) {
            console.error('[Crypto] Verification failed:', e);
            return false;
        }
    }
}

/**
 * Authenticate incoming request:
 * 1. Extract and validate headers
 * 2. Validate timestamp freshness
 * 3. Validate and record nonce (replay protection)
 * 4. Fetch registered client public key
 * 5. Reconstruct canonical request
 * 6. Verify ECDSA signature
 */
export async function authenticateSignedRequest(
    req: Request,
    body: any
): Promise<{ ok: boolean; clientId?: string; error?: string; status?: number }> {
    const clientId = req.headers.get('x-phantom-client');
    const timestampStr = req.headers.get('x-phantom-timestamp');
    const nonce = req.headers.get('x-phantom-nonce');
    const signature = req.headers.get('x-phantom-signature');

    if (!clientId || !timestampStr || !nonce || !signature) {
        return {
            ok: false,
            error: 'Missing required signature headers (x-phantom-client, x-phantom-timestamp, x-phantom-nonce, x-phantom-signature)',
            status: 401
        };
    }

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
        return { ok: false, error: 'Invalid timestamp format', status: 400 };
    }

    // 1. Freshness check
    const now = Date.now();
    if (Math.abs(now - timestamp) > MAX_TIMESTAMP_DRIFT_MS) {
        return {
            ok: false,
            error: `Timestamp outside acceptable window (${MAX_TIMESTAMP_DRIFT_MS / 1000}s). Server time: ${new Date(now).toISOString()}`,
            status: 401
        };
    }

    // 2. Replay check (Nonce)
    cleanOldNonces();
    if (nonceRepo.has(nonce)) {
        return { ok: false, error: 'Nonce already used (replay attack detected)', status: 409 };
    }

    // 3. Client lookup
    const client = clientRepo.get(clientId);
    if (!client || !client.isActive) {
        return { ok: false, error: 'Client ID not registered or inactive', status: 403 };
    }

    // 4. Reconstruct canonical request
    const url = new URL(req.url);
    const canonical = buildCanonicalRequest(req.method, url.pathname, timestamp, nonce, body, clientId);

    // 5. Verify cryptographic signature
    const isValid = await verifySignature(client.publicKeyJwk, canonical, signature);
    if (!isValid) {
        return { ok: false, error: 'Invalid ECDSA signature', status: 401 };
    }

    // Record nonce & update activity
    nonceRepo.record(nonce, clientId, timestamp);
    clientRepo.updateActivity(clientId);

    return { ok: true, clientId };
}
