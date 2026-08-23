import { NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';
import { authenticateSignedRequest } from '@/lib/crypto';
import { evaluateThreatTrust } from '@/lib/trust_model';
import { threatRepo } from '@/lib/db';

export async function POST(req: Request) {
    try {
        const rawBody = await req.text();
        let body: any;
        try {
            body = JSON.parse(rawBody);
        } catch {
            return NextResponse.json({ error: "Malformed JSON body" }, { status: 400 });
        }

        // 1. Authenticate Asymmetric Request Signature
        const auth = await authenticateSignedRequest(req, body);
        if (!auth.ok) {
            return NextResponse.json({ error: auth.error }, { status: auth.status || 401 });
        }

        const clientId = auth.clientId!;
        const { hash, threatType, confidence, evidence } = body;

        // 2. Validate input format
        if (!hash || typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash)) {
            return NextResponse.json({ error: "Invalid SHA-256 hash parameter" }, { status: 400 });
        }

        // 3. Process threat through deterministic trust engine
        let result;
        try {
            result = evaluateThreatTrust({
                hash,
                threatType: threatType || 'MALICIOUS_DOMAIN',
                confidence: typeof confidence === 'number' ? confidence : 0.85,
                clientId,
                evidence
            });
        } catch (trustError: any) {
            return NextResponse.json({ error: trustError.message }, { status: 403 });
        }

        // 4. Record sync log
        const syncId = threatRepo.recordSync(clientId, 1, hash);

        return NextResponse.json({
            success: true,
            threat: result.record,
            isDistributable: result.isDistributable,
            trustEvaluation: result.reason,
            syncId
        }, { status: 201 });

    } catch (e: any) {
        console.error("Authenticated vault submit error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}

export async function GET(req: Request) {
    try {
        const { searchParams } = new URL(req.url);
        const hash = searchParams.get('hash');

        if (!hash) {
            return NextResponse.json({ error: "Hash parameter required" }, { status: 400 });
        }

        const threat = threatRepo.get(hash);
        if (!threat) {
            return NextResponse.json({ error: "Threat not found" }, { status: 404 });
        }

        return NextResponse.json({ threat });
    } catch (e: any) {
        console.error("Vault get error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}
