import { NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';
import { threatRepo } from '@/lib/db';

/**
 * Sync endpoint: returns only validated and distributable threat hashes
 * since a given timestamp (ms).
 */
export async function GET(req: Request) {
    try {
        const { searchParams } = new URL(req.url);
        const sinceStr = searchParams.get('since') || '0';
        const since = parseInt(sinceStr, 10) || 0;
        const clientId = searchParams.get('clientId') || 'anonymous';

        const hashes = threatRepo.getDistributableHashes(since);

        if (hashes.length > 0) {
            threatRepo.recordSync(clientId, hashes.length);
        }

        return NextResponse.json({
            hashes,
            timestamp: Date.now(),
            count: hashes.length
        });
    } catch (e: any) {
        console.error('Vault sync error:', e);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
