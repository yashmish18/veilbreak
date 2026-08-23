import { NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';
import { clientRepo } from '@/lib/db';

export async function POST(req: Request) {
    try {
        const body = await req.json();
        const { clientId, publicKeyJwk } = body;

        if (!clientId || typeof clientId !== 'string' || clientId.length < 8) {
            return NextResponse.json({ error: "Invalid clientId (must be at least 8 chars)" }, { status: 400 });
        }

        if (!publicKeyJwk || typeof publicKeyJwk !== 'object' || publicKeyJwk.kty !== 'EC' || publicKeyJwk.crv !== 'P-256') {
            return NextResponse.json({ error: "Invalid publicKeyJwk (must be ECDSA P-256 JWK)" }, { status: 400 });
        }

        const registered = clientRepo.register(clientId, publicKeyJwk);

        return NextResponse.json({
            success: true,
            message: "Client registered successfully",
            client: registered
        }, { status: 201 });

    } catch (e: any) {
        console.error("Client registration error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}
