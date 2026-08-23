/**
 * identity.js — Per-Installation ECDSA P-256 Identity & Asymmetric Request Signer
 * 
 * Provides:
 *  - Web Crypto ECDSA P-256 Keypair Generation
 *  - Cryptographic Random Client ID (No Math.random())
 *  - Persistent Storage in chrome.storage.local
 *  - Canonical Request Signing (Method, Path, Timestamp, Nonce, Body SHA-256, ClientID)
 *  - Automatic Public Key Registration with Backend API
 */

class ExtensionIdentity {
    constructor() {
        this.clientId = null;
        this.keyPair = null;
        this.publicKeyJwk = null;
        this.isInitialized = false;
    }

    /**
     * Initialize or load existing cryptographic identity from chrome.storage.local
     */
    async initialize() {
        if (this.isInitialized) return this;

        const cryptoObj = (typeof window !== 'undefined' ? window.crypto : null) ||
                          (typeof globalThis !== 'undefined' ? globalThis.crypto : null);

        if (!cryptoObj || !cryptoObj.subtle) {
            throw new Error('Web Crypto API is not available in this environment');
        }

        let stored = {};
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            stored = await chrome.storage.local.get(['bv_client_id', 'bv_key_priv', 'bv_key_pub']);
        }

        if (stored.bv_client_id && stored.bv_key_priv && stored.bv_key_pub) {
            // Load existing identity
            this.clientId = stored.bv_client_id;
            this.publicKeyJwk = stored.bv_key_pub;

            const privateKey = await cryptoObj.subtle.importKey(
                'jwk',
                stored.bv_key_priv,
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['sign']
            );

            const publicKey = await cryptoObj.subtle.importKey(
                'jwk',
                stored.bv_key_pub,
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['verify']
            );

            this.keyPair = { privateKey, publicKey };
        } else {
            // Generate new ECDSA P-256 keypair
            const randomBytes = new Uint8Array(16);
            cryptoObj.getRandomValues(randomBytes);
            this.clientId = 'node_' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');

            this.keyPair = await cryptoObj.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['sign', 'verify']
            );

            const privJwk = await cryptoObj.subtle.exportKey('jwk', this.keyPair.privateKey);
            const pubJwk = await cryptoObj.subtle.exportKey('jwk', this.keyPair.publicKey);
            this.publicKeyJwk = pubJwk;

            if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                await chrome.storage.local.set({
                    bv_client_id: this.clientId,
                    bv_key_priv: privJwk,
                    bv_key_pub: pubJwk,
                    bv_identity_registered: false
                });
            }
        }

        this.isInitialized = true;
        return this;
    }

    /**
     * Compute SHA-256 hex string using Web Crypto
     */
    async sha256(data) {
        const cryptoObj = (typeof window !== 'undefined' ? window.crypto : null) || globalThis.crypto;
        const encoded = new TextEncoder().encode(data);
        const buf = await cryptoObj.subtle.digest('SHA-256', encoded);
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Register public key with server
     */
    async ensureRegistered(apiBaseUrl = 'http://localhost:3000/api/vault') {
        if (!this.isInitialized) await this.initialize();

        try {
            const res = await fetch(`${apiBaseUrl}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clientId: this.clientId,
                    publicKeyJwk: this.publicKeyJwk
                })
            });

            if (res.ok) {
                if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                    await chrome.storage.local.set({ bv_identity_registered: true });
                }
                return true;
            }
        } catch (e) {
            // Server offline, will retry on next interaction
        }
        return false;
    }

    /**
     * Sign an HTTP request and generate security headers
     * Canonical Format: METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256\nCLIENT_ID
     */
    async signRequest(method, urlOrPath, body = null) {
        if (!this.isInitialized) await this.initialize();

        const cryptoObj = (typeof window !== 'undefined' ? window.crypto : null) || globalThis.crypto;
        const timestamp = Date.now();

        // Cryptographically secure random nonce
        const nonceBytes = new Uint8Array(16);
        cryptoObj.getRandomValues(nonceBytes);
        const nonce = Array.from(nonceBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        // Compute body hash
        const bodyStr = typeof body === 'string' ? body : (body ? JSON.stringify(body) : '');
        const bodyHash = await this.sha256(bodyStr);

        // Normalize path
        let path = urlOrPath;
        try {
            if (urlOrPath.startsWith('http://') || urlOrPath.startsWith('https://')) {
                path = new URL(urlOrPath).pathname;
            }
        } catch {}
        path = path.split('?')[0];

        const canonical = `${method.toUpperCase().trim()}\n${path.trim()}\n${timestamp}\n${nonce}\n${bodyHash}\n${this.clientId}`;
        const canonicalBytes = new TextEncoder().encode(canonical);

        // Sign with ECDSA P-256
        const signatureBuf = await cryptoObj.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            this.keyPair.privateKey,
            canonicalBytes
        );

        // Convert signature buffer to base64
        const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuf)));

        return {
            'x-phantom-client': this.clientId,
            'x-phantom-timestamp': String(timestamp),
            'x-phantom-nonce': nonce,
            'x-phantom-signature': signatureBase64
        };
    }
}

// Singleton export
const identityInstance = new ExtensionIdentity();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ExtensionIdentity, identity: identityInstance };
} else if (typeof window !== 'undefined') {
    window.ExtensionIdentity = ExtensionIdentity;
    window.extensionIdentity = identityInstance;
}

export { ExtensionIdentity, identityInstance as identity };
