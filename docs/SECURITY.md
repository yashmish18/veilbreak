# Browser Vigilant — Security Architecture & Threat Model

## 1. Executive Security Summary

Browser Vigilant (PHANTOM Engine) is an on-device, multi-layered AI cybersecurity shield designed to detect and block phishing attacks, UPI fraud scams, malicious downloads, and DOM-based credential harvesting in real-time.

This document details the complete security architecture, threat model, cryptographic identity system, and adversarial defense guarantees.

---

## 2. Security Boundaries & Trust Architecture

```text
┌────────────────────────────────────────────────────────┐
│                      Web Page                          │
│   (Untrusted Context — Malicious Phishing / Scripts)   │
└──────────────────────────┬─────────────────────────────┘
                           │ postMessage (Origin-Whitelisted & Schema-Validated)
┌──────────────────────────▼─────────────────────────────┐
│                   Content Script                       │
│    (Isolated World — Heuristics + WASM/JS + ONNX)      │
└──────────────────────────┬─────────────────────────────┘
                           │ chrome.runtime.sendMessage (Internal MV3 IPC)
┌──────────────────────────▼─────────────────────────────┐
│              Extension Service Worker                  │
│    (Background Context — Pre-Nav Scan + Cryptography) │
└──────────────────────────┬─────────────────────────────┘
                           │ HTTPS + ECDSA P-256 Signed Requests + Nonces
┌──────────────────────────▼─────────────────────────────┐
│                 Backend API Gateway                    │
│      (Canonical Signature Auth + Rate Limiting)        │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│               SQLite Threat Vault                      │
│     (Durable Storage + Deterministic Trust Engine)     │
└────────────────────────────────────────────────────────┘
```

---

## 3. Cryptographic Identity & Request Authentication

### 3.1 Per-Installation ECDSA P-256 Identity
- **No Shared Master Secrets**: Browser Vigilant does NOT use client-distributed master API keys or secrets.
- **Web Crypto P-256 Keypair**: Every extension instance generates a unique ECDSA P-256 keypair on installation using the Web Crypto API (`crypto.subtle.generateKey`).
- **Cryptographic Node ID**: A cryptographically random 128-bit identifier (`node_<hex>`) generated via `crypto.getRandomValues`.

### 3.2 Asymmetric Request Signing Protocol
All write operations (`POST /api/vault/submit`) require asymmetric cryptographic signatures.

**Canonical Request Format:**
```text
HTTP_METHOD
PATH
TIMESTAMP
NONCE
BODY_SHA256
CLIENT_ID
```

**Security Headers:**
- `x-phantom-client`: Client / Node identifier.
- `x-phantom-timestamp`: Unix timestamp (ms) of request creation.
- `x-phantom-nonce`: 128-bit cryptographically secure random nonce.
- `x-phantom-signature`: Base64-encoded ECDSA P-256 signature across the canonical request.

### 3.3 Replay Protection
1. **Freshness Window**: Timestamps outside ±5 minutes of server time are rejected (`401 Unauthorized`).
2. **Nonce De-duplication**: Nonces are recorded in SQLite (`used_nonces` table). Reused nonces are rejected (`409 Conflict`).
3. **Key Substitution Resistance**: Signatures are verified strictly against the public key registered for `x-phantom-client`.

---

## 4. Threat Intelligence Trust Model

To prevent threat intelligence poisoning, submissions from individual clients do NOT immediately become globally trusted.

```text
[OBSERVED]
    │
    ▼ (Authenticated ECDSA signature verified)
[AUTHENTICATED]
    │
    ▼ (ML confidence >= 0.75 + Multi-signal heuristics)
[VALIDATED]
    │
    ▼ (Multi-reporter corroboration OR single observation >= 0.92)
[CONFIRMED]
    │
    ▼ (Eligible for client distribution)
[DISTRIBUTABLE]
```

### 4.1 Vault Poisoning Defense
- **Protected Core Domain Safeguard**: Hardcoded SHA-256 pre-computed hashes for top global domains (`google.com`, `github.com`, `apple.com`, `microsoft.com`, `amazon.com`, `paypal.com`, etc.).
- Attempted reports targeting protected domains trigger an immediate hard rejection (`403 Forbidden`).
- **Schema & Format Validation**: Hashes must strictly conform to 64-character hexadecimal SHA-256 format.
- **Confidence Range Clamping**: Clamped to `[0.0, 1.0]`.

---

## 5. Web Dashboard Bridge Security

The extension exposes a `window.addEventListener("message")` listener to communicate with the local web dashboard.

### 5.1 Strict Origin Whitelist
Only explicitly authorized dashboard origins are accepted:
- `http://localhost:3000`
- `http://127.0.0.1:3000`
- `https://localhost:3000`
- `https://127.0.0.1:3000`

All messages from other origins (e.g. untrusted third-party webpages) are dropped immediately.

### 5.2 Schema Validation
Privileged actions such as `SAVE_SETTINGS` validate that all fields conform to strict types (boolean flags, numeric thresholds `0.0 - 1.0`, sanitized string arrays for allowlist). Malicious script injection or setting disabling attacks are rejected.

---

## 6. Privacy Protections

- **Zero Raw URL Transmission**: No full URLs, paths, query parameters, search terms, or form inputs leave the browser.
- **SHA-256 Domain Fingerprints**: Threat records store only irreversible SHA-256 hashes of hostnames.
- **Bounded Local History**: Scan history is capped at 100 entries with sanitized metadata (hostname only, no PII).

---

## 7. Client-Side Cryptographic Merkle Threat Ledger

- **Deterministic Root Hash**: Leaf hashes sorted and hashed recursively to produce a single Merkle Root.
- **O(log n) Inclusion Proofs**: Compact proofs enable verification of whether a domain is flagged.
- **Tamper Detection**: On service worker startup, all stored blocks are verified against the recalculated Merkle Root. Discrepancies set `bv_vault_tampered = true`.

---

## 8. Offline & Failure Resilience

- **100% On-Device Detection**: All 5 layers of detection (Pre-nav, WASM/JS Feature Extractor, ONNX ML Random Forest, Heuristics, DOM behavioral scanning) execute locally inside the browser.
- **Backend Outage Independence**: If the Next.js server or SQLite database is offline, local threat detection continues at full capability without degradation.

---

## 9. Security Assumptions & Out of Scope

- **Out of Scope**:
  - Fully compromised host operating system (malware with root/SYSTEM privileges).
  - Physical machine seizure with memory dump inspection.
  - Rogue extensions granted privileged Chrome DevTools debugging capabilities.
