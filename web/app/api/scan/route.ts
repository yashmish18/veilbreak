import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

interface Finding {
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    title?: string;
    detail: string;
    recommendation: string;
    module?: string;
    cookie?: string;
    issue?: string;
    type?: string;
    technology?: string;
    version?: string;
    status?: string;
    riskLevel?: string;
}

interface RiskCluster {
    name: string;
    description: string;
    components: string[];
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

function cleanUrl(input: string): { valid: boolean; normalized: string; hostname: string; error?: string } {
    let urlStr = input.trim();
    if (!urlStr) {
        return { valid: false, normalized: '', hostname: '', error: 'URL is required.' };
    }

    if (urlStr === 'demo://vulnerable' || urlStr === 'demo:vulnerable' || urlStr.toLowerCase().includes('demo-vulnerable')) {
        return { valid: true, normalized: 'demo://vulnerable', hostname: 'vulnerable-bank-demo.local' };
    }

    if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
        urlStr = 'https://' + urlStr;
    }

    try {
        const parsed = new URL(urlStr);
        if (!parsed.hostname || (!parsed.hostname.includes('.') && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1')) {
            return { valid: false, normalized: '', hostname: '', error: 'Please enter a valid domain (e.g. example.com)' };
        }
        return { valid: true, normalized: parsed.toString(), hostname: parsed.hostname };
    } catch {
        return { valid: false, normalized: '', hostname: '', error: 'Invalid URL format.' };
    }
}

export async function POST(req: NextRequest) {
    try {
        const body = await req.json().catch(() => ({}));
        const targetRaw = body.url;
        const dependencies = body.packageJson || body.dependencies;

        if (dependencies) {
            return handleDependencyAudit(dependencies);
        }

        return handleScan(targetRaw);
    } catch (err: any) {
        return NextResponse.json({ error: err.message || 'Scan execution failed' }, { status: 500 });
    }
}

export async function GET(req: NextRequest) {
    const { searchParams } = new URL(req.url);
    const targetRaw = searchParams.get('url');
    return handleScan(targetRaw || '');
}

async function handleScan(targetRaw: string) {
    const cleaned = cleanUrl(targetRaw);
    if (!cleaned.valid) {
        return NextResponse.json({ error: cleaned.error }, { status: 400 });
    }

    // ── Simulated Vulnerable Demo Target (For Hackathon Demos & Offline Testing) ──
    if (cleaned.normalized === 'demo://vulnerable') {
        return NextResponse.json({
            success: true,
            result: generateDemoReport()
        });
    }

    const targetUrl = cleaned.normalized;
    const targetHost = cleaned.hostname;
    const startTime = performance.now();

    let html = '';
    let responseHeaders: Record<string, string> = {};
    let status = 200;
    let isHttps = targetUrl.startsWith('https://');
    let latencyMs = 0;

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 9000);
        const fetchStart = performance.now();

        const res = await fetch(targetUrl, {
            method: 'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PHANTOM/2.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
            signal: controller.signal,
            redirect: 'follow'
        });

        latencyMs = Math.round(performance.now() - fetchStart);
        clearTimeout(timeoutId);
        status = res.status;
        html = await res.text();

        res.headers.forEach((val, key) => {
            responseHeaders[key.toLowerCase()] = val;
        });
    } catch (err: any) {
        return NextResponse.json({
            error: `Could not reach ${targetHost}: ${err.message || 'Connection timed out or host unreachable'}. Make sure the target is online and accessible.`,
            target: targetHost,
            url: targetUrl
        }, { status: 502 });
    }

    // ── Module 1: Tech Stack Fingerprinting ──
    const techStack = fingerprintTechStack(html, responseHeaders);

    // ── Module 2: Defensive Security Headers ──
    const securityHeaders = analyzeSecurityHeaders(responseHeaders, isHttps, targetHost);

    // ── Module 3: Legacy Tech & CVE Exposure ──
    const legacyTech = detectLegacyTech(techStack, html);

    // ── Module 4: Suspicious In-Page Content ──
    const suspiciousContent = scanSuspiciousContent(html, targetHost);

    // ── Module 5: External Resources & Supply Chain ──
    const externalResources = auditExternalResources(html, targetHost, isHttps);

    // ── Module 6: Cookie & Session Token Isolation ──
    const cookieSecurity = auditCookieSecurity(responseHeaders, isHttps);

    // ── Module 7: Health Check & Latency Diagnostics ──
    const healthCheck = auditHealthCheck(status, latencyMs, responseHeaders, isHttps);

    // ── Module 8: Invisible Failure Detection ──
    const invisibleFailures = auditInvisibleFailures(html, status, responseHeaders);

    const scanMs = +(performance.now() - startTime).toFixed(1);

    // ── Weighted Overall Risk Score Computation ──
    const weights = {
        secHeaders: 0.25,
        legacyTech: 0.20,
        suspicious: 0.25,
        external: 0.15,
        cookies: 0.10,
        health: 0.05,
    };

    const secScore = securityHeaders.score;
    const legacyScore = legacyTech.count === 0 ? 100 :
        legacyTech.overallRisk === 'CRITICAL' ? 10 :
        legacyTech.overallRisk === 'HIGH' ? 30 : 60;
    const suspScore = suspiciousContent.count === 0 ? 100 :
        suspiciousContent.threatLevel === 'CRITICAL' ? 0 :
        suspiciousContent.threatLevel === 'HIGH' ? 20 : 50;
    const extScore = externalResources.flaggedCount === 0 ? 100 :
        Math.max(0, 100 - externalResources.flaggedCount * 20);
    const cookieScore = cookieSecurity.score;
    const healthScore = healthCheck.healthScore;

    const overallScore = Math.round(
        secScore * weights.secHeaders +
        legacyScore * weights.legacyTech +
        suspScore * weights.suspicious +
        extScore * weights.external +
        cookieScore * weights.cookies +
        healthScore * weights.health
    );

    const overallRisk = overallScore >= 80 ? 'LOW' :
        overallScore >= 60 ? 'MEDIUM' :
        overallScore >= 40 ? 'HIGH' : 'CRITICAL';

    const allFindings: Finding[] = [
        ...securityHeaders.findings.map(f => ({ ...f, module: 'security_headers' })),
        ...legacyTech.legacyComponents.map(f => ({ ...f, module: 'legacy_tech', severity: f.riskLevel as any })),
        ...suspiciousContent.indicators.map(f => ({ ...f, module: 'suspicious_content' })),
        ...externalResources.flagged.map(f => ({ ...f, title: f.reason, detail: `Origin: ${f.origin}`, recommendation: 'Review origin trustworthiness.', module: 'external_resources', severity: 'MEDIUM' as const })),
        ...cookieSecurity.findings.map(f => ({ ...f, module: 'cookie_security' })),
        ...invisibleFailures.findings.map(f => ({ ...f, module: 'invisible_failures' }))
    ];

    // ── Compound Risk Clusters ──
    const riskClusters: RiskCluster[] = [];
    if (legacyTech.count > 0 && securityHeaders.findings.length > 2) {
        riskClusters.push({
            name: 'Legacy Stack + Weak Security Configuration',
            description: 'Outdated libraries combined with missing defensive security headers create an elevated attack surface.',
            components: [
                ...legacyTech.legacyComponents.map(l => l.technology),
                ...securityHeaders.findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').map(f => f.title || 'Security Header Deficiency')
            ],
            riskLevel: 'HIGH'
        });
    }

    if (suspiciousContent.count > 0 && externalResources.flaggedCount > 0) {
        riskClusters.push({
            name: 'Suspicious Code & Untrusted Supply Chain',
            description: 'Suspicious script behaviors detected in conjunction with untrusted external resources.',
            components: [
                ...suspiciousContent.indicators.map(i => i.type || 'Suspicious Script Pattern'),
                ...externalResources.flagged.map(f => f.origin)
            ],
            riskLevel: 'CRITICAL'
        });
    }

    if (!isHttps) {
        riskClusters.push({
            name: 'Unencrypted Communication Vector',
            description: 'Plaintext HTTP transmission exposes all credentials, session tokens, and DOM payloads to eavesdropping.',
            components: ['Unencrypted HTTP Protocol', 'Plaintext Data In Transit'],
            riskLevel: 'CRITICAL'
        });
    }

    const report = {
        target: targetHost,
        url: targetUrl,
        httpStatus: status,
        timestamp: Date.now(),
        scanMs,
        overallScore,
        overallRisk,
        modules: {
            techStack,
            securityHeaders,
            legacyTech,
            suspiciousContent,
            externalResources,
            cookieSecurity,
            healthCheck,
            invisibleFailures,
        },
        totalFindings: allFindings.length,
        findings: allFindings,
        riskClusters,
        criticalCount: allFindings.filter(f => f.severity === 'CRITICAL').length,
        highCount: allFindings.filter(f => f.severity === 'HIGH').length,
        mediumCount: allFindings.filter(f => f.severity === 'MEDIUM').length,
        lowCount: allFindings.filter(f => f.severity === 'LOW').length,
    };

    return NextResponse.json({ success: true, result: report });
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 1: Tech Stack Fingerprinting
// ─────────────────────────────────────────────────────────────────────────────
function fingerprintTechStack(html: string, headers: Record<string, string>) {
    const detected: string[] = [];
    const versions: Record<string, string> = {};

    if (html.includes('__NEXT_DATA__') || html.includes('/_next/')) {
        detected.push('Next.js');
        const nextVer = html.match(/"buildId":"([^"]+)"/);
        if (nextVer) versions['Next.js'] = nextVer[1].slice(0, 10);
    }
    if (html.includes('react') || html.includes('data-reactroot') || html.includes('__REACT_DEVTOOLS')) {
        if (!detected.includes('React')) detected.push('React');
    }
    if (html.includes('__NUXT__') || html.includes('/_nuxt/')) {
        detected.push('Nuxt.js');
    }
    if (html.includes('data-v-') || html.includes('vue.js') || html.includes('vue.min.js')) {
        detected.push('Vue.js');
    }
    if (html.includes('ng-version') || html.includes('ng-app') || html.includes('angular.js')) {
        detected.push('Angular');
        const ngVer = html.match(/ng-version="([^"]+)"/);
        if (ngVer) versions['Angular'] = ngVer[1];
    }
    if (html.includes('svelte-') || html.includes('__svelte__')) {
        detected.push('Svelte');
    }

    const jqMatch = html.match(/jquery[.-]([0-9.]+)(?:\.min)?\.js/i) || html.match(/jQuery\s+v?([0-9.]+)/i);
    if (jqMatch || html.toLowerCase().includes('jquery')) {
        detected.push('jQuery');
        if (jqMatch) versions['jQuery'] = jqMatch[1];
    }

    const bsMatch = html.match(/bootstrap[.-]([0-9.]+)(?:\.min)?\.(?:js|css)/i) || html.match(/Bootstrap\s+v?([0-9.]+)/i);
    if (bsMatch || html.includes('class="btn btn-') || html.includes('class="container-fluid"')) {
        detected.push('Bootstrap');
        if (bsMatch) versions['Bootstrap'] = bsMatch[1];
    }

    if (html.includes('tailwind') || /class="[^"]*(?:flex|grid|hidden|bg-|text-|px-|py-)[^"]*"/.test(html)) {
        detected.push('Tailwind CSS');
    }

    if (html.includes('wp-content') || html.includes('wp-includes')) {
        detected.push('WordPress');
        const wpVer = html.match(/<meta[^>]+name="generator"[^>]+content="WordPress\s*([0-9.]+)"/i);
        if (wpVer) versions['WordPress'] = wpVer[1];
    }
    if (html.includes('cdn.shopify.com') || html.includes('Shopify.theme')) {
        detected.push('Shopify');
    }

    const serverHeader = headers['server'] || '';
    if (serverHeader) {
        if (serverHeader.toLowerCase().includes('cloudflare')) detected.push('Cloudflare');
        if (serverHeader.toLowerCase().includes('nginx')) detected.push('Nginx');
        if (serverHeader.toLowerCase().includes('apache')) detected.push('Apache');
        if (serverHeader.toLowerCase().includes('vercel')) detected.push('Vercel');
    }

    const poweredBy = headers['x-powered-by'] || '';
    if (poweredBy) {
        if (poweredBy.toLowerCase().includes('express')) detected.push('Express.js');
        if (poweredBy.toLowerCase().includes('php')) {
            detected.push('PHP');
            const phpVer = poweredBy.match(/PHP\/([0-9.]+)/i);
            if (phpVer) versions['PHP'] = phpVer[1];
        }
        if (poweredBy.toLowerCase().includes('asp.net')) detected.push('ASP.NET');
    }

    if (html.includes('__VIEWSTATE') || html.includes('__EVENTVALIDATION')) {
        if (!detected.includes('ASP.NET')) detected.push('ASP.NET');
    }

    return {
        technologies: Array.from(new Set(detected)),
        versions,
        count: Array.from(new Set(detected)).length
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 2: Defensive Security Headers
// ─────────────────────────────────────────────────────────────────────────────
function analyzeSecurityHeaders(headers: Record<string, string>, isHttps: boolean, hostname: string) {
    const findings: Finding[] = [];
    let score = 100;

    if (!headers['content-security-policy']) {
        findings.push({
            severity: 'HIGH',
            title: 'Missing Content-Security-Policy',
            detail: 'No CSP header detected. Increases exposure to XSS and clickjacking attacks.',
            recommendation: "Deploy a Content-Security-Policy (e.g. default-src 'self')."
        });
        score -= 20;
    } else {
        const csp = headers['content-security-policy'];
        if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
            findings.push({
                severity: 'MEDIUM',
                title: 'Weak Content-Security-Policy Directives',
                detail: `CSP allows unsafe script execution ('unsafe-inline' or 'unsafe-eval').`,
                recommendation: 'Refactor inline scripts and use nonces/hashes instead of unsafe directives.'
            });
            score -= 10;
        }
    }

    if (isHttps && !headers['strict-transport-security']) {
        findings.push({
            severity: 'HIGH',
            title: 'Missing Strict-Transport-Security (HSTS)',
            detail: 'HTTPS site is missing HSTS header. Vulnerable to SSL stripping and protocol downgrade.',
            recommendation: 'Enable HSTS with max-age=31536000; includeSubDomains; preload.'
        });
        score -= 15;
    }

    if (!headers['x-frame-options'] && (!headers['content-security-policy'] || !headers['content-security-policy'].includes('frame-ancestors'))) {
        findings.push({
            severity: 'MEDIUM',
            title: 'Missing X-Frame-Options',
            detail: 'Site does not restrict framing via X-Frame-Options or CSP frame-ancestors.',
            recommendation: 'Set X-Frame-Options: SAMEORIGIN or DENY.'
        });
        score -= 10;
    }

    if (!headers['x-content-type-options'] || !headers['x-content-type-options'].includes('nosniff')) {
        findings.push({
            severity: 'MEDIUM',
            title: 'Missing X-Content-Type-Options: nosniff',
            detail: 'Browser may attempt to MIME-sniff response bodies, risking script execution.',
            recommendation: 'Set X-Content-Type-Options: nosniff on all HTTP responses.'
        });
        score -= 10;
    }

    if (!headers['referrer-policy']) {
        findings.push({
            severity: 'LOW',
            title: 'Missing Referrer-Policy',
            detail: 'No Referrer-Policy header configured. Sensitive URL parameters may leak to third parties.',
            recommendation: 'Set Referrer-Policy: strict-origin-when-cross-origin.'
        });
        score -= 5;
    }

    if (!headers['permissions-policy']) {
        findings.push({
            severity: 'LOW',
            title: 'Missing Permissions-Policy',
            detail: 'Browser features (camera, microphone, geolocation) are not explicitly restricted.',
            recommendation: 'Set Permissions-Policy: camera=(), microphone=(), geolocation=().'
        });
        score -= 5;
    }

    if (headers['server'] && /\/[\d.]+/.test(headers['server'])) {
        findings.push({
            severity: 'MEDIUM',
            title: 'Server Version Disclosure',
            detail: `Server header exposes software version: "${headers['server']}".`,
            recommendation: 'Mask server software versions to prevent targeted version-specific exploits.'
        });
        score -= 5;
    }

    if (headers['x-powered-by']) {
        findings.push({
            severity: 'MEDIUM',
            title: 'Technology Disclosure via X-Powered-By',
            detail: `X-Powered-By reveals backend stack: "${headers['x-powered-by']}".`,
            recommendation: 'Disable X-Powered-By header in your backend configuration.'
        });
        score -= 5;
    }

    if (!isHttps && hostname !== 'localhost' && hostname !== '127.0.0.1') {
        findings.push({
            severity: 'CRITICAL',
            title: 'Unencrypted HTTP Connection',
            detail: 'Site is served over plain HTTP without TLS encryption. Credentials and session tokens are transmitted in plaintext.',
            recommendation: 'Migrate to HTTPS and enforce TLS 1.3 encryption.'
        });
        score -= 30;
    }

    return {
        headers,
        findings,
        score: Math.max(0, score),
        totalChecks: 9
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 3: Legacy Tech & CVE Exposure
// ─────────────────────────────────────────────────────────────────────────────
function detectLegacyTech(techStack: { technologies: string[]; versions: Record<string, string> }, html: string) {
    const legacyFindings: Finding[] = [];
    const versions = techStack.versions;

    if (versions['jQuery']) {
        const v = versions['jQuery'];
        const major = parseInt(v.split('.')[0] || '0', 10);
        const minor = parseInt(v.split('.')[1] || '0', 10);
        if (major < 2) {
            legacyFindings.push({
                technology: 'jQuery',
                version: v,
                riskLevel: 'CRITICAL',
                severity: 'CRITICAL',
                detail: `jQuery ${v} is severely outdated and vulnerable to prototype pollution and XSS (CVE-2020-11022, CVE-2020-11023).`,
                recommendation: 'Upgrade to jQuery 3.7+ immediately.'
            });
        } else if (major === 2 || (major === 3 && minor < 5)) {
            legacyFindings.push({
                technology: 'jQuery',
                version: v,
                riskLevel: 'HIGH',
                severity: 'HIGH',
                detail: `jQuery ${v} contains unpatched cross-site scripting vulnerabilities.`,
                recommendation: 'Upgrade to jQuery 3.7+.'
            });
        }
    }

    if (html.includes('angular.min.js') && (html.includes('1.') || html.includes('ng-app'))) {
        legacyFindings.push({
            technology: 'AngularJS (1.x)',
            version: '1.x',
            riskLevel: 'HIGH',
            severity: 'HIGH',
            detail: 'AngularJS reached official End-of-Life (EOL) in 2021 and receives zero security updates.',
            recommendation: 'Migrate legacy AngularJS components to modern Angular or React.'
        });
    }

    if (versions['Bootstrap']) {
        const major = parseInt(versions['Bootstrap'].split('.')[0] || '0', 10);
        if (major < 4) {
            legacyFindings.push({
                technology: 'Bootstrap',
                version: versions['Bootstrap'],
                riskLevel: 'MEDIUM',
                severity: 'MEDIUM',
                detail: `Bootstrap ${versions['Bootstrap']} is End-of-Life with known XSS in tooltips and popovers.`,
                recommendation: 'Upgrade to Bootstrap 5+.'
            });
        }
    }

    if (versions['WordPress']) {
        const major = parseFloat(versions['WordPress']);
        if (major < 6.2) {
            legacyFindings.push({
                technology: 'WordPress',
                version: versions['WordPress'],
                riskLevel: 'HIGH',
                severity: 'HIGH',
                detail: `WordPress ${versions['WordPress']} is behind current security releases.`,
                recommendation: 'Update WordPress core to the latest stable branch.'
            });
        }
    }

    if (html.includes('name="__VIEWSTATE"') || html.includes('name="__EVENTVALIDATION"')) {
        legacyFindings.push({
            technology: 'ASP.NET WebForms ViewState',
            version: 'Legacy ViewState',
            riskLevel: 'MEDIUM',
            severity: 'MEDIUM',
            detail: 'ASP.NET WebForms ViewState detected. Unencrypted ViewState can lead to deserialization vulnerabilities.',
            recommendation: 'Enable ViewStateMac and encryption, or transition to ASP.NET Core.'
        });
    }

    const overallRisk = legacyFindings.length === 0 ? 'LOW' :
        legacyFindings.some(f => f.riskLevel === 'CRITICAL') ? 'CRITICAL' :
        legacyFindings.some(f => f.riskLevel === 'HIGH') ? 'HIGH' : 'MEDIUM';

    return {
        legacyComponents: legacyFindings,
        overallRisk,
        count: legacyFindings.length
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 4: Suspicious In-Page Script Analysis
// ─────────────────────────────────────────────────────────────────────────────
function scanSuspiciousContent(html: string, hostname: string) {
    const indicators: Finding[] = [];
    const lowerHtml = html.toLowerCase();

    const minerSignatures = [
        'coinhive', 'cryptonight', 'minero.cc', 'coin-hive',
        'jsecoin', 'cryptoloot', 'webminepool', 'monerominer',
        'coinimp.com', 'minr.pw', 'authedmine'
    ];
    for (const sig of minerSignatures) {
        if (lowerHtml.includes(sig)) {
            indicators.push({
                type: 'CRYPTO_MINER',
                severity: 'CRITICAL',
                detail: `In-browser crypto mining signature found: "${sig}".`,
                recommendation: 'Remove unauthorized background compute scripts immediately.'
            });
            break;
        }
    }

    const obfuscationPatterns = [
        { regex: /eval\s*\(\s*atob\s*\(/gi, name: 'eval(atob()) dynamic payload execution' },
        { regex: /eval\s*\(\s*unescape\s*\(/gi, name: 'eval(unescape()) obfuscation chain' },
        { regex: /eval\s*\(\s*String\.fromCharCode/gi, name: 'eval(String.fromCharCode()) code de-obfuscation' },
        { regex: /new\s+Function\s*\(\s*atob/gi, name: 'new Function(atob()) construct execution' }
    ];

    for (const { regex, name } of obfuscationPatterns) {
        if (regex.test(html)) {
            indicators.push({
                type: 'OBFUSCATED_CODE',
                severity: 'HIGH',
                detail: `Suspicious obfuscation chain detected: ${name}.`,
                recommendation: 'Audit inline scripts to eliminate hidden execution payloads.'
            });
        }
    }

    if (/addEventListener\s*\(\s*['"]key(?:down|press|up)['"]/i.test(html) &&
        /(?:fetch|XMLHttpRequest|navigator\.sendBeacon)\s*\(/i.test(html)) {
        indicators.push({
            type: 'KEYLOGGER_PATTERN',
            severity: 'CRITICAL',
            detail: 'Keystroke listener combined with immediate network exfiltration telemetry detected.',
            recommendation: 'Inspect input event handlers for credential harvesting.'
        });
    }

    const formActions = html.match(/<form[^>]+action=["']([^"']+)["']/gi) || [];
    const suspiciousTlds = new Set(['xyz', 'tk', 'top', 'cf', 'ml', 'ga', 'gq', 'pw', 'cc', 'icu', 'click']);

    for (const form of formActions) {
        const actionMatch = form.match(/action=["'](https?:\/\/[^"']+)["']/i);
        if (actionMatch) {
            try {
                const actionHost = new URL(actionMatch[1]).hostname;
                if (actionHost !== hostname) {
                    const tld = actionHost.split('.').pop()?.toLowerCase() || '';
                    if (suspiciousTlds.has(tld)) {
                        indicators.push({
                            type: 'FORMJACKING',
                            severity: 'CRITICAL',
                            detail: `Form transmits credentials/data to external suspicious domain: "${actionHost}".`,
                            recommendation: 'Ensure form actions only submit to authenticated first-party APIs.'
                        });
                    }
                }
            } catch {}
        }
    }

    const webshellKeywords = ['shell_exec(', 'passthru(', 'gzinflate(base64_decode', 'str_rot13('];
    for (const kw of webshellKeywords) {
        if (html.includes(kw)) {
            indicators.push({
                type: 'WEBSHELL_INDICATOR',
                severity: 'HIGH',
                detail: `Known webshell/backdoor execution keyword found: "${kw}".`,
                recommendation: 'Perform immediate code integrity audit for injected backdoors.'
            });
            break;
        }
    }

    const threatLevel = indicators.length === 0 ? 'CLEAN' :
        indicators.some(i => i.severity === 'CRITICAL') ? 'CRITICAL' :
        indicators.some(i => i.severity === 'HIGH') ? 'HIGH' : 'MEDIUM';

    return {
        indicators,
        threatLevel,
        count: indicators.length
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 5: Supply Chain & External Dependencies
// ─────────────────────────────────────────────────────────────────────────────
function auditExternalResources(html: string, hostname: string, isHttps: boolean) {
    const origins = new Map<string, { types: string[]; classification: string }>();

    const trustedCdns = [
        /cdnjs\.cloudflare\.com/, /cdn\.jsdelivr\.net/, /unpkg\.com/,
        /ajax\.googleapis\.com/, /fonts\.googleapis\.com/, /fonts\.gstatic\.com/,
        /code\.jquery\.com/, /stackpath\.bootstrapcdn\.com/, /cdn\.shopify\.com/,
        /\.cloudfront\.net$/, /\.akamaihd\.net$/, /\.fastly\.net$/,
        /\.google\.com$/, /\.gstatic\.com$/, /\.googleapis\.com$/,
        /\.github\.com$/, /\.githubusercontent\.com$/, /\.cloudflare\.com$/,
        /\.stripe\.com$/, /\.paypal\.com$/
    ];

    const suspiciousTlds = new Set(['xyz', 'tk', 'top', 'cf', 'ml', 'ga', 'gq', 'pw', 'cc', 'icu', 'club', 'click']);

    function classify(host: string): string {
        if (host === hostname) return 'self';
        if (trustedCdns.some(pattern => pattern.test(host))) return 'trusted_cdn';
        const tld = host.split('.').pop()?.toLowerCase() || '';
        if (suspiciousTlds.has(tld)) return 'suspicious';
        return 'external';
    }

    const scripts = html.match(/<script[^>]+src=["']([^"']+)["']/gi) || [];
    for (const s of scripts) {
        const src = s.match(/src=["']([^"']+)["']/i)?.[1];
        if (src && (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//'))) {
            try {
                const fullUrl = src.startsWith('//') ? 'https:' + src : src;
                const h = new URL(fullUrl).hostname;
                if (h !== hostname) {
                    if (!origins.has(h)) origins.set(h, { types: [], classification: classify(h) });
                    origins.get(h)!.types.push('script');
                }
            } catch {}
        }
    }

    const links = html.match(/<link[^>]+href=["']([^"']+)["']/gi) || [];
    for (const l of links) {
        const href = l.match(/href=["']([^"']+)["']/i)?.[1];
        if (href && (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//'))) {
            try {
                const fullUrl = href.startsWith('//') ? 'https:' + href : href;
                const h = new URL(fullUrl).hostname;
                if (h !== hostname) {
                    if (!origins.has(h)) origins.set(h, { types: [], classification: classify(h) });
                    origins.get(h)!.types.push('stylesheet');
                }
            } catch {}
        }
    }

    const flagged: { origin: string; reason: string; types: string[] }[] = [];
    origins.forEach((info, origin) => {
        if (info.classification === 'suspicious') {
            flagged.push({ origin, reason: 'Suspicious TLD Domain', types: info.types });
        }
    });

    if (isHttps) {
        const httpResources = html.match(/(?:src|href)=["']http:\/\/[^"']+["']/gi) || [];
        for (const res of httpResources) {
            const match = res.match(/http:\/\/([^/"']+)/i);
            if (match && match[1]) {
                flagged.push({ origin: match[1], reason: 'Mixed Content (Insecure HTTP on HTTPS)', types: ['insecure_http'] });
            }
        }
    }

    const externalList = Array.from(origins.entries()).map(([origin, info]) => ({
        origin,
        classification: info.classification,
        resourceTypes: Array.from(new Set(info.types))
    }));

    return {
        externalOrigins: externalList,
        totalExternal: origins.size,
        trustedCount: externalList.filter(e => e.classification === 'trusted_cdn').length,
        untrustedCount: externalList.filter(e => e.classification === 'external' || e.classification === 'suspicious').length,
        flagged,
        flaggedCount: flagged.length
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 6: Cookie & Session Token Security
// ─────────────────────────────────────────────────────────────────────────────
function auditCookieSecurity(headers: Record<string, string>, isHttps: boolean) {
    const findings: Finding[] = [];
    const setCookie = headers['set-cookie'] || '';
    let score = 100;

    if (!setCookie) {
        return {
            totalCookies: 0,
            findings: [],
            score: 100
        };
    }

    const cookies = setCookie.split(/,(?=[^;]+=[^;]+)/g);

    for (const raw of cookies) {
        const parts = raw.split(';').map(p => p.trim());
        const [nameVal] = parts;
        const name = nameVal.split('=')[0] || 'cookie';
        const hasHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
        const hasSecure = parts.some(p => p.toLowerCase() === 'secure');
        const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));

        const sensitiveNames = ['session', 'token', 'auth', 'jwt', 'sid', 'login', 'phpsessid'];
        const isSensitive = sensitiveNames.some(s => name.toLowerCase().includes(s));

        if (isSensitive && !hasHttpOnly) {
            findings.push({
                severity: 'HIGH',
                cookie: name,
                issue: 'Missing HttpOnly Flag',
                detail: `Authentication cookie "${name}" lacks HttpOnly flag and can be accessed by client scripts.`,
                recommendation: `Add HttpOnly flag to ${name} in Set-Cookie header.`
            });
            score -= 15;
        }

        if (isSensitive && !hasSecure && isHttps) {
            findings.push({
                severity: 'HIGH',
                cookie: name,
                issue: 'Missing Secure Flag',
                detail: `Sensitive cookie "${name}" does not enforce Secure flag on HTTPS connection.`,
                recommendation: `Add Secure flag to ${name} in Set-Cookie header.`
            });
            score -= 15;
        }

        if (!sameSitePart || sameSitePart.toLowerCase().includes('samesite=none')) {
            findings.push({
                severity: 'LOW',
                cookie: name,
                issue: 'Missing SameSite Isolation',
                detail: `Cookie "${name}" has no explicit SameSite policy (or SameSite=None), risking CSRF.`,
                recommendation: `Set SameSite=Lax or SameSite=Strict on cookie ${name}.`
            });
            score -= 5;
        }
    }

    return {
        totalCookies: cookies.length,
        findings,
        score: Math.max(0, score)
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 7: Health Check & Latency Diagnostics
// ─────────────────────────────────────────────────────────────────────────────
function auditHealthCheck(status: number, latencyMs: number, headers: Record<string, string>, isHttps: boolean) {
    const compression = headers['content-encoding'] || 'none';
    const isCompressed = compression !== 'none';
    const isOkStatus = status >= 200 && status < 400;

    let healthScore = 100;
    if (!isOkStatus) healthScore -= 30;
    if (latencyMs > 1000) healthScore -= 20;
    else if (latencyMs > 500) healthScore -= 10;
    if (!isCompressed) healthScore -= 10;
    if (!isHttps) healthScore -= 20;

    return {
        status,
        latencyMs,
        compression,
        isCompressed,
        isHttps,
        healthScore: Math.max(0, healthScore),
        serverTiming: headers['server-timing'] || 'none',
        cacheControl: headers['cache-control'] || 'none'
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 8: Invisible Failure Detection
// ─────────────────────────────────────────────────────────────────────────────
function auditInvisibleFailures(html: string, status: number, headers: Record<string, string>) {
    const findings: Finding[] = [];

    // Empty body with HTTP 200
    if (status === 200 && html.trim().length < 50) {
        findings.push({
            severity: 'HIGH',
            title: 'Invisible Silent Failure (Empty HTTP 200 Response)',
            detail: 'Server returned HTTP 200 OK but response body is nearly empty, indicating an unhandled runtime error.',
            recommendation: 'Verify application routing and API handler error bubbling.'
        });
    }

    // CORS Wildcard with credentials
    if (headers['access-control-allow-origin'] === '*' && headers['access-control-allow-credentials'] === 'true') {
        findings.push({
            severity: 'CRITICAL',
            title: 'Insecure CORS Configuration',
            detail: 'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials allows arbitrary origins to make authenticated requests.',
            recommendation: 'Specify exact trusted origins in Access-Control-Allow-Origin.'
        });
    }

    // Missing HTML Title / Meta
    if (!html.includes('<title>') || html.includes('<title></title>')) {
        findings.push({
            severity: 'LOW',
            title: 'Missing Page Title Metadata',
            detail: 'HTML lacks a valid <title> tag, degrading SEO and browser security context identification.',
            recommendation: 'Add descriptive <title> tag to the document head.'
        });
    }

    return {
        count: findings.length,
        findings
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Module 9: Dependency / Package.json CVE Audit
// ─────────────────────────────────────────────────────────────────────────────
function handleDependencyAudit(pkgRaw: string | object) {
    let pkg: any = {};
    try {
        pkg = typeof pkgRaw === 'string' ? JSON.parse(pkgRaw) : pkgRaw;
    } catch {
        return NextResponse.json({ error: 'Invalid package.json format. Please provide valid JSON.' }, { status: 400 });
    }

    const allDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {})
    };

    const KNOWN_VULNERABILITIES: Record<string, { maxVersion: string; cve: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; description: string; fix: string }> = {
        'lodash': { maxVersion: '4.17.21', cve: 'CVE-2021-23337', severity: 'HIGH', description: 'Command injection via template function.', fix: 'Upgrade to lodash >= 4.17.21' },
        'axios': { maxVersion: '1.6.0', cve: 'CVE-2023-45857', severity: 'HIGH', description: 'Cross-site request forgery and SSRF vulnerability.', fix: 'Upgrade to axios >= 1.6.0' },
        'minimist': { maxVersion: '1.2.6', cve: 'CVE-2021-44906', severity: 'CRITICAL', description: 'Prototype pollution in CLI argument parsing.', fix: 'Upgrade to minimist >= 1.2.6' },
        'jsonwebtoken': { maxVersion: '9.0.0', cve: 'CVE-2022-23529', severity: 'CRITICAL', description: 'Insecure key verification leading to arbitrary code execution.', fix: 'Upgrade to jsonwebtoken >= 9.0.0' },
        'express': { maxVersion: '4.19.2', cve: 'CVE-2024-29041', severity: 'MEDIUM', description: 'Open redirect vulnerability via malformed URLs.', fix: 'Upgrade to express >= 4.19.2' },
        'tar': { maxVersion: '6.1.9', cve: 'CVE-2021-37712', severity: 'HIGH', description: 'Arbitrary file creation via directory traversal.', fix: 'Upgrade to tar >= 6.1.9' },
        'moment': { maxVersion: '2.29.4', cve: 'CVE-2022-31129', severity: 'HIGH', description: 'ReDoS vulnerability in RFC2822 date parser.', fix: 'Upgrade to moment >= 2.29.4' },
        'glob-parent': { maxVersion: '5.1.2', cve: 'CVE-2020-28469', severity: 'HIGH', description: 'Regular Expression Denial of Service (ReDoS).', fix: 'Upgrade to glob-parent >= 5.1.2' },
        'semver': { maxVersion: '7.5.2', cve: 'CVE-2022-25883', severity: 'HIGH', description: 'ReDoS in semantic version parser.', fix: 'Upgrade to semver >= 7.5.2' }
    };

    const findings: Finding[] = [];
    const auditedPackages: { name: string; version: string; status: 'vulnerable' | 'safe'; cve?: string; severity?: string }[] = [];

    for (const [dep, verStr] of Object.entries(allDeps)) {
        const cleanVer = (verStr as string).replace(/[^0-9.]/g, '');
        const vuln = KNOWN_VULNERABILITIES[dep];

        if (vuln) {
            findings.push({
                severity: vuln.severity,
                title: `${dep}@${verStr} (${vuln.cve})`,
                detail: vuln.description,
                recommendation: vuln.fix,
                module: 'dependency_audit',
                technology: dep,
                version: verStr as string
            });
            auditedPackages.push({
                name: dep,
                version: verStr as string,
                status: 'vulnerable',
                cve: vuln.cve,
                severity: vuln.severity
            });
        } else {
            auditedPackages.push({
                name: dep,
                version: verStr as string,
                status: 'safe'
            });
        }
    }

    const score = Math.max(0, 100 - findings.filter(f => f.severity === 'CRITICAL').length * 30 - findings.filter(f => f.severity === 'HIGH').length * 20 - findings.filter(f => f.severity === 'MEDIUM').length * 10);

    return NextResponse.json({
        success: true,
        type: 'dependency_audit',
        result: {
            totalDependencies: Object.keys(allDeps).length,
            vulnerabilitiesCount: findings.length,
            score,
            packages: auditedPackages,
            findings
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulated Vulnerable Demo Target (For Hackathon Demos)
// ─────────────────────────────────────────────────────────────────────────────
function generateDemoReport() {
    return {
        target: "vulnerable-bank-demo.local",
        url: "http://vulnerable-bank-demo.local",
        httpStatus: 200,
        timestamp: Date.now(),
        scanMs: 142.6,
        overallScore: 24,
        overallRisk: "CRITICAL",
        modules: {
            techStack: {
                technologies: ["jQuery", "Bootstrap", "PHP", "Apache", "WordPress", "ASP.NET"],
                versions: {
                    "jQuery": "1.8.3",
                    "Bootstrap": "3.3.7",
                    "PHP": "5.6.40",
                    "WordPress": "5.2.1"
                },
                count: 6
            },
            securityHeaders: {
                headers: {
                    "server": "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k",
                    "x-powered-by": "PHP/5.6.40"
                },
                findings: [
                    { severity: "CRITICAL", title: "Unencrypted HTTP Connection", detail: "Site is served over plain HTTP without TLS encryption.", recommendation: "Migrate to HTTPS and enforce TLS 1.3 encryption." },
                    { severity: "HIGH", title: "Missing Content-Security-Policy", detail: "No CSP header detected. Increases exposure to XSS and clickjacking.", recommendation: "Deploy a Content-Security-Policy (e.g. default-src 'self')." },
                    { severity: "HIGH", title: "Missing Strict-Transport-Security (HSTS)", detail: "Vulnerable to SSL stripping and protocol downgrade.", recommendation: "Enable HSTS with max-age=31536000." },
                    { severity: "MEDIUM", title: "Missing X-Frame-Options", detail: "Site does not restrict framing via X-Frame-Options.", recommendation: "Set X-Frame-Options: SAMEORIGIN or DENY." },
                    { severity: "MEDIUM", title: "Server Version Disclosure", detail: "Server header exposes: 'Apache/2.4.6 (CentOS) OpenSSL/1.0.2k'.", recommendation: "Mask server software versions in Apache config." },
                    { severity: "MEDIUM", title: "Technology Disclosure via X-Powered-By", detail: "X-Powered-By reveals: 'PHP/5.6.40'.", recommendation: "Disable expose_php in php.ini." }
                ],
                score: 15,
                totalChecks: 9
            },
            legacyTech: {
                legacyComponents: [
                    { technology: "jQuery", version: "1.8.3", riskLevel: "CRITICAL", severity: "CRITICAL", detail: "jQuery 1.8.3 has known prototype pollution and XSS (CVE-2020-11022, CVE-2020-11023).", recommendation: "Upgrade to jQuery 3.7+ immediately." },
                    { technology: "PHP", version: "5.6.40", riskLevel: "CRITICAL", severity: "CRITICAL", detail: "PHP 5.6 is End-of-Life since 2018 with critical remote code execution vulnerabilities.", recommendation: "Migrate to PHP 8.2+ immediately." },
                    { technology: "WordPress", version: "5.2.1", riskLevel: "HIGH", severity: "HIGH", detail: "WordPress 5.2.1 is unpatched against multiple authenticated privilege escalation exploits.", recommendation: "Update to WordPress 6.x." },
                    { technology: "Bootstrap", version: "3.3.7", riskLevel: "MEDIUM", severity: "MEDIUM", detail: "Bootstrap 3.3.7 is End-of-Life with known XSS in tooltips and popovers.", recommendation: "Upgrade to Bootstrap 5+." }
                ],
                overallRisk: "CRITICAL",
                count: 4
            },
            suspiciousContent: {
                indicators: [
                    { type: "CRYPTO_MINER", severity: "CRITICAL", detail: "In-browser crypto mining script detected: 'coinhive.min.js'.", recommendation: "Remove unauthorized background compute scripts immediately." },
                    { type: "OBFUSCATED_CODE", severity: "HIGH", detail: "eval(atob()) dynamic payload execution chain found in inline script.", recommendation: "Audit inline scripts to eliminate hidden execution payloads." },
                    { type: "FORMJACKING", severity: "CRITICAL", detail: "Login form submits credentials to suspicious domain: 'https://exfiltrate-auth.xyz/harvest'.", recommendation: "Ensure form actions only submit to authenticated first-party APIs." }
                ],
                threatLevel: "CRITICAL",
                count: 3
            },
            externalResources: {
                externalOrigins: [
                    { origin: "coinhive.com", classification: "suspicious", resourceTypes: ["script"] },
                    { origin: "exfiltrate-auth.xyz", classification: "suspicious", resourceTypes: ["form_action"] },
                    { origin: "code.jquery.com", classification: "trusted_cdn", resourceTypes: ["script"] },
                    { origin: "cdn.jsdelivr.net", classification: "trusted_cdn", resourceTypes: ["stylesheet"] }
                ],
                totalExternal: 4,
                trustedCount: 2,
                untrustedCount: 2,
                flagged: [
                    { origin: "coinhive.com", reason: "Known Crypto Miner Host", types: ["script"] },
                    { origin: "exfiltrate-auth.xyz", reason: "Suspicious TLD Domain", types: ["form_action"] }
                ],
                flaggedCount: 2
            },
            cookieSecurity: {
                totalCookies: 2,
                findings: [
                    { severity: "HIGH", cookie: "PHPSESSID", issue: "Missing HttpOnly Flag", detail: "Session token 'PHPSESSID' lacks HttpOnly flag and can be accessed via document.cookie.", recommendation: "Set session.cookie_httponly = 1 in php.ini." },
                    { severity: "HIGH", cookie: "PHPSESSID", issue: "Missing Secure Flag", detail: "Session token transmitted over plain HTTP without encryption.", recommendation: "Enforce HTTPS and enable session.cookie_secure = 1." }
                ],
                score: 30
            },
            healthCheck: {
                status: 200,
                latencyMs: 380,
                compression: "none",
                isCompressed: false,
                isHttps: false,
                healthScore: 40,
                serverTiming: "none",
                cacheControl: "no-cache"
            },
            invisibleFailures: {
                count: 1,
                findings: [
                    { severity: "CRITICAL", title: "Insecure CORS Wildcard Configuration", detail: "Access-Control-Allow-Origin: * allows any domain to read responses.", recommendation: "Restrict allowed origins." }
                ]
            }
        },
        totalFindings: 18,
        findings: [
            { severity: "CRITICAL", title: "Unencrypted HTTP Connection", detail: "Site is served over plain HTTP without TLS encryption.", recommendation: "Migrate to HTTPS.", module: "security_headers" },
            { severity: "CRITICAL", title: "In-Browser Crypto Miner", detail: "Mining script 'coinhive.min.js' detected.", recommendation: "Remove immediately.", module: "suspicious_content" },
            { severity: "CRITICAL", title: "Formjacking Credential Theft", detail: "Form submits to exfiltrate-auth.xyz.", recommendation: "Change form target.", module: "suspicious_content" },
            { severity: "CRITICAL", title: "jQuery 1.8.3 Vulnerabilities", detail: "Vulnerable to prototype pollution and XSS (CVE-2020-11022).", recommendation: "Upgrade to jQuery 3.7+.", module: "legacy_tech" },
            { severity: "CRITICAL", title: "PHP 5.6 End-of-Life", detail: "Critical unpatched RCE vulnerabilities in runtime.", recommendation: "Upgrade to PHP 8.2+.", module: "legacy_tech" },
            { severity: "HIGH", title: "Missing Content-Security-Policy", detail: "No CSP header detected.", recommendation: "Deploy CSP header.", module: "security_headers" },
            { severity: "HIGH", title: "Missing HSTS Header", detail: "Vulnerable to downgrade attacks.", recommendation: "Enable HSTS.", module: "security_headers" },
            { severity: "HIGH", title: "Session Cookie Exposed to JS", detail: "PHPSESSID lacks HttpOnly flag.", recommendation: "Add HttpOnly flag.", module: "cookie_security" },
            { severity: "HIGH", title: "eval(atob()) Obfuscation", detail: "Obfuscated payload found in inline script.", recommendation: "Audit inline script.", module: "suspicious_content" },
            { severity: "HIGH", title: "WordPress 5.2.1 Vulnerabilities", detail: "Outdated WordPress core.", recommendation: "Update WordPress.", module: "legacy_tech" }
        ],
        riskClusters: [
            {
                name: "Legacy Stack + Weak Security Configuration",
                description: "Outdated libraries combined with missing defensive security headers create an elevated attack surface.",
                components: ["jQuery 1.8.3", "PHP 5.6", "Missing Content-Security-Policy", "Missing HSTS"],
                riskLevel: "CRITICAL"
            },
            {
                name: "Active Credential Formjacking & Data Exfiltration",
                description: "Forms sending data to untrusted external domains with obfuscated scripts.",
                components: ["exfiltrate-auth.xyz", "eval(atob()) obfuscation", "Unencrypted HTTP"],
                riskLevel: "CRITICAL"
            },
            {
                name: "In-Browser Cryptocurrency Mining",
                description: "Unauthorized cryptominer scripts consuming visitor CPU compute.",
                components: ["coinhive.min.js", "coinhive.com"],
                riskLevel: "CRITICAL"
            }
        ],
        criticalCount: 5,
        highCount: 5,
        mediumCount: 6,
        lowCount: 2
    };
}
