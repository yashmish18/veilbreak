<script>
    import { onMount } from "svelte";

    export let tabUrl = "";
    export let currentTabId = null;

    let scanning = false;
    let scanResult = null;
    let scanError = "";
    let activeModuleTab = "all"; // 'all', 'tech', 'headers', 'legacy', 'suspicious', 'supply', 'cookies'
    let expandedClusters = true;
    let copied = false;

    // Current scanning step for visual feedback
    let scanStep = "";

    onMount(() => {
        // If tabUrl is valid, auto-run scan or allow 1-click scan
        if (tabUrl && (tabUrl.startsWith("http://") || tabUrl.startsWith("https://"))) {
            runScan();
        }
    });

    async function runScan() {
        if (scanning) return;
        scanning = true;
        scanError = "";
        scanStep = "Initializing PHANTOM Engine...";

        try {
            // Step progression animation
            const steps = [
                "Fingerprinting Tech Stack & Frameworks...",
                "Analyzing Defensive HTTP Headers...",
                "Auditing Legacy Technologies & CVEs...",
                "Scanning In-Page Scripts & Obfuscation...",
                "Mapping External Supply Chain Origins...",
                "Auditing Cookie & Token Isolation...",
                "Synthesizing Multi-Signal Risk Clusters..."
            ];

            let stepIdx = 0;
            const stepInterval = setInterval(() => {
                if (stepIdx < steps.length) {
                    scanStep = steps[stepIdx++];
                }
            }, 120);

            // Send message to active tab content script
            let response = null;
            if (currentTabId) {
                try {
                    response = await chrome.tabs.sendMessage(currentTabId, { type: "PHANTOM_SCAN" });
                } catch (e) {
                    // Fallback to runtime message
                    response = await chrome.runtime.sendMessage({ type: "PHANTOM_SCAN", tabId: currentTabId });
                }
            } else {
                response = await chrome.runtime.sendMessage({ type: "PHANTOM_SCAN" });
            }

            clearInterval(stepInterval);

            if (response && response.success && response.result) {
                scanResult = response.result;
            } else if (response && response.result) {
                scanResult = response.result;
            } else if (response && response.error) {
                scanError = response.error;
            } else {
                // If content script wasn't ready (e.g. extension page or file url), show helpful message
                scanError = "Could not connect to target page. Make sure you are on a live HTTP/HTTPS website.";
            }
        } catch (err) {
            console.error("[PHANTOM Scan Error]:", err);
            scanError = err.message || "Failed to execute PHANTOM scan.";
        } finally {
            scanning = false;
            scanStep = "";
        }
    }

    function getRiskColor(risk) {
        if (risk === "CRITICAL") return "#ef4444";
        if (risk === "HIGH") return "#f97316";
        if (risk === "MEDIUM") return "#f59e0b";
        return "#10b981";
    }

    function getSeverityBg(sev) {
        if (sev === "CRITICAL") return "rgba(239, 68, 68, 0.12)";
        if (sev === "HIGH") return "rgba(249, 115, 22, 0.12)";
        if (sev === "MEDIUM") return "rgba(245, 158, 11, 0.12)";
        return "rgba(16, 185, 129, 0.12)";
    }

    function copyReport() {
        if (!scanResult) return;
        const text = JSON.stringify(scanResult, null, 2);
        navigator.clipboard.writeText(text).then(() => {
            copied = true;
            setTimeout(() => (copied = false), 2000);
        });
    }

    function exportJson() {
        if (!scanResult) return;
        const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `phantom-report-${scanResult.target || "scan"}-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }
</script>

<div class="phantom-view">
    <!-- Header banner -->
    <div class="phantom-header">
        <div class="target-info">
            <div class="target-badge">
                <span class="pulse-dot"></span>
                <span class="target-domain">{scanResult?.target || (tabUrl ? new URL(tabUrl).hostname : "No Target Active")}</span>
            </div>
            <span class="engine-badge">PHANTOM v2.0</span>
        </div>

        <button class="scan-btn {scanning ? 'scanning' : ''}" on:click={runScan} disabled={scanning}>
            {#if scanning}
                <span class="spinner"></span>
                <span>Scanning...</span>
            {:else}
                <span>⚡ Run Deep Scan</span>
            {/if}
        </button>
    </div>

    <!-- Live Scan Progress -->
    {#if scanning}
        <div class="scanning-card">
            <div class="radar-scan">
                <div class="radar-beam"></div>
            </div>
            <p class="scan-step-text">{scanStep || "Analyzing attack surface..."}</p>
        </div>
    {/if}

    <!-- Error state -->
    {#if scanError && !scanning}
        <div class="error-card">
            <span class="err-icon">⚠️</span>
            <div class="err-body">
                <h4>Assessment Notice</h4>
                <p>{scanError}</p>
            </div>
        </div>
    {/if}

    <!-- Scan Results -->
    {#if scanResult && !scanning}
        <!-- Score Dashboard -->
        <div class="score-card" style="--risk-color: {getRiskColor(scanResult.overallRisk)}">
            <div class="score-main">
                <div class="score-circle">
                    <span class="score-num">{scanResult.overallScore}</span>
                    <span class="score-max">/ 100</span>
                </div>
                <div class="score-details">
                    <div class="risk-badge" style="color: {getRiskColor(scanResult.overallRisk)}; background: {getSeverityBg(scanResult.overallRisk)}">
                        {scanResult.overallRisk} RISK
                    </div>
                    <span class="target-summary">
                        {scanResult.totalFindings} Findings · {scanResult.scanMs}ms
                    </span>
                </div>
            </div>

            <!-- Severity breakdown bars -->
            <div class="severity-pills">
                <span class="sev-pill crit">Crit: {scanResult.criticalCount || 0}</span>
                <span class="sev-pill high">High: {scanResult.highCount || 0}</span>
                <span class="sev-pill med">Med: {scanResult.mediumCount || 0}</span>
                <span class="sev-pill low">Low: {scanResult.lowCount || 0}</span>
            </div>
        </div>

        <!-- Risk Clusters (Compound Risks) -->
        {#if scanResult.riskClusters && scanResult.riskClusters.length > 0}
            <div class="cluster-section">
                <div class="cluster-header" on:click={() => (expandedClusters = !expandedClusters)}>
                    <h4>⚡ Compound Risk Clusters ({scanResult.riskClusters.length})</h4>
                    <span class="toggle-arrow">{expandedClusters ? "▲" : "▼"}</span>
                </div>
                {#if expandedClusters}
                    <div class="cluster-list">
                        {#each scanResult.riskClusters as cluster}
                            <div class="cluster-item">
                                <div class="cluster-title">
                                    <span class="cluster-tag">{cluster.riskLevel}</span>
                                    <strong>{cluster.name}</strong>
                                </div>
                                <p class="cluster-desc">{cluster.description}</p>
                                <div class="cluster-tags">
                                    {#each cluster.components as comp}
                                        <span class="comp-tag">{comp}</span>
                                    {/each}
                                </div>
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        {/if}

        <!-- Module Filter Tabs -->
        <div class="module-nav">
            <button class="mod-btn {activeModuleTab === 'all' ? 'active' : ''}" on:click={() => (activeModuleTab = 'all')}>All</button>
            <button class="mod-btn {activeModuleTab === 'tech' ? 'active' : ''}" on:click={() => (activeModuleTab = 'tech')}>Tech Stack</button>
            <button class="mod-btn {activeModuleTab === 'headers' ? 'active' : ''}" on:click={() => (activeModuleTab = 'headers')}>Headers</button>
            <button class="mod-btn {activeModuleTab === 'legacy' ? 'active' : ''}" on:click={() => (activeModuleTab = 'legacy')}>Legacy CVE</button>
            <button class="mod-btn {activeModuleTab === 'suspicious' ? 'active' : ''}" on:click={() => (activeModuleTab = 'suspicious')}>Scripts</button>
            <button class="mod-btn {activeModuleTab === 'supply' ? 'active' : ''}" on:click={() => (activeModuleTab = 'supply')}>Supply Chain</button>
            <button class="mod-btn {activeModuleTab === 'cookies' ? 'active' : ''}" on:click={() => (activeModuleTab = 'cookies')}>Cookies</button>
        </div>

        <!-- Module 1: Tech Stack Fingerprints -->
        {#if activeModuleTab === 'all' || activeModuleTab === 'tech'}
            <div class="module-card">
                <div class="mod-title">
                    <span>🧩 Tech Stack Fingerprints</span>
                    <span class="count-badge">{scanResult.modules.techStack.count} detected</span>
                </div>
                {#if scanResult.modules.techStack.technologies.length === 0}
                    <p class="empty-txt">No framework signatures detected in DOM.</p>
                {:else}
                    <div class="tech-grid">
                        {#each scanResult.modules.techStack.technologies as tech}
                            <div class="tech-pill">
                                <span class="tech-name">{tech}</span>
                                {#if scanResult.modules.techStack.versions[tech]}
                                    <span class="tech-ver">{scanResult.modules.techStack.versions[tech]}</span>
                                {/if}
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        {/if}

        <!-- Module 2: Security Headers -->
        {#if activeModuleTab === 'all' || activeModuleTab === 'headers'}
            <div class="module-card">
                <div class="mod-title">
                    <span>🛡️ Defensive HTTP Headers</span>
                    <span class="score-badge" style="color: {getRiskColor(scanResult.modules.securityHeaders.score >= 70 ? 'LOW' : 'HIGH')}">
                        Score: {scanResult.modules.securityHeaders.score}/100
                    </span>
                </div>
                {#if scanResult.modules.securityHeaders.findings.length === 0}
                    <p class="clean-txt">✓ All essential security headers configured securely.</p>
                {:else}
                    <div class="findings-list">
                        {#each scanResult.modules.securityHeaders.findings as finding}
                            <div class="finding-item" style="border-left-color: {getRiskColor(finding.severity)}">
                                <div class="finding-header">
                                    <span class="sev-badge" style="color: {getRiskColor(finding.severity)}; background: {getSeverityBg(finding.severity)}">{finding.severity}</span>
                                    <strong>{finding.title}</strong>
                                </div>
                                <p class="finding-detail">{finding.detail}</p>
                                <p class="finding-rec">💡 <em>{finding.recommendation}</em></p>
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        {/if}

        <!-- Module 3: Legacy Tech & CVEs -->
        {#if activeModuleTab === 'all' || activeModuleTab === 'legacy'}
            <div class="module-card">
                <div class="mod-title">
                    <span>⚠️ Legacy Technologies & CVE Exposure</span>
                    <span class="risk-pill" style="color: {getRiskColor(scanResult.modules.legacyTech.overallRisk)}">
                        {scanResult.modules.legacyTech.overallRisk}
                    </span>
                </div>
                {#if scanResult.modules.legacyTech.legacyComponents.length === 0}
                    <p class="clean-txt">✓ No outdated or End-of-Life libraries detected.</p>
                {:else}
                    <div class="findings-list">
                        {#each scanResult.modules.legacyTech.legacyComponents as leg}
                            <div class="finding-item" style="border-left-color: {getRiskColor(leg.riskLevel)}">
                                <div class="finding-header">
                                    <span class="sev-badge" style="color: {getRiskColor(leg.riskLevel)}; background: {getSeverityBg(leg.riskLevel)}">{leg.riskLevel}</span>
                                    <strong>{leg.technology} ({leg.version})</strong>
                                </div>
                                <p class="finding-detail">{leg.detail}</p>
                                <p class="finding-rec">💡 <em>{leg.recommendation}</em></p>
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        {/if}

        <!-- Module 4: Suspicious In-Page Content -->
        {#if activeModuleTab === 'all' || activeModuleTab === 'suspicious'}
            <div class="module-card">
                <div class="mod-title">
                    <span>🔍 In-Page Suspicious Script Analysis</span>
                    <span class="risk-pill" style="color: {getRiskColor(scanResult.modules.suspiciousContent.threatLevel)}">
                        {scanResult.modules.suspiciousContent.threatLevel}
                    </span>
                </div>
                {#if scanResult.modules.suspiciousContent.indicators.length === 0}
                    <p class="clean-txt">✓ Zero crypto miners, keyloggers, or obfuscation chains detected.</p>
                {:else}
                    <div class="findings-list">
                        {#each scanResult.modules.suspiciousContent.indicators as ind}
                            <div class="finding-item" style="border-left-color: {getRiskColor(ind.severity)}">
                                <div class="finding-header">
                                    <span class="sev-badge" style="color: {getRiskColor(ind.severity)}; background: {getSeverityBg(ind.severity)}">{ind.severity}</span>
                                    <strong>{ind.type}</strong>
                                </div>
                                <p class="finding-detail">{ind.detail}</p>
                                <p class="finding-rec">💡 <em>{ind.recommendation}</em></p>
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        {/if}

        <!-- Module 5: Supply Chain & Resource Audit -->
        {#if activeModuleTab === 'all' || activeModuleTab === 'supply'}
            <div class="module-card">
                <div class="mod-title">
                    <span>🌐 Supply Chain & External Dependencies</span>
                    <span class="count-badge">{scanResult.modules.externalResources.totalExternal} origins</span>
                </div>
                <div class="supply-summary">
                    <span class="supply-stat">Trusted CDNs: <strong>{scanResult.modules.externalResources.trustedCount}</strong></span>
                    <span class="supply-stat">Untrusted/External: <strong>{scanResult.modules.externalResources.untrustedCount}</strong></span>
                </div>
                {#if scanResult.modules.externalResources.flagged.length > 0}
                    <div class="flagged-origins">
                        {#each scanResult.modules.externalResources.flagged as flag}
                            <div class="flag-item">
                                <span class="flag-host">{flag.origin}</span>
                                <span class="flag-reason">{flag.reason}</span>
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        {/if}

        <!-- Module 6: Cookie & Token Security -->
        {#if activeModuleTab === 'all' || activeModuleTab === 'cookies'}
            <div class="module-card">
                <div class="mod-title">
                    <span>🍪 Cookie & Session Token Isolation</span>
                    <span class="score-badge" style="color: {getRiskColor(scanResult.modules.cookieSecurity.score >= 70 ? 'LOW' : 'HIGH')}">
                        Score: {scanResult.modules.cookieSecurity.score}/100
                    </span>
                </div>
                {#if scanResult.modules.cookieSecurity.findings.length === 0}
                    <p class="clean-txt">✓ No insecure or exposed authentication cookies found.</p>
                {:else}
                    <div class="findings-list">
                        {#each scanResult.modules.cookieSecurity.findings as finding}
                            <div class="finding-item" style="border-left-color: {getRiskColor(finding.severity)}">
                                <div class="finding-header">
                                    <span class="sev-badge" style="color: {getRiskColor(finding.severity)}; background: {getSeverityBg(finding.severity)}">{finding.severity}</span>
                                    <strong>{finding.cookie}</strong>
                                </div>
                                <p class="finding-detail">{finding.issue}: {finding.detail}</p>
                                <p class="finding-rec">💡 <em>{finding.recommendation}</em></p>
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        {/if}

        <!-- Action buttons -->
        <div class="report-actions">
            <button class="action-btn" on:click={copyReport}>
                {copied ? "✓ Copied!" : "📋 Copy Report JSON"}
            </button>
            <button class="action-btn primary" on:click={exportJson}>
                💾 Export Report File
            </button>
        </div>
    {/if}
</div>

<style>
    .phantom-view {
        display: flex;
        flex-direction: column;
        gap: 14px;
        padding: 4px 0 16px;
    }

    /* Header */
    .phantom-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
    }
    .target-info {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .target-badge {
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .pulse-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10b981;
        box-shadow: 0 0 8px rgba(16, 185, 129, 0.6);
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(0.85); }
    }
    .target-domain {
        font-size: 13px;
        font-weight: 700;
        color: var(--text-primary);
        max-width: 180px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .engine-badge {
        font-size: 9px;
        font-weight: 700;
        color: #6366f1;
        letter-spacing: 0.05em;
    }

    .scan-btn {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 8px 14px;
        border-radius: 10px;
        background: linear-gradient(135deg, #4f46e5, #7c3aed);
        color: #ffffff;
        font-size: 12px;
        font-weight: 700;
        border: none;
        cursor: pointer;
        transition: all 0.2s;
        box-shadow: 0 2px 8px rgba(99, 102, 241, 0.3);
    }
    .scan-btn:hover:not(:disabled) {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
    }
    .scan-btn:disabled {
        opacity: 0.7;
        cursor: not-allowed;
    }

    /* Scanning animation card */
    .scanning-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 24px 16px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 12px;
        text-align: center;
    }
    .radar-scan {
        width: 48px;
        height: 48px;
        border-radius: 50%;
        border: 2px solid rgba(99, 102, 241, 0.3);
        position: relative;
        overflow: hidden;
    }
    .radar-beam {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        border-radius: 50%;
        background: conic-gradient(from 0deg, rgba(99, 102, 241, 0.6), transparent 60%);
        animation: spin 1.2s linear infinite;
    }
    @keyframes spin {
        100% { transform: rotate(360deg); }
    }
    .scan-step-text {
        font-size: 12px;
        font-weight: 600;
        color: var(--text-secondary);
    }

    /* Error card */
    .error-card {
        display: flex;
        gap: 10px;
        background: rgba(245, 158, 11, 0.1);
        border: 1px solid rgba(245, 158, 11, 0.3);
        border-radius: 10px;
        padding: 12px;
    }
    .err-icon { font-size: 18px; }
    .err-body h4 { font-size: 12px; font-weight: 700; color: #f59e0b; margin-bottom: 2px; }
    .err-body p { font-size: 11px; color: var(--text-secondary); }

    /* Score Card */
    .score-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 14px 16px;
        display: flex;
        flex-direction: column;
        gap: 12px;
    }
    .score-main {
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .score-circle {
        width: 54px;
        height: 54px;
        border-radius: 50%;
        border: 3px solid var(--risk-color);
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        background: rgba(0, 0, 0, 0.02);
    }
    .score-num {
        font-size: 18px;
        font-weight: 800;
        color: var(--risk-color);
        line-height: 1;
    }
    .score-max {
        font-size: 9px;
        color: var(--text-muted);
        font-weight: 600;
    }
    .score-details {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    .risk-badge {
        display: inline-block;
        font-size: 11px;
        font-weight: 800;
        padding: 3px 8px;
        border-radius: 6px;
        letter-spacing: 0.05em;
    }
    .target-summary {
        font-size: 11px;
        color: var(--text-muted);
    }
    .severity-pills {
        display: flex;
        gap: 6px;
    }
    .sev-pill {
        flex: 1;
        text-align: center;
        font-size: 10px;
        font-weight: 700;
        padding: 4px 6px;
        border-radius: 6px;
    }
    .sev-pill.crit { color: #ef4444; background: rgba(239, 68, 68, 0.1); }
    .sev-pill.high { color: #f97316; background: rgba(249, 115, 22, 0.1); }
    .sev-pill.med { color: #f59e0b; background: rgba(245, 158, 11, 0.1); }
    .sev-pill.low { color: #10b981; background: rgba(16, 185, 129, 0.1); }

    /* Risk Clusters */
    .cluster-section {
        background: rgba(99, 102, 241, 0.05);
        border: 1px solid rgba(99, 102, 241, 0.2);
        border-radius: 12px;
        overflow: hidden;
    }
    .cluster-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 12px;
        cursor: pointer;
    }
    .cluster-header h4 {
        font-size: 11px;
        font-weight: 800;
        color: #6366f1;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .toggle-arrow { font-size: 9px; color: #6366f1; }
    .cluster-list {
        padding: 0 12px 10px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .cluster-item {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 8px 10px;
    }
    .cluster-title {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        color: var(--text-primary);
        margin-bottom: 2px;
    }
    .cluster-tag {
        font-size: 8px;
        font-weight: 800;
        padding: 2px 4px;
        border-radius: 4px;
        color: #ef4444;
        background: rgba(239, 68, 68, 0.1);
    }
    .cluster-desc {
        font-size: 10px;
        color: var(--text-secondary);
        margin-bottom: 4px;
    }
    .cluster-tags {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
    }
    .comp-tag {
        font-size: 9px;
        padding: 2px 6px;
        border-radius: 4px;
        background: var(--bg-secondary);
        color: var(--text-muted);
    }

    /* Module Nav */
    .module-nav {
        display: flex;
        gap: 4px;
        overflow-x: auto;
        padding-bottom: 2px;
    }
    .mod-btn {
        flex-shrink: 0;
        padding: 4px 8px;
        font-size: 10px;
        font-weight: 700;
        border-radius: 6px;
        border: 1px solid var(--border);
        background: var(--bg-card);
        color: var(--text-secondary);
        cursor: pointer;
    }
    .mod-btn.active {
        background: #4f46e5;
        color: #ffffff;
        border-color: #4f46e5;
    }

    /* Module Cards */
    .module-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .mod-title {
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 12px;
        font-weight: 700;
        color: var(--text-primary);
    }
    .count-badge, .score-badge, .risk-pill {
        font-size: 10px;
        font-weight: 700;
        color: var(--text-muted);
    }

    /* Tech Grid */
    .tech-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
    }
    .tech-pill {
        display: flex;
        align-items: center;
        gap: 4px;
        background: var(--bg-secondary);
        padding: 4px 8px;
        border-radius: 6px;
        font-size: 11px;
    }
    .tech-name { font-weight: 600; color: var(--text-primary); }
    .tech-ver { font-size: 9px; color: #6366f1; font-weight: 700; background: rgba(99, 102, 241, 0.1); padding: 1px 4px; border-radius: 4px; }

    /* Findings List */
    .findings-list {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .finding-item {
        border-left: 3px solid #10b981;
        background: var(--bg-secondary);
        padding: 6px 8px;
        border-radius: 0 6px 6px 0;
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .finding-header {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        color: var(--text-primary);
    }
    .sev-badge {
        font-size: 8px;
        font-weight: 800;
        padding: 1px 4px;
        border-radius: 3px;
    }
    .finding-detail { font-size: 10px; color: var(--text-secondary); }
    .finding-rec { font-size: 9px; color: var(--text-muted); }

    .supply-summary {
        display: flex;
        gap: 12px;
        font-size: 11px;
        color: var(--text-secondary);
    }
    .flagged-origins {
        display: flex;
        flex-direction: column;
        gap: 4px;
        margin-top: 4px;
    }
    .flag-item {
        display: flex;
        justify-content: space-between;
        font-size: 10px;
        background: rgba(239, 68, 68, 0.08);
        padding: 4px 6px;
        border-radius: 4px;
    }
    .flag-host { font-weight: 600; color: #ef4444; }
    .flag-reason { color: var(--text-muted); }

    .clean-txt {
        font-size: 11px;
        color: #10b981;
        font-weight: 600;
    }
    .empty-txt {
        font-size: 11px;
        color: var(--text-muted);
    }

    /* Actions */
    .report-actions {
        display: flex;
        gap: 8px;
        margin-top: 4px;
    }
    .action-btn {
        flex: 1;
        padding: 8px;
        font-size: 11px;
        font-weight: 700;
        border-radius: 8px;
        border: 1px solid var(--border);
        background: var(--bg-card);
        color: var(--text-primary);
        cursor: pointer;
        transition: all 0.2s;
    }
    .action-btn:hover {
        background: var(--bg-secondary);
    }
    .action-btn.primary {
        background: #10b981;
        color: #ffffff;
        border-color: #10b981;
    }
    .action-btn.primary:hover {
        background: #059669;
    }
</style>
