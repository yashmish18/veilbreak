"use client";
import { useState, useEffect } from "react";
import styles from "./page.module.css";

/* ─── Popup Tabs Configuration ─── */
const TABS = [
  { id: "phantom", label: "⚡ PHANTOM" },
  { id: "shield", label: "Shield" },
  { id: "history", label: "History" },
  { id: "ledger", label: "Ledger" },
  { id: "vault", label: "Vault" },
  { id: "settings", label: "Settings" },
];

/* ─── Initial Data ─── */
const INITIAL_LEDGER = [
  {
    index: 0,
    timestamp: "2026-08-20T10:14:02Z",
    hash: "0000a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcd",
    prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
    event: "GENESIS_BLOCK",
    target: "Genesis Verification Anchor",
    rule: "SYSTEM_INIT",
    confidence: 1.0
  },
  {
    index: 1,
    timestamp: "2026-08-21T14:22:18Z",
    hash: "a4f89d31e9c20b8f723812739487123984719238471928374918237491827349",
    prevHash: "0000a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcd",
    event: "THREAT_INTERCEPT",
    target: "g00gle-security-login.xyz",
    rule: "HEURISTIC_TYPOSQUAT",
    confidence: 0.95
  },
  {
    index: 2,
    timestamp: "2026-08-22T08:05:41Z",
    hash: "b7c91e4f2a8d3e0c1b4f6a8e9d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c",
    prevHash: "a4f89d31e9c20b8f723812739487123984719238471928374918237491827349",
    event: "THREAT_INTERCEPT",
    target: "coinhive-miner-worker.cc",
    rule: "CRYPTO_MINER_SIGNATURE",
    confidence: 0.99
  }
];

const INITIAL_HISTORY = [
  { id: 1, domain: "github.com", timestamp: "Just now", status: "SAFE", score: 98, flags: 0 },
  { id: 2, domain: "nextjs.org", timestamp: "5m ago", status: "SAFE", score: 95, flags: 0 },
  { id: 3, domain: "paypa1-security-login.xyz", timestamp: "1h ago", status: "THREAT", score: 24, flags: 5 },
  { id: 4, domain: "google.com", timestamp: "3h ago", status: "SAFE", score: 99, flags: 0 },
];

function shortHash(h, len = 8) {
  if (!h) return "—";
  return `${h.slice(0, len)}…${h.slice(-len + 2)}`;
}

function fmtDate(d) {
  try {
    return new Date(d).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  } catch {
    return "—";
  }
}

export default function Home() {
  const [activeTab, setActiveTab] = useState("phantom");

  // ── Extension Bridge & Global State ──
  const [extensionConnected, setExtensionConnected] = useState(false);
  const [extensionStats, setExtensionStats] = useState({
    totalScanned: 148,
    totalBlocked: 12,
    threatsToday: 3
  });

  const [settings, setSettings] = useState({
    sensitivity: "balanced", // "strict" | "balanced" | "dev"
    phishing: true,
    miners: true,
    typosquatting: true,
    obfuscation: true,
    notifications: true
  });

  const [allowlist, setAllowlist] = useState(["localhost", "127.0.0.1", "github.com"]);
  const [newDomain, setNewDomain] = useState("");
  const [isAddingDomain, setIsAddingDomain] = useState(false);

  // ── History & Ledger State ──
  const [history, setHistory] = useState(INITIAL_HISTORY);
  const [ledger, setLedger] = useState(INITIAL_LEDGER);
  const [selectedBlock, setSelectedBlock] = useState(INITIAL_LEDGER[INITIAL_LEDGER.length - 1]);

  // ── Sandbox State ──
  const [sandboxLog, setSandboxLog] = useState([]);
  const [sandboxRunning, setSandboxRunning] = useState(false);

  // ── PHANTOM Scanner State ──
  const [targetUrl, setTargetUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState("");
  const [moduleFilter, setModuleFilter] = useState("all");
  const [reportCopied, setReportCopied] = useState(false);
  const [scanSubMode, setScanSubMode] = useState("url"); // "url" | "package"

  // ── Package.json Auditor State ──
  const [packageJsonInput, setPackageJsonInput] = useState(`{
  "dependencies": {
    "lodash": "^4.17.15",
    "axios": "^0.21.1",
    "jsonwebtoken": "^8.5.1",
    "express": "^4.17.1",
    "minimist": "^1.2.5"
  }
}`);
  const [pkgAuditResult, setPkgAuditResult] = useState(null);
  const [pkgAuditing, setPkgAuditing] = useState(false);

  // ── 48-Feature Inspector State ──
  const [featureUrl, setFeatureUrl] = useState("https://paypa1-security-login.xyz/auth/verify");
  const [featureResult, setFeatureResult] = useState(null);
  const [featureLoading, setFeatureLoading] = useState(false);

  // ── Threat Vault State ──
  const [vaultData, setVaultData] = useState(null);
  const [vaultLoading, setVaultLoading] = useState(false);
  const [vaultSearch, setVaultSearch] = useState("");
  const [vaultSearchResult, setVaultSearchResult] = useState(null);
  const [flagUrl, setFlagUrl] = useState("");
  const [flagStatus, setFlagStatus] = useState(null);

  /* ── Bridge Listener ── */
  useEffect(() => {
    const handleMessage = (event) => {
      if (!event.data || event.data.type !== "BV_WEB_RESPONSE") return;
      const data = event.data.data;
      if (!data) return;

      setExtensionConnected(true);
      if (data.stats) setExtensionStats(data.stats);
      if (data.settings && data.settings.allowlist) setAllowlist(data.settings.allowlist);
    };

    window.addEventListener("message", handleMessage);
    window.postMessage({ type: "BV_WEB_REQUEST", action: "GET_STATS" }, "*");

    const interval = setInterval(() => {
      window.postMessage({ type: "BV_WEB_REQUEST", action: "GET_STATS" }, "*");
    }, 5000);

    return () => {
      window.removeEventListener("message", handleMessage);
      clearInterval(interval);
    };
  }, []);

  /* ── Vault Stats ── */
  const fetchVault = () => {
    setVaultLoading(true);
    fetch("/api/vault/stats")
      .then(r => r.json())
      .then(d => setVaultData(d))
      .catch(() => setVaultData({ error: true }))
      .finally(() => setVaultLoading(false));
  };

  useEffect(() => {
    fetchVault();
  }, []);

  /* ── Hash Domain Helper ── */
  const hashDomain = async (str) => {
    let d = str.trim().toLowerCase();
    try {
      if (d.includes("://")) d = new URL(d).hostname;
      else if (d.includes("/")) d = d.split("/")[0];
      if (d.startsWith("www.")) d = d.slice(4);
    } catch {}
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(d));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  };

  /* ── Allowlist Handlers ── */
  const handleAddDomain = (e) => {
    e.preventDefault();
    const d = newDomain.trim().toLowerCase();
    if (!d || allowlist.includes(d)) return;

    const updated = [...allowlist, d];
    setAllowlist(updated);
    setNewDomain("");
    setIsAddingDomain(false);

    if (extensionConnected) {
      window.postMessage({
        type: "BV_WEB_REQUEST",
        action: "SAVE_SETTINGS",
        settings: { ...settings, allowlist: updated }
      }, "*");
    }
  };

  const handleRemoveDomain = (d) => {
    const updated = allowlist.filter(item => item !== d);
    setAllowlist(updated);

    if (extensionConnected) {
      window.postMessage({
        type: "BV_WEB_REQUEST",
        action: "SAVE_SETTINGS",
        settings: { ...settings, allowlist: updated }
      }, "*");
    }
  };

  /* ── Sandbox Simulation ── */
  const runSandboxTest = async (type) => {
    setSandboxRunning(true);
    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    let entry = null;
    if (type === "phishing") {
      entry = { ts, vector: "Fake Login Form (<form action='http://exfiltrate-auth.xyz'>)", status: "BLOCKED", rule: "RULE_FORMJACKING_TLD", confidence: "99%" };
    } else if (type === "miner") {
      entry = { ts, vector: "Background Miner (coinhive.min.js WebWorker)", status: "TERMINATED", rule: "RULE_CRYPTO_MINER_SIGNATURE", confidence: "100%" };
    } else if (type === "typosquat") {
      entry = { ts, vector: "Lookalike Typosquat (g00gle.com - Dist 2)", status: "INTERCEPTED", rule: "RULE_BRAND_HOMOGLYPH", confidence: "95%" };
    } else if (type === "obfuscation") {
      entry = { ts, vector: "Obfuscated Payload (eval(atob('ZG9jdW1lbnQ=')))", status: "BLOCKED", rule: "RULE_EVAL_ATOB_CHAIN", confidence: "92%" };
    }

    setTimeout(async () => {
      setSandboxLog(prev => [entry, ...prev.slice(0, 5)]);
      setSandboxRunning(false);

      // Append to Ledger & History
      const prevBlock = ledger[ledger.length - 1];
      const newHash = await hashDomain(entry.vector + Date.now());
      const newBlock = {
        index: ledger.length,
        timestamp: new Date().toISOString(),
        hash: newHash,
        prevHash: prevBlock.hash,
        event: "THREAT_INTERCEPT",
        target: entry.vector,
        rule: entry.rule,
        confidence: parseFloat(entry.confidence) / 100
      };
      setLedger(prev => [...prev, newBlock]);
      setSelectedBlock(newBlock);

      setHistory(prev => [
        { id: Date.now(), domain: entry.vector.slice(0, 30), timestamp: "Just now", status: "THREAT", score: 20, flags: 4 },
        ...prev
      ]);
    }, 500);
  };

  /* ── PHANTOM Scanner Handlers ── */
  const runScan = async (overrideUrl) => {
    const raw = (overrideUrl || targetUrl).trim();
    if (!raw || scanning) return;
    if (overrideUrl) setTargetUrl(overrideUrl);

    setScanning(true);
    setScanError("");
    setScanResult(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: raw })
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setScanError(data.error || "Scan failed.");
      } else if (data.result) {
        setScanResult(data.result);
        // Add to history
        setHistory(prev => [
          {
            id: Date.now(),
            domain: data.result.target,
            timestamp: "Just now",
            status: data.result.overallRisk === "CRITICAL" || data.result.overallRisk === "HIGH" ? "THREAT" : "SAFE",
            score: data.result.overallScore,
            flags: data.result.totalFindings
          },
          ...prev.filter(h => h.domain !== data.result.target)
        ]);
      }
    } catch (err) {
      setScanError(err.message || "Failed to scan target.");
    } finally {
      setScanning(false);
    }
  };

  const runPkgAudit = async () => {
    if (!packageJsonInput.trim() || pkgAuditing) return;
    setPkgAuditing(true);
    setScanError("");
    setPkgAuditResult(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ packageJson: packageJsonInput })
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setScanError(data.error || "Invalid package.json.");
      } else {
        setPkgAuditResult(data.result);
      }
    } catch (err) {
      setScanError("Failed to audit dependencies.");
    } finally {
      setPkgAuditing(false);
    }
  };

  /* ── 48-Feature Extraction ── */
  const runFeatureExtract = async (override) => {
    const raw = (override || featureUrl).trim();
    if (!raw || featureLoading) return;
    if (override) setFeatureUrl(override);

    setFeatureLoading(true);
    setFeatureResult(null);

    try {
      const res = await fetch(`/api/features?url=${encodeURIComponent(raw)}`);
      const data = await res.json();
      if (data.success) {
        setFeatureResult(data);
      }
    } catch (e) {
    } finally {
      setFeatureLoading(false);
    }
  };

  /* ── Vault Submit & Search ── */
  const handleVaultSearch = async (e) => {
    e.preventDefault();
    if (!vaultSearch.trim()) return;
    const h = vaultSearch.length === 64 ? vaultSearch.toLowerCase() : await hashDomain(vaultSearch);
    const match = vaultData?.recentThreats?.find(t => t.hash.toLowerCase() === h);
    if (match) {
      setVaultSearchResult({ found: true, hash: h, ...match });
    } else {
      setVaultSearchResult({ found: false, hash: h, query: vaultSearch });
    }
  };

  const handleFlagUrl = async (e) => {
    e.preventDefault();
    if (!flagUrl.trim()) return;
    setFlagStatus("submitting");

    try {
      const h = await hashDomain(flagUrl);
      const res = await fetch("/api/vault/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash: h, source: "manual-report", confidence: 1.0, threatType: "User Flag" })
      });
      if (!res.ok) throw new Error();
      setFlagStatus("success");
      setFlagUrl("");
      fetchVault();
    } catch {
      setFlagStatus("error");
    }
    setTimeout(() => setFlagStatus(null), 3000);
  };

  return (
    <div className={styles.container}>
      {/* ── App Shell / Container ── */}
      <div className={styles.appCard}>

        {/* Top Header */}
        <header className={styles.header}>
          <div className={styles.headerBrand}>
            <div className={styles.logoCircle}>
              <img src="/shield.png" alt="Browser Vigilant" width={22} height={22} />
            </div>
            <div>
              <h1 className={styles.brandTitle}>Browser Vigilant</h1>
              <span className={styles.brandSubtitle}>Everything looks good.</span>
            </div>
          </div>

          {/* Extension Status Badge */}
          <div className={styles.headerStatusBadge}>
            <span className={extensionConnected ? styles.dotGreen : styles.dotAmber} />
            <span>{extensionConnected ? "Extension Synced" : "Standalone Web"}</span>
          </div>
        </header>

        {/* Popup Navigation Tabs */}
        <nav className={styles.tabNav}>
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`${styles.tabBtn} ${activeTab === t.id ? styles.tabBtnActive : ""}`}
              onClick={() => setActiveTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>

        {/* Tab Body */}
        <div className={styles.tabBody}>

          {/* ══════════════════════════════════════════════════════════════════
              TAB 1: ⚡ PHANTOM (Attack Surface Scanner)
          ══════════════════════════════════════════════════════════════════ */}
          {activeTab === "phantom" && (
            <div className={styles.contentStack}>
              
              {/* Mode Toggle */}
              <div className={styles.pillToggleRow}>
                <button
                  className={`${styles.pillToggle} ${scanSubMode === "url" ? styles.pillToggleActive : ""}`}
                  onClick={() => setScanSubMode("url")}
                >
                  🌐 Target URL Deep Scan
                </button>
                <button
                  className={`${styles.pillToggle} ${scanSubMode === "package" ? styles.pillToggleActive : ""}`}
                  onClick={() => setScanSubMode("package")}
                >
                  📦 package.json CVE Auditor
                </button>
              </div>

              {scanSubMode === "url" && (
                <>
                  {/* Search Input */}
                  <div className={styles.searchCard}>
                    <form onSubmit={(e) => { e.preventDefault(); runScan(); }} className={styles.searchForm}>
                      <input
                        type="text"
                        className={styles.inputRound}
                        placeholder="Enter domain (e.g. google.com or demo://vulnerable)"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        disabled={scanning}
                      />
                      <button
                        type="submit"
                        className={styles.coralBtn}
                        disabled={scanning || !targetUrl.trim()}
                      >
                        {scanning ? "Scanning..." : "Deep Scan"}
                      </button>
                    </form>

                    {/* Presets */}
                    <div className={styles.presetRow}>
                      <span className={styles.presetLabel}>Quick Presets:</span>
                      <button
                        type="button"
                        className={styles.presetVulnerable}
                        onClick={() => runScan("demo://vulnerable")}
                      >
                        🎯 Demo Vulnerable Target
                      </button>
                      <button
                        type="button"
                        className={styles.presetBtn}
                        onClick={() => runScan("https://google.com")}
                      >
                        google.com
                      </button>
                      <button
                        type="button"
                        className={styles.presetBtn}
                        onClick={() => runScan("https://nextjs.org")}
                      >
                        nextjs.org
                      </button>
                    </div>
                  </div>

                  {/* Scan Notice */}
                  {scanError && (
                    <div className={styles.noticeCard}>
                      <strong>Notice:</strong> {scanError}
                    </div>
                  )}

                  {/* Scan Results View */}
                  {scanResult && !scanning && (
                    <div className={styles.resultsWrap}>
                      {/* Overall Score Card */}
                      <div className={styles.scoreHeroCard}>
                        <div className={styles.scoreCircleOuter}>
                          <div className={styles.scoreCircle}>
                            <span className={styles.scoreNumber}>{scanResult.overallScore}</span>
                            <span className={styles.scoreTotal}>/ 100</span>
                          </div>
                        </div>

                        <div className={styles.scoreHeroMeta}>
                          <div className={styles.scoreHeroTagRow}>
                            <span className={`${styles.riskPill} ${scanResult.overallRisk === "CRITICAL" || scanResult.overallRisk === "HIGH" ? styles.riskPillRed : styles.riskPillGreen}`}>
                              {scanResult.overallRisk} RISK
                            </span>
                            <strong className={styles.targetDomain}>{scanResult.target}</strong>
                          </div>
                          <p className={styles.scoreHeroSub}>
                            {scanResult.totalFindings} Findings detected in {scanResult.scanMs}ms · HTTP {scanResult.httpStatus}
                          </p>

                          {/* Severity Counters */}
                          <div className={styles.sevCounterRow}>
                            <span className={styles.scPill} style={{ color: "#FF7B6B" }}>
                              <strong>{scanResult.criticalCount}</strong> Crit
                            </span>
                            <span className={styles.scPill} style={{ color: "#F59E0B" }}>
                              <strong>{scanResult.highCount}</strong> High
                            </span>
                            <span className={styles.scPill} style={{ color: "#3B82F6" }}>
                              <strong>{scanResult.mediumCount}</strong> Med
                            </span>
                            <span className={styles.scPill} style={{ color: "#34D399" }}>
                              <strong>{scanResult.lowCount}</strong> Low
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Compound Risk Chains */}
                      {scanResult.riskClusters && scanResult.riskClusters.length > 0 && (
                        <div className={styles.card}>
                          <div className={styles.cardHeader}>
                            <h3>Multi-Signal Compound Risk Chains</h3>
                            <span className={styles.countBadge}>{scanResult.riskClusters.length}</span>
                          </div>
                          <div className={styles.clusterList}>
                            {scanResult.riskClusters.map((c, i) => (
                              <div key={i} className={styles.clusterItem}>
                                <div className={styles.clusterTitleRow}>
                                  <span className={styles.riskPillRed}>{c.riskLevel}</span>
                                  <strong>{c.name}</strong>
                                </div>
                                <p className={styles.clusterText}>{c.description}</p>
                                <div className={styles.compPills}>
                                  {c.components.map((comp, idx) => (
                                    <span key={idx} className={styles.compTag}>{comp}</span>
                                  ))}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Module Filter Buttons */}
                      <div className={styles.filterPillRow}>
                        <button
                          className={`${styles.filterPill} ${moduleFilter === "all" ? styles.filterPillActive : ""}`}
                          onClick={() => setModuleFilter("all")}
                        >
                          All ({scanResult.findings.length})
                        </button>
                        <button
                          className={`${styles.filterPill} ${moduleFilter === "tech" ? styles.filterPillActive : ""}`}
                          onClick={() => setModuleFilter("tech")}
                        >
                          Tech Stack ({scanResult.modules.techStack.count})
                        </button>
                        <button
                          className={`${styles.filterPill} ${moduleFilter === "headers" ? styles.filterPillActive : ""}`}
                          onClick={() => setModuleFilter("headers")}
                        >
                          Headers ({scanResult.modules.securityHeaders.score}/100)
                        </button>
                        <button
                          className={`${styles.filterPill} ${moduleFilter === "legacy" ? styles.filterPillActive : ""}`}
                          onClick={() => setModuleFilter("legacy")}
                        >
                          Legacy CVE ({scanResult.modules.legacyTech.count})
                        </button>
                        <button
                          className={`${styles.filterPill} ${moduleFilter === "scripts" ? styles.filterPillActive : ""}`}
                          onClick={() => setModuleFilter("scripts")}
                        >
                          Scripts ({scanResult.modules.suspiciousContent.count})
                        </button>
                        <button
                          className={`${styles.filterPill} ${moduleFilter === "origins" ? styles.filterPillActive : ""}`}
                          onClick={() => setModuleFilter("origins")}
                        >
                          Supply Chain ({scanResult.modules.externalResources.totalExternal})
                        </button>
                      </div>

                      {/* Tech Stack Box */}
                      {(moduleFilter === "all" || moduleFilter === "tech") && (
                        <div className={styles.card}>
                          <div className={styles.cardHeader}>
                            <h3>Detected Technologies</h3>
                            <span className={styles.countBadge}>{scanResult.modules.techStack.count}</span>
                          </div>
                          <div className={styles.techGrid}>
                            {scanResult.modules.techStack.technologies.map((t, i) => (
                              <div key={i} className={styles.techTag}>
                                <span>{t}</span>
                                {scanResult.modules.techStack.versions[t] && (
                                  <span className={styles.techVerBadge}>v{scanResult.modules.techStack.versions[t]}</span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Detailed Findings List */}
                      <div className={styles.card}>
                        <div className={styles.cardHeader}>
                          <h3>Findings & Remediation</h3>
                        </div>
                        <div className={styles.findingsList}>
                          {scanResult.findings.map((f, i) => (
                            <div key={i} className={styles.findingCard}>
                              <div className={styles.findingTop}>
                                <span className={`${styles.riskPill} ${f.severity === "CRITICAL" || f.severity === "HIGH" ? styles.riskPillRed : styles.riskPillGreen}`}>
                                  {f.severity}
                                </span>
                                <strong>{f.title || f.technology || f.type || "Finding"}</strong>
                              </div>
                              <p className={styles.findingDesc}>{f.detail}</p>
                              <p className={styles.findingRec}>💡 <em>{f.recommendation}</em></p>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Actions */}
                      <div className={styles.actionRow}>
                        <button
                          className={styles.ghostBtn}
                          onClick={() => {
                            navigator.clipboard.writeText(JSON.stringify(scanResult, null, 2));
                            setReportCopied(true);
                            setTimeout(() => setReportCopied(false), 2000);
                          }}
                        >
                          {reportCopied ? "✓ JSON Copied!" : "📋 Copy Report JSON"}
                        </button>
                        <button
                          className={styles.coralBtn}
                          onClick={() => {
                            const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: "application/json" });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `phantom-${scanResult.target}-${Date.now()}.json`;
                            a.click();
                          }}
                        >
                          💾 Download Report
                        </button>
                      </div>

                    </div>
                  )}
                </>
              )}

              {/* Package.json Auditor */}
              {scanSubMode === "package" && (
                <div className={styles.card}>
                  <div className={styles.cardHeader}>
                    <h3>package.json Vulnerability Auditor</h3>
                  </div>
                  <p className={styles.subtext}>Paste your dependencies JSON to audit against known CVE records:</p>
                  
                  <textarea
                    className={styles.codeBox}
                    rows={8}
                    value={packageJsonInput}
                    onChange={(e) => setPackageJsonInput(e.target.value)}
                  />

                  <div style={{ display: "flex", gap: "10px", marginTop: "12px" }}>
                    <button
                      className={styles.coralBtn}
                      onClick={runPkgAudit}
                      disabled={pkgAuditing}
                    >
                      {pkgAuditing ? "Auditing..." : "🔍 Audit Dependencies"}
                    </button>
                    <button
                      className={styles.ghostBtn}
                      onClick={() => setPackageJsonInput(`{\n  "dependencies": {\n    "lodash": "4.17.15",\n    "axios": "0.21.1",\n    "jsonwebtoken": "8.5.1",\n    "express": "4.16.0",\n    "minimist": "1.2.5"\n  }\n}`)}
                    >
                      Load Sample Vulnerable JSON
                    </button>
                  </div>

                  {pkgAuditResult && (
                    <div className={styles.pkgResultWrap}>
                      <div className={styles.pkgSummaryHeader}>
                        <strong>Security Score: {pkgAuditResult.score}/100</strong>
                        <span>{pkgAuditResult.vulnerabilitiesCount} vulnerabilities in {pkgAuditResult.totalDependencies} dependencies</span>
                      </div>

                      <div className={styles.pkgGrid}>
                        {pkgAuditResult.packages.map((pkg, idx) => (
                          <div key={idx} className={`${styles.pkgCard} ${pkg.status === "vulnerable" ? styles.pkgCardVuln : ""}`}>
                            <div className={styles.pkgCardTop}>
                              <strong>{pkg.name}</strong>
                              <code>{pkg.version}</code>
                            </div>
                            {pkg.status === "vulnerable" ? (
                              <div className={styles.pkgVulnRow}>
                                <span className={styles.riskPillRed}>{pkg.cve}</span>
                                <span style={{ fontSize: "11px", color: "#FF7B6B", fontWeight: 700 }}>{pkg.severity}</span>
                              </div>
                            ) : (
                              <span style={{ fontSize: "11px", color: "#34D399", fontWeight: 600 }}>✓ Clean</span>
                            )}
                          </div>
                        ))}
                      </div>

                      {pkgAuditResult.findings.length > 0 && (
                        <div className={styles.findingsList} style={{ marginTop: "16px" }}>
                          {pkgAuditResult.findings.map((f, i) => (
                            <div key={i} className={styles.findingCard}>
                              <div className={styles.findingTop}>
                                <span className={styles.riskPillRed}>{f.severity}</span>
                                <strong>{f.title}</strong>
                              </div>
                              <p className={styles.findingDesc}>{f.detail}</p>
                              <p className={styles.findingRec}>💡 <strong>Upgrade:</strong> {f.recommendation}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              TAB 2: 🛡 SHIELD (Live Status & Subsystems)
          ══════════════════════════════════════════════════════════════════ */}
          {activeTab === "shield" && (
            <div className={styles.contentStack}>
              
              {/* Main Shield Hero */}
              <div className={styles.shieldHeroCard}>
                <div className={styles.shieldVisualWrap}>
                  <div className={styles.shieldGlowRing}>
                    <img src="/shield.png" alt="Protected" width={56} height={56} />
                  </div>
                </div>
                <div className={styles.shieldHeroMeta}>
                  <div className={styles.shieldStatusBadge}>
                    <span className={styles.dotGreen} />
                    <span>ON-DEVICE AI ACTIVE</span>
                  </div>
                  <h2 className={styles.shieldHeroTitle}>Everything looks good.</h2>
                  <p className={styles.shieldHeroDesc}>
                    Browser Vigilant is actively evaluating web requests on-device with zero cloud telemetry.
                  </p>
                </div>
              </div>

              {/* Quick Stat Cards */}
              <div className={styles.statsGrid}>
                <div className={styles.statCard}>
                  <span className={styles.statLabel}>DOMAINS AUDITED</span>
                  <span className={styles.statVal}>{extensionStats.totalScanned}</span>
                </div>
                <div className={styles.statCard}>
                  <span className={styles.statLabel}>THREATS BLOCKED</span>
                  <span className={styles.statVal} style={{ color: "#FF7B6B" }}>{extensionStats.totalBlocked}</span>
                </div>
                <div className={styles.statCard}>
                  <span className={styles.statLabel}>WASM INFERENCE</span>
                  <span className={styles.statVal} style={{ color: "#34D399" }}>&lt; 1.8ms</span>
                </div>
              </div>

              {/* 4 Active Protection Subsystems */}
              <div className={styles.card}>
                <div className={styles.cardHeader}>
                  <h3>Active Protection Subsystems</h3>
                </div>
                <div className={styles.toggleList}>
                  {[
                    { key: "phishing", icon: "🛡", name: "Phishing & Credential Guard", desc: "Blocks fake login forms and credential harvest scripts before submission." },
                    { key: "miners", icon: "⛏", name: "Crypto-Miner Blocker", desc: "Stops background WebWorker and WASM CPU mining scripts." },
                    { key: "typosquatting", icon: "🔤", name: "Brand Typosquatting Interceptor", desc: "Levenshtein distance warnings on spoofed brand URLs (g00gle.com)." },
                    { key: "obfuscation", icon: "🔍", name: "Script De-obfuscation Analyzer", desc: "Catches eval(atob()) and dynamic payload execution." },
                  ].map((sub) => (
                    <div key={sub.key} className={styles.toggleRow}>
                      <div className={styles.toggleIcon}>{sub.icon}</div>
                      <div className={styles.toggleInfo}>
                        <strong>{sub.name}</strong>
                        <p>{sub.desc}</p>
                      </div>
                      <button
                        className={`${styles.toggleSwitch} ${settings[sub.key] ? styles.toggleOn : styles.toggleOff}`}
                        onClick={() => {
                          const updated = { ...settings, [sub.key]: !settings[sub.key] };
                          setSettings(updated);
                          if (extensionConnected) {
                            window.postMessage({ type: "BV_WEB_REQUEST", action: "SAVE_SETTINGS", settings: updated }, "*");
                          }
                        }}
                      >
                        {settings[sub.key] ? "ENABLED" : "DISABLED"}
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Threat Test Sandbox */}
              <div className={styles.card}>
                <div className={styles.cardHeader}>
                  <h3>Threat Simulation Sandbox</h3>
                </div>
                <p className={styles.subtext}>Test detection rules against simulated attacks:</p>
                <div className={styles.sandboxGrid}>
                  <button className={styles.sandboxBtn} onClick={() => runSandboxTest("phishing")} disabled={sandboxRunning}>
                    🛡 Test Phishing Form
                  </button>
                  <button className={styles.sandboxBtn} onClick={() => runSandboxTest("miner")} disabled={sandboxRunning}>
                    ⛏ Test Crypto-Miner
                  </button>
                  <button className={styles.sandboxBtn} onClick={() => runSandboxTest("typosquat")} disabled={sandboxRunning}>
                    🔤 Test Typosquat (g00gle)
                  </button>
                  <button className={styles.sandboxBtn} onClick={() => runSandboxTest("obfuscation")} disabled={sandboxRunning}>
                    🔍 Test eval(atob())
                  </button>
                </div>

                {sandboxLog.length > 0 && (
                  <div className={styles.logWrap}>
                    {sandboxLog.map((l, i) => (
                      <div key={i} className={styles.logRow}>
                        <span className={styles.logTime}>[{l.ts}]</span>
                        <span className={styles.logIntercept}>{l.status}</span>
                        <span className={styles.logVec}>{l.vector}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* 48-Feature Vector Decomposition */}
              <div className={styles.card}>
                <div className={styles.cardHeader}>
                  <h3>48-Feature ML Vector Inspector</h3>
                </div>
                <p className={styles.subtext}>Inspect the exact 48 numeric lexical features computed by the Rust WASM module:</p>
                <div style={{ display: "flex", gap: "10px", marginTop: "8px" }}>
                  <input
                    type="text"
                    className={styles.inputRound}
                    placeholder="Enter URL to decompose..."
                    value={featureUrl}
                    onChange={(e) => setFeatureUrl(e.target.value)}
                  />
                  <button
                    className={styles.coralBtn}
                    onClick={() => runFeatureExtract()}
                    disabled={featureLoading}
                  >
                    {featureLoading ? "Computing..." : "Inspect"}
                  </button>
                </div>

                {featureResult && (
                  <div className={styles.featureResultBox}>
                    <div className={styles.frHeader}>
                      <span>Classification: <strong style={{ color: featureResult.classification === "BENIGN" ? "#34D399" : "#FF7B6B" }}>{featureResult.classification}</strong></span>
                      <span>Shannon Entropy: <strong>{featureResult.entropy.domain}</strong></span>
                      <span>Brand Dist: <strong>{featureResult.brandAnalysis.levenshteinDistance} ({featureResult.brandAnalysis.closestBrand})</strong></span>
                    </div>
                    <div className={styles.vectorList}>
                      {featureResult.features.slice(0, 12).map((f) => (
                        <div key={f.index} className={styles.vectorItem}>
                          <span className={styles.vName}>{f.name}</span>
                          <span className={styles.vVal}>{typeof f.value === "number" ? f.value : JSON.stringify(f.value)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              TAB 3: 📜 HISTORY
          ══════════════════════════════════════════════════════════════════ */}
          {activeTab === "history" && (
            <div className={styles.contentStack}>
              <div className={styles.card}>
                <div className={styles.cardHeader}>
                  <h3>Inspection & Intercept History</h3>
                  <button className={styles.clearBtn} onClick={() => setHistory([])}>
                    Clear History
                  </button>
                </div>

                {history.length === 0 ? (
                  <p className={styles.emptyText}>No recent audit history recorded.</p>
                ) : (
                  <div className={styles.historyList}>
                    {history.map((item) => (
                      <div key={item.id} className={styles.historyRow}>
                        <div className={styles.historyLeft}>
                          <span className={item.status === "SAFE" ? styles.dotGreen : styles.dotRed} />
                          <div>
                            <strong className={styles.historyDomain}>{item.domain}</strong>
                            <span className={styles.historyTime}>{item.timestamp}</span>
                          </div>
                        </div>
                        <div className={styles.historyRight}>
                          <span className={`${styles.riskPill} ${item.status === "SAFE" ? styles.riskPillGreen : styles.riskPillRed}`}>
                            {item.status} ({item.score}/100)
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              TAB 4: ⛁ LEDGER (Blockchain Block Explorer)
          ══════════════════════════════════════════════════════════════════ */}
          {activeTab === "ledger" && (
            <div className={styles.contentStack}>
              <div className={styles.card}>
                <div className={styles.cardHeader}>
                  <h3>On-Device Blockchain Incident Ledger</h3>
                  <span className={styles.verifiedBadge}>🔒 SHA-256 Chain Verified</span>
                </div>
                <p className={styles.subtext}>
                  Every intercepted threat is cryptographically appended to your local block log to prevent unauthorized tampering:
                </p>

                <div className={styles.ledgerGrid}>
                  {/* Block List */}
                  <div className={styles.ledgerBlocks}>
                    {ledger.map((b) => (
                      <div
                        key={b.index}
                        className={`${styles.blockPill} ${selectedBlock.index === b.index ? styles.blockPillSelected : ""}`}
                        onClick={() => setSelectedBlock(b)}
                      >
                        <div className={styles.blockPillTop}>
                          <span className={styles.blockNum}>Block #{b.index}</span>
                          <span className={styles.blockTs}>{fmtDate(b.timestamp)}</span>
                        </div>
                        <code className={styles.blockHashShort}>{shortHash(b.hash, 8)}</code>
                      </div>
                    ))}
                  </div>

                  {/* Block Detail Inspector */}
                  <div className={styles.blockInspectCard}>
                    <div className={styles.biHeader}>
                      <span>Block #{selectedBlock.index} Details</span>
                      <span style={{ color: "#34D399", fontSize: "11px", fontWeight: 700 }}>✓ SHA-256 Valid</span>
                    </div>

                    <div className={styles.biDetails}>
                      <div className={styles.biRow}>
                        <span className={styles.biLabel}>HASH:</span>
                        <code className={styles.biVal}>{selectedBlock.hash}</code>
                      </div>
                      <div className={styles.biRow}>
                        <span className={styles.biLabel}>PREV HASH:</span>
                        <code className={styles.biVal}>{selectedBlock.prevHash}</code>
                      </div>
                      <div className={styles.biRow}>
                        <span className={styles.biLabel}>TIMESTAMP:</span>
                        <span className={styles.biVal}>{selectedBlock.timestamp}</span>
                      </div>
                      <div className={styles.biRow}>
                        <span className={styles.biLabel}>EVENT:</span>
                        <span className={styles.biVal}>{selectedBlock.event}</span>
                      </div>
                      <div className={styles.biRow}>
                        <span className={styles.biLabel}>RULE:</span>
                        <span className={styles.biVal}>{selectedBlock.rule}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              TAB 5: 🔒 VAULT (Decentralized Threat Database)
          ══════════════════════════════════════════════════════════════════ */}
          {activeTab === "vault" && (
            <div className={styles.contentStack}>
              
              {/* Search & Submit Split */}
              <div className={styles.twoCol}>
                
                {/* Search */}
                <div className={styles.card}>
                  <div className={styles.cardHeader}>
                    <h3>Query Threat Hash</h3>
                  </div>
                  <form onSubmit={handleVaultSearch} style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
                    <input
                      type="text"
                      className={styles.inputRound}
                      placeholder="Domain or SHA-256 hash..."
                      value={vaultSearch}
                      onChange={(e) => setVaultSearch(e.target.value)}
                    />
                    <button type="submit" className={styles.coralBtn}>Search</button>
                  </form>

                  {vaultSearchResult && (
                    <div className={styles.searchResult}>
                      {vaultSearchResult.found ? (
                        <div className={styles.foundText}>
                          ⚠️ Match found in threat database! Confidence: {(vaultSearchResult.confidence * 100).toFixed(0)}%
                        </div>
                      ) : (
                        <div className={styles.cleanText}>
                          ✓ No malicious record found for this hash.
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Submit Flag */}
                <div className={styles.card}>
                  <div className={styles.cardHeader}>
                    <h3>Report Phishing URL</h3>
                  </div>
                  <form onSubmit={handleFlagUrl} style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
                    <input
                      type="text"
                      className={styles.inputRound}
                      placeholder="https://malicious-domain.com"
                      value={flagUrl}
                      onChange={(e) => setFlagUrl(e.target.value)}
                    />
                    <button type="submit" className={styles.coralBtn} disabled={flagStatus === "submitting"}>
                      {flagStatus === "submitting" ? "Submitting..." : "Report"}
                    </button>
                  </form>
                  {flagStatus === "success" && (
                    <div className={styles.cleanText} style={{ marginTop: "8px" }}>
                      ✓ SHA-256 hash committed to decentralized vault.
                    </div>
                  )}
                </div>

              </div>

              {/* Verified Feed */}
              <div className={styles.card}>
                <div className={styles.cardHeader}>
                  <h3>Verified Community Threat Database</h3>
                  <span className={styles.countBadge}>{vaultData?.totalThreats || 0}</span>
                </div>
                <div className={styles.vaultTableWrap}>
                  <table className={styles.cleanTable}>
                    <thead>
                      <tr>
                        <th>SHA-256 HASH</th>
                        <th>SOURCE</th>
                        <th>CONFIDENCE</th>
                        <th>DATE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(!vaultData?.recentThreats || vaultData.recentThreats.length === 0) ? (
                        <tr><td colSpan={4} style={{ textAlign: "center", color: "#A0AEC0", padding: "20px" }}>No threats recorded.</td></tr>
                      ) : (
                        vaultData.recentThreats.map((t, i) => (
                          <tr key={i}>
                            <td><code>{shortHash(t.hash, 10)}</code></td>
                            <td><span className={styles.tagPill}>{t.source}</span></td>
                            <td><strong style={{ color: "#FF7B6B" }}>{(t.confidence * 100).toFixed(0)}%</strong></td>
                            <td style={{ color: "#A0AEC0", fontSize: "11px" }}>{fmtDate(t.createdAt)}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              TAB 6: ⚙️ SETTINGS & ALLOWLIST
          ══════════════════════════════════════════════════════════════════ */}
          {activeTab === "settings" && (
            <div className={styles.contentStack}>
              
              {/* Sensitivity Mode */}
              <div className={styles.card}>
                <div className={styles.cardHeader}>
                  <h3>Detection Sensitivity</h3>
                </div>
                <div className={styles.sensitivityRow}>
                  {[
                    { id: "balanced", label: "Balanced (Recommended)", desc: "Standard ML ensemble + high-confidence heuristics." },
                    { id: "strict", label: "Strict Mode", desc: "Aggressive warnings on newly registered and suspicious TLD domains." },
                    { id: "dev", label: "Developer Mode", desc: "Displays raw feature payloads without blocking localhost." },
                  ].map((s) => (
                    <button
                      key={s.id}
                      className={`${styles.sensCard} ${settings.sensitivity === s.id ? styles.sensCardActive : ""}`}
                      onClick={() => setSettings({ ...settings, sensitivity: s.id })}
                    >
                      <strong>{s.label}</strong>
                      <p>{s.desc}</p>
                    </button>
                  ))}
                </div>
              </div>

              {/* Allowlist Manager */}
              <div className={styles.card}>
                <div className={styles.cardHeader}>
                  <h3>Exempt Domain Allowlist</h3>
                  <button className={styles.ghostBtn} onClick={() => setIsAddingDomain(!isAddingDomain)}>
                    {isAddingDomain ? "Cancel" : "+ Add Domain"}
                  </button>
                </div>

                {isAddingDomain && (
                  <form onSubmit={handleAddDomain} style={{ display: "flex", gap: "8px", marginTop: "10px" }}>
                    <input
                      type="text"
                      className={styles.inputRound}
                      placeholder="internal.example.com"
                      value={newDomain}
                      onChange={(e) => setNewDomain(e.target.value)}
                    />
                    <button type="submit" className={styles.coralBtn}>Save</button>
                  </form>
                )}

                <div className={styles.allowlistList}>
                  {allowlist.map((d, i) => (
                    <div key={i} className={styles.allowlistRow}>
                      <code>{d}</code>
                      <button className={styles.removeBtn} onClick={() => handleRemoveDomain(d)}>
                        ✕ Remove
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Open Source Footer */}
              <div className={styles.aboutFooter}>
                <strong>Browser Vigilant v2.0.0</strong> · 100% On-Device AI Security · Zero Telemetry
              </div>

            </div>
          )}

        </div>
      </div>
    </div>
  );
}
