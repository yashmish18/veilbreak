// Browser Vigilant - Unified Connection Script
// Connects web backend, popup UI, and blockchain components

class BrowserVigilantConnector {
    constructor() {
        this.extensionId = null;
        this.webApiUrl = 'http://localhost:3000'; // Default for local development
        this.isExtensionAvailable = false;
        this.blockchainReady = false;
    }

    // Initialize all components
    async initialize() {
        console.log('🚀 Initializing Browser Vigilant components...');
        
        // Check if running in extension context
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            this.extensionId = chrome.runtime.id;
            this.isExtensionAvailable = true;
            console.log('✓ Extension context detected');
        }

        // Initialize blockchain components
        await this.initializeBlockchain();
        
        // Connect to web API
        await this.connectWebApi();
        
        console.log('✅ All components initialized successfully');
    }

    // Initialize blockchain threat vault
    async initializeBlockchain() {
        try {
            // Import blockchain components dynamically
            if (typeof window !== 'undefined') {
                // Browser environment
                await this.loadBlockchainScripts();
            } else {
                // Node.js environment
                // Blockchain components would be imported differently
            }
            
            this.blockchainReady = true;
            console.log('✓ Blockchain threat vault ready');
        } catch (error) {
            console.error('❌ Blockchain initialization failed:', error);
        }
    }

    // Load blockchain scripts in browser environment
    async loadBlockchainScripts() {
        const scripts = [
            'blockchain/merkle_tree.js',
            'blockchain/federated_consensus.js',
            'blockchain/threat_registry.js',
            'blockchain/blockchain_vault.js'
        ];

        for (const scriptPath of scripts) {
            await this.loadScript(scriptPath);
        }
    }

    // Load individual script
    loadScript(src) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    // Connect to web API
    async connectWebApi() {
        try {
            // Test connection to web API
            const response = await fetch(`${this.webApiUrl}/api/vault/stats`);
            if (response.ok) {
                console.log('✓ Web API connection established');
                return true;
            }
        } catch (error) {
            console.warn('⚠ Web API not available (this is normal for extension-only usage)');
        }
        return false;
    }

    // Extension communication methods
    async sendMessageToExtension(message) {
        if (!this.isExtensionAvailable) {
            throw new Error('Extension not available');
        }

        return new Promise((resolve, reject) => {
            chrome.runtime.sendMessage(this.extensionId, message, (response) => {
                if (chrome.runtime.lastError) {
                    reject(chrome.runtime.lastError);
                } else {
                    resolve(response);
                }
            });
        });
    }

    // Web API communication methods
    async submitThreatToWeb(hash, source, confidence, threatType) {
        try {
            const response = await fetch(`${this.webApiUrl}/api/vault/submit`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    hash,
                    source,
                    confidence,
                    threatType
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to submit threat to web API:', error);
            return null;
        }
    }

    async syncThreatsFromWeb(since = null) {
        try {
            const url = new URL(`${this.webApiUrl}/api/vault/sync`);
            if (since) {
                url.searchParams.append('since', since.toString());
            }

            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to sync threats from web API:', error);
            return null;
        }
    }

    async getWebStats() {
        try {
            const response = await fetch(`${this.webApiUrl}/api/vault/stats`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to get web stats:', error);
            return null;
        }
    }

    // Unified threat management
    async submitThreat(hash, source, confidence, threatType, options = {}) {
        const results = {
            extension: null,
            web: null,
            blockchain: null
        };

        // Submit to extension (if available)
        if (this.isExtensionAvailable) {
            try {
                results.extension = await this.sendMessageToExtension({
                    type: 'SUBMIT_THREAT',
                    hash,
                    source,
                    confidence,
                    threatType
                });
            } catch (error) {
                console.error('Extension submission failed:', error);
            }
        }

        // Submit to web API (if available)
        if (options.useWebApi) {
            results.web = await this.submitThreatToWeb(hash, source, confidence, threatType);
        }

        // Submit to blockchain (if available)
        if (this.blockchainReady && typeof window !== 'undefined' && window.BlockchainThreatVault) {
            try {
                const vault = new window.BlockchainThreatVault();
                await vault.initialize();
                results.blockchain = await vault.submitThreat(hash, confidence, threatType, {
                    source,
                    confidence
                });
            } catch (error) {
                console.error('Blockchain submission failed:', error);
            }
        }

        return results;
    }

    // Get unified statistics
    async getUnifiedStats() {
        const stats = {
            extension: null,
            web: null,
            blockchain: null
        };

        // Get extension stats
        if (this.isExtensionAvailable) {
            try {
                stats.extension = await this.sendMessageToExtension({
                    type: 'GET_STATS'
                });
            } catch (error) {
                console.error('Failed to get extension stats:', error);
            }
        }

        // Get web stats
        stats.web = await this.getWebStats();

        // Get blockchain stats
        if (this.blockchainReady && typeof window !== 'undefined' && window.BlockchainThreatVault) {
            try {
                const vault = new window.BlockchainThreatVault();
                await vault.initialize();
                stats.blockchain = await vault.getStatistics();
            } catch (error) {
                console.error('Failed to get blockchain stats:', error);
            }
        }

        return stats;
    }

    // Health check
    async healthCheck() {
        const health = {
            extension: this.isExtensionAvailable,
            webApi: await this.connectWebApi(),
            blockchain: this.blockchainReady,
            timestamp: Date.now()
        };

        console.log('Health check results:', health);
        return health;
    }
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    // Node.js environment
    module.exports = BrowserVigilantConnector;
} else if (typeof window !== 'undefined') {
    // Browser environment
    window.BrowserVigilantConnector = BrowserVigilantConnector;
    
    // Auto-initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.bvConnector = new BrowserVigilantConnector();
            window.bvConnector.initialize();
        });
    } else {
        window.bvConnector = new BrowserVigilantConnector();
        window.bvConnector.initialize();
    }
}

// Usage examples:
/*
// In extension popup:
const connector = new BrowserVigilantConnector();
await connector.initialize();

// Submit a threat
const results = await connector.submitThreat(
    'a1b2c3d4e5f6...', 
    'extension-ml', 
    0.95, 
    'PHISHING',
    { useWebApi: true }
);

// Get all stats
const stats = await connector.getUnifiedStats();
console.log('Unified stats:', stats);
*/