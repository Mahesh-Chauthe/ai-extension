class ExtensionBackground {
    constructor() {
        this.apiUrl = 'http://localhost:3000';
        this.organizationData = null;
        this.accessToken = null;
        this.init();
    }

    init() {
        this.setupMessageHandlers();
        this.setupStorageHandlers();
        this.loadStoredData();
    }

    setupMessageHandlers() {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open for async response
        });
    }

    setupStorageHandlers() {
        chrome.storage.onChanged.addListener((changes, namespace) => {
            if (namespace === 'local' && changes.organizationToken) {
                this.loadStoredData();
            }
        });
    }

    async loadStoredData() {
        try {
            const result = await chrome.storage.local.get(['organizationToken', 'organizationData']);
            this.accessToken = result.organizationToken;
            this.organizationData = result.organizationData;
            
            if (this.organizationData) {
                this.updateBadge('ON');
            } else {
                this.updateBadge('OFF');
            }
        } catch (error) {
            console.error('Failed to load stored data:', error);
        }
    }

    async handleMessage(message, sender, sendResponse) {
        try {
            switch (message.action) {
                case 'authenticated':
                    await this.handleAuthentication(message);
                    sendResponse({ success: true });
                    break;

                case 'logout':
                    await this.handleLogout();
                    sendResponse({ success: true });
                    break;

                case 'scanPage':
                    const scanResult = await this.scanPageContent(message.content);
                    sendResponse({ results: scanResult });
                    break;

                case 'reportActivity':
                    await this.logActivity(message.activity);
                    sendResponse({ success: true });
                    break;

                case 'getOrganizationData':
                    sendResponse({ 
                        organization: this.organizationData,
                        token: this.accessToken
                    });
                    break;

                default:
                    sendResponse({ error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Message handling error:', error);
            sendResponse({ error: error.message });
        }
    }

    async handleAuthentication(message) {
        this.organizationData = message.organization;
        this.accessToken = message.token;
        
        await this.logActivity({
            action: 'EXTENSION_AUTHENTICATED',
            details: `Authenticated with organization: ${message.organization.name}`,
            timestamp: new Date().toISOString()
        });

        this.updateBadge('ON');
        
        // Set up periodic sync
        this.setupPeriodicSync();
    }

    async handleLogout() {
        await this.logActivity({
            action: 'EXTENSION_LOGOUT',
            details: 'User logged out from extension',
            timestamp: new Date().toISOString()
        });

        this.organizationData = null;
        this.accessToken = null;
        this.updateBadge('OFF');
    }

    async scanPageContent(content) {
        if (!this.organizationData) {
            return [];
        }

        const sensitivePatterns = [
            {
                name: 'Credit Card',
                pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
                type: 'financial'
            },
            {
                name: 'Social Security Number',
                pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
                type: 'pii'
            },
            {
                name: 'Email Address',
                pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
                type: 'pii'
            },
            {
                name: 'Phone Number',
                pattern: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
                type: 'pii'
            },
            {
                name: 'API Key',
                pattern: /\b[A-Za-z0-9]{32,}\b/g,
                type: 'credential'
            }
        ];

        const results = [];
        
        sensitivePatterns.forEach(pattern => {
            const matches = content.match(pattern.pattern);
            if (matches) {
                results.push({
                    type: pattern.name,
                    description: `Found ${matches.length} instance(s) of ${pattern.name}`,
                    category: pattern.type,
                    count: matches.length
                });
            }
        });

        // Log scan activity
        await this.logActivity({
            action: 'PAGE_SCANNED',
            details: `Scanned page, found ${results.length} sensitive data types`,
            timestamp: new Date().toISOString(),
            results: results
        });

        return results;
    }

    async logActivity(activity) {
        try {
            const result = await chrome.storage.local.get(['activityLog']);
            const activityLog = result.activityLog || [];
            
            activityLog.push({
                ...activity,
                id: Date.now(),
                organizationId: this.organizationData?.id
            });
            
            // Keep only last 100 activities
            if (activityLog.length > 100) {
                activityLog.splice(0, activityLog.length - 100);
            }
            
            await chrome.storage.local.set({ activityLog });
            
            // Send to server if authenticated
            if (this.accessToken && this.organizationData) {
                this.sendActivityToServer(activity);
            }
        } catch (error) {
            console.error('Failed to log activity:', error);
        }
    }

    async sendActivityToServer(activity) {
        try {
            await fetch(`${this.apiUrl}/api/activity/log`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.accessToken}`
                },
                body: JSON.stringify({
                    ...activity,
                    organizationId: this.organizationData.id,
                    extensionVersion: chrome.runtime.getManifest().version
                })
            });
        } catch (error) {
            console.error('Failed to send activity to server:', error);
        }
    }

    updateBadge(text) {
        chrome.action.setBadgeText({ text });
        chrome.action.setBadgeBackgroundColor({ 
            color: text === 'ON' ? '#10b981' : '#6b7280' 
        });
    }

    setupPeriodicSync() {
        // Sync activity every 5 minutes
        setInterval(async () => {
            if (this.accessToken && this.organizationData) {
                await this.syncWithServer();
            }
        }, 5 * 60 * 1000);
    }

    async syncWithServer() {
        try {
            const result = await chrome.storage.local.get(['activityLog']);
            const activityLog = result.activityLog || [];
            
            // Send unsent activities
            const unsentActivities = activityLog.filter(a => !a.synced);
            
            if (unsentActivities.length > 0) {
                await fetch(`${this.apiUrl}/api/activity/bulk`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.accessToken}`
                    },
                    body: JSON.stringify({
                        activities: unsentActivities,
                        organizationId: this.organizationData.id
                    })
                });
                
                // Mark as synced
                unsentActivities.forEach(a => a.synced = true);
                await chrome.storage.local.set({ activityLog });
            }
        } catch (error) {
            console.error('Sync failed:', error);
        }
    }
}

// Initialize background service
new ExtensionBackground();