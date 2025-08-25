class ExtensionBackground {
    constructor() {
        this.apiUrl = 'http://localhost:8080';
        this.organizationData = null;
        this.userData = null;
        this.extensionToken = null;
        this.settings = {
            enableNotifications: true,
            enableChatbotMonitoring: true,
            enableFormMonitoring: true,
            sensitivityLevel: 'medium'
        };
        this.init();
    }

    init() {
        this.setupMessageHandlers();
        this.setupStorageHandlers();
        this.loadStoredData();
        this.setupPeriodicSync();
    }

    setupMessageHandlers() {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open for async response
        });
    }

    setupStorageHandlers() {
        chrome.storage.onChanged.addListener((changes, namespace) => {
            if (namespace === 'local') {
                if (changes.extensionToken) {
                    this.loadStoredData();
                }
                if (changes.enableNotifications || changes.enableChatbotMonitoring || changes.enableFormMonitoring || changes.sensitivityLevel) {
                    this.loadSettings();
                }
            }
        });
    }

    async loadStoredData() {
        try {
            const result = await chrome.storage.local.get(['extensionToken', 'organizationData', 'userData']);
            this.extensionToken = result.extensionToken;
            this.organizationData = result.organizationData;
            this.userData = result.userData;
            
            if (this.organizationData) {
                this.updateBadge('ON');
            } else {
                this.updateBadge('OFF');
            }
        } catch (error) {
            console.error('Failed to load stored data:', error);
        }
    }

    async loadSettings() {
        try {
            const result = await chrome.storage.local.get([
                'enableNotifications',
                'enableChatbotMonitoring', 
                'enableFormMonitoring',
                'sensitivityLevel'
            ]);
            
            this.settings = {
                enableNotifications: result.enableNotifications !== false,
                enableChatbotMonitoring: result.enableChatbotMonitoring !== false,
                enableFormMonitoring: result.enableFormMonitoring !== false,
                sensitivityLevel: result.sensitivityLevel || 'medium'
            };
        } catch (error) {
            console.error('Failed to load settings:', error);
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

                case 'logActivity':
                    await this.logActivity(message.activity);
                    sendResponse({ success: true });
                    break;

                case 'settingsUpdated':
                    this.settings = message.settings;
                    await this.notifyContentScripts('settingsUpdated', this.settings);
                    sendResponse({ success: true });
                    break;

                case 'getAuthData':
                    sendResponse({ 
                        organization: this.organizationData,
                        user: this.userData,
                        token: this.extensionToken,
                        settings: this.settings
                    });
                    break;

                case 'sensitiveDataDetected':
                    await this.handleSensitiveDataDetection(message.data, sender.tab);
                    sendResponse({ success: true });
                    break;

                case 'chatbotBlocked':
                    await this.handleChatbotBlocked(message.data, sender.tab);
                    sendResponse({ success: true });
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
        this.userData = message.user;
        this.extensionToken = message.token;
        
        await this.logActivity({
            action: 'EXTENSION_AUTHENTICATED',
            details: `User ${message.user.name} authenticated with organization: ${message.organization.name}`,
            timestamp: new Date().toISOString()
        });

        this.updateBadge('ON');
        
        // Notify all content scripts
        await this.notifyContentScripts('authenticated', {
            organization: this.organizationData,
            user: this.userData,
            settings: this.settings
        });
    }

    async handleLogout() {
        await this.logActivity({
            action: 'EXTENSION_LOGOUT',
            details: 'User logged out from extension',
            timestamp: new Date().toISOString()
        });

        this.organizationData = null;
        this.userData = null;
        this.extensionToken = null;
        this.updateBadge('OFF');
        
        // Notify all content scripts
        await this.notifyContentScripts('logout', {});
    }

    async scanPageContent(content) {
        if (!this.organizationData) {
            return [];
        }

        const sensitivePatterns = this.getSensitivePatterns();
        const results = [];
        
        sensitivePatterns.forEach(pattern => {
            const matches = content.match(pattern.regex);
            if (matches) {
                results.push({
                    type: pattern.name,
                    description: `Found ${matches.length} instance(s) of ${pattern.name}`,
                    category: pattern.category,
                    count: matches.length,
                    severity: pattern.severity
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

    getSensitivePatterns() {
        const patterns = [
            {
                name: 'Credit Card Number',
                regex: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g,
                category: 'financial',
                severity: 'high'
            },
            {
                name: 'Social Security Number',
                regex: /\b\d{3}-\d{2}-\d{4}\b/g,
                category: 'pii',
                severity: 'high'
            },
            {
                name: 'Email Address',
                regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
                category: 'pii',
                severity: 'medium'
            },
            {
                name: 'Phone Number',
                regex: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
                category: 'pii',
                severity: 'medium'
            },
            {
                name: 'API Key',
                regex: /\b[A-Za-z0-9]{32,}\b/g,
                category: 'credential',
                severity: 'critical'
            },
            {
                name: 'JWT Token',
                regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
                category: 'credential',
                severity: 'critical'
            },
            {
                name: 'AWS Access Key',
                regex: /AKIA[0-9A-Z]{16}/g,
                category: 'credential',
                severity: 'critical'
            },
            {
                name: 'Password Pattern',
                regex: /(?:password|pwd|pass)\s*[:=]\s*[^\s]{6,}/gi,
                category: 'credential',
                severity: 'high'
            }
        ];

        // Filter by sensitivity level
        if (this.settings.sensitivityLevel === 'low') {
            return patterns.filter(p => p.severity === 'critical');
        } else if (this.settings.sensitivityLevel === 'medium') {
            return patterns.filter(p => ['critical', 'high'].includes(p.severity));
        } else {
            return patterns; // high sensitivity - all patterns
        }
    }

    async handleSensitiveDataDetection(data, tab) {
        if (!this.settings.enableNotifications) return;

        // Show notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon48.png',
            title: 'Sensitive Data Detected',
            message: `${data.type} detected on ${new URL(tab.url).hostname}`
        });

        // Log the detection
        await this.logActivity({
            action: 'SENSITIVE_DATA_DETECTED',
            details: `${data.type} detected: ${data.description}`,
            timestamp: new Date().toISOString(),
            url: tab.url
        });

        // Send to server
        await this.sendToServer('/api/activity', {
            userId: this.userData?.id,
            orgId: this.organizationData?.id,
            action: 'SENSITIVE_DATA_DETECTED',
            details: `${data.type} detected on ${new URL(tab.url).hostname}`,
            url: tab.url,
            timestamp: new Date().toISOString()
        });
    }

    async handleChatbotBlocked(data, tab) {
        if (!this.settings.enableNotifications) return;

        // Show notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon48.png',
            title: 'AI Chatbot Blocked',
            message: `Sensitive data blocked from ${data.chatbot} on ${new URL(tab.url).hostname}`
        });

        // Log the block
        await this.logActivity({
            action: 'CHATBOT_BLOCKED',
            details: `Blocked sensitive data from being sent to ${data.chatbot}`,
            timestamp: new Date().toISOString(),
            url: tab.url
        });
    }

    async logActivity(activity) {
        try {
            const result = await chrome.storage.local.get(['activityLog']);
            const activityLog = result.activityLog || [];
            
            activityLog.push({
                ...activity,
                id: Date.now(),
                organizationId: this.organizationData?.id,
                userId: this.userData?.id
            });
            
            // Keep only last 100 activities
            if (activityLog.length > 100) {
                activityLog.splice(0, activityLog.length - 100);
            }
            
            await chrome.storage.local.set({ activityLog });
            
            // Send to server if authenticated
            if (this.extensionToken && this.organizationData) {
                await this.sendToServer('/api/activity', activity);
            }
        } catch (error) {
            console.error('Failed to log activity:', error);
        }
    }

    async sendToServer(endpoint, data) {
        try {
            await fetch(`${this.apiUrl}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.extensionToken}`
                },
                body: JSON.stringify({
                    ...data,
                    organizationId: this.organizationData?.id,
                    userId: this.userData?.id,
                    extensionVersion: chrome.runtime.getManifest().version
                })
            });
        } catch (error) {
            console.error('Failed to send to server:', error);
        }
    }

    async notifyContentScripts(action, data) {
        try {
            const tabs = await chrome.tabs.query({});
            
            for (const tab of tabs) {
                try {
                    await chrome.tabs.sendMessage(tab.id, {
                        action: action,
                        data: data
                    });
                } catch (error) {
                    // Tab might not have content script loaded, ignore
                }
            }
        } catch (error) {
            console.error('Failed to notify content scripts:', error);
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
            if (this.extensionToken && this.organizationData) {
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
                        'Authorization': `Bearer ${this.extensionToken}`
                    },
                    body: JSON.stringify({
                        activities: unsentActivities,
                        organizationId: this.organizationData.id,
                        userId: this.userData.id
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