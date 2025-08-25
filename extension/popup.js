class ExtensionPopup {
    constructor() {
        this.apiUrl = 'http://localhost:8080';
        this.init();
    }

    async init() {
        await this.checkAuthStatus();
        this.bindEvents();
        this.loadStats();
    }

    async checkAuthStatus() {
        const result = await chrome.storage.local.get(['extensionToken', 'organizationData', 'userEmail']);
        
        if (result.extensionToken && result.organizationData) {
            this.showDashboard(result.organizationData, result.userEmail);
        } else {
            this.showAuthScreen();
        }
    }

    showAuthScreen() {
        document.getElementById('authScreen').classList.remove('hidden');
        document.getElementById('dashboardScreen').classList.add('hidden');
        document.getElementById('activityScreen').classList.add('hidden');
        document.getElementById('settingsScreen').classList.add('hidden');
    }

    showDashboard(orgData, userEmail) {
        document.getElementById('authScreen').classList.add('hidden');
        document.getElementById('dashboardScreen').classList.remove('hidden');
        document.getElementById('activityScreen').classList.add('hidden');
        document.getElementById('settingsScreen').classList.add('hidden');
        
        document.getElementById('headerSubtitle').textContent = orgData.name;
        document.getElementById('orgName').textContent = orgData.name;
        document.getElementById('userEmail').textContent = userEmail || 'user@' + orgData.domain;
    }

    showActivity() {
        document.getElementById('dashboardScreen').classList.add('hidden');
        document.getElementById('activityScreen').classList.remove('hidden');
        this.loadActivity();
    }

    showSettings() {
        document.getElementById('dashboardScreen').classList.add('hidden');
        document.getElementById('settingsScreen').classList.remove('hidden');
        this.loadSettings();
    }

    bindEvents() {
        // Authentication
        document.getElementById('authenticateBtn').addEventListener('click', () => {
            this.authenticate();
        });

        document.getElementById('extensionToken').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.authenticate();
            }
        });

        // Dashboard actions
        document.getElementById('scanPageBtn').addEventListener('click', () => {
            this.scanCurrentPage();
        });

        document.getElementById('viewActivityBtn').addEventListener('click', () => {
            this.showActivity();
        });

        document.getElementById('settingsBtn').addEventListener('click', () => {
            this.showSettings();
        });

        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.logout();
        });

        // Navigation
        document.getElementById('backToDashboard').addEventListener('click', () => {
            this.checkAuthStatus();
        });

        document.getElementById('backFromSettings').addEventListener('click', () => {
            this.checkAuthStatus();
        });

        // Settings
        document.getElementById('saveSettingsBtn').addEventListener('click', () => {
            this.saveSettings();
        });
    }

    async authenticate() {
        const token = document.getElementById('extensionToken').value.trim();
        
        if (!token) {
            this.showError('Please enter an extension token');
            return;
        }

        try {
            const response = await fetch(`${this.apiUrl}/api/validate-extension-token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ token })
            });

            const data = await response.json();

            if (data.valid) {
                // Store authentication data
                await chrome.storage.local.set({
                    extensionToken: token,
                    organizationData: data.organization,
                    userData: data.user,
                    userEmail: data.user.email,
                    authenticatedAt: new Date().toISOString()
                });

                // Notify background script
                chrome.runtime.sendMessage({
                    action: 'authenticated',
                    organization: data.organization,
                    user: data.user,
                    token: token
                });

                this.showDashboard(data.organization, data.user.email);
                this.showSuccess('Authentication successful!');
                
                // Log authentication
                this.logActivity('EXTENSION_AUTHENTICATED', 'User authenticated with extension');
            } else {
                this.showError('Invalid extension token');
            }
        } catch (error) {
            console.error('Authentication error:', error);
            this.showError('Authentication failed. Please check your connection.');
        }
    }

    async scanCurrentPage() {
        try {
            // Get current tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            // Send message to content script to scan page
            const response = await chrome.tabs.sendMessage(tab.id, {
                action: 'scanPage'
            });

            if (response && response.results) {
                this.displayScanResults(response.results);
                
                // Update stats
                await this.updateStats('pagesScanned', 1);
                if (response.results.length > 0) {
                    await this.updateStats('threatsBlocked', response.results.length);
                }
            } else {
                this.showScanResults('No sensitive data detected on this page.');
            }
        } catch (error) {
            console.error('Scan error:', error);
            this.showError('Failed to scan page. Please refresh and try again.');
        }
    }

    displayScanResults(results) {
        const scanResult = document.getElementById('scanResult');
        const scanDetails = document.getElementById('scanDetails');
        
        if (results.length === 0) {
            scanDetails.innerHTML = '<p style="color: #10b981;">✅ No sensitive data detected</p>';
        } else {
            let html = `<p style="color: #dc2626; font-weight: 600;">⚠️ Found ${results.length} potential security issue(s):</p>`;
            
            results.forEach(result => {
                html += `
                    <div class="threat-item">
                        <div class="threat-type">${result.type}</div>
                        <div class="threat-desc">${result.description}</div>
                    </div>
                `;
            });
            
            scanDetails.innerHTML = html;
            
            // Show notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon48.png',
                title: 'Security Alert',
                message: `Found ${results.length} sensitive data item(s) on this page`
            });
        }
        
        scanResult.classList.remove('hidden');
        
        // Hide after 10 seconds
        setTimeout(() => {
            scanResult.classList.add('hidden');
        }, 10000);
    }

    async loadActivity() {
        const activityList = document.getElementById('activityList');
        
        try {
            const result = await chrome.storage.local.get(['activityLog']);
            const activities = result.activityLog || [];
            
            if (activities.length === 0) {
                activityList.innerHTML = '<p style="color: #6b7280; text-align: center; padding: 2rem;">No recent activity</p>';
                return;
            }
            
            let html = '';
            activities.slice(-15).reverse().forEach(activity => {
                const date = new Date(activity.timestamp).toLocaleString();
                const iconMap = {
                    'PAGE_SCANNED': '🔍',
                    'SENSITIVE_DATA_DETECTED': '⚠️',
                    'CHATBOT_BLOCKED': '🚫',
                    'FORM_MONITORED': '📝',
                    'EXTENSION_AUTHENTICATED': '✅'
                };
                
                html += `
                    <div style="padding: 0.75rem; border-bottom: 1px solid #e5e7eb; border-left: 3px solid #7c3aed;">
                        <div style="font-weight: 600; color: #374151;">
                            ${iconMap[activity.action] || '📋'} ${activity.action.replace(/_/g, ' ')}
                        </div>
                        <div style="font-size: 0.8rem; color: #6b7280; margin-top: 0.25rem;">${date}</div>
                        <div style="font-size: 0.9rem; color: #4b5563; margin-top: 0.25rem;">${activity.details}</div>
                    </div>
                `;
            });
            
            activityList.innerHTML = html;
        } catch (error) {
            console.error('Failed to load activity:', error);
            activityList.innerHTML = '<p style="color: #dc2626; text-align: center; padding: 2rem;">Failed to load activity</p>';
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
            
            document.getElementById('enableNotifications').checked = result.enableNotifications !== false;
            document.getElementById('enableChatbotMonitoring').checked = result.enableChatbotMonitoring !== false;
            document.getElementById('enableFormMonitoring').checked = result.enableFormMonitoring !== false;
            document.getElementById('sensitivityLevel').value = result.sensitivityLevel || 'medium';
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    async saveSettings() {
        try {
            const settings = {
                enableNotifications: document.getElementById('enableNotifications').checked,
                enableChatbotMonitoring: document.getElementById('enableChatbotMonitoring').checked,
                enableFormMonitoring: document.getElementById('enableFormMonitoring').checked,
                sensitivityLevel: document.getElementById('sensitivityLevel').value
            };
            
            await chrome.storage.local.set(settings);
            
            // Notify content script of settings change
            chrome.runtime.sendMessage({
                action: 'settingsUpdated',
                settings: settings
            });
            
            this.showSuccess('Settings saved successfully!');
            
            setTimeout(() => {
                this.checkAuthStatus();
            }, 1000);
        } catch (error) {
            console.error('Failed to save settings:', error);
            this.showError('Failed to save settings');
        }
    }

    async loadStats() {
        try {
            const result = await chrome.storage.local.get(['extensionStats']);
            const stats = result.extensionStats || { pagesScanned: 0, threatsBlocked: 0 };
            
            document.getElementById('pagesScanned').textContent = stats.pagesScanned || 0;
            document.getElementById('threatsBlocked').textContent = stats.threatsBlocked || 0;
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    async updateStats(statName, increment) {
        try {
            const result = await chrome.storage.local.get(['extensionStats']);
            const stats = result.extensionStats || { pagesScanned: 0, threatsBlocked: 0 };
            
            stats[statName] = (stats[statName] || 0) + increment;
            
            await chrome.storage.local.set({ extensionStats: stats });
            
            document.getElementById(statName).textContent = stats[statName];
        } catch (error) {
            console.error('Failed to update stats:', error);
        }
    }

    async logActivity(action, details) {
        try {
            const result = await chrome.storage.local.get(['activityLog']);
            const activityLog = result.activityLog || [];
            
            activityLog.push({
                id: Date.now(),
                action,
                details,
                timestamp: new Date().toISOString(),
                url: window.location.href
            });
            
            // Keep only last 100 activities
            if (activityLog.length > 100) {
                activityLog.splice(0, activityLog.length - 100);
            }
            
            await chrome.storage.local.set({ activityLog });
            
            // Send to background script for server sync
            chrome.runtime.sendMessage({
                action: 'logActivity',
                activity: {
                    action,
                    details,
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            console.error('Failed to log activity:', error);
        }
    }

    async logout() {
        if (confirm('Are you sure you want to logout?')) {
            await chrome.storage.local.clear();
            chrome.runtime.sendMessage({ action: 'logout' });
            this.showAuthScreen();
            document.getElementById('extensionToken').value = '';
            this.showSuccess('Logged out successfully');
        }
    }

    showSuccess(message) {
        this.showStatus(message, 'success');
    }

    showError(message) {
        this.showStatus(message, 'error');
    }

    showStatus(message, type) {
        // Remove existing status messages
        const existingStatus = document.querySelector('.temp-status');
        if (existingStatus) {
            existingStatus.remove();
        }

        const statusDiv = document.createElement('div');
        statusDiv.className = `status ${type} temp-status`;
        statusDiv.textContent = message;
        
        const content = document.querySelector('.content');
        content.insertBefore(statusDiv, content.firstChild);
        
        // Remove after 3 seconds
        setTimeout(() => {
            statusDiv.remove();
        }, 3000);
    }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ExtensionPopup();
});