class ExtensionPopup {
    constructor() {
        this.apiUrl = 'http://localhost:3000';
        this.init();
    }

    async init() {
        await this.checkAuthStatus();
        this.bindEvents();
    }

    async checkAuthStatus() {
        const result = await chrome.storage.local.get(['organizationToken', 'organizationData', 'userEmail']);
        
        if (result.organizationToken && result.organizationData) {
            this.showDashboard(result.organizationData, result.userEmail);
        } else {
            this.showAuthScreen();
        }
    }

    showAuthScreen() {
        document.getElementById('authScreen').classList.remove('hidden');
        document.getElementById('dashboardScreen').classList.add('hidden');
        document.getElementById('activityScreen').classList.add('hidden');
    }

    showDashboard(orgData, userEmail) {
        document.getElementById('authScreen').classList.add('hidden');
        document.getElementById('dashboardScreen').classList.remove('hidden');
        document.getElementById('activityScreen').classList.add('hidden');
        
        document.getElementById('headerSubtitle').textContent = orgData.name;
        document.getElementById('orgName').textContent = orgData.name;
        document.getElementById('userEmail').textContent = userEmail || 'user@' + orgData.domain;
    }

    showActivity() {
        document.getElementById('dashboardScreen').classList.add('hidden');
        document.getElementById('activityScreen').classList.remove('hidden');
        this.loadActivity();
    }

    bindEvents() {
        // Authentication
        document.getElementById('authenticateBtn').addEventListener('click', () => {
            this.authenticate();
        });

        document.getElementById('accessToken').addEventListener('keypress', (e) => {
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
            this.openSettings();
        });

        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.logout();
        });

        // Navigation
        document.getElementById('backToDashboard').addEventListener('click', () => {
            this.checkAuthStatus();
        });
    }

    async authenticate() {
        const token = document.getElementById('accessToken').value.trim();
        
        if (!token) {
            this.showError('Please enter an access token');
            return;
        }

        try {
            const response = await fetch(`${this.apiUrl}/api/validate-token`, {
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
                    organizationToken: token,
                    organizationData: data.organization,
                    userEmail: `user@${data.organization.domain}`,
                    authenticatedAt: new Date().toISOString()
                });

                // Notify background script
                chrome.runtime.sendMessage({
                    action: 'authenticated',
                    organization: data.organization,
                    token: token
                });

                this.showDashboard(data.organization, `user@${data.organization.domain}`);
                this.showSuccess('Authentication successful!');
            } else {
                this.showError('Invalid access token');
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
            let html = `<p style="color: #dc2626;">⚠️ Found ${results.length} potential issue(s):</p><ul>`;
            results.forEach(result => {
                html += `<li><strong>${result.type}</strong>: ${result.description}</li>`;
            });
            html += '</ul>';
            scanDetails.innerHTML = html;
        }
        
        scanResult.classList.remove('hidden');
        
        // Hide after 5 seconds
        setTimeout(() => {
            scanResult.classList.add('hidden');
        }, 5000);
    }

    async loadActivity() {
        const activityList = document.getElementById('activityList');
        
        try {
            const result = await chrome.storage.local.get(['activityLog']);
            const activities = result.activityLog || [];
            
            if (activities.length === 0) {
                activityList.innerHTML = '<p style="color: #6b7280;">No recent activity</p>';
                return;
            }
            
            let html = '';
            activities.slice(-10).reverse().forEach(activity => {
                const date = new Date(activity.timestamp).toLocaleString();
                html += `
                    <div style="padding: 0.5rem; border-bottom: 1px solid #e5e7eb;">
                        <div style="font-weight: 600; color: #374151;">${activity.action}</div>
                        <div style="font-size: 0.8rem; color: #6b7280;">${date}</div>
                        <div style="font-size: 0.9rem; color: #4b5563;">${activity.details}</div>
                    </div>
                `;
            });
            
            activityList.innerHTML = html;
        } catch (error) {
            console.error('Failed to load activity:', error);
            activityList.innerHTML = '<p style="color: #dc2626;">Failed to load activity</p>';
        }
    }

    openSettings() {
        chrome.tabs.create({
            url: chrome.runtime.getURL('settings.html')
        });
    }

    async logout() {
        if (confirm('Are you sure you want to logout?')) {
            await chrome.storage.local.clear();
            chrome.runtime.sendMessage({ action: 'logout' });
            this.showAuthScreen();
            document.getElementById('accessToken').value = '';
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