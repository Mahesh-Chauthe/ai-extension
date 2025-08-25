class ContentScriptMonitor {
    constructor() {
        this.isAuthenticated = false;
        this.organizationData = null;
        this.monitoringActive = false;
        this.init();
    }

    async init() {
        await this.checkAuthStatus();
        this.setupMessageHandlers();
        
        if (this.isAuthenticated) {
            this.startMonitoring();
        }
    }

    async checkAuthStatus() {
        try {
            const response = await chrome.runtime.sendMessage({
                action: 'getOrganizationData'
            });
            
            if (response && response.organization) {
                this.isAuthenticated = true;
                this.organizationData = response.organization;
            }
        } catch (error) {
            console.error('Failed to check auth status:', error);
        }
    }

    setupMessageHandlers() {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true;
        });
    }

    async handleMessage(message, sender, sendResponse) {
        switch (message.action) {
            case 'scanPage':
                const content = this.extractPageContent();
                const response = await chrome.runtime.sendMessage({
                    action: 'scanPage',
                    content: content
                });
                sendResponse(response);
                break;

            case 'startMonitoring':
                this.startMonitoring();
                sendResponse({ success: true });
                break;

            case 'stopMonitoring':
                this.stopMonitoring();
                sendResponse({ success: true });
                break;
        }
    }

    startMonitoring() {
        if (this.monitoringActive || !this.isAuthenticated) return;
        
        this.monitoringActive = true;
        this.setupFormMonitoring();
        this.setupClipboardMonitoring();
        this.setupFileUploadMonitoring();
        this.setupAIChatbotMonitoring();
        
        this.reportActivity('MONITORING_STARTED', 'Content monitoring activated');
    }

    stopMonitoring() {
        this.monitoringActive = false;
        this.reportActivity('MONITORING_STOPPED', 'Content monitoring deactivated');
    }

    setupFormMonitoring() {
        document.addEventListener('input', (event) => {
            if (!this.monitoringActive) return;
            
            const element = event.target;
            if (element.type === 'password' || element.type === 'email' || 
                element.name?.toLowerCase().includes('credit') ||
                element.name?.toLowerCase().includes('ssn')) {
                
                this.reportActivity('SENSITIVE_INPUT_DETECTED', 
                    `Sensitive input field detected: ${element.type || element.name}`);
            }
        });

        document.addEventListener('submit', (event) => {
            if (!this.monitoringActive) return;
            
            const form = event.target;
            const sensitiveFields = this.analyzeSensitiveFields(form);
            
            if (sensitiveFields.length > 0) {
                this.reportActivity('FORM_SUBMISSION_DETECTED', 
                    `Form with ${sensitiveFields.length} sensitive fields submitted`);
            }
        });
    }

    setupClipboardMonitoring() {
        document.addEventListener('paste', (event) => {
            if (!this.monitoringActive) return;
            
            const clipboardData = event.clipboardData?.getData('text');
            if (clipboardData && this.containsSensitiveData(clipboardData)) {
                this.reportActivity('SENSITIVE_PASTE_DETECTED', 
                    'Potentially sensitive data pasted');
            }
        });

        document.addEventListener('copy', (event) => {
            if (!this.monitoringActive) return;
            
            const selectedText = window.getSelection().toString();
            if (selectedText && this.containsSensitiveData(selectedText)) {
                this.reportActivity('SENSITIVE_COPY_DETECTED', 
                    'Potentially sensitive data copied');
            }
        });
    }

    setupFileUploadMonitoring() {
        document.addEventListener('change', (event) => {
            if (!this.monitoringActive) return;
            
            const element = event.target;
            if (element.type === 'file' && element.files.length > 0) {
                const files = Array.from(element.files);
                const sensitiveFiles = files.filter(file => 
                    this.isSensitiveFileType(file.name) || file.size > 10 * 1024 * 1024
                );
                
                if (sensitiveFiles.length > 0) {
                    this.reportActivity('FILE_UPLOAD_DETECTED', 
                        `${sensitiveFiles.length} potentially sensitive files selected for upload`);
                }
            }
        });
    }

    setupAIChatbotMonitoring() {
        // Monitor for AI chatbot interfaces
        const aiChatbotSelectors = [
            '[data-testid*="chat"]',
            '[class*="chat"]',
            '[id*="chat"]',
            'textarea[placeholder*="message"]',
            'textarea[placeholder*="ask"]'
        ];

        aiChatbotSelectors.forEach(selector => {
            const elements = document.querySelectorAll(selector);
            elements.forEach(element => {
                element.addEventListener('input', (event) => {
                    if (!this.monitoringActive) return;
                    
                    const text = event.target.value;
                    if (text.length > 100 && this.containsSensitiveData(text)) {
                        this.reportActivity('AI_CHATBOT_SENSITIVE_INPUT', 
                            'Potentially sensitive data entered in AI chatbot');
                    }
                });
            });
        });
    }

    extractPageContent() {
        // Extract text content from page
        const textContent = document.body.innerText || document.body.textContent || '';
        
        // Extract form data
        const forms = Array.from(document.forms);
        const formData = forms.map(form => {
            const inputs = Array.from(form.elements);
            return inputs.map(input => input.value || input.placeholder || '').join(' ');
        }).join(' ');

        return textContent + ' ' + formData;
    }

    analyzeSensitiveFields(form) {
        const sensitiveFields = [];
        const elements = Array.from(form.elements);
        
        elements.forEach(element => {
            const name = (element.name || '').toLowerCase();
            const type = (element.type || '').toLowerCase();
            const placeholder = (element.placeholder || '').toLowerCase();
            
            if (type === 'password' || type === 'email' ||
                name.includes('credit') || name.includes('card') ||
                name.includes('ssn') || name.includes('social') ||
                placeholder.includes('credit') || placeholder.includes('card')) {
                
                sensitiveFields.push({
                    type: element.type,
                    name: element.name,
                    placeholder: element.placeholder
                });
            }
        });
        
        return sensitiveFields;
    }

    containsSensitiveData(text) {
        const sensitivePatterns = [
            /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit card
            /\b\d{3}-\d{2}-\d{4}\b/, // SSN
            /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
            /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/, // Phone
            /\b[A-Za-z0-9]{32,}\b/ // API keys
        ];
        
        return sensitivePatterns.some(pattern => pattern.test(text));
    }

    isSensitiveFileType(filename) {
        const sensitiveExtensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt'];
        const sensitiveKeywords = ['confidential', 'private', 'secret', 'personal', 'financial'];
        
        const extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
        const nameContainsSensitive = sensitiveKeywords.some(keyword => 
            filename.toLowerCase().includes(keyword)
        );
        
        return sensitiveExtensions.includes(extension) || nameContainsSensitive;
    }

    async reportActivity(action, details) {
        try {
            await chrome.runtime.sendMessage({
                action: 'reportActivity',
                activity: {
                    action,
                    details,
                    url: window.location.href,
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            console.error('Failed to report activity:', error);
        }
    }
}

// Initialize content script when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new ContentScriptMonitor();
    });
} else {
    new ContentScriptMonitor();
}