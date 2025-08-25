class ContentScriptMonitor {
    constructor() {
        this.isAuthenticated = false;
        this.organizationData = null;
        this.userData = null;
        this.monitoringActive = false;
        this.settings = {
            enableNotifications: true,
            enableChatbotMonitoring: true,
            enableFormMonitoring: true,
            sensitivityLevel: 'medium'
        };
        this.chatbotSelectors = {
            'ChatGPT': ['[data-testid="send-button"]', 'textarea[placeholder*="message"]', '#prompt-textarea'],
            'Claude': ['[data-testid="send-button"]', 'div[contenteditable="true"]'],
            'Gemini': ['button[aria-label*="Send"]', 'textarea[placeholder*="Enter a prompt"]'],
            'Copilot': ['button[aria-label*="Submit"]', 'textarea[placeholder*="Ask me anything"]'],
            'Perplexity': ['button[aria-label*="Submit"]', 'textarea[placeholder*="Ask anything"]']
        };
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
                action: 'getAuthData'
            });
            
            if (response && response.organization) {
                this.isAuthenticated = true;
                this.organizationData = response.organization;
                this.userData = response.user;
                this.settings = response.settings || this.settings;
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

            case 'authenticated':
                this.isAuthenticated = true;
                this.organizationData = message.data.organization;
                this.userData = message.data.user;
                this.settings = message.data.settings;
                this.startMonitoring();
                sendResponse({ success: true });
                break;

            case 'logout':
                this.isAuthenticated = false;
                this.stopMonitoring();
                sendResponse({ success: true });
                break;

            case 'settingsUpdated':
                this.settings = message.data;
                this.updateMonitoring();
                sendResponse({ success: true });
                break;
        }
    }

    startMonitoring() {
        if (this.monitoringActive || !this.isAuthenticated) return;
        
        this.monitoringActive = true;
        
        if (this.settings.enableFormMonitoring) {
            this.setupFormMonitoring();
            this.setupClipboardMonitoring();
            this.setupFileUploadMonitoring();
        }
        
        if (this.settings.enableChatbotMonitoring) {
            this.setupAIChatbotMonitoring();
        }
        
        this.reportActivity('MONITORING_STARTED', 'Content monitoring activated');
        console.log('Enterprise Security: Monitoring started');
    }

    stopMonitoring() {
        this.monitoringActive = false;
        this.reportActivity('MONITORING_STOPPED', 'Content monitoring deactivated');
        console.log('Enterprise Security: Monitoring stopped');
    }

    updateMonitoring() {
        if (this.monitoringActive) {
            this.stopMonitoring();
            this.startMonitoring();
        }
    }

    setupFormMonitoring() {
        // Monitor input events
        document.addEventListener('input', (event) => {
            if (!this.monitoringActive) return;
            
            const element = event.target;
            if (this.isSensitiveField(element)) {
                const sensitiveData = this.analyzeSensitiveContent(element.value);
                
                if (sensitiveData.length > 0) {
                    this.handleSensitiveDataDetection(sensitiveData[0], element);
                }
            }
        }, true);

        // Monitor form submissions
        document.addEventListener('submit', (event) => {
            if (!this.monitoringActive) return;
            
            const form = event.target;
            const sensitiveFields = this.analyzeSensitiveFields(form);
            
            if (sensitiveFields.length > 0) {
                // Show warning modal
                if (this.shouldBlockSubmission(sensitiveFields)) {
                    event.preventDefault();
                    this.showSensitiveDataWarning(sensitiveFields, () => {
                        form.submit();
                    });
                }
                
                this.reportActivity('FORM_SUBMISSION_DETECTED', 
                    `Form with ${sensitiveFields.length} sensitive fields submitted`);
            }
        }, true);
    }

    setupClipboardMonitoring() {
        // Monitor paste events
        document.addEventListener('paste', (event) => {
            if (!this.monitoringActive) return;
            
            const clipboardData = event.clipboardData?.getData('text');
            if (clipboardData) {
                const sensitiveData = this.analyzeSensitiveContent(clipboardData);
                
                if (sensitiveData.length > 0) {
                    this.reportActivity('SENSITIVE_PASTE_DETECTED', 
                        `Potentially sensitive data pasted: ${sensitiveData[0].type}`);
                    
                    chrome.runtime.sendMessage({
                        action: 'sensitiveDataDetected',
                        data: sensitiveData[0]
                    });
                }
            }
        }, true);

        // Monitor copy events
        document.addEventListener('copy', (event) => {
            if (!this.monitoringActive) return;
            
            const selectedText = window.getSelection().toString();
            if (selectedText) {
                const sensitiveData = this.analyzeSensitiveContent(selectedText);
                
                if (sensitiveData.length > 0) {
                    this.reportActivity('SENSITIVE_COPY_DETECTED', 
                        `Potentially sensitive data copied: ${sensitiveData[0].type}`);
                }
            }
        }, true);
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
                    
                    chrome.runtime.sendMessage({
                        action: 'sensitiveDataDetected',
                        data: {
                            type: 'File Upload',
                            description: `${sensitiveFiles.length} sensitive files selected`,
                            files: sensitiveFiles.map(f => f.name)
                        }
                    });
                }
            }
        }, true);
    }

    setupAIChatbotMonitoring() {
        // Detect chatbot interfaces
        const chatbotDetected = this.detectChatbotInterface();
        
        if (chatbotDetected) {
            console.log(`Enterprise Security: Detected ${chatbotDetected} interface`);
            this.monitorChatbotInputs(chatbotDetected);
        }
        
        // Monitor for dynamically loaded chatbot interfaces
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.addedNodes.length > 0) {
                    const chatbot = this.detectChatbotInterface();
                    if (chatbot && !this.chatbotMonitored) {
                        this.monitorChatbotInputs(chatbot);
                    }
                }
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    detectChatbotInterface() {
        for (const [chatbot, selectors] of Object.entries(this.chatbotSelectors)) {
            for (const selector of selectors) {
                if (document.querySelector(selector)) {
                    return chatbot;
                }
            }
        }
        
        // Generic detection
        const chatbotKeywords = ['chat', 'ai', 'assistant', 'bot'];
        const title = document.title.toLowerCase();
        const url = window.location.hostname.toLowerCase();
        
        for (const keyword of chatbotKeywords) {
            if (title.includes(keyword) || url.includes(keyword)) {
                return 'AI Chatbot';
            }
        }
        
        return null;
    }

    monitorChatbotInputs(chatbotName) {
        if (this.chatbotMonitored) return;
        this.chatbotMonitored = true;
        
        // Monitor all text inputs and contenteditable elements
        const inputSelectors = [
            'textarea',
            'input[type="text"]',
            '[contenteditable="true"]',
            '[role="textbox"]'
        ];
        
        inputSelectors.forEach(selector => {
            document.addEventListener('input', (event) => {
                if (!this.monitoringActive) return;
                
                const element = event.target;
                if (element.matches && element.matches(selector)) {
                    const text = element.value || element.textContent || element.innerText;
                    
                    if (text.length > 50) { // Only check substantial inputs
                        const sensitiveData = this.analyzeSensitiveContent(text);
                        
                        if (sensitiveData.length > 0) {
                            this.handleChatbotSensitiveData(sensitiveData, chatbotName, element);
                        }
                    }
                }
            }, true);
        });
        
        // Monitor send button clicks
        document.addEventListener('click', (event) => {
            if (!this.monitoringActive) return;
            
            const element = event.target;
            const isSendButton = this.isChatbotSendButton(element);
            
            if (isSendButton) {
                const inputElement = this.findChatbotInput();
                if (inputElement) {
                    const text = inputElement.value || inputElement.textContent || inputElement.innerText;
                    const sensitiveData = this.analyzeSensitiveContent(text);
                    
                    if (sensitiveData.length > 0) {
                        event.preventDefault();
                        event.stopPropagation();
                        
                        this.showChatbotWarning(sensitiveData, chatbotName, () => {
                            // User confirmed, allow the action
                            element.click();
                        });
                        
                        return false;
                    }
                }
            }
        }, true);
    }

    isChatbotSendButton(element) {
        const sendKeywords = ['send', 'submit', 'post', 'ask'];
        const ariaLabel = (element.getAttribute('aria-label') || '').toLowerCase();
        const buttonText = (element.textContent || '').toLowerCase();
        const className = (element.className || '').toLowerCase();
        
        return sendKeywords.some(keyword => 
            ariaLabel.includes(keyword) || 
            buttonText.includes(keyword) || 
            className.includes(keyword)
        ) || element.type === 'submit';
    }

    findChatbotInput() {
        const selectors = [
            'textarea:focus',
            '[contenteditable="true"]:focus',
            'textarea[placeholder*="message"]',
            'textarea[placeholder*="ask"]',
            '[contenteditable="true"]'
        ];
        
        for (const selector of selectors) {
            const element = document.querySelector(selector);
            if (element) return element;
        }
        
        return null;
    }

    handleChatbotSensitiveData(sensitiveData, chatbotName, element) {
        // Highlight the sensitive content
        this.highlightSensitiveContent(element);
        
        // Report to background
        chrome.runtime.sendMessage({
            action: 'sensitiveDataDetected',
            data: {
                type: `${chatbotName} Input`,
                description: `${sensitiveData[0].type} detected in ${chatbotName}`,
                chatbot: chatbotName
            }
        });
        
        this.reportActivity('AI_CHATBOT_SENSITIVE_INPUT', 
            `${sensitiveData[0].type} detected in ${chatbotName} input`);
    }

    showChatbotWarning(sensitiveData, chatbotName, onConfirm) {
        const modal = this.createWarningModal(
            `⚠️ Sensitive Data Warning`,
            `You're about to send sensitive information (${sensitiveData[0].type}) to ${chatbotName}. This may violate your organization's security policy.`,
            [
                {
                    text: 'Send Anyway',
                    class: 'btn-danger',
                    action: () => {
                        chrome.runtime.sendMessage({
                            action: 'chatbotBlocked',
                            data: {
                                type: sensitiveData[0].type,
                                chatbot: chatbotName,
                                action: 'allowed'
                            }
                        });
                        onConfirm();
                        this.removeModal(modal);
                    }
                },
                {
                    text: 'Cancel',
                    class: 'btn-secondary',
                    action: () => {
                        chrome.runtime.sendMessage({
                            action: 'chatbotBlocked',
                            data: {
                                type: sensitiveData[0].type,
                                chatbot: chatbotName,
                                action: 'blocked'
                            }
                        });
                        this.removeModal(modal);
                    }
                }
            ]
        );
    }

    showSensitiveDataWarning(sensitiveFields, onConfirm) {
        const fieldList = sensitiveFields.map(f => f.type).join(', ');
        
        const modal = this.createWarningModal(
            `🔒 Sensitive Data Detected`,
            `This form contains sensitive information: ${fieldList}. Are you sure you want to submit?`,
            [
                {
                    text: 'Submit Anyway',
                    class: 'btn-danger',
                    action: () => {
                        onConfirm();
                        this.removeModal(modal);
                    }
                },
                {
                    text: 'Cancel',
                    class: 'btn-secondary',
                    action: () => {
                        this.removeModal(modal);
                    }
                }
            ]
        );
    }

    createWarningModal(title, message, buttons) {
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
        `;
        
        const content = document.createElement('div');
        content.style.cssText = `
            background: white;
            padding: 2rem;
            border-radius: 12px;
            max-width: 500px;
            margin: 2rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        `;
        
        content.innerHTML = `
            <h3 style="margin-bottom: 1rem; color: #dc2626; font-size: 1.2rem;">${title}</h3>
            <p style="margin-bottom: 2rem; line-height: 1.5; color: #374151;">${message}</p>
            <div style="display: flex; gap: 1rem; justify-content: flex-end;">
                ${buttons.map((btn, i) => `
                    <button id="modal-btn-${i}" style="
                        padding: 0.75rem 1.5rem;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: 600;
                        ${btn.class === 'btn-danger' ? 'background: #dc2626; color: white;' : 'background: #6b7280; color: white;'}
                    ">${btn.text}</button>
                `).join('')}
            </div>
        `;
        
        modal.appendChild(content);
        document.body.appendChild(modal);
        
        // Bind button events
        buttons.forEach((btn, i) => {
            const buttonElement = content.querySelector(`#modal-btn-${i}`);
            buttonElement.addEventListener('click', btn.action);
        });
        
        return modal;
    }

    removeModal(modal) {
        if (modal && modal.parentNode) {
            modal.parentNode.removeChild(modal);
        }
    }

    highlightSensitiveContent(element) {
        element.style.border = '2px solid #dc2626';
        element.style.backgroundColor = '#fef2f2';
        
        setTimeout(() => {
            element.style.border = '';
            element.style.backgroundColor = '';
        }, 3000);
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

    isSensitiveField(element) {
        const name = (element.name || '').toLowerCase();
        const type = (element.type || '').toLowerCase();
        const placeholder = (element.placeholder || '').toLowerCase();
        const id = (element.id || '').toLowerCase();
        
        const sensitiveKeywords = [
            'password', 'pwd', 'pass',
            'credit', 'card', 'ccn', 'cvv',
            'ssn', 'social', 'security',
            'bank', 'account', 'routing',
            'api', 'key', 'token', 'secret'
        ];
        
        return type === 'password' || 
               type === 'email' ||
               sensitiveKeywords.some(keyword => 
                   name.includes(keyword) || 
                   placeholder.includes(keyword) || 
                   id.includes(keyword)
               );
    }

    analyzeSensitiveFields(form) {
        const sensitiveFields = [];
        const elements = Array.from(form.elements);
        
        elements.forEach(element => {
            if (this.isSensitiveField(element) && element.value) {
                const sensitiveData = this.analyzeSensitiveContent(element.value);
                
                if (sensitiveData.length > 0) {
                    sensitiveFields.push({
                        element: element,
                        type: sensitiveData[0].type,
                        field: element.name || element.id || 'unknown'
                    });
                }
            }
        });
        
        return sensitiveFields;
    }

    analyzeSensitiveContent(text) {
        const patterns = [
            {
                name: 'Credit Card Number',
                regex: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g,
                severity: 'high'
            },
            {
                name: 'Social Security Number',
                regex: /\b\d{3}-\d{2}-\d{4}\b/g,
                severity: 'high'
            },
            {
                name: 'Email Address',
                regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
                severity: 'medium'
            },
            {
                name: 'Phone Number',
                regex: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
                severity: 'medium'
            },
            {
                name: 'API Key',
                regex: /\b[A-Za-z0-9]{32,}\b/g,
                severity: 'critical'
            },
            {
                name: 'JWT Token',
                regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
                severity: 'critical'
            }
        ];
        
        const results = [];
        
        patterns.forEach(pattern => {
            const matches = text.match(pattern.regex);
            if (matches) {
                results.push({
                    type: pattern.name,
                    matches: matches,
                    count: matches.length,
                    severity: pattern.severity
                });
            }
        });
        
        return results;
    }

    shouldBlockSubmission(sensitiveFields) {
        // Block if any critical severity fields are found
        return sensitiveFields.some(field => 
            field.type.includes('API Key') || 
            field.type.includes('JWT Token') ||
            field.type.includes('Credit Card')
        );
    }

    isSensitiveFileType(filename) {
        const sensitiveExtensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt', '.zip'];
        const sensitiveKeywords = ['confidential', 'private', 'secret', 'personal', 'financial', 'backup'];
        
        const extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
        const nameContainsSensitive = sensitiveKeywords.some(keyword => 
            filename.toLowerCase().includes(keyword)
        );
        
        return sensitiveExtensions.includes(extension) || nameContainsSensitive;
    }

    async reportActivity(action, details) {
        try {
            await chrome.runtime.sendMessage({
                action: 'logActivity',
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