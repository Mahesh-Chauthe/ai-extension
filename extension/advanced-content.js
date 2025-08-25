// Advanced Content Script for Enterprise Security Extension
class AdvancedSecurityMonitor {
  constructor() {
    this.isActive = false
    this.config = null
    this.detectionQueue = []
    this.chatbotPolicies = []
    this.sensitivePatterns = {
      'credit_card': /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
      'ssn': /\b\d{3}-?\d{2}-?\d{4}\b/g,
      'email': /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      'phone': /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
      'api_key': /\b[A-Za-z0-9]{32,}\b/g,
      'jwt_token': /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
      'password': /(?i)\b(password|pwd|pass)\s*[:=]\s*[^\s]+/g,
      'aws_key': /AKIA[0-9A-Z]{16}/g,
      'github_token': /ghp_[a-zA-Z0-9]{36}/g,
      'slack_token': /xox[baprs]-([0-9a-zA-Z]{10,48})?/g,
      'stripe_key': /sk_live_[0-9a-zA-Z]{24}/g,
      'paypal_key': /access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}/g
    }
    
    this.aiChatbots = [
      { name: 'ChatGPT', domains: ['chat.openai.com', 'chatgpt.com'], selectors: ['textarea[data-id]', '#prompt-textarea'] },
      { name: 'Claude', domains: ['claude.ai'], selectors: ['div[contenteditable="true"]'] },
      { name: 'Gemini', domains: ['gemini.google.com', 'bard.google.com'], selectors: ['textarea', 'div[contenteditable="true"]'] },
      { name: 'Bing Chat', domains: ['bing.com'], selectors: ['textarea[class*="input"]'] },
      { name: 'Character.AI', domains: ['character.ai'], selectors: ['textarea'] },
      { name: 'Perplexity', domains: ['perplexity.ai'], selectors: ['textarea'] }
    ]
    
    this.init()
  }

  async init() {
    // Check if user is authenticated
    const authStatus = await chrome.runtime.sendMessage({ action: 'checkAuth' })
    
    if (!authStatus.authenticated) {
      return
    }

    this.isActive = true
    
    // Load configuration
    await this.loadConfig()
    
    // Start monitoring
    this.startMonitoring()
    
    // Check if current site is an AI chatbot
    this.checkAIChatbot()
    
    console.log('Advanced Security Monitor initialized')
  }

  async loadConfig() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'getConfig' })
      this.config = response.config
      this.chatbotPolicies = response.chatbotPolicies || []
    } catch (error) {
      console.error('Failed to load config:', error)
    }
  }

  startMonitoring() {
    // Monitor form inputs
    this.monitorFormInputs()
    
    // Monitor clipboard operations
    this.monitorClipboard()
    
    // Monitor text selection
    this.monitorTextSelection()
    
    // Monitor dynamic content changes
    this.monitorDynamicContent()
    
    // Monitor file uploads
    this.monitorFileUploads()
  }

  monitorFormInputs() {
    // Monitor all input fields
    const inputs = document.querySelectorAll('input, textarea')
    
    inputs.forEach(input => {
      // Real-time monitoring
      input.addEventListener('input', (e) => {
        this.debounce(() => {
          this.analyzeContent(e.target.value, {
            source: 'form_input',
            element: e.target.tagName,
            type: e.target.type,
            name: e.target.name,
            id: e.target.id
          })
        }, 500)()
      })
      
      // Monitor paste events
      input.addEventListener('paste', (e) => {
        setTimeout(() => {
          this.analyzeContent(e.target.value, {
            source: 'paste_input',
            element: e.target.tagName,
            type: e.target.type
          })
        }, 100)
      })
    })
  }

  monitorClipboard() {
    document.addEventListener('copy', (e) => {
      const selectedText = window.getSelection().toString()
      if (selectedText) {
        this.analyzeContent(selectedText, {
          source: 'clipboard_copy',
          action: 'copy'
        })
      }
    })
  }

  monitorTextSelection() {
    document.addEventListener('mouseup', () => {
      const selectedText = window.getSelection().toString()
      if (selectedText && selectedText.length > 10) {
        this.analyzeContent(selectedText, {
          source: 'text_selection',
          length: selectedText.length
        })
      }
    })
  }

  monitorDynamicContent() {
    // Monitor for dynamically added content
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.TEXT_NODE && node.textContent.length > 20) {
              this.analyzeContent(node.textContent, {
                source: 'dynamic_content',
                type: 'text_node'
              })
            } else if (node.nodeType === Node.ELEMENT_NODE) {
              // Check for new input fields
              const newInputs = node.querySelectorAll('input, textarea')
              newInputs.forEach(input => {
                this.monitorSingleInput(input)
              })
            }
          })
        }
      })
    })

    observer.observe(document.body, {
      childList: true,
      subtree: true
    })
  }

  monitorFileUploads() {
    document.addEventListener('change', (e) => {
      if (e.target.type === 'file' && e.target.files.length > 0) {
        Array.from(e.target.files).forEach(file => {
          this.analyzeFileUpload(file, {
            source: 'file_upload',
            fileName: file.name,
            fileSize: file.size,
            fileType: file.type
          })
        })
      }
    })
  }

  checkAIChatbot() {
    const currentDomain = window.location.hostname
    const chatbot = this.aiChatbots.find(bot => 
      bot.domains.some(domain => currentDomain.includes(domain))
    )

    if (chatbot) {
      this.handleAIChatbotDetection(chatbot)
    }
  }

  async handleAIChatbotDetection(chatbot) {
    // Get policy for this chatbot
    const policy = this.chatbotPolicies.find(p => p.chatbot_name === chatbot.name)
    const action = policy ? policy.policy : 'warn'

    // Show warning banner
    this.showChatbotWarning(chatbot, action)

    // Monitor chatbot input fields
    chatbot.selectors.forEach(selector => {
      const elements = document.querySelectorAll(selector)
      elements.forEach(element => {
        this.monitorChatbotInput(element, chatbot)
      })
    })

    // Log chatbot access
    chrome.runtime.sendMessage({
      action: 'logSecurityEvent',
      data: {
        event_type: 'ai_chatbot_access',
        chatbot_name: chatbot.name,
        domain: window.location.hostname,
        action: action,
        url: window.location.href
      }
    })
  }

  monitorChatbotInput(element, chatbot) {
    element.addEventListener('input', (e) => {
      this.debounce(() => {
        this.analyzeContent(e.target.value, {
          source: 'ai_chatbot_input',
          chatbot: chatbot.name,
          element: e.target.tagName
        })
      }, 300)()
    })

    // Monitor before sending
    element.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        this.analyzeChatbotSubmission(e.target.value, chatbot)
      }
    })
  }

  async analyzeChatbotSubmission(content, chatbot) {
    if (!content || content.length < 10) return

    const analysis = await this.analyzeContent(content, {
      source: 'ai_chatbot_submission',
      chatbot: chatbot.name,
      critical: true
    })

    if (analysis && analysis.hasSensitiveData && analysis.riskScore > 0.7) {
      // High risk - potentially block
      const shouldBlock = await this.showBlockDialog(analysis, chatbot)
      if (shouldBlock) {
        // Clear the input
        event.target.value = ''
        event.preventDefault()
        return false
      }
    }
  }

  async analyzeContent(content, metadata = {}) {
    if (!content || content.length < 5) return null

    try {
      // Local quick analysis first
      const quickAnalysis = this.quickAnalyze(content)
      
      if (quickAnalysis.hasSensitiveData) {
        // Send to backend for detailed analysis
        const response = await chrome.runtime.sendMessage({
          action: 'analyzeSensitiveData',
          data: {
            content: content,
            url: window.location.href,
            source: metadata.source || 'content_monitor',
            metadata: metadata
          }
        })

        if (response && response.hasSensitiveData) {
          this.handleSensitiveDataDetection(response, metadata)
          return response
        }
      }
    } catch (error) {
      console.error('Content analysis error:', error)
    }

    return null
  }

  quickAnalyze(content) {
    const detections = []
    
    for (const [type, pattern] of Object.entries(this.sensitivePatterns)) {
      const matches = content.match(pattern)
      if (matches) {
        detections.push({
          type,
          count: matches.length,
          severity: this.getSeverity(type)
        })
      }
    }

    return {
      hasSensitiveData: detections.length > 0,
      detections,
      riskScore: this.calculateRiskScore(detections)
    }
  }

  handleSensitiveDataDetection(analysis, metadata) {
    // Show appropriate warning based on risk level
    if (analysis.riskScore > 0.8) {
      this.showCriticalAlert(analysis, metadata)
    } else if (analysis.riskScore > 0.5) {
      this.showWarningNotification(analysis, metadata)
    } else {
      this.showInfoNotification(analysis, metadata)
    }

    // Add visual indicators
    this.addVisualIndicators(analysis, metadata)
  }

  showChatbotWarning(chatbot, action) {
    const banner = document.createElement('div')
    banner.id = 'security-extension-chatbot-banner'
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: ${action === 'block' ? '#dc2626' : '#f59e0b'};
      color: white;
      padding: 12px;
      text-align: center;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 14px;
      z-index: 10000;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    `
    
    banner.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: center; gap: 10px;">
        <span>🛡️</span>
        <span><strong>Security Monitor:</strong> AI Chatbot detected (${chatbot.name}). ${action === 'block' ? 'Blocked by policy' : 'Please avoid sharing sensitive information'}.</span>
        <button onclick="this.parentElement.parentElement.remove()" style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 4px 8px; border-radius: 4px; cursor: pointer;">×</button>
      </div>
    `
    
    document.body.insertBefore(banner, document.body.firstChild)
    
    // Auto-hide after 10 seconds
    setTimeout(() => {
      if (banner.parentNode) {
        banner.remove()
      }
    }, 10000)
  }

  showCriticalAlert(analysis, metadata) {
    const modal = document.createElement('div')
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.8);
      z-index: 10001;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    `
    
    modal.innerHTML = `
      <div style="background: white; padding: 30px; border-radius: 12px; max-width: 500px; margin: 20px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <div style="font-size: 48px; margin-bottom: 10px;">🚨</div>
          <h2 style="color: #dc2626; margin: 0;">Critical Security Alert</h2>
        </div>
        <p style="margin-bottom: 15px;">Highly sensitive data detected:</p>
        <ul style="margin-bottom: 20px; padding-left: 20px;">
          ${analysis.detections.map(d => `<li>${d.type}: ${d.count} occurrence(s)</li>`).join('')}
        </ul>
        <p style="margin-bottom: 20px; font-weight: bold; color: #dc2626;">
          Risk Score: ${Math.round(analysis.riskScore * 100)}%
        </p>
        <div style="text-align: center;">
          <button onclick="this.closest('div[style*=\"position: fixed\"]').remove()" 
                  style="background: #dc2626; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px;">
            I Understand
          </button>
        </div>
      </div>
    `
    
    document.body.appendChild(modal)
  }

  showWarningNotification(analysis, metadata) {
    this.showNotification('⚠️ Sensitive Data Detected', `Risk: ${Math.round(analysis.riskScore * 100)}%`, '#f59e0b')
  }

  showInfoNotification(analysis, metadata) {
    this.showNotification('ℹ️ Potential Sensitive Data', `Risk: ${Math.round(analysis.riskScore * 100)}%`, '#3b82f6')
  }

  showNotification(title, message, color) {
    const notification = document.createElement('div')
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${color};
      color: white;
      padding: 15px 20px;
      border-radius: 8px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 14px;
      z-index: 10000;
      box-shadow: 0 4px 20px rgba(0,0,0,0.15);
      max-width: 300px;
      animation: slideIn 0.3s ease-out;
    `
    
    notification.innerHTML = `
      <div style="font-weight: bold; margin-bottom: 5px;">${title}</div>
      <div>${message}</div>
    `
    
    // Add animation
    const style = document.createElement('style')
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `
    document.head.appendChild(style)
    
    document.body.appendChild(notification)
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.remove()
      }
    }, 5000)
  }

  async analyzeFileUpload(file, metadata) {
    // Check file type for potential sensitive data
    const sensitiveFileTypes = ['.csv', '.xlsx', '.json', '.sql', '.txt', '.log']
    const isSensitiveType = sensitiveFileTypes.some(type => file.name.toLowerCase().endsWith(type))
    
    if (isSensitiveType) {
      this.showNotification(
        '📁 File Upload Detected', 
        `Uploading ${file.name} - Please ensure no sensitive data`, 
        '#f59e0b'
      )
      
      // Log file upload
      chrome.runtime.sendMessage({
        action: 'logSecurityEvent',
        data: {
          event_type: 'file_upload',
          file_name: file.name,
          file_size: file.size,
          file_type: file.type,
          url: window.location.href,
          ...metadata
        }
      })
    }
  }

  getSeverity(type) {
    const severityMap = {
      'credit_card': 'critical',
      'ssn': 'critical',
      'api_key': 'high',
      'jwt_token': 'high',
      'password': 'high',
      'aws_key': 'critical',
      'github_token': 'high',
      'slack_token': 'high',
      'stripe_key': 'critical',
      'paypal_key': 'critical',
      'email': 'medium',
      'phone': 'medium'
    }
    return severityMap[type] || 'low'
  }

  calculateRiskScore(detections) {
    let score = 0
    detections.forEach(detection => {
      const severityScore = {
        'critical': 25,
        'high': 15,
        'medium': 10,
        'low': 5
      }[detection.severity] || 5
      
      score += detection.count * severityScore
    })
    
    return Math.min(score / 100, 1)
  }

  debounce(func, wait) {
    let timeout
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout)
        func(...args)
      }
      clearTimeout(timeout)
      timeout = setTimeout(later, wait)
    }
  }

  monitorSingleInput(input) {
    input.addEventListener('input', (e) => {
      this.debounce(() => {
        this.analyzeContent(e.target.value, {
          source: 'dynamic_input',
          element: e.target.tagName,
          type: e.target.type
        })
      }, 500)()
    })
  }

  addVisualIndicators(analysis, metadata) {
    // Add subtle visual indicators for detected sensitive data
    if (metadata.element) {
      const element = document.activeElement
      if (element && (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA')) {
        element.style.borderLeft = `3px solid ${analysis.riskScore > 0.7 ? '#dc2626' : '#f59e0b'}`
      }
    }
  }
}

// Initialize the security monitor
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new AdvancedSecurityMonitor()
  })
} else {
  new AdvancedSecurityMonitor()
}