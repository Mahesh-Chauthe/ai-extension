// Content script for sensitive data detection
const chrome = window.chrome // Declare the chrome variable

class SensitiveDataDetector {
  constructor() {
    this.isMonitoring = false
    this.debounceTimer = null
    this.lastAnalyzedContent = ""
    this.aiChatbotSelectors = [
      // ChatGPT
      'textarea[placeholder*="Message ChatGPT"]',
      'div[contenteditable="true"][data-id*="root"]',
      // Claude
      'div[contenteditable="true"][data-testid="chat-input"]',
      // Bard/Gemini
      'div[contenteditable="true"][aria-label*="Enter a prompt"]',
      // Bing Chat
      'textarea[placeholder*="Ask me anything"]',
      // Character.AI
      'textarea[placeholder*="Type a message"]',
      // Perplexity
      'textarea[placeholder*="Ask anything"]',
      // Generic AI chat patterns
      'textarea[placeholder*="chat"]',
      'textarea[placeholder*="ask"]',
      'div[contenteditable="true"][class*="chat"]',
      'div[contenteditable="true"][class*="input"]'
    ]
    this.sensitivePatterns = {
      credentials: {
        patterns: [
          /(?:password|pwd|pass)\s*[:=]\s*\S+/gi,
          /(?:username|user|login)\s*[:=]\s*\S+/gi,
          /(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*[\w\-\.]+/gi,
          /(?:secret|private[_-]?key)\s*[:=]\s*[\w\-\.]+/gi
        ],
        severity: 'critical'
      },
      financial: {
        patterns: [
          /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, // Credit cards
          /\b\d{3}-\d{2}-\d{4}\b/g, // SSN
          /\b\d{9}\b/g, // Bank routing
          /\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?/g // Currency amounts
        ],
        severity: 'high'
      },
      personal: {
        patterns: [
          /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email
          /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, // Phone
          /\b\d{1,5}\s\w+\s(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)\b/gi // Address
        ],
        severity: 'medium'
      },
      technical: {
        patterns: [
          /\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, // IP addresses
          /\b[A-Fa-f0-9]{32,}\b/g, // Hashes/tokens
          /(?:https?:\/\/)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&=]*)/g // URLs
        ],
        severity: 'low'
      }
    }

    this.init()
  }

  async init() {
    // Check if user is authenticated and has permissions
    const response = await chrome.runtime.sendMessage({ action: "checkAuth" })
    if (response.authenticated) {
      this.startMonitoring()
    }

    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      switch (request.action) {
        case "blockSensitiveContent":
          this.blockSensitiveContent(request.data)
          break
        case "startMonitoring":
          this.startMonitoring()
          break
        case "stopMonitoring":
          this.stopMonitoring()
          break
      }
    })
  }

  startMonitoring() {
    if (this.isMonitoring) return

    this.isMonitoring = true

    // Monitor form inputs
    this.monitorFormInputs()

    // Monitor text areas and contenteditable elements
    this.monitorTextAreas()

    // Monitor clipboard operations
    this.monitorClipboard()

    // Monitor dynamic content changes
    this.monitorDynamicContent()
  }

  stopMonitoring() {
    this.isMonitoring = false
    // Remove event listeners if needed
  }

  monitorFormInputs() {
    const inputs = document.querySelectorAll('input[type="text"], input[type="email"], input[type="password"]')

    inputs.forEach((input) => {
      input.addEventListener("blur", (e) => {
        this.analyzeContent(e.target.value, "form_input")
      })

      input.addEventListener("paste", (e) => {
        setTimeout(() => {
          this.analyzeContent(e.target.value, "paste_input")
        }, 100)
      })
    })
  }

  monitorTextAreas() {
    const textAreas = document.querySelectorAll('textarea, [contenteditable="true"]')

    textAreas.forEach((element) => {
      element.addEventListener("input", (e) => {
        clearTimeout(this.debounceTimer)
        this.debounceTimer = setTimeout(() => {
          const content = element.value || element.textContent
          this.analyzeContent(content, "text_area")
        }, 1000) // Debounce for 1 second
      })
    })
  }

  monitorClipboard() {
    document.addEventListener("paste", async (e) => {
      try {
        const clipboardData = e.clipboardData || window.clipboardData
        const pastedData = clipboardData.getData("text")

        if (pastedData && pastedData.length > 10) {
          await this.analyzeContent(pastedData, "clipboard")
        }
      } catch (error) {
        console.error("Clipboard monitoring error:", error)
      }
    })
  }

  monitorDynamicContent() {
    // Monitor for dynamically added content
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === "childList") {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.TEXT_NODE && node.textContent.length > 50) {
              this.analyzeContent(node.textContent, "dynamic_content")
            }
          })
        }
      })
    })

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    })
  }

  async analyzeContent(content, source) {
    if (!content || content.length < 10 || content === this.lastAnalyzedContent) {
      return
    }

    this.lastAnalyzedContent = content

    try {
      const analysis = await chrome.runtime.sendMessage({
        action: "analyzeSensitiveData",
        data: {
          content: content,
          url: window.location.href,
          source: source,
        },
      })

      if (analysis && analysis.hasSensitiveData) {
        this.handleSensitiveDataDetection(analysis, source)
      }
    } catch (error) {
      console.error("Content analysis error:", error)
    }
  }

  handleSensitiveDataDetection(analysis, source) {
    // Create visual warning
    this.showSensitiveDataWarning(analysis)

    // Log detection
    console.warn("Sensitive data detected:", {
      riskScore: analysis.riskScore,
      detections: analysis.detections,
      source: source,
      action: analysis.action,
    })

    // Apply restrictions based on risk level
    if (analysis.action === "block") {
      this.blockSensitiveContent(analysis)
    } else if (analysis.action === "warn") {
      this.warnSensitiveContent(analysis)
    }
  }

  showSensitiveDataWarning(analysis) {
    // Remove existing warnings
    const existingWarnings = document.querySelectorAll(".sensitive-data-warning")
    existingWarnings.forEach((warning) => warning.remove())

    // Create warning banner
    const warning = document.createElement("div")
    warning.className = "sensitive-data-warning"
    warning.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: ${analysis.action === "block" ? "#dc3545" : "#ffc107"};
      color: ${analysis.action === "block" ? "white" : "#212529"};
      padding: 12px 20px;
      text-align: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      font-weight: 500;
      z-index: 10000;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      border-bottom: 3px solid ${analysis.action === "block" ? "#c82333" : "#e0a800"};
    `

    const riskLevel = analysis.aiAnalysis.riskLevel || "medium"
    const detectionCount = analysis.detections.length

    warning.innerHTML = `
      <strong>⚠️ Sensitive Data Detected</strong> - 
      Risk Level: ${riskLevel.toUpperCase()} | 
      ${detectionCount} pattern(s) found | 
      ${analysis.action === "block" ? "Content blocked for security" : "Please review before sharing"}
      <button onclick="this.parentElement.remove()" style="
        background: none;
        border: none;
        color: inherit;
        font-size: 18px;
        float: right;
        cursor: pointer;
        padding: 0;
        margin-left: 15px;
      ">×</button>
    `

    document.body.insertBefore(warning, document.body.firstChild)

    // Auto-remove warning after 10 seconds for non-critical issues
    if (analysis.action !== "block") {
      setTimeout(() => {
        if (warning.parentElement) {
          warning.remove()
        }
      }, 10000)
    }
  }

  blockSensitiveContent(analysis) {
    // Create overlay to block content
    const overlay = document.createElement("div")
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(220, 53, 69, 0.95);
      color: white;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      z-index: 999999;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `

    overlay.innerHTML = `
      <div style="text-align: center; max-width: 500px; padding: 40px;">
        <h1 style="font-size: 48px; margin-bottom: 20px;">🚫</h1>
        <h2 style="margin-bottom: 20px;">Content Blocked</h2>
        <p style="font-size: 18px; line-height: 1.6; margin-bottom: 30px;">
          Critical sensitive data has been detected on this page. 
          Access has been restricted for security purposes.
        </p>
        <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px; margin-bottom: 30px;">
          <strong>Risk Level:</strong> ${(analysis.aiAnalysis.riskLevel || "critical").toUpperCase()}<br>
          <strong>Detections:</strong> ${analysis.detections.length} pattern(s)<br>
          <strong>Organization:</strong> ${analysis.organization || "Unknown"}
        </div>
        <button onclick="window.history.back()" style="
          background: white;
          color: #dc3545;
          border: none;
          padding: 12px 24px;
          border-radius: 6px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          margin-right: 10px;
        ">Go Back</button>
        <button onclick="this.parentElement.parentElement.remove()" style="
          background: transparent;
          color: white;
          border: 2px solid white;
          padding: 10px 22px;
          border-radius: 6px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
        ">Override (Admin)</button>
      </div>
    `

    document.body.appendChild(overlay)
  }

  warnSensitiveContent(analysis) {
    // Add visual indicators to potentially sensitive elements
    const inputs = document.querySelectorAll('input, textarea, [contenteditable="true"]')

    inputs.forEach((element) => {
      const content = element.value || element.textContent || ""
      if (content && this.containsSensitiveData(content, analysis)) {
        element.style.border = "2px solid #ffc107"
        element.style.boxShadow = "0 0 5px rgba(255, 193, 7, 0.5)"

        // Add tooltip
        element.title = "Warning: This field may contain sensitive data"
      }
    })
  }

  containsSensitiveData(content, analysis) {
    // Simple check if content matches any detected patterns
    return analysis.detections.some((detection) => {
      // This is a simplified check - in practice, you'd want more sophisticated matching
      return content.toLowerCase().includes(detection.name.toLowerCase())
    })
  }
}

// Initialize sensitive data detector
const sensitiveDataDetector = new SensitiveDataDetector()
