// Enhanced background script with AI chatbot detection and S3 integration
const chrome = window.chrome

class ExtensionBackgroundService {
  constructor() {
    this.apiBaseUrl = 'https://api.extension-system.com'
    this.isAuthenticated = false
    this.userConfig = null
    this.s3Config = null
    
    this.init()
  }

  async init() {
    // Listen for extension installation
    chrome.runtime.onInstalled.addListener((details) => {
      if (details.reason === 'install') {
        this.handleFirstInstall()
      }
    })

    // Listen for messages from content scripts
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse)
      return true // Keep message channel open for async responses
    })

    // Initialize authentication check
    await this.checkAuthentication()
  }

  async handleFirstInstall() {
    // Open onboarding page
    chrome.tabs.create({
      url: chrome.runtime.getURL('onboarding.html')
    })
  }

  async handleMessage(request, sender, sendResponse) {
    try {
      switch (request.action) {
        case 'checkAuth':
          const authStatus = await this.checkAuthentication()
          sendResponse({ authenticated: authStatus })
          break

        case 'analyzeSensitiveData':
          const analysis = await this.analyzeSensitiveData(request.data)
          sendResponse(analysis)
          break

        case 'logSecurityEvent':
          await this.logSecurityEvent(request.data)
          sendResponse({ success: true })
          break

        case 'uploadToS3':
          const uploadResult = await this.uploadToS3(request.data)
          sendResponse(uploadResult)
          break

        case 'getAIChatbotList':
          const chatbots = await this.getAIChatbotList()
          sendResponse({ chatbots })
          break

        default:
          sendResponse({ error: 'Unknown action' })
      }
    } catch (error) {
      console.error('Background script error:', error)
      sendResponse({ error: error.message })
    }
  }

  async checkAuthentication() {
    try {
      const stored = await chrome.storage.local.get(['authToken', 'userConfig'])
      
      if (!stored.authToken) {
        this.isAuthenticated = false
        return false
      }

      // Validate token with backend
      const response = await fetch(`${this.apiBaseUrl}/api/auth/validate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${stored.authToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const data = await response.json()
        this.isAuthenticated = true
        this.userConfig = data.user
        return true
      } else {
        // Token invalid, clear storage
        await chrome.storage.local.remove(['authToken', 'userConfig'])
        this.isAuthenticated = false
        return false
      }
    } catch (error) {
      console.error('Auth check error:', error)
      this.isAuthenticated = false
      return false
    }
  }

  async analyzeSensitiveData(data) {
    try {
      const stored = await chrome.storage.local.get(['authToken'])
      
      if (!stored.authToken) {
        throw new Error('Not authenticated')
      }

      // Enhanced analysis for AI chatbots
      const analysisPayload = {
        ...data,
        userAgent: navigator.userAgent,
        timestamp: new Date().toISOString(),
        extensionVersion: chrome.runtime.getManifest().version
      }

      const response = await fetch(`${this.apiBaseUrl}/api/analyze/sensitive-data`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${stored.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(analysisPayload)
      })

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`)
      }

      const analysis = await response.json()

      // If high-risk content detected, store evidence in S3
      if (analysis.riskScore > 0.7) {
        await this.storeEvidenceInS3({
          analysis,
          content: data.content,
          metadata: {
            url: data.url,
            source: data.source,
            timestamp: new Date().toISOString(),
            userId: this.userConfig?.id,
            organizationId: this.userConfig?.organization?.id
          }
        })
      }

      return analysis
    } catch (error) {
      console.error('Sensitive data analysis error:', error)
      return {
        hasSensitiveData: false,
        error: error.message
      }
    }
  }

  async logSecurityEvent(eventData) {
    try {
      const stored = await chrome.storage.local.get(['authToken'])
      
      if (!stored.authToken) {
        return
      }

      await fetch(`${this.apiBaseUrl}/api/security/events`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${stored.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ...eventData,
          extensionVersion: chrome.runtime.getManifest().version,
          userAgent: navigator.userAgent
        })
      })
    } catch (error) {
      console.error('Security event logging error:', error)
    }
  }

  async storeEvidenceInS3(evidenceData) {
    try {
      const stored = await chrome.storage.local.get(['authToken'])
      
      if (!stored.authToken) {
        return
      }

      // Get S3 upload URL from backend
      const response = await fetch(`${this.apiBaseUrl}/api/storage/upload-url`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${stored.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: 'security_evidence',
          contentType: 'application/json'
        })
      })

      if (!response.ok) {
        throw new Error('Failed to get upload URL')
      }

      const { uploadUrl, key } = await response.json()

      // Upload evidence to S3
      const uploadResponse = await fetch(uploadUrl, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(evidenceData)
      })

      if (uploadResponse.ok) {
        console.log('Evidence stored in S3:', key)
        
        // Notify backend about successful upload
        await fetch(`${this.apiBaseUrl}/api/storage/upload-complete`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${stored.authToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            key,
            type: 'security_evidence',
            metadata: evidenceData.metadata
          })
        })
      }
    } catch (error) {
      console.error('S3 storage error:', error)
    }
  }

  async getAIChatbotList() {
    try {
      const stored = await chrome.storage.local.get(['authToken'])
      
      if (!stored.authToken) {
        return []
      }

      const response = await fetch(`${this.apiBaseUrl}/api/config/ai-chatbots`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${stored.authToken}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        return data.chatbots || []
      }
    } catch (error) {
      console.error('AI chatbot list error:', error)
    }

    // Fallback to default list
    return [
      { name: 'ChatGPT', domain: 'chat.openai.com', riskLevel: 'high' },
      { name: 'Claude', domain: 'claude.ai', riskLevel: 'high' },
      { name: 'Bard/Gemini', domain: 'bard.google.com', riskLevel: 'medium' },
      { name: 'Bing Chat', domain: 'bing.com', riskLevel: 'medium' },
      { name: 'Character.AI', domain: 'character.ai', riskLevel: 'low' },
      { name: 'Perplexity', domain: 'perplexity.ai', riskLevel: 'medium' }
    ]
  }

  async uploadToS3(data) {
    try {
      const stored = await chrome.storage.local.get(['authToken'])
      
      if (!stored.authToken) {
        throw new Error('Not authenticated')
      }

      // Get presigned URL from backend
      const response = await fetch(`${this.apiBaseUrl}/api/storage/upload-url`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${stored.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: data.type || 'general',
          contentType: data.contentType || 'application/octet-stream',
          filename: data.filename
        })
      })

      if (!response.ok) {
        throw new Error('Failed to get upload URL')
      }

      const { uploadUrl, key } = await response.json()

      // Upload file to S3
      const uploadResponse = await fetch(uploadUrl, {
        method: 'PUT',
        headers: {
          'Content-Type': data.contentType || 'application/octet-stream'
        },
        body: data.content
      })

      if (uploadResponse.ok) {
        return {
          success: true,
          key: key,
          url: uploadUrl.split('?')[0] // Remove query parameters
        }
      } else {
        throw new Error('Upload failed')
      }
    } catch (error) {
      console.error('S3 upload error:', error)
      return {
        success: false,
        error: error.message
      }
    }
  }
}

// Initialize background service
const backgroundService = new ExtensionBackgroundService()

// Context menu for quick actions
chrome.contextMenus.create({
  id: 'analyze-selection',
  title: 'Analyze Selected Text for Sensitive Data',
  contexts: ['selection']
})

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'analyze-selection') {
    // Inject content script to analyze selected text
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      function: () => {
        const selectedText = window.getSelection().toString()
        if (selectedText) {
          chrome.runtime.sendMessage({
            action: 'analyzeSensitiveData',
            data: {
              content: selectedText,
              url: window.location.href,
              source: 'context_menu_selection'
            }
          })
        }
      }
    })
  }
})

// Periodic cleanup of stored data
setInterval(async () => {
  try {
    const stored = await chrome.storage.local.get()
    const now = Date.now()
    const oneWeek = 7 * 24 * 60 * 60 * 1000

    // Clean up old cached data
    Object.keys(stored).forEach(key => {
      if (key.startsWith('cache_') && stored[key].timestamp) {
        if (now - stored[key].timestamp > oneWeek) {
          chrome.storage.local.remove(key)
        }
      }
    })
  } catch (error) {
    console.error('Cleanup error:', error)
  }
}, 24 * 60 * 60 * 1000) // Run daily