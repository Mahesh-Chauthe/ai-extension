// Local sensitive data analyzer - no external APIs required
class LocalSensitiveDataAnalyzer {
  constructor() {
    this.patterns = {
      credentials: {
        patterns: [
          { regex: /(?:password|pwd|pass)\s*[:=]\s*\S+/gi, name: 'Password', severity: 'critical' },
          { regex: /(?:username|user|login)\s*[:=]\s*\S+/gi, name: 'Username', severity: 'high' },
          { regex: /(?:api[_-]?key|apikey)\s*[:=]\s*[\w\-\.]+/gi, name: 'API Key', severity: 'critical' },
          { regex: /(?:access[_-]?token|bearer)\s*[:=]?\s*[\w\-\.]+/gi, name: 'Access Token', severity: 'critical' },
          { regex: /(?:secret|private[_-]?key)\s*[:=]\s*[\w\-\.]+/gi, name: 'Secret Key', severity: 'critical' },
          { regex: /(?:client[_-]?secret)\s*[:=]\s*[\w\-\.]+/gi, name: 'Client Secret', severity: 'critical' }
        ],
        weight: 1.0
      },
      financial: {
        patterns: [
          { regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, name: 'Credit Card', severity: 'critical' },
          { regex: /\b\d{3}-\d{2}-\d{4}\b/g, name: 'SSN', severity: 'critical' },
          { regex: /\b\d{9}\b/g, name: 'Bank Routing', severity: 'high' },
          { regex: /\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?/g, name: 'Currency Amount', severity: 'medium' },
          { regex: /\b(?:IBAN|iban)\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{1,23}\b/gi, name: 'IBAN', severity: 'high' }
        ],
        weight: 0.9
      },
      personal: {
        patterns: [
          { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, name: 'Email Address', severity: 'medium' },
          { regex: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g, name: 'Phone Number', severity: 'medium' },
          { regex: /\b\d{1,5}\s\w+\s(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)\b/gi, name: 'Street Address', severity: 'medium' },
          { regex: /\b(?:DOB|Date of Birth|Birthday):\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/gi, name: 'Date of Birth', severity: 'high' }
        ],
        weight: 0.6
      },
      technical: {
        patterns: [
          { regex: /\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, name: 'IP Address', severity: 'low' },
          { regex: /\b[A-Fa-f0-9]{32,}\b/g, name: 'Hash/Token', severity: 'medium' },
          { regex: /(?:https?:\/\/)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&=]*)/g, name: 'URL', severity: 'low' },
          { regex: /-----BEGIN [A-Z\s]+-----[\s\S]*?-----END [A-Z\s]+-----/g, name: 'Private Key/Certificate', severity: 'critical' }
        ],
        weight: 0.4
      },
      medical: {
        patterns: [
          { regex: /\b(?:medical record|patient id|mrn)\s*[:=]?\s*\w+/gi, name: 'Medical Record', severity: 'high' },
          { regex: /\b(?:diagnosis|condition|medication|prescription)\s*[:=]?\s*[\w\s]+/gi, name: 'Medical Information', severity: 'high' },
          { regex: /\b\d{3}-\d{2}-\d{4}\b/g, name: 'Potential Medical ID', severity: 'medium' }
        ],
        weight: 0.8
      }
    }

    this.contextualKeywords = {
      high_risk: ['confidential', 'secret', 'private', 'internal', 'restricted', 'classified'],
      medium_risk: ['personal', 'sensitive', 'protected', 'proprietary'],
      low_risk: ['public', 'open', 'general', 'common']
    }

    this.aiChatbotDomains = [
      'chat.openai.com', 'claude.ai', 'bard.google.com', 'bing.com',
      'character.ai', 'perplexity.ai', 'poe.com', 'you.com'
    ]
  }

  analyze(content, context = {}) {
    if (!content || content.length < 10) {
      return this.createAnalysisResult(false, 0, [], 'allow')
    }

    const detections = []
    let totalRiskScore = 0
    let maxSeverityScore = 0

    // Pattern-based detection
    for (const [category, categoryData] of Object.entries(this.patterns)) {
      for (const pattern of categoryData.patterns) {
        const matches = content.match(pattern.regex)
        if (matches) {
          const severityScore = this.getSeverityScore(pattern.severity)
          const detection = {
            category,
            name: pattern.name,
            severity: pattern.severity,
            matches: matches.length,
            weight: categoryData.weight
          }
          
          detections.push(detection)
          totalRiskScore += severityScore * categoryData.weight * matches.length
          maxSeverityScore = Math.max(maxSeverityScore, severityScore)
        }
      }
    }

    // Contextual analysis
    const contextScore = this.analyzeContext(content, context)
    totalRiskScore += contextScore

    // AI chatbot detection bonus
    if (this.isAIChatbot(context.url)) {
      totalRiskScore *= 1.5 // Increase risk for AI chatbots
    }

    // Normalize risk score (0-1)
    const normalizedScore = Math.min(totalRiskScore / 10, 1)
    
    // Determine action
    const action = this.determineAction(normalizedScore, maxSeverityScore)
    
    return this.createAnalysisResult(
      normalizedScore > 0.3,
      normalizedScore,
      detections,
      action,
      this.generateRecommendations(detections, context)
    )
  }

  getSeverityScore(severity) {
    const scores = {
      'low': 1,
      'medium': 3,
      'high': 6,
      'critical': 10
    }
    return scores[severity] || 1
  }

  analyzeContext(content, context) {
    let contextScore = 0
    const lowerContent = content.toLowerCase()

    // Check for high-risk keywords
    for (const keyword of this.contextualKeywords.high_risk) {
      if (lowerContent.includes(keyword)) {
        contextScore += 2
      }
    }

    // Check for medium-risk keywords
    for (const keyword of this.contextualKeywords.medium_risk) {
      if (lowerContent.includes(keyword)) {
        contextScore += 1
      }
    }

    // Reduce score for low-risk keywords
    for (const keyword of this.contextualKeywords.low_risk) {
      if (lowerContent.includes(keyword)) {
        contextScore -= 0.5
      }
    }

    // Context-specific scoring
    if (context.source === 'form_input' || context.source === 'paste_input') {
      contextScore += 1 // Higher risk for form inputs
    }

    if (context.source === 'clipboard') {
      contextScore += 0.5 // Medium risk for clipboard
    }

    return Math.max(contextScore, 0)
  }

  isAIChatbot(url) {
    if (!url) return false
    
    return this.aiChatbotDomains.some(domain => 
      url.toLowerCase().includes(domain)
    )
  }

  determineAction(riskScore, maxSeverityScore) {
    if (riskScore > 0.8 || maxSeverityScore >= 10) {
      return 'block'
    } else if (riskScore > 0.5 || maxSeverityScore >= 6) {
      return 'warn'
    } else if (riskScore > 0.3) {
      return 'notify'
    }
    return 'allow'
  }

  generateRecommendations(detections, context) {
    const recommendations = []

    if (detections.some(d => d.category === 'credentials')) {
      recommendations.push('Remove or mask authentication credentials before sharing')
    }

    if (detections.some(d => d.category === 'financial')) {
      recommendations.push('Financial information detected - ensure compliance with PCI DSS')
    }

    if (detections.some(d => d.category === 'personal')) {
      recommendations.push('Personal information found - verify GDPR/CCPA compliance')
    }

    if (this.isAIChatbot(context.url)) {
      recommendations.push('AI chatbot detected - avoid sharing sensitive company data')
    }

    if (recommendations.length === 0) {
      recommendations.push('Review content for any sensitive information before sharing')
    }

    return recommendations
  }

  createAnalysisResult(hasSensitiveData, riskScore, detections, action, recommendations = []) {
    return {
      hasSensitiveData,
      riskScore,
      detections,
      action,
      recommendations,
      aiAnalysis: {
        riskLevel: this.getRiskLevel(riskScore),
        confidence: Math.min(riskScore * 1.2, 1),
        detectedTypes: detections.map(d => d.name)
      },
      timestamp: new Date().toISOString()
    }
  }

  getRiskLevel(score) {
    if (score > 0.8) return 'critical'
    if (score > 0.6) return 'high'
    if (score > 0.4) return 'medium'
    return 'low'
  }

  // Method to update patterns dynamically
  updatePatterns(newPatterns) {
    this.patterns = { ...this.patterns, ...newPatterns }
  }

  // Method to add custom organization patterns
  addOrganizationPatterns(orgPatterns) {
    if (!this.patterns.organization) {
      this.patterns.organization = { patterns: [], weight: 0.9 }
    }
    this.patterns.organization.patterns.push(...orgPatterns)
  }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = LocalSensitiveDataAnalyzer
} else if (typeof window !== 'undefined') {
  window.LocalSensitiveDataAnalyzer = LocalSensitiveDataAnalyzer
}