require('dotenv').config()
const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const { Pool } = require('pg')
const Redis = require('redis')
const crypto = require('crypto')

const app = express()
const port = process.env.PORT || 3000

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password123@postgres-service:5432/extension_db',
  ssl: false
})

// Redis connection
const redis = Redis.createClient({
  url: process.env.REDIS_URL || 'redis://redis-service:6379'
})
redis.connect().catch(console.error)

// Middleware
app.use(helmet())
app.use(cors({ origin: true, credentials: true }))
app.use(express.json({ limit: '10mb' }))

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
})
app.use(limiter)

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ error: 'Access token required' })
  }

  jwt.verify(token, process.env.JWT_SECRET || 'supersecretjwtkey', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' })
    req.user = user
    next()
  })
}

// Role-based access control
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' })
    }
    next()
  }
}

// Advanced sensitive data patterns
const SENSITIVE_PATTERNS = {
  'credit_card': /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
  'ssn': /\b\d{3}-?\d{2}-?\d{4}\b/g,
  'email': /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  'phone': /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
  'api_key': /\b[A-Za-z0-9]{32,}\b/g,
  'jwt_token': /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
  'password': /(?i)\b(password|pwd|pass)\s*[:=]\s*[^\s]+/g,
  'aws_key': /AKIA[0-9A-Z]{16}/g,
  'github_token': /ghp_[a-zA-Z0-9]{36}/g,
  'slack_token': /xox[baprs]-([0-9a-zA-Z]{10,48})?/g
}

// AI Chatbot detection patterns
const AI_CHATBOTS = [
  { name: 'ChatGPT', domains: ['chat.openai.com', 'chatgpt.com'], risk: 'high' },
  { name: 'Claude', domains: ['claude.ai'], risk: 'high' },
  { name: 'Gemini', domains: ['gemini.google.com', 'bard.google.com'], risk: 'medium' },
  { name: 'Bing Chat', domains: ['bing.com'], risk: 'medium' },
  { name: 'Character.AI', domains: ['character.ai'], risk: 'low' },
  { name: 'Perplexity', domains: ['perplexity.ai'], risk: 'medium' }
]

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() })
})

app.get('/ready', async (req, res) => {
  try {
    await pool.query('SELECT 1')
    await redis.ping()
    res.json({ status: 'ready' })
  } catch (error) {
    res.status(503).json({ status: 'not ready', error: error.message })
  }
})

// Master Admin Authentication
app.post('/api/master/login', async (req, res) => {
  try {
    const { email, password, masterKey } = req.body

    // Verify master key
    if (masterKey !== process.env.MASTER_KEY) {
      return res.status(401).json({ error: 'Invalid master key' })
    }

    const userResult = await pool.query(
      'SELECT * FROM master_admins WHERE email = $1 AND status = $2',
      [email, 'active']
    )

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const user = userResult.rows[0]
    const validPassword = await bcrypt.compare(password, user.password_hash)

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const token = jwt.sign(
      { userId: user.id, role: 'master_admin', email: user.email },
      process.env.JWT_SECRET || 'supersecretjwtkey',
      { expiresIn: '24h' }
    )

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: 'master_admin'
      }
    })
  } catch (error) {
    console.error('Master login error:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// Organization Admin Authentication
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, organizationDomain } = req.body

    const userResult = await pool.query(`
      SELECT u.*, o.name as org_name, o.domain as org_domain, o.status as org_status
      FROM users u
      JOIN organizations o ON u.organization_id = o.id
      WHERE u.email = $1 AND (o.domain = $2 OR $2 IS NULL)
      AND u.status = 'active' AND o.status = 'active'
    `, [email, organizationDomain])

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const user = userResult.rows[0]
    const validPassword = await bcrypt.compare(password, user.password_hash)

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const token = jwt.sign({
      userId: user.id,
      organizationId: user.organization_id,
      role: user.role,
      email: user.email
    }, process.env.JWT_SECRET || 'supersecretjwtkey', { expiresIn: '24h' })

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organization: {
          id: user.organization_id,
          name: user.org_name,
          domain: user.org_domain
        }
      }
    })
  } catch (error) {
    console.error('Login error:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// Master Admin - Create Organization
app.post('/api/master/organizations', authenticateToken, requireRole(['master_admin']), async (req, res) => {
  try {
    const { name, domain, totalSeats, adminEmail, adminPassword, adminFirstName, adminLastName } = req.body

    // Create organization
    const orgResult = await pool.query(`
      INSERT INTO organizations (name, domain, total_seats, status)
      VALUES ($1, $2, $3, 'active')
      RETURNING id
    `, [name, domain, totalSeats])

    const organizationId = orgResult.rows[0].id

    // Create organization admin
    const hashedPassword = await bcrypt.hash(adminPassword, 10)
    await pool.query(`
      INSERT INTO users (email, password_hash, first_name, last_name, role, organization_id, status)
      VALUES ($1, $2, $3, $4, 'org_admin', $5, 'active')
    `, [adminEmail, hashedPassword, adminFirstName, adminLastName, organizationId])

    res.json({ success: true, organizationId })
  } catch (error) {
    console.error('Create organization error:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// Organization Admin - Create User
app.post('/api/org/users', authenticateToken, requireRole(['org_admin']), async (req, res) => {
  try {
    const { email, password, firstName, lastName, role } = req.body
    const organizationId = req.user.organizationId

    // Check seat limit
    const orgResult = await pool.query(
      'SELECT total_seats, used_seats FROM organizations WHERE id = $1',
      [organizationId]
    )

    if (orgResult.rows[0].used_seats >= orgResult.rows[0].total_seats) {
      return res.status(400).json({ error: 'Seat limit exceeded' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    await pool.query(`
      INSERT INTO users (email, password_hash, first_name, last_name, role, organization_id, status)
      VALUES ($1, $2, $3, $4, $5, $6, 'active')
    `, [email, hashedPassword, firstName, lastName, role, organizationId])

    // Update used seats
    await pool.query(
      'UPDATE organizations SET used_seats = used_seats + 1 WHERE id = $1',
      [organizationId]
    )

    res.json({ success: true })
  } catch (error) {
    console.error('Create user error:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// Advanced Sensitive Data Analysis
app.post('/api/analyze/sensitive-data', authenticateToken, async (req, res) => {
  try {
    const { content, url, source } = req.body
    const userId = req.user.userId
    const organizationId = req.user.organizationId

    if (!content) {
      return res.status(400).json({ error: 'Content is required' })
    }

    const detections = []
    let riskScore = 0

    // Pattern-based detection
    for (const [type, pattern] of Object.entries(SENSITIVE_PATTERNS)) {
      const matches = content.match(pattern)
      if (matches) {
        detections.push({
          type,
          count: matches.length,
          severity: getSeverity(type),
          matches: matches.slice(0, 3) // Limit for privacy
        })
        riskScore += matches.length * getSeverityScore(type)
      }
    }

    // AI Chatbot detection
    const chatbotDetection = detectAIChatbot(url)
    if (chatbotDetection) {
      detections.push({
        type: 'ai_chatbot',
        chatbot: chatbotDetection.name,
        risk: chatbotDetection.risk,
        severity: 'high'
      })
      riskScore += 50
    }

    // Normalize risk score
    riskScore = Math.min(riskScore / 100, 1)

    // Determine action
    let action = 'allow'
    if (riskScore > 0.8) action = 'block'
    else if (riskScore > 0.5) action = 'warn'

    // Log detection
    if (detections.length > 0) {
      const contentHash = crypto.createHash('sha256').update(content).digest('hex')
      await pool.query(`
        INSERT INTO sensitive_detections 
        (user_id, organization_id, content_hash, detected_patterns, severity, url, action_taken, source)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [userId, organizationId, contentHash, JSON.stringify(detections), 
          getOverallSeverity(detections), url, action, source])
    }

    res.json({
      hasSensitiveData: detections.length > 0,
      riskScore,
      detections,
      action,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Analysis error:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// Get AI Chatbots list
app.get('/api/config/ai-chatbots', authenticateToken, (req, res) => {
  res.json({ chatbots: AI_CHATBOTS })
})

// Analytics Dashboard
app.get('/api/analytics/dashboard', authenticateToken, async (req, res) => {
  try {
    const organizationId = req.user.organizationId

    const stats = await pool.query(`
      SELECT 
        COUNT(*) as total_detections,
        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
        COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count,
        COUNT(CASE WHEN action_taken = 'block' THEN 1 END) as blocked_count
      FROM sensitive_detections 
      WHERE organization_id = $1 AND created_at >= NOW() - INTERVAL '30 days'
    `, [organizationId])

    const users = await pool.query(
      'SELECT COUNT(*) as active_users FROM users WHERE organization_id = $1 AND status = $2',
      [organizationId, 'active']
    )

    res.json({
      detectionStats: stats.rows[0],
      activeUsers: users.rows[0].active_users,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Analytics error:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// Helper functions
function getSeverity(type) {
  const severityMap = {
    'credit_card': 'critical',
    'ssn': 'critical',
    'api_key': 'high',
    'jwt_token': 'high',
    'password': 'high',
    'aws_key': 'critical',
    'github_token': 'high',
    'slack_token': 'high',
    'email': 'medium',
    'phone': 'medium'
  }
  return severityMap[type] || 'low'
}

function getSeverityScore(type) {
  const scoreMap = {
    'critical': 25,
    'high': 15,
    'medium': 10,
    'low': 5
  }
  return scoreMap[getSeverity(type)] || 5
}

function getOverallSeverity(detections) {
  if (detections.some(d => d.severity === 'critical')) return 'critical'
  if (detections.some(d => d.severity === 'high')) return 'high'
  if (detections.some(d => d.severity === 'medium')) return 'medium'
  return 'low'
}

function detectAIChatbot(url) {
  if (!url) return null
  
  for (const chatbot of AI_CHATBOTS) {
    if (chatbot.domains.some(domain => url.includes(domain))) {
      return chatbot
    }
  }
  return null
}

app.listen(port, () => {
  console.log(`Advanced Enterprise Extension Server running on port ${port}`)
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`)
})