const express = require("express")
const cors = require("cors")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const { Pool } = require("pg")
const Redis = require("redis")
const OpenAI = require("openai")
const crypto = require("crypto")

const app = express()
const port = process.env.PORT || 3000

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
})

// Redis connection
const redis = Redis.createClient({
  url: process.env.REDIS_URL,
})
redis.connect()

// OpenAI for advanced sensitive data detection
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
})

// Middleware
app.use(helmet())
app.use(cors())
app.use(express.json({ limit: "10mb" }))

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
})
app.use(limiter)

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ error: "Access token required" })
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" })
    req.user = user
    next()
  })
}

// Role-based access control
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Insufficient permissions" })
    }
    next()
  }
}

// Advanced sensitive data detection using AI
async function detectSensitiveDataAI(content, organizationId) {
  try {
    // Get organization-specific patterns
    const patternsResult = await pool.query(
      "SELECT * FROM sensitive_patterns WHERE organization_id = $1 OR organization_id IS NULL AND is_active = true",
      [organizationId],
    )

    const patterns = patternsResult.rows
    const detectedPatterns = []

    // Regex-based detection
    for (const pattern of patterns) {
      const regex = new RegExp(pattern.regex_pattern, "gi")
      if (regex.test(content)) {
        detectedPatterns.push({
          name: pattern.pattern_name,
          severity: pattern.severity,
          description: pattern.description,
        })
      }
    }

    // AI-based contextual analysis
    const aiPrompt = `
    Analyze the following text for sensitive information that might not be caught by regex patterns.
    Look for:
    - Personal identifiable information (PII)
    - Financial information
    - Medical information
    - Confidential business data
    - Security credentials
    - Private communications
    
    Text to analyze: "${content}"
    
    Respond with a JSON object containing:
    {
      "hasSensitiveData": boolean,
      "confidence": number (0-1),
      "detectedTypes": ["type1", "type2"],
      "riskLevel": "low|medium|high|critical"
    }
    `

    const aiResponse = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [{ role: "user", content: aiPrompt }],
      temperature: 0.1,
      max_tokens: 500,
    })

    let aiAnalysis = {}
    try {
      aiAnalysis = JSON.parse(aiResponse.choices[0].message.content)
    } catch (e) {
      console.error("Failed to parse AI response:", e)
      aiAnalysis = { hasSensitiveData: false, confidence: 0 }
    }

    return {
      regexDetections: detectedPatterns,
      aiAnalysis: aiAnalysis,
      overallRisk: Math.max(detectedPatterns.length > 0 ? 0.7 : 0, aiAnalysis.confidence || 0),
    }
  } catch (error) {
    console.error("Sensitive data detection error:", error)
    return { regexDetections: [], aiAnalysis: {}, overallRisk: 0 }
  }
}

// Health check endpoints
app.get("/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() })
})

app.get("/ready", async (req, res) => {
  try {
    await pool.query("SELECT 1")
    await redis.ping()
    res.json({ status: "ready" })
  } catch (error) {
    res.status(503).json({ status: "not ready", error: error.message })
  }
})

// Authentication endpoints
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password, organizationDomain } = req.body

    // Find user with organization
    const userResult = await pool.query(
      `
      SELECT u.*, o.name as org_name, o.domain as org_domain, o.status as org_status
      FROM users u
      JOIN organizations o ON u.organization_id = o.id
      WHERE u.email = $1 AND (o.domain = $2 OR $2 IS NULL)
      AND u.status = 'active' AND o.status = 'active'
    `,
      [email, organizationDomain],
    )

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" })
    }

    const user = userResult.rows[0]
    const validPassword = await bcrypt.compare(password, user.password_hash)

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" })
    }

    // Update last login
    await pool.query("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", [user.id])

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: user.id,
        organizationId: user.organization_id,
        role: user.role,
        email: user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY || "24h" },
    )

    // Log audit event
    await pool.query(
      `
      INSERT INTO audit_logs (user_id, organization_id, action, details, ip_address)
      VALUES ($1, $2, 'login', $3, $4)
    `,
      [user.id, user.organization_id, JSON.stringify({ success: true }), req.ip],
    )

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
          domain: user.org_domain,
        },
      },
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// License validation endpoint
app.post("/api/license/validate", authenticateToken, async (req, res) => {
  try {
    const { licenseKey } = req.body
    const userId = req.user.userId

    // Validate license
    const licenseResult = await pool.query(
      `
      SELECT l.*, o.name as org_name, o.total_seats, o.used_seats
      FROM licenses l
      JOIN organizations o ON l.organization_id = o.id
      WHERE l.license_key = $1 AND l.status = 'active'
      AND (l.expiry_date IS NULL OR l.expiry_date > CURRENT_TIMESTAMP)
    `,
      [licenseKey],
    )

    if (licenseResult.rows.length === 0) {
      return res.status(403).json({ error: "Invalid or expired license" })
    }

    const license = licenseResult.rows[0]

    // Check seat availability
    if (license.used_seats >= license.total_seats) {
      return res.status(403).json({ error: "License seat limit exceeded" })
    }

    // Cache license validation
    await redis.setex(`license:${licenseKey}`, 3600, JSON.stringify(license))

    res.json({
      valid: true,
      license: {
        type: license.license_type,
        features: license.features,
        organization: license.org_name,
        seatsUsed: license.used_seats,
        totalSeats: license.total_seats,
      },
    })
  } catch (error) {
    console.error("License validation error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Sensitive data analysis endpoint
app.post("/api/analyze/sensitive-data", authenticateToken, async (req, res) => {
  try {
    const { content, url } = req.body
    const userId = req.user.userId
    const organizationId = req.user.organizationId

    if (!content) {
      return res.status(400).json({ error: "Content is required" })
    }

    // Perform sensitive data detection
    const analysis = await detectSensitiveDataAI(content, organizationId)

    // Create content hash for privacy
    const contentHash = crypto.createHash("sha256").update(content).digest("hex")

    // Log detection if sensitive data found
    if (analysis.overallRisk > Number.parseFloat(process.env.SENSITIVE_DATA_THRESHOLD || "0.5")) {
      await pool.query(
        `
        INSERT INTO sensitive_detections 
        (user_id, organization_id, content_hash, detected_patterns, severity, url, action_taken)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
        [
          userId,
          organizationId,
          contentHash,
          JSON.stringify([...analysis.regexDetections, ...(analysis.aiAnalysis.detectedTypes || [])]),
          analysis.aiAnalysis.riskLevel || "medium",
          url,
          analysis.overallRisk > 0.8 ? "blocked" : "warned",
        ],
      )
    }

    res.json({
      hasSensitiveData: analysis.overallRisk > Number.parseFloat(process.env.SENSITIVE_DATA_THRESHOLD || "0.5"),
      riskScore: analysis.overallRisk,
      detections: analysis.regexDetections,
      aiAnalysis: analysis.aiAnalysis,
      action: analysis.overallRisk > 0.8 ? "block" : analysis.overallRisk > 0.5 ? "warn" : "allow",
    })
  } catch (error) {
    console.error("Sensitive data analysis error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Organization management endpoints (Master Admin only)
app.post("/api/admin/organizations", authenticateToken, requireRole(["master_admin"]), async (req, res) => {
  try {
    const { name, domain, totalSeats, licenseType } = req.body

    const result = await pool.query(
      `
      INSERT INTO organizations (name, domain, total_seats, license_type)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `,
      [name, domain, totalSeats || 10, licenseType || "basic"],
    )

    // Create default license
    const licenseKey = crypto.randomBytes(32).toString("hex")
    await pool.query(
      `
      INSERT INTO licenses (organization_id, license_key, license_type, features)
      VALUES ($1, $2, $3, $4)
    `,
      [result.rows[0].id, licenseKey, licenseType || "basic", JSON.stringify(["basic_features"])],
    )

    res.json({ organization: result.rows[0], licenseKey })
  } catch (error) {
    console.error("Create organization error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// User management endpoints (Org Admin)
app.post("/api/org/users", authenticateToken, requireRole(["org_admin", "master_admin"]), async (req, res) => {
  try {
    const { email, firstName, lastName, role } = req.body
    const organizationId = req.user.role === "master_admin" ? req.body.organizationId : req.user.organizationId

    // Check seat availability
    const orgResult = await pool.query("SELECT total_seats, used_seats FROM organizations WHERE id = $1", [
      organizationId,
    ])

    if (orgResult.rows[0].used_seats >= orgResult.rows[0].total_seats) {
      return res.status(403).json({ error: "Organization seat limit exceeded" })
    }

    // Generate temporary password
    const tempPassword = crypto.randomBytes(12).toString("hex")
    const passwordHash = await bcrypt.hash(tempPassword, 10)
    const licenseKey = crypto.randomBytes(32).toString("hex")

    const userResult = await pool.query(
      `
      INSERT INTO users (organization_id, email, password_hash, first_name, last_name, role, license_key)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, email, first_name, last_name, role, license_key
    `,
      [organizationId, email, passwordHash, firstName, lastName, role || "user", licenseKey],
    )

    // Update used seats
    await pool.query("UPDATE organizations SET used_seats = used_seats + 1 WHERE id = $1", [organizationId])

    res.json({
      user: userResult.rows[0],
      temporaryPassword: tempPassword,
    })
  } catch (error) {
    console.error("Create user error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Analytics endpoints
app.get("/api/analytics/dashboard", authenticateToken, requireRole(["org_admin", "master_admin"]), async (req, res) => {
  try {
    const organizationId = req.user.role === "master_admin" ? null : req.user.organizationId

    let query = `
      SELECT 
        COUNT(DISTINCT u.id) as total_users,
        COUNT(DISTINCT CASE WHEN u.last_login > CURRENT_TIMESTAMP - INTERVAL '30 days' THEN u.id END) as active_users,
        COUNT(DISTINCT sd.id) as sensitive_detections,
        COUNT(DISTINCT CASE WHEN sd.severity = 'critical' THEN sd.id END) as critical_detections
      FROM users u
      LEFT JOIN sensitive_detections sd ON u.id = sd.user_id
    `

    const params = []
    if (organizationId) {
      query += " WHERE u.organization_id = $1"
      params.push(organizationId)
    }

    const result = await pool.query(query, params)

    res.json(result.rows[0])
  } catch (error) {
    console.error("Analytics error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

app.listen(port, () => {
  console.log(`Extension API server running on port ${port}`)
})
