const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'enterprise-jwt-secret-key-2024';

// In-memory storage
const organizations = new Map();
const users = new Map();
const orgTokens = new Map();

// Initialize default organizations
const initData = () => {
  const techCorpId = 'org_techcorp_001';
  const startupId = 'org_startup_002';
  
  const techCorpToken = 'tc_' + crypto.randomBytes(16).toString('hex');
  const startupToken = 'sx_' + crypto.randomBytes(16).toString('hex');
  
  organizations.set(techCorpId, {
    id: techCorpId,
    name: 'TechCorp Inc',
    domain: 'techcorp.com',
    accessToken: techCorpToken,
    createdAt: new Date().toISOString(),
    status: 'active'
  });
  
  organizations.set(startupId, {
    id: startupId,
    name: 'StartupXYZ',
    domain: 'startupxyz.com',
    accessToken: startupToken,
    createdAt: new Date().toISOString(),
    status: 'active'
  });
  
  // Create org tokens mapping
  orgTokens.set(techCorpToken, techCorpId);
  orgTokens.set(startupToken, startupId);
  
  console.log('=== ORGANIZATION ACCESS TOKENS ===');
  console.log('TechCorp Inc:', techCorpToken);
  console.log('StartupXYZ:', startupToken);
  console.log('=====================================');
};

initData();

// Generate secure extension token
const generateExtensionToken = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let token = 'ext_';
  for (let i = 0; i < 20; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
};

// Middleware to verify org token
const verifyOrgToken = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !orgTokens.has(token)) {
    return res.status(401).json({ error: 'Invalid access token' });
  }
  req.orgId = orgTokens.get(token);
  next();
};

// Master Admin Routes
app.post('/api/master/login', async (req, res) => {
  const { email, password } = req.body;
  if (email === 'admin@enterprise.com' && password === 'admin123') {
    const token = jwt.sign({ role: 'master', email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, role: 'master' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/api/master/organizations', (req, res) => {
  const orgs = Array.from(organizations.values());
  res.json(orgs);
});

app.post('/api/master/organizations', (req, res) => {
  const { name, domain } = req.body;
  const id = 'org_' + crypto.randomBytes(8).toString('hex');
  const accessToken = name.toLowerCase().replace(/\s+/g, '').substring(0, 3) + '_' + crypto.randomBytes(16).toString('hex');
  
  const org = {
    id,
    name,
    domain,
    accessToken,
    createdAt: new Date().toISOString(),
    status: 'active'
  };
  
  organizations.set(id, org);
  orgTokens.set(accessToken, id);
  
  console.log(`New organization created: ${name} - Token: ${accessToken}`);
  res.json(org);
});

// Organization Portal Routes
app.post('/api/org/login', (req, res) => {
  const { accessToken, email } = req.body;
  
  console.log(`Login attempt - Token: ${accessToken}, Email: ${email}`);
  
  if (!orgTokens.has(accessToken)) {
    console.log('Token not found in orgTokens map');
    return res.status(401).json({ error: 'Invalid access token or email. Please check your credentials.' });
  }
  
  const orgId = orgTokens.get(accessToken);
  const org = organizations.get(orgId);
  
  if (!org) {
    console.log('Organization not found for orgId:', orgId);
    return res.status(401).json({ error: 'Organization not found' });
  }
  
  console.log(`Login successful for organization: ${org.name}`);
  
  const token = jwt.sign({ 
    role: 'org_admin', 
    orgId, 
    email,
    orgName: org.name 
  }, JWT_SECRET, { expiresIn: '24h' });
  
  res.json({ 
    token, 
    role: 'org_admin', 
    organization: org.name,
    orgId 
  });
});

app.get('/api/org/users', verifyOrgToken, (req, res) => {
  const orgUsers = Array.from(users.values()).filter(u => u.orgId === req.orgId);
  res.json(orgUsers);
});

app.post('/api/org/users', verifyOrgToken, (req, res) => {
  const { name, email, role } = req.body;
  const userId = 'user_' + crypto.randomBytes(8).toString('hex');
  const extensionToken = generateExtensionToken();
  
  const user = {
    id: userId,
    name,
    email,
    role: role || 'user',
    orgId: req.orgId,
    extensionToken,
    createdAt: new Date().toISOString(),
    status: 'active'
  };
  
  users.set(userId, user);
  console.log(`User created: ${name} - Extension Token: ${extensionToken}`);
  res.json(user);
});

app.get('/api/org/analytics', verifyOrgToken, (req, res) => {
  const orgUsers = Array.from(users.values()).filter(u => u.orgId === req.orgId);
  res.json({
    totalUsers: orgUsers.length,
    activeUsers: orgUsers.filter(u => u.status === 'active').length,
    totalScans: Math.floor(Math.random() * 1000),
    threatsBlocked: Math.floor(Math.random() * 50)
  });
});

// Extension API
app.post('/api/extension/validate', (req, res) => {
  const { token } = req.body;
  const user = Array.from(users.values()).find(u => u.extensionToken === token);
  
  if (user) {
    const org = organizations.get(user.orgId);
    res.json({ 
      valid: true, 
      user: { name: user.name, email: user.email },
      organization: org.name 
    });
  } else {
    res.status(401).json({ valid: false, error: 'Invalid extension token' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Enterprise API running on port ${PORT}`);
  console.log('Master Portal: http://localhost:8090');
  console.log('Organization Portal: http://localhost:8091');
  console.log('\n=== Available Organizations ===');
  organizations.forEach(org => {
    console.log(`${org.name}: ${org.accessToken}`);
  });
});