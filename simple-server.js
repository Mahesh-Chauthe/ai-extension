const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// In-memory storage
const organizations = new Map();
const users = new Map();
const orgTokens = new Map();
const masterAdmins = new Map();

// Initialize master admin
masterAdmins.set('mahesh@gmail.com', 'Aurion#2025');

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
  
  orgTokens.set(techCorpToken, techCorpId);
  orgTokens.set(startupToken, startupId);
  
  console.log('=== ORGANIZATION ACCESS TOKENS ===');
  console.log('TechCorp Inc:', techCorpToken);
  console.log('StartupXYZ:', startupToken);
  console.log('=====================================');
};

initData();

// Generate extension token
const generateExtensionToken = () => {
  return 'ext_' + crypto.randomBytes(16).toString('hex');
};

// Master Admin Routes
app.post('/api/master/login', (req, res) => {
  const { email, password } = req.body;
  if (masterAdmins.has(email) && masterAdmins.get(email) === password) {
    res.json({ token: 'master-token', role: 'master' });
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
  
  console.log(`New organization: ${name} - Token: ${accessToken}`);
  res.json(org);
});

// Organization Portal Routes
app.post('/api/org/login', (req, res) => {
  const { accessToken, email } = req.body;
  
  if (!orgTokens.has(accessToken)) {
    return res.status(401).json({ error: 'Invalid access token or email. Please check your credentials.' });
  }
  
  const orgId = orgTokens.get(accessToken);
  const org = organizations.get(orgId);
  
  res.json({ 
    token: 'org-token', 
    role: 'org_admin', 
    organization: org.name,
    orgId 
  });
});

app.get('/api/org/users', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !orgTokens.has(token)) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  const orgId = orgTokens.get(token);
  const orgUsers = Array.from(users.values()).filter(u => u.orgId === orgId);
  res.json(orgUsers);
});

app.post('/api/org/users', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !orgTokens.has(token)) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  const { name, email, role } = req.body;
  const userId = 'user_' + crypto.randomBytes(8).toString('hex');
  const extensionToken = generateExtensionToken();
  const orgId = orgTokens.get(token);
  
  const user = {
    id: userId,
    name,
    email,
    role: role || 'user',
    orgId,
    extensionToken,
    createdAt: new Date().toISOString(),
    status: 'active'
  };
  
  users.set(userId, user);
  res.json(user);
});

app.get('/api/org/analytics', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !orgTokens.has(token)) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  const orgId = orgTokens.get(token);
  const orgUsers = Array.from(users.values()).filter(u => u.orgId === orgId);
  
  res.json({
    totalUsers: orgUsers.length,
    activeUsers: orgUsers.filter(u => u.status === 'active').length,
    totalScans: Math.floor(Math.random() * 1000),
    threatsBlocked: Math.floor(Math.random() * 50)
  });
});

const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('\nAvailable organizations:');
  organizations.forEach(org => {
    console.log(`${org.name}: ${org.accessToken}`);
  });
});