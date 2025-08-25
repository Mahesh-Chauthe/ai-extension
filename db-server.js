const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Database simulation
const db = {
  master_admins: [
    { id: 1, email: 'mahesh@gmail.com', password: 'Aurion#2025', role: 'master', status: 'active' }
  ],
  organizations: [],
  users: [],
  org_tokens: []
};

// Initialize default organizations
const initData = () => {
  const techCorpToken = 'tc_' + crypto.randomBytes(16).toString('hex');
  const startupToken = 'sx_' + crypto.randomBytes(16).toString('hex');
  
  db.organizations = [
    {
      id: 'org_techcorp_001',
      name: 'TechCorp Inc',
      domain: 'techcorp.com',
      accessToken: techCorpToken,
      createdAt: new Date().toISOString(),
      status: 'active'
    },
    {
      id: 'org_startup_002',
      name: 'StartupXYZ',
      domain: 'startupxyz.com',
      accessToken: startupToken,
      createdAt: new Date().toISOString(),
      status: 'active'
    }
  ];
  
  db.org_tokens = [
    { token: techCorpToken, orgId: 'org_techcorp_001' },
    { token: startupToken, orgId: 'org_startup_002' }
  ];
  
  console.log('Database initialized');
  console.log('Master Admin: mahesh@gmail.com / Aurion#2025');
  console.log('TechCorp Token:', techCorpToken);
  console.log('StartupXYZ Token:', startupToken);
};

initData();

// Database queries
const findMasterAdmin = (email, password) => {
  return db.master_admins.find(admin => admin.email === email && admin.password === password && admin.status === 'active');
};

const findOrgByToken = (token) => {
  const tokenRecord = db.org_tokens.find(t => t.token === token);
  if (!tokenRecord) return null;
  return db.organizations.find(org => org.id === tokenRecord.orgId);
};

const getOrgUsers = (orgId) => {
  return db.users.filter(user => user.orgId === orgId);
};

// Master Admin Routes
app.post('/api/master/login', (req, res) => {
  const { email, password } = req.body;
  console.log(`Login attempt: ${email}`);
  
  const admin = findMasterAdmin(email, password);
  if (admin) {
    console.log('Login successful');
    res.json({ token: 'master-' + crypto.randomBytes(16).toString('hex'), role: 'master' });
  } else {
    console.log('Login failed - invalid credentials');
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/api/master/organizations', (req, res) => {
  res.json(db.organizations);
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
  
  db.organizations.push(org);
  db.org_tokens.push({ token: accessToken, orgId: id });
  
  console.log(`New organization created: ${name} - Token: ${accessToken}`);
  res.json(org);
});

// Organization Portal Routes
app.post('/api/org/login', (req, res) => {
  const { accessToken, email } = req.body;
  console.log(`Org login attempt: Token=${accessToken}, Email=${email}`);
  
  const org = findOrgByToken(accessToken);
  if (!org) {
    console.log('Invalid access token');
    return res.status(401).json({ error: 'Invalid access token or email. Please check your credentials.' });
  }
  
  console.log(`Login successful for organization: ${org.name}`);
  res.json({ 
    token: 'org-' + crypto.randomBytes(16).toString('hex'), 
    role: 'org_admin', 
    organization: org.name,
    orgId: org.id 
  });
});

app.get('/api/org/users', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !findOrgByToken(token)) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  const tokenRecord = db.org_tokens.find(t => t.token === token);
  const users = getOrgUsers(tokenRecord.orgId);
  res.json(users);
});

app.post('/api/org/users', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !findOrgByToken(token)) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  const { name, email, role } = req.body;
  const userId = 'user_' + crypto.randomBytes(8).toString('hex');
  const extensionToken = 'ext_' + crypto.randomBytes(20).toString('hex');
  const tokenRecord = db.org_tokens.find(t => t.token === token);
  
  const user = {
    id: userId,
    name,
    email,
    role: role || 'user',
    orgId: tokenRecord.orgId,
    extensionToken,
    createdAt: new Date().toISOString(),
    status: 'active'
  };
  
  db.users.push(user);
  console.log(`User created: ${name} - Extension Token: ${extensionToken}`);
  res.json(user);
});

app.get('/api/org/analytics', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !findOrgByToken(token)) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  const tokenRecord = db.org_tokens.find(t => t.token === token);
  const users = getOrgUsers(tokenRecord.orgId);
  
  res.json({
    totalUsers: users.length,
    activeUsers: users.filter(u => u.status === 'active').length,
    totalScans: Math.floor(Math.random() * 1000),
    threatsBlocked: Math.floor(Math.random() * 50)
  });
});

const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Database Server running on http://localhost:${PORT}`);
  console.log('Master Admin Credentials: mahesh@gmail.com / Aurion#2025');
});