const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Database with master admin
const db = {
  master_admins: [
    { email: 'mahesh@gmail.com', password: 'Aurion#2025' }
  ],
  organizations: [],
  users: [],
  org_tokens: []
};

// Master login
app.post('/api/master/login', (req, res) => {
  const { email, password } = req.body;
  const admin = db.master_admins.find(a => a.email === email && a.password === password);
  
  if (admin) {
    res.json({ token: 'master-token', role: 'master' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Get organizations
app.get('/api/master/organizations', (req, res) => {
  res.json(db.organizations);
});

// Create organization
app.post('/api/master/organizations', (req, res) => {
  const { name, domain } = req.body;
  const id = 'org_' + crypto.randomBytes(8).toString('hex');
  const accessToken = name.toLowerCase().replace(/\s+/g, '').substring(0, 3) + '_' + crypto.randomBytes(16).toString('hex');
  
  const org = {
    id, name, domain, accessToken,
    createdAt: new Date().toISOString(),
    status: 'active'
  };
  
  db.organizations.push(org);
  db.org_tokens.push({ token: accessToken, orgId: id });
  res.json(org);
});

// Org login
app.post('/api/org/login', (req, res) => {
  const { accessToken, email } = req.body;
  const tokenRecord = db.org_tokens.find(t => t.token === accessToken);
  
  if (tokenRecord) {
    const org = db.organizations.find(o => o.id === tokenRecord.orgId);
    res.json({ token: 'org-token', role: 'org_admin', organization: org.name, orgId: org.id });
  } else {
    res.status(401).json({ error: 'Invalid access token or email. Please check your credentials.' });
  }
});

// Get users
app.get('/api/org/users', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const tokenRecord = db.org_tokens.find(t => t.token === token);
  
  if (tokenRecord) {
    const users = db.users.filter(u => u.orgId === tokenRecord.orgId);
    res.json(users);
  } else {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Create user
app.post('/api/org/users', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const tokenRecord = db.org_tokens.find(t => t.token === token);
  
  if (tokenRecord) {
    const { name, email, role } = req.body;
    const user = {
      id: 'user_' + crypto.randomBytes(8).toString('hex'),
      name, email, role: role || 'user',
      orgId: tokenRecord.orgId,
      extensionToken: 'ext_' + crypto.randomBytes(20).toString('hex'),
      createdAt: new Date().toISOString(),
      status: 'active'
    };
    
    db.users.push(user);
    res.json(user);
  } else {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Analytics
app.get('/api/org/analytics', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const tokenRecord = db.org_tokens.find(t => t.token === token);
  
  if (tokenRecord) {
    const users = db.users.filter(u => u.orgId === tokenRecord.orgId);
    res.json({
      totalUsers: users.length,
      activeUsers: users.filter(u => u.status === 'active').length,
      totalScans: Math.floor(Math.random() * 1000),
      threatsBlocked: Math.floor(Math.random() * 50)
    });
  } else {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(8080, () => {
  console.log('Server running on http://localhost:8080');
  console.log('Master Admin: mahesh@gmail.com / Aurion#2025');
});