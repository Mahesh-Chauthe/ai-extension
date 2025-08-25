const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'master_secret_key_2024';

// In-memory storage (replace with database)
let organizations = [];
let users = [];
let auditLogs = [];
let extensions = [];

// Master Admin credentials
const MASTER_ADMIN = {
    email: 'master@system.com',
    password: '$2b$10$hash', // bcrypt hash of 'master123'
    role: 'master_admin'
};

// Middleware
function authenticateMaster(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'master_admin') {
            return res.status(403).json({ error: 'Master admin access required' });
        }
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

function generateToken() {
    return 'ext_' + Math.random().toString(36).substr(2, 16);
}

function generateId(prefix) {
    return prefix + '_' + Math.random().toString(36).substr(2, 8);
}

function addAuditLog(user, action, organization, details) {
    auditLogs.push({
        id: generateId('audit'),
        timestamp: new Date().toISOString(),
        user,
        action,
        organization,
        details
    });
}

// Authentication
app.post('/api/master/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (email === MASTER_ADMIN.email && password === 'master123') {
        const token = jwt.sign(
            { email, role: 'master_admin' },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        addAuditLog('Master Admin', 'LOGIN', 'System', 'Master admin login');
        
        res.json({
            token,
            user: { email, role: 'master_admin', name: 'Master Administrator' }
        });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Organizations Management
app.get('/api/master/organizations', authenticateMaster, (req, res) => {
    res.json(organizations);
});

app.post('/api/master/organizations', authenticateMaster, (req, res) => {
    const { name, domain, adminEmail, userLimit } = req.body;
    
    const organization = {
        id: generateId('org'),
        name,
        domain,
        adminEmail,
        userLimit: parseInt(userLimit),
        status: 'active',
        createdAt: new Date().toISOString(),
        accessToken: generateToken(),
        userCount: 0
    };
    
    organizations.push(organization);
    
    // Create organization admin
    const admin = {
        id: generateId('user'),
        email: adminEmail,
        name: 'Organization Admin',
        role: 'org_admin',
        organizationId: organization.id,
        organizationName: name,
        status: 'active',
        createdAt: new Date().toISOString(),
        accessToken: organization.accessToken
    };
    
    users.push(admin);
    organization.userCount = 1;
    
    addAuditLog('Master Admin', 'CREATE_ORGANIZATION', name, `Created organization ${name} with admin ${adminEmail}`);
    
    res.json({ organization, admin });
});

app.put('/api/master/organizations/:id', authenticateMaster, (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    
    const orgIndex = organizations.findIndex(o => o.id === id);
    if (orgIndex === -1) {
        return res.status(404).json({ error: 'Organization not found' });
    }
    
    organizations[orgIndex] = { ...organizations[orgIndex], ...updates };
    
    addAuditLog('Master Admin', 'UPDATE_ORGANIZATION', organizations[orgIndex].name, 'Organization updated');
    
    res.json(organizations[orgIndex]);
});

app.delete('/api/master/organizations/:id', authenticateMaster, (req, res) => {
    const { id } = req.params;
    
    const org = organizations.find(o => o.id === id);
    if (!org) {
        return res.status(404).json({ error: 'Organization not found' });
    }
    
    // Remove organization and all its users
    organizations = organizations.filter(o => o.id !== id);
    const removedUsers = users.filter(u => u.organizationId === id);
    users = users.filter(u => u.organizationId !== id);
    
    addAuditLog('Master Admin', 'DELETE_ORGANIZATION', org.name, `Deleted organization and ${removedUsers.length} users`);
    
    res.json({ message: 'Organization deleted', removedUsers: removedUsers.length });
});

// Users Management
app.get('/api/master/users', authenticateMaster, (req, res) => {
    res.json(users);
});

app.get('/api/master/users/organization/:orgId', authenticateMaster, (req, res) => {
    const { orgId } = req.params;
    const orgUsers = users.filter(u => u.organizationId === orgId);
    res.json(orgUsers);
});

app.post('/api/master/users', authenticateMaster, (req, res) => {
    const { email, name, role, organizationId } = req.body;
    
    const organization = organizations.find(o => o.id === organizationId);
    if (!organization) {
        return res.status(404).json({ error: 'Organization not found' });
    }
    
    if (organization.userCount >= organization.userLimit) {
        return res.status(400).json({ error: 'User limit exceeded' });
    }
    
    const user = {
        id: generateId('user'),
        email,
        name,
        role,
        organizationId,
        organizationName: organization.name,
        status: 'active',
        createdAt: new Date().toISOString(),
        accessToken: organization.accessToken
    };
    
    users.push(user);
    organization.userCount++;
    
    addAuditLog('Master Admin', 'CREATE_USER', organization.name, `Created user ${email}`);
    
    res.json(user);
});

app.delete('/api/master/users/:id', authenticateMaster, (req, res) => {
    const { id } = req.params;
    
    const user = users.find(u => u.id === id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    users = users.filter(u => u.id !== id);
    
    // Update organization user count
    const org = organizations.find(o => o.id === user.organizationId);
    if (org) org.userCount--;
    
    addAuditLog('Master Admin', 'DELETE_USER', user.organizationName, `Deleted user ${user.email}`);
    
    res.json({ message: 'User deleted' });
});

// Extension Management
app.get('/api/master/extensions', authenticateMaster, (req, res) => {
    res.json(extensions);
});

app.post('/api/master/extensions', authenticateMaster, (req, res) => {
    const { version, description } = req.body;
    
    const extension = {
        id: generateId('ext'),
        version,
        description,
        status: 'active',
        createdAt: new Date().toISOString(),
        organizations: organizations.map(o => o.id)
    };
    
    extensions.push(extension);
    
    addAuditLog('Master Admin', 'DEPLOY_EXTENSION', 'System', `Deployed extension ${version}`);
    
    res.json(extension);
});

// Audit Logs
app.get('/api/master/audit', authenticateMaster, (req, res) => {
    res.json(auditLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
});

// Analytics
app.get('/api/master/analytics', authenticateMaster, (req, res) => {
    const stats = {
        totalOrganizations: organizations.length,
        totalUsers: users.length,
        activeOrganizations: organizations.filter(o => o.status === 'active').length,
        activeUsers: users.filter(u => u.status === 'active').length,
        totalExtensions: extensions.length,
        recentActivity: auditLogs.slice(-10)
    };
    
    res.json(stats);
});

// Organization Token Validation (for extension)
app.post('/api/validate-token', (req, res) => {
    const { token } = req.body;
    
    const organization = organizations.find(o => o.accessToken === token);
    if (!organization) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    res.json({
        valid: true,
        organization: {
            id: organization.id,
            name: organization.name,
            domain: organization.domain
        }
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'Master API', timestamp: new Date().toISOString() });
});

// Initialize sample data
function initializeSampleData() {
    const sampleOrg = {
        id: 'org_sample01',
        name: 'TechCorp Inc',
        domain: 'techcorp.com',
        adminEmail: 'admin@techcorp.com',
        userLimit: 100,
        status: 'active',
        createdAt: new Date().toISOString(),
        accessToken: 'ext_abc123def456ghi789',
        userCount: 2
    };
    
    organizations.push(sampleOrg);
    
    users.push({
        id: 'user_admin01',
        email: 'admin@techcorp.com',
        name: 'John Admin',
        role: 'org_admin',
        organizationId: sampleOrg.id,
        organizationName: sampleOrg.name,
        status: 'active',
        createdAt: new Date().toISOString(),
        accessToken: sampleOrg.accessToken
    });
    
    users.push({
        id: 'user_emp01',
        email: 'user1@techcorp.com',
        name: 'Jane Employee',
        role: 'user',
        organizationId: sampleOrg.id,
        organizationName: sampleOrg.name,
        status: 'active',
        createdAt: new Date().toISOString(),
        accessToken: sampleOrg.accessToken
    });
    
    addAuditLog('System', 'INITIALIZE', 'System', 'Sample data initialized');
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Master API running on port ${PORT}`);
    initializeSampleData();
});

module.exports = app;