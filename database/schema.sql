-- Organizations table
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    domain VARCHAR(255),
    total_seats INTEGER DEFAULT 10,
    used_seats INTEGER DEFAULT 0,
    license_type VARCHAR(50) DEFAULT 'basic',
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'user', -- 'master_admin', 'org_admin', 'user'
    license_key VARCHAR(255) UNIQUE,
    status VARCHAR(20) DEFAULT 'active',
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Licenses table
CREATE TABLE licenses (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    license_key VARCHAR(255) NOT NULL UNIQUE,
    license_type VARCHAR(50) NOT NULL, -- 'basic', 'premium', 'enterprise'
    features JSONB, -- JSON array of enabled features
    expiry_date TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sensitive data patterns table
CREATE TABLE sensitive_patterns (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    pattern_name VARCHAR(100) NOT NULL,
    regex_pattern TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs table
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sensitive data detections table
CREATE TABLE sensitive_detections (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    content_hash VARCHAR(64), -- SHA-256 hash of content
    detected_patterns JSONB, -- Array of detected pattern names
    severity VARCHAR(20),
    url TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action_taken VARCHAR(50) DEFAULT 'warned' -- 'warned', 'blocked', 'logged'
);

-- Insert default sensitive patterns
INSERT INTO sensitive_patterns (organization_id, pattern_name, regex_pattern, description, severity) VALUES
(NULL, 'Credit Card', '\b(?:\d{4}[-\s]?){3}\d{4}\b', 'Credit card numbers', 'high'),
(NULL, 'SSN', '\b\d{3}-\d{2}-\d{4}\b', 'Social Security Numbers', 'critical'),
(NULL, 'Email', '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email addresses', 'medium'),
(NULL, 'Phone', '\b\d{3}-\d{3}-\d{4}\b|$$\d{3}$$\s?\d{3}-\d{4}', 'Phone numbers', 'low'),
(NULL, 'API Key', '\b[A-Za-z0-9]{32,}\b', 'Potential API keys', 'high'),
(NULL, 'Password', '(?i)(password|pwd|pass)\s*[:=]\s*\S+', 'Password fields', 'critical');

-- Create indexes
CREATE INDEX idx_users_org_id ON users(organization_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_licenses_org_id ON licenses(organization_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_org_id ON audit_logs(organization_id);
CREATE INDEX idx_sensitive_detections_user_id ON sensitive_detections(user_id);
