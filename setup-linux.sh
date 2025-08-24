#!/bin/bash

echo "Setting up Enterprise Extension Backend on Linux..."

# Install Node.js if not present
if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# Install PostgreSQL
if ! command -v psql &> /dev/null; then
    echo "Installing PostgreSQL..."
    sudo apt-get update
    sudo apt-get install -y postgresql postgresql-contrib
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
fi

# Install Redis
if ! command -v redis-cli &> /dev/null; then
    echo "Installing Redis..."
    sudo apt-get install -y redis-server
    sudo systemctl start redis-server
    sudo systemctl enable redis-server
fi

# Setup backend
echo "Installing backend dependencies..."
cd backend
npm install

echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Create database: sudo -u postgres createdb extension_db"
echo "2. Run schema: sudo -u postgres psql -d extension_db -f ../database/schema.sql"
echo "3. Update backend/.env with your credentials"
echo "4. Start server: npm start"