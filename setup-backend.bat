@echo off
echo Setting up Enterprise Extension Backend...

echo.
echo Step 1: Installing backend dependencies...
cd backend
npm install

echo.
echo Step 2: Setting up database (PostgreSQL required)...
echo Please ensure PostgreSQL is running and create database 'extension_db'
echo Run: createdb extension_db
echo Then: psql -d extension_db -f ../database/schema.sql

echo.
echo Step 3: Update .env file with your database credentials
echo Edit backend/.env file with your actual database URL and API keys

echo.
echo Setup complete! To start the server:
echo cd backend
echo npm start

pause