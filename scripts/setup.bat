@echo off
echo Setting up Enterprise Extension System...
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Node.js is not installed. Please install Node.js 18+ first.
    echo Download from: https://nodejs.org/
    pause
    exit /b 1
)

REM Check if pnpm is installed
pnpm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing pnpm...
    npm install -g pnpm
)

REM Install dependencies
echo Installing dependencies...
pnpm install

REM Check if .env exists
if not exist ".env" (
    echo Creating .env file from template...
    copy ".env.example" ".env"
    echo.
    echo IMPORTANT: Please update the .env file with your actual configuration values:
    echo - DATABASE_URL: Your PostgreSQL connection string
    echo - REDIS_URL: Your Redis connection string  
    echo - JWT_SECRET: A secure random string
    echo - OPENAI_API_KEY: Your OpenAI API key (optional)
    echo.
)

echo.
echo Setup complete! Next steps:
echo.
echo 1. Install and start PostgreSQL and Redis
echo 2. Create database: createdb extension_db
echo 3. Run database schema: psql -d extension_db -f database/schema.sql
echo 4. Update .env file with your configuration
echo 5. Start backend: node backend/server.js
echo 6. Start frontend: pnpm dev
echo 7. Load extension in Chrome from extension/ folder
echo.
echo For detailed instructions, see README.md
pause