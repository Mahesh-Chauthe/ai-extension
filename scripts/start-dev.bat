@echo off
echo Starting Enterprise Extension System in Development Mode...
echo.

REM Check if .env exists
if not exist ".env" (
    echo Error: .env file not found. Please run setup.bat first.
    pause
    exit /b 1
)

REM Start backend in background
echo Starting backend server...
start "Backend Server" cmd /k "node backend/server.js"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend
echo Starting frontend development server...
start "Frontend Server" cmd /k "pnpm dev"

echo.
echo Development servers are starting...
echo.
echo Backend: http://localhost:3000
echo Frontend: http://localhost:3001
echo.
echo To load the browser extension:
echo 1. Open Chrome and go to chrome://extensions/
echo 2. Enable "Developer mode"
echo 3. Click "Load unpacked" and select the extension/ folder
echo.
echo Press any key to exit...
pause >nul