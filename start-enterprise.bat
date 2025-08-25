@echo off
echo Starting Enterprise Security System...
echo.

cd /d "%~dp0"

echo Installing dependencies...
call npm install express cors jsonwebtoken bcrypt

echo.
echo Starting API server on port 8080...
start "Enterprise API" cmd /k "node test-server.js"

timeout /t 3 /nobreak >nul

echo Opening Master Portal...
start "" "master-portal-local.html"

timeout /t 2 /nobreak >nul

echo Opening Organization Portal...
start "" "org-portal-local.html"

echo.
echo ========================================
echo Enterprise System Started Successfully!
echo ========================================
echo.
echo API Server: http://localhost:8080
echo Master Portal: master-portal-local.html
echo Organization Portal: org-portal-local.html
echo.
echo Login credentials:
echo Master Portal: master@company.com / SecurePass2024!
echo.
echo Organization tokens will be displayed in the API console
echo ========================================
pause