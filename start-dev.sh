#!/bin/bash

echo "Starting Enterprise Extension System..."

# Start backend
echo "Starting backend server..."
cd backend
npm start &
BACKEND_PID=$!

# Start frontend
echo "Starting frontend..."
cd ..
pnpm dev &
FRONTEND_PID=$!

echo "Backend running on http://localhost:3000"
echo "Frontend running on http://localhost:3001"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for interrupt
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait