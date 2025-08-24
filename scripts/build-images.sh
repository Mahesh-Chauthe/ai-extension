#!/bin/bash

# Build Docker Images for Enterprise Extension System

set -e

echo "🐳 Building Docker images for Enterprise Extension System"

# Build backend image
echo "📦 Building backend image..."
docker build -f docker/Dockerfile.backend -t extension-backend:latest .

# Build frontend image
echo "🌐 Building frontend image..."
docker build -f docker/Dockerfile.frontend -t extension-frontend:latest .

echo "✅ Docker images built successfully!"
echo "📋 Available images:"
docker images | grep extension-

echo ""
echo "🚀 Next steps:"
echo "   1. Push images to your registry (if using remote cluster)"
echo "   2. Run ./scripts/deploy.sh to deploy to Kubernetes"