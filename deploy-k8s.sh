#!/bin/bash

echo "Deploying to Kubernetes..."

# Build images
echo "Building Docker images..."
docker build -f docker/Dockerfile.backend -t extension-backend:latest .
docker build -f docker/Dockerfile.frontend -t extension-frontend:latest .

# Load images to minikube (if using minikube)
if command -v minikube &> /dev/null; then
    echo "Loading images to minikube..."
    minikube image load extension-backend:latest
    minikube image load extension-frontend:latest
fi

# Deploy to Kubernetes
echo "Deploying to Kubernetes..."
kubectl apply -f kubernetes/

# Wait for deployments
echo "Waiting for deployments..."
kubectl wait --for=condition=available --timeout=300s deployment/backend-api -n extension-system
kubectl wait --for=condition=available --timeout=300s deployment/admin-dashboard -n extension-system

# Show status
echo "Deployment Status:"
kubectl get pods -n extension-system

echo ""
echo "Access the application:"
echo "kubectl port-forward svc/backend-service 3000:80 -n extension-system"
echo "kubectl port-forward svc/frontend-service 3001:80 -n extension-system"