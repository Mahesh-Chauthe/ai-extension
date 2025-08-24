#!/bin/bash

# Enterprise Extension System Deployment Script

set -e

echo "🚀 Starting Enterprise Extension System Deployment"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is not installed. Please install kubectl first."
    exit 1
fi

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to Kubernetes cluster. Please check your kubeconfig."
    exit 1
fi

echo "✅ Kubernetes cluster is accessible"

# Build Docker images
echo "🐳 Building Docker images..."
./scripts/build-images.sh

# Create namespace
echo "📦 Creating namespace..."
kubectl apply -f kubernetes/namespace.yaml

# Apply ConfigMaps and Secrets
echo "🔧 Applying configuration..."
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/secrets.yaml

# Deploy databases
echo "🗄️ Deploying databases..."
kubectl apply -f kubernetes/postgres-deployment.yaml
kubectl apply -f kubernetes/redis-deployment.yaml

# Wait for databases to be ready
echo "⏳ Waiting for databases to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/postgres -n extension-system
kubectl wait --for=condition=available --timeout=300s deployment/redis -n extension-system

# Initialize database
echo "🔄 Initializing database..."
kubectl create configmap db-schema --from-file=database/schema.sql -n extension-system --dry-run=client -o yaml | kubectl apply -f -

# Run database migrations
echo "📊 Running database migrations..."
kubectl run db-migration --image=postgres:15 --rm -i --restart=Never -n extension-system \
  --env="PGPASSWORD=password123" \
  --overrides='{
    "spec": {
      "containers": [{
        "name": "db-migration",
        "image": "postgres:15",
        "command": ["sh", "-c"],
        "args": ["until pg_isready -h postgres-service -p 5432; do sleep 2; done && psql -h postgres-service -U postgres -d extension_db -f /schema/schema.sql"],
        "volumeMounts": [{
          "name": "schema",
          "mountPath": "/schema"
        }]
      }],
      "volumes": [{
        "name": "schema",
        "configMap": {
          "name": "db-schema"
        }
      }]
    }
  }' -- sleep 30

# Deploy backend
echo "🖥️ Deploying backend API..."
kubectl apply -f kubernetes/backend-deployment.yaml

# Deploy frontend
echo "🌐 Deploying frontend..."
kubectl apply -f kubernetes/frontend-deployment.yaml

# Apply HPA
echo "📈 Setting up auto-scaling..."
kubectl apply -f kubernetes/hpa.yaml

# Apply ingress
echo "🌍 Setting up ingress..."
kubectl apply -f kubernetes/ingress.yaml

# Wait for deployments
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/backend-api -n extension-system
kubectl wait --for=condition=available --timeout=300s deployment/admin-dashboard -n extension-system

echo "✅ Deployment completed successfully!"

# Display status
echo "📊 Deployment Status:"
kubectl get pods -n extension-system
kubectl get services -n extension-system
kubectl get ingress -n extension-system

echo ""
echo "🎉 Enterprise Extension System is now deployed!"
echo "📝 Next steps:"
echo "   1. Configure DNS to point to your ingress IP"
echo "   2. Set up SSL certificates"
echo "   3. Create your first organization and users"
echo "   4. Build and publish the browser extension"
echo ""
echo "🔗 Access URLs:"
echo "   API: https://api.extension-system.com"
echo "   Admin Dashboard: https://admin.extension-system.com"
