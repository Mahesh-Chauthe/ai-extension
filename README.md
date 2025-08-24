# Enterprise Security Extension System

Advanced enterprise extension with sensitive data detection, organization management, and comprehensive security monitoring.

## Features

- **Sensitive Data Detection**: AI-powered detection of PII, financial data, and confidential information
- **Organization Management**: Multi-tenant architecture with role-based access control
- **Real-time Monitoring**: Live monitoring of web content and user activities
- **License Management**: Flexible licensing system with seat management
- **Audit Logging**: Comprehensive audit trails for compliance
- **Browser Extension**: Chrome extension for real-time protection

## Architecture

- **Frontend**: Next.js 15 with TypeScript and Tailwind CSS
- **Backend**: Node.js with Express.js
- **Database**: PostgreSQL with Redis caching
- **AI Integration**: OpenAI API for advanced content analysis
- **Extension**: Chrome Extension Manifest V3

## Prerequisites

- Node.js 18+ and pnpm
- PostgreSQL 13+
- Redis 6+
- OpenAI API key (optional, for AI features)

## Quick Start

### 1. Install Dependencies

```bash
pnpm install
```

### 2. Setup Database

```bash
# Start PostgreSQL and Redis
# Windows (using chocolatey):
choco install postgresql redis

# Or use Docker:
docker run --name postgres -e POSTGRES_PASSWORD=password123 -p 5432:5432 -d postgres:13
docker run --name redis -p 6379:6379 -d redis:6-alpine
```

Create the database:
```bash
createdb extension_db
psql -d extension_db -f database/schema.sql
```

### 3. Configure Environment

Copy `.env.example` to `.env` and update values:
```bash
cp .env.example .env
```

Update the following in `.env`:
- `DATABASE_URL`: Your PostgreSQL connection string
- `REDIS_URL`: Your Redis connection string
- `JWT_SECRET`: A secure random string
- `OPENAI_API_KEY`: Your OpenAI API key (optional)

### 4. Start Development Servers

Start the backend server:
```bash
node backend/server.js
```

Start the frontend (in a new terminal):
```bash
pnpm dev
```

### 5. Load Browser Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `extension/` folder
4. The extension icon should appear in your toolbar

## Usage

### Web Dashboard

1. Open http://localhost:3001 in your browser
2. View system status and analytics
3. Configure organization settings

### Browser Extension

1. Click the extension icon in your browser toolbar
2. Sign in with your organization credentials
3. The extension will monitor pages for sensitive data
4. Click "Analyze Page" to manually scan current page

### API Endpoints

- `POST /api/auth/login` - User authentication
- `POST /api/license/validate` - License validation
- `POST /api/analyze/sensitive-data` - Content analysis
- `GET /api/analytics/dashboard` - Analytics data

## Development

### Project Structure

```
├── app/                    # Next.js app directory
├── backend/               # Express.js backend
├── components/            # React components
├── database/             # Database schema and migrations
├── extension/            # Chrome extension files
├── hooks/               # React hooks
├── lib/                 # Utility functions
├── public/              # Static assets
└── styles/              # CSS styles
```

### Adding New Features

1. Backend: Add routes in `backend/server.js`
2. Frontend: Create components in `components/`
3. Extension: Update `extension/` files
4. Database: Add migrations to `database/`

## Deployment

### Using Docker

Build images:
```bash
docker build -f docker/Dockerfile.backend -t extension-backend .
docker build -f docker/Dockerfile.frontend -t extension-frontend .
```

### Using Kubernetes

Deploy to Kubernetes:
```bash
kubectl apply -f kubernetes/
```

### Manual Deployment

1. Build the frontend: `pnpm build`
2. Start the backend: `NODE_ENV=production node backend/server.js`
3. Serve the frontend: `pnpm start`

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |
| `JWT_SECRET` | JWT signing secret | - |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `PORT` | Backend server port | 3000 |
| `SENSITIVE_DATA_THRESHOLD` | Detection threshold (0-1) | 0.5 |

### Sensitive Data Patterns

Default patterns include:
- Credit card numbers
- Social Security Numbers
- Email addresses
- Phone numbers
- API keys
- Passwords

Add custom patterns via the database or API.

## Security

- All API endpoints require JWT authentication
- Passwords are hashed using bcrypt
- Rate limiting on all endpoints
- CORS and security headers configured
- Content Security Policy implemented

## License

This project is licensed under the MIT License.

## Support

For support and questions:
- Create an issue on GitHub
- Contact: support@extension-system.com
- Documentation: https://docs.extension-system.com