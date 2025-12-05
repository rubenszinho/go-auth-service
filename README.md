# Go Auth Service

A modern, production-ready authentication microservice built with Go. Provides JWT-based authentication with OAuth 2.0 support for Google, GitHub, and Microsoft providers.

## Overview

This service handles user authentication and authorization for SaaS applications. It's designed to work as a standalone microservice that can be integrated with other backend services (e.g., Python backends) through its REST API.

### Key Features

- **JWT Authentication** - Access and refresh token management with configurable expiry
- **OAuth 2.0 Integration** - Support for Google, GitHub, and Microsoft providers
- **User Management** - Registration, login, profile management, and password handling
- **Role-Based Access Control** - User roles (user, admin, super) with middleware protection
- **Email Domain Filtering** - Optional restriction to specific email domains
- **Session Management** - Secure session handling with refresh token rotation
- **CORS Support** - Configurable cross-origin resource sharing
- **Structured Logging** - Production-ready logging with Zap
- **Database Migrations** - SQL-based schema migrations
- **Docker Ready** - Multi-stage build with distroless final image

## Tech Stack

- **Language**: Go 1.24
- **Framework**: Gorilla Mux (HTTP router)
- **Database**: PostgreSQL with GORM
- **Cache**: Redis (optional)
- **Authentication**: golang-jwt/jwt, golang.org/x/oauth2
- **Validation**: go-playground/validator
- **Logging**: uber-go/zap

## Project Structure

```
├── api/v1/                    # OpenAPI specification
├── cmd/
│   ├── migrate/               # Database migration CLI
│   └── server/                # Main application entry point
├── internal/
│   ├── cache/                 # Redis caching layer
│   ├── config/                # Configuration management
│   ├── database/              # Database connection and setup
│   ├── handlers/              # HTTP request handlers
│   ├── middleware/            # Auth, CORS, logging middleware
│   ├── models/                # Data models and DTOs
│   └── services/              # Business logic layer
├── migrations/                # SQL migration files
├── pkg/
│   ├── jwt/                   # JWT token management
│   └── oauth/                 # OAuth provider implementations
└── scripts/                   # Database and deployment scripts
```

## API Endpoints

### Authentication

| Method | Endpoint                | Description                |
| ------ | ----------------------- | -------------------------- |
| POST   | `/api/v1/auth/register` | Register a new user        |
| POST   | `/api/v1/auth/login`    | Login with email/password  |
| POST   | `/api/v1/auth/refresh`  | Refresh access token       |
| POST   | `/api/v1/auth/logout`   | Logout (invalidate tokens) |
| GET    | `/api/v1/auth/profile`  | Get current user profile   |

### OAuth 2.0

| Method | Endpoint                                 | Description            |
| ------ | ---------------------------------------- | ---------------------- |
| GET    | `/api/v1/auth/oauth/{provider}/login`    | Initiate OAuth flow    |
| GET    | `/api/v1/auth/oauth/{provider}/callback` | OAuth callback handler |

### User Queries (Service-to-Service)

| Method | Endpoint                    | Description                |
| ------ | --------------------------- | -------------------------- |
| GET    | `/api/v1/users/{id}`        | Get user basic info        |
| GET    | `/api/v1/users/{id}/exists` | Check if user exists       |
| POST   | `/api/v1/users/validate`    | Validate multiple user IDs |

## Configuration

The service is configured via environment variables. Create a `.env` file:

```env
# Server
PORT=8080
HOST=0.0.0.0
ENV=development
AUTH_FRONTEND_URL=http://localhost:3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=auth_service
DB_SSL_MODE=disable

# JWT
JWT_SECRET=your-super-secret-key-min-32-chars
JWT_EXPIRY=24h
JWT_REFRESH_EXPIRY=168h

# OAuth Providers (optional)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URL=http://localhost:8080/api/v1/auth/oauth/google/callback

GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URL=http://localhost:8080/api/v1/auth/oauth/github/callback

MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
MICROSOFT_REDIRECT_URL=http://localhost:8080/api/v1/auth/oauth/microsoft/callback

# Security
BCRYPT_COST=12
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
ENABLE_EMAIL_DOMAIN_FILTER=false
ALLOWED_EMAIL_DOMAINS=example.com,company.com

# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

## Getting Started

### Prerequisites

- Go 1.24+
- PostgreSQL 14+
- Redis (optional, for caching)
- Make (optional, for using Makefile commands)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/rubenszinho/go-auth-service.git
cd go-auth-service
```

2. Install dependencies:

```bash
make deps
# or
go mod download
```

3. Set up the database:

```bash
# Run migrations
make migrate
# or
go run ./cmd/migrate
```

4. Run the server:

```bash
make run
# or
go run ./cmd/server/main.go
```

### Docker

Build and run with Docker:

```bash
# Build image
make docker-build

# Run container
docker run -p 8080:8080 --env-file .env auth-service
```

## Development

### Available Make Commands

```bash
make help           # Show available commands
make deps           # Install dependencies
make build          # Build the application
make run            # Run locally
make test           # Run tests
make test-coverage  # Run tests with coverage
make lint           # Run linter
make docker-build   # Build Docker image
make docker-run     # Run Docker container
```

### Running Tests

```bash
make test
# or
go test -v ./...
```

## Authentication Flow

### Standard Login

1. Client sends credentials to `/auth/login`
2. Service validates credentials and returns access + refresh tokens
3. Client includes access token in `Authorization: Bearer <token>` header
4. On token expiry, client uses refresh token at `/auth/refresh`

### OAuth Flow

1. Client redirects to `/auth/oauth/{provider}/login`
2. User authenticates with OAuth provider
3. Provider redirects to callback URL
4. Service exchanges code for tokens and creates/updates user
5. Client receives JWT tokens

## Security Features

- **Password Hashing**: bcrypt with configurable cost
- **Token Security**: Short-lived access tokens, secure refresh token rotation
- **Email Domain Filter**: Restrict registration to specific domains
- **CORS**: Configurable allowed origins
- **Role-Based Access**: Middleware for role verification

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contact

Rubrion Team - hello@rubrion.ai
