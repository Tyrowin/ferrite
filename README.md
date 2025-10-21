# Ferrite

A fast, type-safe backend service built with Rust, Axum, and Diesel. Secure APIs for notes, bookmarks, and todos.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Development](#development)
- [Security](#security)
- [Testing](#testing)

## Features

- 🚀 High-performance Rust backend with Axum
- 🔒 Type-safe database operations with Diesel
- 🐳 Production-ready Docker setup with multi-stage builds
- 🛡️ Security-hardened distroless runtime image (no default credentials!)
- 📦 Docker Compose orchestration for local development
- 🔐 JWT authentication with mandatory secret configuration
- 📊 PostgreSQL database
- 🔒 Environment-based configuration (no hardcoded secrets)

## Quick Start

### Local Development (Without Docker)

1. **Install Dependencies**

   ```bash
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

   # Install Diesel CLI
   cargo install diesel_cli --no-default-features --features postgres
   ```

2. **Setup Database**

   ```bash
   # Start PostgreSQL (or use Docker Compose)
   docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine

   # Run migrations
   diesel migration run
   ```

3. **Configure Environment**

   ```bash
   # REQUIRED: Create .env file from example
   cp .env.example .env

   # Edit .env and set secure values:
   # - DATABASE_URL with your PostgreSQL credentials
   # - JWT_SECRET (minimum 32 characters)
   # Generate JWT secret: openssl rand -base64 32
   ```

4. **Run the Application**
   ```bash
   cargo run --release
   ```

### Quick Start with Docker Compose (Recommended)

**IMPORTANT: Security Setup Required**

Before running, you MUST create a `.env` file with your secure credentials:

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and set secure values for:
# - POSTGRES_USER
# - POSTGRES_PASSWORD
# - JWT_SECRET (minimum 32 characters)
# NEVER use the example values in production!
```

Generate secure secrets:

```bash
# Generate a strong JWT secret
openssl rand -base64 32

# Generate a strong password
pwgen -s 32 1
# Or on Windows PowerShell:
# [System.Web.Security.Membership]::GeneratePassword(32,10)
```

Then start the services:

```bash
# Start all services (backend + database)
docker-compose up -d

# View logs
docker-compose logs -f ferrite

# Stop services
docker-compose down
```

## Docker Deployment

### Multi-Stage Dockerfile Architecture

The project uses a secure two-stage build process:

**Stage 1: Build** (`rust:1.83-bookworm`)

- Compiles Rust application with full optimizations
- Leverages layer caching for dependencies
- Strips binary to reduce size

**Stage 2: Runtime** (`distroless/cc-debian12:nonroot`)

- Minimal image with only runtime dependencies
- No shell, package manager, or unnecessary tools
- Runs as non-root user (UID 65532)
- Significantly reduced attack surface

### Security Features

- ✅ Non-root user (UID 65532)
- ✅ Distroless base image
- ✅ Stripped binary
- ✅ No privilege escalation
- ✅ Minimal attack surface

### Build and Run

#### Build Docker Image

```bash
# Build the image
docker build -t ferrite:latest .

# Build with specific Rust version
docker build --build-arg RUST_VERSION=1.83 -t ferrite:latest .
```

#### Run with Docker Compose

```bash
# Start all services
docker-compose up -d

# Start with PgAdmin for database management
docker-compose --profile tools up -d

# View logs
docker-compose logs -f ferrite

# Stop services
docker-compose down

# Remove volumes (WARNING: deletes data)
docker-compose down -v
```

#### Run Standalone Container

```bash
# SECURITY: Never use these example values!
# Set real credentials in your environment or .env file
docker run -d \
  --name ferrite-backend \
  -p 8080:8080 \
  -e DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@host:5432/${POSTGRES_DB}" \
  -e JWT_SECRET="${JWT_SECRET}" \
  -e RUST_LOG=info \
  ferrite:latest
```

### Docker Compose Services

**PostgreSQL Database**

- Image: `postgres:16-alpine`
- Port: 5432
- Persistent volume for data
- Health checks enabled

**Ferrite Backend**

- Multi-stage build from Dockerfile
- Port: 8080
- Waits for healthy database
- Non-root user with security hardening

**PgAdmin (Optional)**

- Port: 5050
- Access: http://localhost:5050
- Start with: `docker-compose --profile tools up`

### Environment Configuration

**SECURITY CRITICAL: All values are REQUIRED**

1. Copy the example file:

   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and provide secure values:

```bash
# Database - Use strong credentials
POSTGRES_USER=your_db_username
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=ferrite
POSTGRES_PORT=5432

# Application
APP_PORT=8080
HOST=0.0.0.0
PORT=8080

# JWT Secret - MUST be at least 32 characters
# Generate with: openssl rand -base64 32
JWT_SECRET=your_secure_jwt_secret_at_least_32_characters

# Logging
RUST_LOG=info,ferrite=debug
RUST_BACKTRACE=1

# PgAdmin (only if using --profile tools)
PGADMIN_EMAIL=admin@ferrite.local
PGADMIN_PASSWORD=your_pgadmin_password
PGADMIN_PORT=5050
```

**Security Best Practices:**

- ✅ Never commit `.env` files to version control
- ✅ Use strong, randomly generated passwords
- ✅ Generate JWT secret: `openssl rand -base64 32`
- ✅ Rotate secrets regularly
- ✅ Set restrictive file permissions: `chmod 600 .env`
- ✅ Use different credentials for dev/staging/production

### Database Migrations in Docker

```bash
# Option 1: Using diesel CLI in container with environment variables
docker run --rm \
  --network ferrite_ferrite-network \
  -v $(pwd)/migrations:/migrations \
  -e DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}" \
  rust:1.83-bookworm \
  bash -c "cargo install diesel_cli --no-default-features --features postgres && diesel migration run"

# Option 2: Exec into running container
docker-compose exec ferrite /bin/sh
```

## Development

### Prerequisites

- Rust 1.83 or higher
- PostgreSQL 12+
- Diesel CLI: `cargo install diesel_cli --no-default-features --features postgres`

### Project Structure

```
ferrite/
├── src/
│   ├── main.rs              # Application entry point
│   ├── db.rs                # Database connection
│   ├── errors.rs            # Error handling
│   ├── models/              # Data models
│   ├── routes/              # API routes
│   └── security/            # Security middleware
├── migrations/              # Database migrations
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Local development orchestration
└── .env                     # Environment variables
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with coverage
cargo test --all-features

# Run in Docker
docker build --target builder -t ferrite:test .
docker run --rm ferrite:test cargo test
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint code
cargo clippy --all-targets --all-features -- -D warnings

# Run security audit
cargo audit
```

## Security

⚠️ **IMPORTANT: No Default Credentials**

Ferrite requires explicit configuration of all security-sensitive environment variables. The application will NOT start with defaults.

**Required:** See [SECURITY.md](SECURITY.md) for comprehensive security guidelines.

### Quick Security Setup

1. **Create environment file:**

   ```bash
   cp .env.example .env
   ```

2. **Generate secure secrets:**

   ```bash
   # JWT Secret (minimum 32 characters)
   openssl rand -base64 32

   # Strong password
   pwgen -s 32 1
   ```

3. **Edit `.env` with your secrets** (NEVER commit this file!)

### Security Tooling

**Dependency Auditing**

- Install: `cargo install --locked cargo-audit`
- Run: `cargo audit` from repository root
- The `audit.toml` enforces database freshness and fails on warnings
- To silence specific advisories, add `RUSTSEC-` ID in `audit.toml`

**Static Analysis**

- Run `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery -W clippy::future_not_send -W clippy::print_stdout -W clippy::print_stderr -W clippy::dbg_macro`
- `clippy.toml` bans `unwrap`/`expect`, unchecked indexing, and `dbg!` usage

### Production Security Checklist

- [ ] Generate strong, unique JWT_SECRET (32+ characters)
- [ ] Use secure database passwords (16+ characters)
- [ ] Never commit `.env` files to version control
- [ ] Keep base images updated regularly
- [ ] Run security scans: `docker scan ferrite:latest`
- [ ] Enable HTTPS/TLS in production
- [ ] Configure rate limiting at reverse proxy
- [ ] Set up monitoring and security alerts
- [ ] Use Docker secrets or vault in production
- [ ] Rotate credentials regularly

For detailed security practices, see [SECURITY.md](SECURITY.md).

## Testing

### Unit Tests

```bash
cargo test
```

### Integration Tests

```bash
cargo test --test '*'
```

### Load Testing

```bash
# Example with wrk
wrk -t4 -c100 -d30s http://localhost:8080/health
```

## Monitoring

### Docker Health Checks

```bash
# Check container status
docker-compose ps

# View resource usage
docker stats

# Check logs
docker-compose logs -f
```

### Database Backup

```bash
# Export
docker-compose exec postgres pg_dump -U postgres ferrite > backup.sql

# Restore
docker-compose exec -T postgres psql -U postgres ferrite < backup.sql
```

## Troubleshooting

### Common Issues

**Database connection errors**

```bash
# Check PostgreSQL health
docker-compose ps postgres

# Verify DATABASE_URL in .env
echo $DATABASE_URL
```

**Build failures**

```bash
# Clear build cache
cargo clean
docker builder prune

# Rebuild without cache
docker build --no-cache -t ferrite:latest .
```

**Permission errors in Docker**

- Ensure migrations directory is readable
- Check volume mount permissions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

See [LICENSE](LICENSE) file for details.
