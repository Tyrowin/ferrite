# Security Policy

## Overview

Ferrite takes security seriously. This document outlines security best practices and configuration requirements.

## Environment Variables Security

### Critical: No Default Credentials

**All environment variables MUST be explicitly set.** The application will NOT start with default or hardcoded credentials.

Required environment variables:

- `POSTGRES_USER` - Database username
- `POSTGRES_PASSWORD` - Database password (strong password required)
- `POSTGRES_DB` - Database name
- `JWT_SECRET` - JWT signing secret (minimum 32 characters)

### Setting Up Secure Environment

1. **Never commit `.env` files** to version control

   - The `.gitignore` is configured to block `.env` files
   - Only `.env.example` (with no real credentials) should be committed

2. **Generate strong secrets:**

   ```bash
   # Generate JWT secret (Linux/Mac)
   openssl rand -base64 32

   # Generate strong password (Linux)
   pwgen -s 32 1

   # Generate password (Windows PowerShell)
   [System.Web.Security.Membership]::GeneratePassword(32,10)
   ```

3. **Set restrictive file permissions:**

   ```bash
   # Linux/Mac
   chmod 600 .env

   # Ensure only owner can read/write
   ls -la .env  # Should show: -rw-------
   ```

4. **Use different credentials per environment:**
   - Development: `.env.dev`
   - Staging: `.env.staging`
   - Production: `.env.production`
   - Never reuse credentials across environments

## Docker Security

### Container Security Features

✅ **Non-root user**: All containers run as non-root (UID 65532)
✅ **Distroless base**: Minimal attack surface, no shell or package manager
✅ **No new privileges**: Containers cannot escalate privileges
✅ **Health checks**: Automatic monitoring and restart
✅ **Network isolation**: Services communicate on isolated Docker network

### Production Deployment Checklist

- [ ] Set strong, unique `POSTGRES_PASSWORD` (32+ characters)
- [ ] Set strong, unique `JWT_SECRET` (32+ characters minimum)
- [ ] Set strong, unique `PGADMIN_PASSWORD` if using PgAdmin
- [ ] Use different credentials than development
- [ ] Enable TLS/SSL for database connections
- [ ] Configure firewall rules to restrict access
- [ ] Use Docker secrets for sensitive data (Swarm/Kubernetes)
- [ ] Enable Docker Content Trust (image signing)
- [ ] Regularly update base images and dependencies
- [ ] Monitor logs for suspicious activity
- [ ] Set up automated backups
- [ ] Implement rate limiting at reverse proxy level

## JWT Security

### JWT Secret Requirements

- **Minimum length**: 32 characters (256 bits)
- **Recommended length**: 64 characters (512 bits)
- **Character set**: Use base64 or random alphanumeric
- **Rotation**: Rotate JWT secrets regularly (e.g., every 90 days)

### Example Generation

```bash
# Good: 32 bytes = 256 bits
openssl rand -base64 32

# Better: 64 bytes = 512 bits
openssl rand -base64 64
```

## Database Security

### Password Requirements

- Minimum 16 characters
- Mix of uppercase, lowercase, numbers, and special characters
- No dictionary words or common patterns
- Unique per environment

### Connection Security

For production, enable SSL/TLS in PostgreSQL:

```yaml
# docker-compose.yml - Production database
environment:
  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
  POSTGRES_INITDB_ARGS: "--ssl=on"
```

Update connection string:

```
DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=require
```

## Secrets Management

### For Production Environments

**Do NOT use `.env` files in production.** Instead, use:

1. **Docker Secrets** (Docker Swarm):

   ```bash
   echo "my_secret" | docker secret create jwt_secret -
   ```

2. **Kubernetes Secrets**:

   ```bash
   kubectl create secret generic ferrite-secrets \
     --from-literal=jwt-secret='your_secret' \
     --from-literal=db-password='your_password'
   ```

3. **Cloud Provider Secret Managers**:

   - AWS Secrets Manager
   - Azure Key Vault
   - Google Cloud Secret Manager
   - HashiCorp Vault

4. **Environment Variables via Orchestrator**:
   - Injected at runtime
   - Never stored in images or version control

## Security Updates

### Keeping Dependencies Updated

```bash
# Check for Rust security advisories
cargo audit

# Update dependencies
cargo update

# Rebuild Docker images regularly
docker-compose build --no-cache
```

### Base Image Updates

The project uses:

- `rust:1.83-bookworm` (builder)
- `gcr.io/distroless/cc-debian12:nonroot` (runtime)

Update regularly for security patches.

## Reporting Security Issues

If you discover a security vulnerability, please email the maintainers directly rather than opening a public issue.

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)

## Compliance

This project follows:

- OWASP Application Security Verification Standard (ASVS)
- CIS Docker Benchmark
- Rust Security Working Group guidelines
