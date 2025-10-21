# ================================
# Stage 1: Build Environment
# ================================
FROM rust:1.83-bookworm AS builder

# Install required dependencies for diesel and postgres
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy dependency manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy the actual source code
COPY . .

# Build the application with full optimizations
# Touch main.rs to ensure it's rebuilt even though we cached deps
RUN touch src/main.rs && \
    cargo build --release --locked

# Strip the binary to reduce size
RUN strip /app/target/release/ferrite

# ================================
# Stage 2: Runtime Environment
# ================================
FROM gcr.io/distroless/cc-debian12:nonroot

# Metadata labels
LABEL maintainer="ferrite-team" \
      description="Ferrite - Fast, type-safe backend service" \
      version="0.1.0"

# Copy only the compiled binary from builder
COPY --from=builder /app/target/release/ferrite /usr/local/bin/ferrite

# Copy migration files for runtime database setup
COPY --from=builder --chown=nonroot:nonroot /app/migrations /app/migrations

# Set working directory
WORKDIR /app

# Distroless images run as nonroot user (UID 65532) by default
# This provides additional security by not running as root
USER nonroot:nonroot

# Expose the application port
EXPOSE 8080

# Health check to ensure the service is running
# Note: Distroless doesn't include curl/wget, so we rely on container orchestration health checks
# or use a TCP check instead

# Set environment variables for production
ENV RUST_LOG=info \
    RUST_BACKTRACE=1

# Run the application
ENTRYPOINT ["/usr/local/bin/ferrite"]
