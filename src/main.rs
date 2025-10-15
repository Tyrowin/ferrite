mod db;
mod errors;
mod logging;
mod models;
mod routes;
mod schema;
mod security;

use std::net::SocketAddr;

use axum::{Extension, Router, extract::DefaultBodyLimit, middleware, serve};
use db::establish_pool;
use routes::create_router;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging with environment-based configuration
    init_tracing();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting Ferrite backend service"
    );

    let pool = establish_pool().await;

    let router: Router = create_router()
        .layer(middleware::from_fn(security::headers::set_security_headers))
        .layer(DefaultBodyLimit::max(security::json::MAX_BODY_SIZE_BYTES))
        .layer(Extension(pool.clone()));

    let app = router.into_make_service_with_connect_info::<SocketAddr>();

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr).await?;

    tracing::info!(
        address = %addr,
        "Server listening for connections"
    );

    serve(listener, app).await?;

    Ok(())
}

/// Initializes the tracing subscriber with structured, context-aware logging
fn init_tracing() {
    // Determine log format based on environment
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Default log levels:
        // - ferrite crate: debug in dev, info in prod
        // - dependencies: warn level
        if cfg!(debug_assertions) {
            EnvFilter::new("ferrite=debug,tower_http=debug,axum=debug,warn")
        } else {
            EnvFilter::new("ferrite=info,warn")
        }
    });

    // Configure JSON logging for production, pretty logging for development
    if cfg!(debug_assertions) {
        // Development: human-readable logs with colors and timestamps
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true)
                    .with_file(true)
                    .pretty(),
            )
            .init();
    } else {
        // Production: JSON logs for structured logging platforms
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_line_number(false)
                    .with_file(false)
                    .json(),
            )
            .init();
    }
}
