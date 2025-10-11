mod db;
mod models;
mod routes;
mod schema;
mod security;

use std::net::SocketAddr;

use axum::{Extension, Router, extract::DefaultBodyLimit, middleware, serve};
use db::establish_pool;
use routes::create_router;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let pool = establish_pool().await;

    let router: Router = create_router()
        .layer(middleware::from_fn(security::headers::set_security_headers))
        .layer(DefaultBodyLimit::max(security::json::MAX_BODY_SIZE_BYTES))
        .layer(Extension(pool.clone()));

    let app = router.into_make_service_with_connect_info::<SocketAddr>();

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr).await?;

    serve(listener, app).await?;

    Ok(())
}
