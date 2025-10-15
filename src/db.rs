use std::time::Duration;

use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use dotenvy::dotenv;

pub type PgPool = Pool<AsyncPgConnection>;

#[tracing::instrument(name = "database_pool_setup")]
pub async fn establish_pool() -> PgPool {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set before creating a connection pool");

    tracing::debug!("Initializing database connection pool");

    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);

    let pool = Pool::builder()
        .max_size(16)
        .min_idle(Some(4))
        .connection_timeout(Duration::from_secs(5))
        .idle_timeout(Some(Duration::from_secs(600)))
        .max_lifetime(Some(Duration::from_secs(3600)))
        .build(manager)
        .await
        .expect("failed to create database connection pool");

    tracing::info!(
        max_size = 16,
        min_idle = 4,
        connection_timeout_secs = 5,
        "Database connection pool established"
    );

    pool
}
