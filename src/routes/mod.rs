use axum::Router;

pub mod auth;
pub mod notes;

pub fn create_router() -> Router {
    tracing::debug!("Creating application router");
    Router::new().merge(auth::router()).merge(notes::router())
}
