use axum::Router;

pub mod auth;
pub mod notes;

pub fn create_router() -> Router {
    Router::new().merge(auth::router()).merge(notes::router())
}
