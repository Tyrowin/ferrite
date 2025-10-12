use std::{num::NonZeroU32, time::Duration};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::http::StatusCode;
use axum::{
    Extension, Json, Router, middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel_async::RunQueryDsl;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::db::PgPool;
use crate::models::user::{
    NewUser, User, ensure_valid_email, ensure_valid_password, ensure_valid_username,
};
use crate::schema::users::dsl::{email as users_email, users};
use crate::security::auth::{JwtAuthError, issue_token};
use crate::security::json::ValidatedJson;
use crate::security::rate_limit::{RateLimiterState, enforce_rate_limit};

pub fn router() -> Router {
    Router::new()
        .route(
            "/auth/register",
            post(register).layer(middleware::from_fn_with_state(
                RateLimiterState::new(
                    NonZeroU32::new(5).expect("burst must be non-zero"),
                    Duration::from_secs(5 * 60),
                ),
                enforce_rate_limit,
            )),
        )
        .route(
            "/auth/login",
            post(login).layer(middleware::from_fn_with_state(
                RateLimiterState::new(
                    NonZeroU32::new(10).expect("burst must be non-zero"),
                    Duration::from_secs(60),
                ),
                enforce_rate_limit,
            )),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

impl RegisterRequest {
    fn validate(&mut self) -> Result<(), String> {
        self.username = self.username.trim().to_string();
        ensure_valid_username(&self.username).map_err(|err| err.to_string())?;

        self.email = self.email.trim().to_lowercase();
        ensure_valid_email(&self.email).map_err(|err| err.to_string())?;

        ensure_valid_password(&self.password).map_err(|err| err.to_string())?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    email: String,
    password: String,
}

impl LoginRequest {
    fn validate(&mut self) -> Result<(), String> {
        self.email = self.email.trim().to_lowercase();
        ensure_valid_email(&self.email).map_err(|err| err.to_string())?;

        if self.password.trim().is_empty() {
            return Err("password must not be empty".to_string());
        }

        if self.password.chars().count() > 256 {
            return Err("password must not exceed 256 characters".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    token: String,
    user: User,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Error)]
pub enum AuthRouteError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("resource conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("connection pool error: {0}")]
    Pool(String),
    #[error("invalid email or password")]
    InvalidCredentials,
    #[error("failed to hash password: {0}")]
    PasswordHashing(String),
    #[error(transparent)]
    Jwt(#[from] JwtAuthError),
}

impl IntoResponse for AuthRouteError {
    fn into_response(self) -> Response {
        match self {
            AuthRouteError::Jwt(err) => err.into_response(),
            AuthRouteError::Validation(message) => error_response(StatusCode::BAD_REQUEST, message),
            AuthRouteError::Conflict(message) => error_response(StatusCode::CONFLICT, message),
            AuthRouteError::Database(message) => {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
            }
            AuthRouteError::Pool(message) => {
                error_response(StatusCode::SERVICE_UNAVAILABLE, message)
            }
            AuthRouteError::InvalidCredentials => error_response(
                StatusCode::UNAUTHORIZED,
                "invalid email or password".to_string(),
            ),
            AuthRouteError::PasswordHashing(message) => {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
            }
        }
    }
}

fn error_response(status: StatusCode, message: String) -> Response {
    let body = Json(ErrorResponse { error: message });
    (status, body).into_response()
}

pub async fn register(
    Extension(pool): Extension<PgPool>,
    ValidatedJson(mut payload): ValidatedJson<RegisterRequest>,
) -> Result<impl IntoResponse, AuthRouteError> {
    payload
        .validate()
        .map_err(|err| AuthRouteError::Validation(err.to_string()))?;

    let RegisterRequest {
        username,
        email,
        password,
    } = payload;

    let password_hash = {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|err| AuthRouteError::PasswordHashing(err.to_string()))?
            .to_string()
    };

    let mut new_user = NewUser {
        username,
        email,
        password_hash,
    };

    new_user
        .validate()
        .map_err(|err| AuthRouteError::Validation(err.to_string()))?;

    let mut conn = pool
        .get()
        .await
        .map_err(|err| AuthRouteError::Pool(err.to_string()))?;

    let user: User = diesel::insert_into(users)
        .values(&new_user)
        .get_result(&mut conn)
        .await
        .map_err(map_diesel_error)?;

    let token = issue_token(user.id)?;

    Ok((StatusCode::CREATED, Json(AuthResponse { token, user })))
}

pub async fn login(
    Extension(pool): Extension<PgPool>,
    ValidatedJson(mut payload): ValidatedJson<LoginRequest>,
) -> Result<impl IntoResponse, AuthRouteError> {
    payload.validate().map_err(AuthRouteError::Validation)?;

    let normalized_email = payload.email.clone();

    let mut conn = pool
        .get()
        .await
        .map_err(|err| AuthRouteError::Pool(err.to_string()))?;

    let user: User = users
        .filter(users_email.eq(&normalized_email))
        .first(&mut conn)
        .await
        .map_err(|err| match err {
            DieselError::NotFound => AuthRouteError::InvalidCredentials,
            other => AuthRouteError::Database(other.to_string()),
        })?;

    let password_hash =
        PasswordHash::new(&user.password_hash).map_err(|_| AuthRouteError::InvalidCredentials)?;

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &password_hash)
        .map_err(|_| AuthRouteError::InvalidCredentials)?;

    let token = issue_token(user.id)?;

    Ok((StatusCode::OK, Json(AuthResponse { token, user })))
}

fn map_diesel_error(error: DieselError) -> AuthRouteError {
    match error {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
            let constraint = info.constraint_name().unwrap_or("unique constraint");
            AuthRouteError::Conflict(format!("duplicate value violates {}", constraint))
        }
        other => AuthRouteError::Database(other.to_string()),
    }
}
