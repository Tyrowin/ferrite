use std::{num::NonZeroU32, sync::OnceLock, time::Duration};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Extension, Json, Router, async_trait,
    extract::FromRequestParts,
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::{Duration as ChronoDuration, Utc};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel_async::RunQueryDsl;
use dotenvy::dotenv;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::db::PgPool;
use crate::models::user::{NewUser, User, ensure_valid_email};
use crate::schema::users::dsl::{email as users_email, users};
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
    #[error("authorization header is missing")]
    MissingAuthHeader,
    #[error("authorization header is malformed")]
    InvalidAuthHeader,
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("JWT_SECRET environment variable is not set")]
    MissingJwtSecret,
    #[error("failed to encode authentication token: {0}")]
    TokenEncoding(String),
}

impl IntoResponse for AuthRouteError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthRouteError::Validation(_) => StatusCode::BAD_REQUEST,
            AuthRouteError::Conflict(_) => StatusCode::CONFLICT,
            AuthRouteError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthRouteError::Pool(_) => StatusCode::SERVICE_UNAVAILABLE,
            AuthRouteError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AuthRouteError::MissingAuthHeader | AuthRouteError::InvalidAuthHeader => {
                StatusCode::UNAUTHORIZED
            }
            AuthRouteError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthRouteError::MissingJwtSecret | AuthRouteError::TokenEncoding(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        let body = Json(ErrorResponse {
            error: self.to_string(),
        });

        (status, body).into_response()
    }
}

pub async fn register(
    Extension(pool): Extension<PgPool>,
    ValidatedJson(mut payload): ValidatedJson<NewUser>,
) -> Result<impl IntoResponse, AuthRouteError> {
    payload
        .validate()
        .map_err(|err| AuthRouteError::Validation(err.to_string()))?;

    let mut conn = pool
        .get()
        .await
        .map_err(|err| AuthRouteError::Pool(err.to_string()))?;

    let user: User = diesel::insert_into(users)
        .values(&payload)
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

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Uuid,
    exp: usize,
    iat: usize,
}

static JWT_SECRET: OnceLock<String> = OnceLock::new();

fn issue_token(user_id: Uuid) -> Result<String, AuthRouteError> {
    let secret = jwt_secret()?;
    let now = Utc::now();
    let expires_at = now + ChronoDuration::hours(24);

    let claims = Claims {
        sub: user_id,
        iat: now.timestamp() as usize,
        exp: expires_at.timestamp() as usize,
    };

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());

    encode(&Header::new(Algorithm::HS256), &claims, &encoding_key)
        .map_err(|err| AuthRouteError::TokenEncoding(err.to_string()))
}

fn decode_token(token: &str) -> Result<Claims, AuthRouteError> {
    let secret = jwt_secret()?;
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|_| AuthRouteError::InvalidToken)
}

fn jwt_secret() -> Result<&'static String, AuthRouteError> {
    if let Some(secret) = JWT_SECRET.get() {
        return Ok(secret);
    }

    dotenv().ok();
    let value = std::env::var("JWT_SECRET").map_err(|_| AuthRouteError::MissingJwtSecret)?;
    Ok(JWT_SECRET.get_or_init(|| value))
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

#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedUser(pub Uuid);

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AuthRouteError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header_value = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthRouteError::MissingAuthHeader)?;

        let header_str = header_value
            .to_str()
            .map_err(|_| AuthRouteError::InvalidAuthHeader)?;

        let token = header_str
            .strip_prefix("Bearer ")
            .ok_or(AuthRouteError::InvalidAuthHeader)?;

        let claims = decode_token(token)?;

        Ok(AuthenticatedUser(claims.sub))
    }
}
