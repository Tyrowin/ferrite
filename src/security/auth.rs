use std::{collections::HashSet, sync::OnceLock};

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{Request, StatusCode, header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedUser(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Error)]
pub enum JwtAuthError {
    #[error("authorization header is missing")]
    MissingAuthHeader,
    #[error("authorization header is malformed")]
    InvalidAuthHeader,
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("authenticated identity not found in request context")]
    MissingIdentity,
    #[error("JWT_SECRET environment variable is not set")]
    MissingJwtSecret,
    #[error("JWT_SECRET value is too weak; provide at least 32 random characters")]
    WeakJwtSecret,
    #[error("failed to encode authentication token: {0}")]
    TokenEncoding(String),
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for JwtAuthError {
    fn into_response(self) -> Response {
        let status = match self {
            JwtAuthError::MissingAuthHeader
            | JwtAuthError::InvalidAuthHeader
            | JwtAuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            JwtAuthError::MissingIdentity
            | JwtAuthError::MissingJwtSecret
            | JwtAuthError::WeakJwtSecret
            | JwtAuthError::TokenEncoding(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = axum::Json(ErrorResponse {
            error: self.to_string(),
        });

        (status, body).into_response()
    }
}

static JWT_SECRET: OnceLock<String> = OnceLock::new();

pub async fn authenticate(
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, JwtAuthError> {
    let header_value = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(JwtAuthError::MissingAuthHeader)?;

    let header_str = header_value
        .to_str()
        .map_err(|_| JwtAuthError::InvalidAuthHeader)?;

    let token = header_str
        .strip_prefix("Bearer ")
        .ok_or(JwtAuthError::InvalidAuthHeader)?;

    let claims = decode_token(token)?;

    {
        let extensions = request.extensions_mut();
        extensions.insert(AuthenticatedUser(claims.sub));
        extensions.insert(claims);
    }

    Ok(next.run(request).await)
}

pub fn issue_token(user_id: Uuid) -> Result<String, JwtAuthError> {
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
        .map_err(|err| JwtAuthError::TokenEncoding(err.to_string()))
}

pub fn decode_token(token: &str) -> Result<Claims, JwtAuthError> {
    let secret = jwt_secret()?;
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|_| JwtAuthError::InvalidToken)
}

fn jwt_secret() -> Result<&'static String, JwtAuthError> {
    JWT_SECRET.get().map(Ok).unwrap_or_else(|| {
        let value = std::env::var("JWT_SECRET").map_err(|_| JwtAuthError::MissingJwtSecret)?;
        ensure_secret_strength(&value)?;
        Ok(JWT_SECRET.get_or_init(|| value))
    })
}

fn ensure_secret_strength(secret: &str) -> Result<(), JwtAuthError> {
    let trimmed = secret.trim();
    if trimmed.len() < 32 {
        return Err(JwtAuthError::WeakJwtSecret);
    }

    let unique_chars = trimmed.chars().collect::<HashSet<_>>();
    if unique_chars.len() < 8 {
        return Err(JwtAuthError::WeakJwtSecret);
    }

    Ok(())
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = JwtAuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .copied()
            .ok_or(JwtAuthError::MissingIdentity)
    }
}
