use std::{collections::HashSet, sync::OnceLock};

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{Request, header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::Response,
};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::AppError;
use crate::logging::{LoggableUuid, SecurityEvent};

#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedUser(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
}

static JWT_SECRET: OnceLock<String> = OnceLock::new();

const MIN_JWT_SECRET_LENGTH: usize = 32;
const MIN_JWT_SECRET_UNIQUE_CHARS: usize = 8;

#[tracing::instrument(name = "authenticate_request", skip(request, next), fields(user_id))]
pub async fn authenticate(
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let header_value = request.headers().get(AUTHORIZATION).ok_or_else(|| {
        crate::log_security_event!(
            SecurityEvent::MissingAuthHeader,
            "Authorization header not provided"
        );
        AppError::MissingAuthHeader
    })?;

    let header_str = header_value.to_str().map_err(|_| {
        crate::log_security_event!(
            SecurityEvent::InvalidAuthHeader,
            "Authorization header contains invalid characters"
        );
        AppError::InvalidAuthHeader
    })?;

    let token = header_str.strip_prefix("Bearer ").ok_or_else(|| {
        crate::log_security_event!(
            SecurityEvent::InvalidAuthHeader,
            "Authorization header missing Bearer prefix"
        );
        AppError::InvalidAuthHeader
    })?;

    let claims = decode_token(token)?;

    // Record user_id in the current span for request tracing
    tracing::Span::current().record("user_id", tracing::field::display(LoggableUuid(claims.sub)));

    tracing::debug!(
        user_id = %LoggableUuid(claims.sub),
        "Request authenticated successfully"
    );

    {
        let extensions = request.extensions_mut();
        extensions.insert(AuthenticatedUser(claims.sub));
        extensions.insert(claims);
    }

    Ok(next.run(request).await)
}

#[tracing::instrument(name = "issue_jwt_token", skip(user_id), fields(user_id = %LoggableUuid(user_id)))]
pub fn issue_token(user_id: Uuid) -> Result<String, AppError> {
    let secret = jwt_secret()?;
    let now = Utc::now();
    let expires_at = now + ChronoDuration::hours(24);

    let claims = Claims {
        sub: user_id,
        iat: now.timestamp() as usize,
        exp: expires_at.timestamp() as usize,
    };

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());

    let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding_key).map_err(|err| {
        tracing::error!(
            user_id = %LoggableUuid(user_id),
            error = %err,
            "Failed to encode JWT token"
        );
        AppError::TokenEncoding(err.to_string())
    })?;

    crate::log_security_event!(
        SecurityEvent::TokenIssuedSuccessfully,
        user_id = %LoggableUuid(user_id),
        "JWT token issued successfully"
    );

    Ok(token)
}

#[tracing::instrument(name = "decode_jwt_token", skip(token))]
pub fn decode_token(token: &str) -> Result<Claims, AppError> {
    let secret = jwt_secret()?;
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|err| {
            crate::log_security_event!(
                SecurityEvent::TokenValidationFailure,
                error = %err,
                "JWT token validation failed"
            );
            tracing::debug!(error = %err, "Token decode error details");
            AppError::InvalidToken
        })
}

fn jwt_secret() -> Result<&'static String, AppError> {
    JWT_SECRET.get().map(Ok).unwrap_or_else(|| {
        let value = std::env::var("JWT_SECRET").map_err(|_| AppError::MissingJwtSecret)?;
        ensure_secret_strength(&value)?;
        Ok(JWT_SECRET.get_or_init(|| value))
    })
}

fn ensure_secret_strength(secret: &str) -> Result<(), AppError> {
    let trimmed = secret.trim();
    if trimmed.len() < MIN_JWT_SECRET_LENGTH {
        return Err(AppError::WeakJwtSecret);
    }

    let unique_chars = trimmed.chars().collect::<HashSet<_>>();
    // Ensure the secret contains enough entropy beyond simple repetition.
    if unique_chars.len() < MIN_JWT_SECRET_UNIQUE_CHARS {
        return Err(AppError::WeakJwtSecret);
    }

    Ok(())
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .copied()
            .ok_or(AppError::MissingIdentity)
    }
}
