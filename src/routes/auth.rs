use std::{num::NonZeroU32, time::Duration};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::http::StatusCode;
use axum::{Extension, Json, Router, middleware, response::IntoResponse, routing::post};
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use diesel_async::RunQueryDsl;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::db::PgPool;
use crate::errors::AppError;
use crate::logging::{LoggableUuid, SanitizedEmail, SanitizedUsername, SecurityEvent};
use crate::models::user::{
    NewUser, User, ensure_valid_email, ensure_valid_password, ensure_valid_username,
};
use crate::schema::users::dsl::{email as users_email, users};
use crate::security::auth::issue_token;
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

#[tracing::instrument(
    name = "register_user",
    skip(pool, payload),
    fields(username, email, user_id)
)]
pub async fn register(
    Extension(pool): Extension<PgPool>,
    ValidatedJson(mut payload): ValidatedJson<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|err| AppError::Validation(err.to_string()))?;

    let username = payload.username.clone();
    let email = payload.email.clone();

    // Record sanitized info in the current span
    tracing::Span::current().record(
        "username",
        tracing::field::display(SanitizedUsername::new(&username)),
    );
    tracing::Span::current().record(
        "email",
        tracing::field::display(SanitizedEmail::new(&email)),
    );

    tracing::debug!(
        username = %SanitizedUsername::new(&username),
        email = %SanitizedEmail::new(&email),
        "Processing registration request"
    );

    let password_hash = {
        let password_string = payload.password.clone();
        tokio::task::spawn_blocking(move || -> Result<String, AppError> {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let hash = argon2
                .hash_password(password_string.as_bytes(), &salt)
                .map_err(|err| AppError::PasswordHashing(err.to_string()))?;
            Ok(hash.to_string())
        })
        .await
        .map_err(|err| AppError::Validation(err.to_string()))??
    };

    let mut new_user = NewUser {
        username: username.clone(),
        email: email.clone(),
        password_hash,
    };

    new_user
        .validate()
        .map_err(|err| AppError::Validation(err.to_string()))?;

    let mut conn = pool
        .get()
        .await
        .map_err(|err| AppError::Pool(err.to_string()))?;

    let user: User = diesel::insert_into(users)
        .values(&new_user)
        .get_result(&mut conn)
        .await
        .map_err(|err| {
            let app_error = AppError::from_diesel(err);

            crate::log_security_event!(
                SecurityEvent::RegistrationFailure,
                username = %SanitizedUsername::new(&username),
                email = %SanitizedEmail::new(&email),
                error = %app_error,
                "User registration failed"
            );

            app_error
        })?;

    // Record user_id in span
    tracing::Span::current().record("user_id", tracing::field::display(LoggableUuid(user.id)));

    let token = issue_token(user.id)?;

    crate::log_security_event!(
        SecurityEvent::RegistrationSuccess,
        user_id = %LoggableUuid(user.id),
        username = %SanitizedUsername::new(&username),
        email = %SanitizedEmail::new(&email),
        "User registered successfully"
    );

    Ok((StatusCode::CREATED, Json(AuthResponse { token, user })))
}

#[tracing::instrument(name = "login_user", skip(pool, payload), fields(email, user_id))]
pub async fn login(
    Extension(pool): Extension<PgPool>,
    ValidatedJson(mut payload): ValidatedJson<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|err| AppError::Validation(err.to_string()))?;

    let normalized_email = payload.email.clone();

    // Record sanitized email in span
    tracing::Span::current().record(
        "email",
        tracing::field::display(SanitizedEmail::new(&normalized_email)),
    );

    tracing::debug!(
        email = %SanitizedEmail::new(&normalized_email),
        "Processing login request"
    );

    let mut conn = pool
        .get()
        .await
        .map_err(|err| AppError::Pool(err.to_string()))?;

    let user: User = users
        .filter(users_email.eq(&normalized_email))
        .first(&mut conn)
        .await
        .map_err(|err| match err {
            DieselError::NotFound => {
                crate::log_security_event!(
                    SecurityEvent::LoginFailure,
                    email = %SanitizedEmail::new(&normalized_email),
                    reason = "user_not_found",
                    "Login failed: user not found"
                );
                AppError::InvalidCredentials
            }
            other => {
                tracing::error!(
                    email = %SanitizedEmail::new(&normalized_email),
                    error = %other,
                    "Database error during login"
                );
                AppError::Database(other)
            }
        })?;

    // Record user_id in span
    tracing::Span::current().record("user_id", tracing::field::display(LoggableUuid(user.id)));

    let password_hash = PasswordHash::new(&user.password_hash).map_err(|_| {
        crate::log_security_event!(
            SecurityEvent::LoginFailure,
            user_id = %LoggableUuid(user.id),
            email = %SanitizedEmail::new(&normalized_email),
            reason = "invalid_password_hash",
            "Login failed: invalid password hash"
        );
        AppError::InvalidCredentials
    })?;

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &password_hash)
        .map_err(|_| {
            crate::log_security_event!(
                SecurityEvent::LoginFailure,
                user_id = %LoggableUuid(user.id),
                email = %SanitizedEmail::new(&normalized_email),
                reason = "incorrect_password",
                "Login failed: incorrect password"
            );
            AppError::InvalidCredentials
        })?;

    let token = issue_token(user.id)?;

    crate::log_security_event!(
        SecurityEvent::LoginSuccess,
        user_id = %LoggableUuid(user.id),
        email = %SanitizedEmail::new(&normalized_email),
        "User logged in successfully"
    );

    Ok((StatusCode::OK, Json(AuthResponse { token, user })))
}
