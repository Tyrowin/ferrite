use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::Serialize;
use std::error::Error as StdError;
use thiserror::Error;

use crate::logging::SecurityEvent;

/// Centralized application error type that encompasses all error variants
/// across different modules and provides consistent error responses.
#[derive(Debug, Error)]
pub enum AppError {
    // Validation errors
    #[error("validation error: {0}")]
    Validation(String),

    // Authentication and authorization errors
    #[error("authorization header is missing")]
    MissingAuthHeader,

    #[error("authorization header is malformed")]
    InvalidAuthHeader,

    #[error("invalid or expired token")]
    InvalidToken,

    #[error("invalid email or password")]
    InvalidCredentials,

    #[error("authenticated identity not found in request context")]
    MissingIdentity,

    // Resource errors
    #[error("resource not found")]
    NotFound,

    #[error("forbidden: you do not have access to this resource")]
    Forbidden,

    #[error("resource conflict: {0}")]
    Conflict(String),

    // Database errors
    #[error("database error")]
    Database(#[source] DieselError),

    #[error("connection pool error: {0}")]
    Pool(String),

    // Security and configuration errors
    #[error("JWT_SECRET environment variable is not set")]
    MissingJwtSecret,

    #[error("JWT_SECRET value is too weak; provide at least 32 random characters")]
    WeakJwtSecret,

    #[error("failed to encode authentication token: {0}")]
    TokenEncoding(String),

    #[error("failed to hash password: {0}")]
    PasswordHashing(String),

    // Rate limiting
    #[error("rate limit exceeded; please try again later")]
    RateLimitExceeded,

    // Request parsing errors
    #[error("invalid JSON payload: {0}")]
    InvalidJson(String),

    #[error("unsupported media type: expected application/json")]
    UnsupportedMediaType,

    #[error("request body too large")]
    PayloadTooLarge,
}

/// Standard JSON error response structure
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl AppError {
    /// Maps a Diesel error to an appropriate AppError variant
    pub fn from_diesel(error: DieselError) -> Self {
        match error {
            DieselError::NotFound => AppError::NotFound,
            DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
                let constraint = info
                    .constraint_name()
                    .unwrap_or("unique constraint")
                    .to_string();
                AppError::Conflict(format!("duplicate value violates {}", constraint))
            }
            DieselError::DatabaseError(DatabaseErrorKind::ForeignKeyViolation, _) => {
                AppError::Conflict("foreign key constraint violation".to_string())
            }
            other => AppError::Database(other),
        }
    }

    /// Determines the HTTP status code for this error
    fn status_code(&self) -> StatusCode {
        match self {
            // 4xx Client errors
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::InvalidJson(_) => StatusCode::BAD_REQUEST,
            AppError::MissingAuthHeader => StatusCode::UNAUTHORIZED,
            AppError::InvalidAuthHeader => StatusCode::UNAUTHORIZED,
            AppError::InvalidToken => StatusCode::UNAUTHORIZED,
            AppError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,

            // 5xx Server errors
            AppError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Pool(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::MissingIdentity => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::MissingJwtSecret => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::WeakJwtSecret => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::TokenEncoding(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::PasswordHashing(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Determines if error details should be exposed to the client
    /// In production (release builds), we hide internal error details
    fn should_expose_details(&self) -> bool {
        if cfg!(debug_assertions) {
            // In debug/development mode, expose all error details
            true
        } else {
            // In production/release mode, only expose client errors (4xx)
            matches!(
                self,
                AppError::Validation(_)
                    | AppError::InvalidJson(_)
                    | AppError::Conflict(_)
                    | AppError::MissingAuthHeader
                    | AppError::InvalidAuthHeader
                    | AppError::InvalidToken
                    | AppError::InvalidCredentials
                    | AppError::Forbidden
                    | AppError::NotFound
                    | AppError::UnsupportedMediaType
                    | AppError::PayloadTooLarge
                    | AppError::RateLimitExceeded
            )
        }
    }

    /// Gets the user-facing error message
    fn user_message(&self) -> String {
        if self.should_expose_details() {
            self.to_string()
        } else {
            // For internal errors in production, return a generic message
            match self {
                AppError::Database(_) => "a database error occurred".to_string(),
                AppError::Pool(_) => "service temporarily unavailable".to_string(),
                AppError::MissingIdentity => "authentication error".to_string(),
                AppError::MissingJwtSecret | AppError::WeakJwtSecret => {
                    "server configuration error".to_string()
                }
                AppError::TokenEncoding(_) => "authentication error".to_string(),
                AppError::PasswordHashing(_) => "password processing error".to_string(),
                // For client errors, use the actual message
                _ => self.to_string(),
            }
        }
    }

    /// Gets optional detailed error information
    /// Only included in debug builds or for client errors
    fn error_details(&self) -> Option<String> {
        if !self.should_expose_details() {
            return None;
        }

        // Include source error details when available and appropriate
        match self {
            AppError::Database(err) => Some(format!("database: {}", err)),
            AppError::Pool(err) => Some(format!("connection pool: {}", err)),
            AppError::TokenEncoding(err) => Some(format!("token encoding: {}", err)),
            AppError::PasswordHashing(err) => Some(format!("password hashing: {}", err)),
            _ => None,
        }
    }

    /// Logs the error with appropriate context
    /// This allows internal errors to be logged even when not exposed to clients
    fn log_error(&self) {
        match self.status_code() {
            code if code.is_client_error() => {
                // Log security events for specific client errors
                match self {
                    AppError::InvalidToken
                    | AppError::InvalidAuthHeader
                    | AppError::MissingAuthHeader => {
                        crate::log_security_event!(
                            SecurityEvent::UnauthorizedAccess,
                            error = %self,
                            status_code = %code,
                            "Unauthorized access attempt"
                        );
                    }
                    AppError::Forbidden => {
                        crate::log_security_event!(
                            SecurityEvent::ForbiddenAccess,
                            error = %self,
                            status_code = %code,
                            "Forbidden access attempt"
                        );
                    }
                    _ => {
                        tracing::warn!(
                            error = %self,
                            status_code = %code,
                            "Client error"
                        );
                    }
                }
            }
            code if code.is_server_error() => {
                tracing::error!(
                    error = %self,
                    status_code = %code,
                    source = ?self.source(),
                    "Server error"
                );
            }
            _ => {}
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Log the error before converting to response
        self.log_error();

        let status = self.status_code();
        let user_message = self.user_message();
        let details = self.error_details();

        let body = Json(ErrorResponse {
            error: user_message,
            details,
        });

        (status, body).into_response()
    }
}

// Conversion implementations for common error types

impl From<DieselError> for AppError {
    fn from(error: DieselError) -> Self {
        AppError::from_diesel(error)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        AppError::TokenEncoding(error.to_string())
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(error: argon2::password_hash::Error) -> Self {
        AppError::PasswordHashing(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_status() {
        let error = AppError::Validation("invalid input".to_string());
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_not_found_error_status() {
        let error = AppError::NotFound;
        assert_eq!(error.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_forbidden_error_status() {
        let error = AppError::Forbidden;
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_rate_limit_error_status() {
        let error = AppError::RateLimitExceeded;
        assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_validation_error_is_exposed() {
        let error = AppError::Validation("test error".to_string());
        assert!(error.should_expose_details());
    }

    #[test]
    fn test_client_errors_have_detailed_messages() {
        let error = AppError::Validation("field 'email' is required".to_string());
        assert!(error.user_message().contains("field 'email' is required"));
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn test_internal_errors_hidden_in_production() {
        let error = AppError::Internal("sensitive internal detail".to_string());
        assert!(!error.should_expose_details());
        assert!(!error.user_message().contains("sensitive internal detail"));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn test_internal_errors_exposed_in_debug() {
        let error = AppError::Database(diesel::result::Error::NotFound);
        assert!(error.should_expose_details());
    }
}
