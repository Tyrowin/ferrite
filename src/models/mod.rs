pub mod note;
pub mod user;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelValidationError {
    #[error("username must be 3-32 ASCII characters consisting of letters, digits, or underscores")]
    InvalidUsername,
    #[error("email must contain a single '@' and a domain section")]
    InvalidEmail,
    #[error(
        "password must be at least 12 characters and include upper, lower, digit, and symbol characters"
    )]
    WeakPassword,
    #[error("note title must be between 1 and 120 visible characters")]
    InvalidNoteTitle,
    #[error("note body must not be empty")]
    InvalidNoteBody,
    #[error("user identifier must be a valid UUID")]
    InvalidUserId,
}

pub type ValidationResult<T> = Result<T, ModelValidationError>;
