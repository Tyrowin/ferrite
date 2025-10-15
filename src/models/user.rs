use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

use crate::schema::users;

use super::{ModelValidationError, ValidationResult};

#[derive(Debug, Clone, Queryable, Identifiable, Serialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password_hash: String,
}

impl NewUser {
    pub fn validate(&mut self) -> ValidationResult<()> {
        self.username = self.username.trim().to_string();
        ensure_valid_username(&self.username)?;

        self.email = self.email.trim().to_lowercase();
        ensure_valid_email(&self.email)?;

        ensure_hash_present(&self.password_hash)?;
        Ok(())
    }
}

pub(crate) fn ensure_valid_username(value: &str) -> ValidationResult<()> {
    let len = value.chars().count();
    let is_ascii = value.is_ascii();
    if !(3..=32).contains(&len) || !is_ascii {
        tracing::debug!(
            length = len,
            is_ascii = is_ascii,
            "Username validation failed: invalid length or non-ASCII characters"
        );
        return Err(ModelValidationError::InvalidUsername);
    }

    let allowed = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !allowed {
        tracing::debug!("Username validation failed: contains invalid characters");
        return Err(ModelValidationError::InvalidUsername);
    }
    Ok(())
}

pub(crate) fn ensure_valid_email(value: &str) -> ValidationResult<()> {
    let len = value.len();
    if !(3..=255).contains(&len) {
        tracing::debug!(length = len, "Email validation failed: invalid length");
        return Err(ModelValidationError::InvalidEmail);
    }

    let mut parts = value.split('@');
    let (Some(local), Some(domain)) = (parts.next(), parts.next()) else {
        tracing::debug!("Email validation failed: missing @ or invalid format");
        return Err(ModelValidationError::InvalidEmail);
    };
    if parts.next().is_some() {
        tracing::debug!("Email validation failed: multiple @ symbols");
        return Err(ModelValidationError::InvalidEmail);
    }

    if local.is_empty() || domain.len() < 3 || !domain.contains('.') {
        tracing::debug!(
            local_empty = local.is_empty(),
            domain_length = domain.len(),
            has_dot = domain.contains('.'),
            "Email validation failed: invalid local or domain part"
        );
        return Err(ModelValidationError::InvalidEmail);
    }

    if !local
        .chars()
        .chain(domain.chars())
        .all(|c| c.is_ascii_graphic() || c == '.')
    {
        tracing::debug!("Email validation failed: contains invalid characters");
        return Err(ModelValidationError::InvalidEmail);
    }

    Ok(())
}

pub(crate) fn ensure_valid_password(password: &str) -> ValidationResult<()> {
    if password.len() < 12 {
        tracing::debug!(
            length = password.len(),
            "Password validation failed: too short (minimum 12 characters)"
        );
        return Err(ModelValidationError::WeakPassword);
    }

    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());

    if has_upper && has_lower && has_digit && has_symbol {
        Ok(())
    } else {
        tracing::debug!(
            has_uppercase = has_upper,
            has_lowercase = has_lower,
            has_digit = has_digit,
            has_symbol = has_symbol,
            "Password validation failed: missing required character types"
        );
        Err(ModelValidationError::WeakPassword)
    }
}

fn ensure_hash_present(password_hash: &str) -> ValidationResult<()> {
    if password_hash.is_empty() {
        tracing::error!("Password hash is empty during validation");
        Err(ModelValidationError::WeakPassword)
    } else {
        Ok(())
    }
}
