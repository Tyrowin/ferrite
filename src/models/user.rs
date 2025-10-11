use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use rand_core::OsRng;
use serde::Deserialize;
use serde::Serialize;
use serde::de::{self, Deserializer};
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

#[derive(Debug, Clone, Insertable, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    #[serde(deserialize_with = "deserialize_username")]
    pub username: String,
    #[serde(deserialize_with = "deserialize_email")]
    pub email: String,
    #[serde(rename = "password", deserialize_with = "deserialize_password")]
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

fn deserialize_username<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(de::Error::custom("username must not be empty"));
    }
    Ok(trimmed)
}

fn deserialize_email<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(de::Error::custom("email must not be empty"));
    }
    Ok(normalized)
}

fn deserialize_password<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let plain = String::deserialize(deserializer)?;
    ensure_valid_password(&plain).map_err(de::Error::custom)?;

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| de::Error::custom(err.to_string()))
}

fn ensure_valid_username(value: &str) -> ValidationResult<()> {
    let len = value.chars().count();
    let is_ascii = value.chars().all(|c| c.is_ascii());
    if !(3..=32).contains(&len) || !is_ascii {
        return Err(ModelValidationError::InvalidUsername);
    }

    let allowed = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !allowed {
        return Err(ModelValidationError::InvalidUsername);
    }
    Ok(())
}

fn ensure_valid_email(value: &str) -> ValidationResult<()> {
    let len = value.len();
    if len < 3 || len > 255 {
        return Err(ModelValidationError::InvalidEmail);
    }

    let mut parts = value.split('@');
    let (local, domain) = match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) => (local, domain),
        _ => return Err(ModelValidationError::InvalidEmail),
    };

    if local.is_empty() || domain.len() < 3 || !domain.contains('.') {
        return Err(ModelValidationError::InvalidEmail);
    }

    if !local
        .chars()
        .chain(domain.chars())
        .all(|c| c.is_ascii_graphic() || c == '.')
    {
        return Err(ModelValidationError::InvalidEmail);
    }

    Ok(())
}

fn ensure_valid_password(password: &str) -> ValidationResult<()> {
    if password.len() < 12 {
        return Err(ModelValidationError::WeakPassword);
    }

    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());

    if has_upper && has_lower && has_digit && has_symbol {
        Ok(())
    } else {
        Err(ModelValidationError::WeakPassword)
    }
}

fn ensure_hash_present(password_hash: &str) -> ValidationResult<()> {
    if password_hash.is_empty() {
        Err(ModelValidationError::WeakPassword)
    } else {
        Ok(())
    }
}
