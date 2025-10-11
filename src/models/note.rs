use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::notes;

use super::{ModelValidationError, ValidationResult};
use crate::models::user::User;

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize)]
#[diesel(table_name = notes)]
#[diesel(belongs_to(User))]
pub struct Note {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable, Deserialize)]
#[diesel(table_name = notes)]
pub struct NewNote {
    pub user_id: Uuid,
    #[serde(deserialize_with = "deserialize_title")]
    pub title: String,
    #[serde(deserialize_with = "deserialize_body")]
    pub body: String,
}

impl NewNote {
    pub fn validate(&mut self) -> ValidationResult<()> {
        if self.user_id == Uuid::nil() {
            return Err(ModelValidationError::InvalidUserId);
        }

        self.title = self.title.trim().to_string();
        ensure_valid_title(&self.title)?;

        self.body = self.body.trim().to_string();
        ensure_valid_body(&self.body)?;
        Ok(())
    }
}

fn deserialize_title<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(de::Error::custom("title must not be empty"));
    }
    Ok(trimmed)
}

fn deserialize_body<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(de::Error::custom("body must not be empty"));
    }
    Ok(trimmed)
}

fn ensure_valid_title(value: &str) -> ValidationResult<()> {
    let len = value.chars().count();
    if len == 0 || len > 120 {
        return Err(ModelValidationError::InvalidNoteTitle);
    }

    if !value.chars().all(|c| !c.is_control()) {
        return Err(ModelValidationError::InvalidNoteTitle);
    }

    Ok(())
}

fn ensure_valid_body(value: &str) -> ValidationResult<()> {
    if value.is_empty() {
        Err(ModelValidationError::InvalidNoteBody)
    } else {
        Ok(())
    }
}
