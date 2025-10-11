use axum::{
    Extension, Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
};
use chrono::Utc;
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::db::PgPool;
use crate::models::note::{NewNote, Note};
use crate::routes::auth::AuthenticatedUser;
use crate::schema::notes::dsl::{
    body as notes_body, created_at as notes_created_at, id as notes_id, notes as notes_table,
    title as notes_title, updated_at as notes_updated_at, user_id as notes_user_id,
};
use crate::security::json::ValidatedJson;

pub fn router() -> Router {
    Router::new()
        .route("/notes", get(list_notes).post(create_note))
        .route("/notes/:id", put(update_note).delete(delete_note))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotePayload {
    title: String,
    body: String,
}

impl NotePayload {
    fn into_new_note(self, user_id: Uuid) -> Result<NewNote, NotesError> {
        let mut note = NewNote {
            user_id,
            title: self.title,
            body: self.body,
        };

        note.validate()
            .map_err(|err| NotesError::Validation(err.to_string()))?;

        Ok(note)
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Error)]
pub enum NotesError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("note not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(String),
    #[error("connection pool error: {0}")]
    Pool(String),
}

impl IntoResponse for NotesError {
    fn into_response(self) -> Response {
        let status = match self {
            NotesError::Validation(_) => StatusCode::BAD_REQUEST,
            NotesError::NotFound => StatusCode::NOT_FOUND,
            NotesError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            NotesError::Pool(_) => StatusCode::SERVICE_UNAVAILABLE,
        };

        let body = Json(ErrorResponse {
            error: self.to_string(),
        });

        (status, body).into_response()
    }
}

pub async fn list_notes(
    Extension(pool): Extension<PgPool>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<Vec<Note>>, NotesError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|err| NotesError::Pool(err.to_string()))?;

    let results = notes_table
        .filter(notes_user_id.eq(user_id))
        .order(notes_created_at.desc())
        .load::<Note>(&mut conn)
        .await
        .map_err(|err| NotesError::Database(err.to_string()))?;

    Ok(Json(results))
}

pub async fn create_note(
    Extension(pool): Extension<PgPool>,
    AuthenticatedUser(user_id): AuthenticatedUser,
    ValidatedJson(payload): ValidatedJson<NotePayload>,
) -> Result<(StatusCode, Json<Note>), NotesError> {
    let new_note = payload.into_new_note(user_id)?;

    let mut conn = pool
        .get()
        .await
        .map_err(|err| NotesError::Pool(err.to_string()))?;

    let note = diesel::insert_into(notes_table)
        .values(&new_note)
        .get_result(&mut conn)
        .await
        .map_err(|err| NotesError::Database(err.to_string()))?;

    Ok((StatusCode::CREATED, Json(note)))
}

pub async fn update_note(
    Extension(pool): Extension<PgPool>,
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(note_id): Path<Uuid>,
    ValidatedJson(payload): ValidatedJson<NotePayload>,
) -> Result<Json<Note>, NotesError> {
    let validator = payload.into_new_note(user_id)?;

    let validated_title = validator.title;
    let validated_body = validator.body;
    let current_time = Utc::now();

    let mut conn = pool
        .get()
        .await
        .map_err(|err| NotesError::Pool(err.to_string()))?;

    let note =
        diesel::update(notes_table.filter(notes_id.eq(note_id).and(notes_user_id.eq(user_id))))
            .set((
                notes_title.eq(validated_title),
                notes_body.eq(validated_body),
                notes_updated_at.eq(current_time),
            ))
            .get_result(&mut conn)
            .await
            .map_err(|err| match err {
                DieselError::NotFound => NotesError::NotFound,
                other => NotesError::Database(other.to_string()),
            })?;

    Ok(Json(note))
}

pub async fn delete_note(
    Extension(pool): Extension<PgPool>,
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(note_id): Path<Uuid>,
) -> Result<StatusCode, NotesError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|err| NotesError::Pool(err.to_string()))?;

    let affected =
        diesel::delete(notes_table.filter(notes_id.eq(note_id).and(notes_user_id.eq(user_id))))
            .execute(&mut conn)
            .await
            .map_err(|err| NotesError::Database(err.to_string()))?;

    if affected == 0 {
        return Err(NotesError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}
