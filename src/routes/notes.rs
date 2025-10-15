use axum::{
    Extension, Json, Router,
    extract::Path,
    http::StatusCode,
    middleware,
    routing::{get, put},
};
use chrono::Utc;
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use diesel_async::RunQueryDsl;
use serde::Deserialize;
use uuid::Uuid;

use crate::db::PgPool;
use crate::errors::AppError;
use crate::logging::LoggableUuid;
use crate::models::note::{NewNote, Note};
use crate::schema::notes::dsl::{
    body as notes_body, created_at as notes_created_at, id as notes_id, notes as notes_table,
    title as notes_title, updated_at as notes_updated_at, user_id as notes_user_id,
};
use crate::security::auth::{AuthenticatedUser, authenticate};
use crate::security::json::ValidatedJson;

pub fn router() -> Router {
    Router::new()
        .route("/notes", get(list_notes).post(create_note))
        .route("/notes/:id", put(update_note).delete(delete_note))
        .layer(middleware::from_fn(authenticate))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotePayload {
    title: String,
    body: String,
}

impl NotePayload {
    fn into_new_note(self, user_id: Uuid) -> Result<NewNote, AppError> {
        let mut note = NewNote {
            user_id,
            title: self.title,
            body: self.body,
        };

        note.validate()
            .map_err(|err| AppError::Validation(err.to_string()))?;

        Ok(note)
    }
}

#[tracing::instrument(
    name = "list_notes",
    skip(pool),
    fields(user_id = %LoggableUuid(user_id))
)]
pub async fn list_notes(
    Extension(pool): Extension<PgPool>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<Vec<Note>>, AppError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|err| AppError::Pool(err.to_string()))?;

    let results = notes_table
        .filter(notes_user_id.eq(user_id))
        .order(notes_created_at.desc())
        .load::<Note>(&mut conn)
        .await
        .map_err(AppError::from_diesel)?;

    tracing::debug!(
        user_id = %LoggableUuid(user_id),
        count = results.len(),
        "Retrieved notes for user"
    );

    Ok(Json(results))
}

#[tracing::instrument(
    name = "create_note",
    skip(pool, payload),
    fields(
        user_id = %LoggableUuid(user_id),
        note_id
    )
)]
pub async fn create_note(
    Extension(pool): Extension<PgPool>,
    AuthenticatedUser(user_id): AuthenticatedUser,
    ValidatedJson(payload): ValidatedJson<NotePayload>,
) -> Result<(StatusCode, Json<Note>), AppError> {
    tracing::debug!(
        user_id = %LoggableUuid(user_id),
        title_length = payload.title.len(),
        body_length = payload.body.len(),
        "Creating new note"
    );

    let new_note = payload.into_new_note(user_id)?;

    let mut conn = pool
        .get()
        .await
        .map_err(|err| AppError::Pool(err.to_string()))?;

    let note = diesel::insert_into(notes_table)
        .values(&new_note)
        .get_result::<Note>(&mut conn)
        .await
        .map_err(AppError::from_diesel)?;

    // Record note_id in span
    tracing::Span::current().record("note_id", tracing::field::display(LoggableUuid(note.id)));

    tracing::info!(
        user_id = %LoggableUuid(user_id),
        note_id = %LoggableUuid(note.id),
        "Note created successfully"
    );

    Ok((StatusCode::CREATED, Json(note)))
}

#[tracing::instrument(
    name = "update_note",
    skip(pool, payload),
    fields(
        user_id = %LoggableUuid(user_id),
        note_id = %LoggableUuid(note_id)
    )
)]
pub async fn update_note(
    Extension(pool): Extension<PgPool>,
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(note_id): Path<Uuid>,
    ValidatedJson(payload): ValidatedJson<NotePayload>,
) -> Result<Json<Note>, AppError> {
    tracing::debug!(
        user_id = %LoggableUuid(user_id),
        note_id = %LoggableUuid(note_id),
        "Updating note"
    );

    let validated_note = payload.into_new_note(user_id)?;

    let validated_title = validated_note.title;
    let validated_body = validated_note.body;
    let current_time = Utc::now();

    let mut conn = pool
        .get()
        .await
        .map_err(|err| AppError::Pool(err.to_string()))?;

    let existing: Note = notes_table
        .filter(notes_id.eq(note_id))
        .first(&mut conn)
        .await
        .map_err(|err| match err {
            DieselError::NotFound => {
                tracing::warn!(
                    user_id = %LoggableUuid(user_id),
                    note_id = %LoggableUuid(note_id),
                    "Note not found for update"
                );
                AppError::NotFound
            }
            other => AppError::from_diesel(other),
        })?;

    if existing.user_id != user_id {
        tracing::warn!(
            user_id = %LoggableUuid(user_id),
            note_id = %LoggableUuid(note_id),
            owner_id = %LoggableUuid(existing.user_id),
            "Forbidden: user attempted to update note owned by another user"
        );
        return Err(AppError::Forbidden);
    }

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
                DieselError::NotFound => AppError::NotFound,
                other => AppError::from_diesel(other),
            })?;

    tracing::info!(
        user_id = %LoggableUuid(user_id),
        note_id = %LoggableUuid(note_id),
        "Note updated successfully"
    );

    Ok(Json(note))
}

#[tracing::instrument(
    name = "delete_note",
    skip(pool),
    fields(
        user_id = %LoggableUuid(user_id),
        note_id = %LoggableUuid(note_id)
    )
)]
pub async fn delete_note(
    Extension(pool): Extension<PgPool>,
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(note_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    tracing::debug!(
        user_id = %LoggableUuid(user_id),
        note_id = %LoggableUuid(note_id),
        "Deleting note"
    );

    let mut conn = pool
        .get()
        .await
        .map_err(|err| AppError::Pool(err.to_string()))?;

    let existing: Note = notes_table
        .filter(notes_id.eq(note_id))
        .first(&mut conn)
        .await
        .map_err(|err| match err {
            DieselError::NotFound => {
                tracing::warn!(
                    user_id = %LoggableUuid(user_id),
                    note_id = %LoggableUuid(note_id),
                    "Note not found for deletion"
                );
                AppError::NotFound
            }
            other => AppError::from_diesel(other),
        })?;

    if existing.user_id != user_id {
        tracing::warn!(
            user_id = %LoggableUuid(user_id),
            note_id = %LoggableUuid(note_id),
            owner_id = %LoggableUuid(existing.user_id),
            "Forbidden: user attempted to delete note owned by another user"
        );
        return Err(AppError::Forbidden);
    }

    let affected =
        diesel::delete(notes_table.filter(notes_id.eq(note_id).and(notes_user_id.eq(user_id))))
            .execute(&mut conn)
            .await
            .map_err(AppError::from_diesel)?;

    if affected == 0 {
        return Err(AppError::NotFound);
    }

    tracing::info!(
        user_id = %LoggableUuid(user_id),
        note_id = %LoggableUuid(note_id),
        "Note deleted successfully"
    );

    Ok(StatusCode::NO_CONTENT)
}
