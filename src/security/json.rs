use axum::{
    async_trait,
    body::to_bytes,
    extract::{FromRequest, Request},
    http::{HeaderMap, HeaderValue, header::CONTENT_TYPE},
};
use serde::de::DeserializeOwned;
use serde_json::{self, Deserializer};

use crate::errors::AppError;

pub const MAX_BODY_SIZE_BYTES: usize = 64 * 1024; // 64 KiB upper bound for request bodies

#[derive(Debug)]
pub struct ValidatedJson<T>(pub T);

fn invalid_content_type(value: Option<&HeaderValue>) -> AppError {
    let received = value
        .and_then(|val| val.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "missing".to_string());

    tracing::warn!(
        content_type = %received,
        "Invalid content type in request"
    );

    AppError::UnsupportedMediaType
}

fn parsing_error(err: serde_path_to_error::Error<serde_json::Error>) -> AppError {
    let path = err.path().to_string();
    let error = err.into_inner();
    let message = if path.is_empty() {
        format!("failed to parse JSON payload: {error}")
    } else {
        format!("failed to parse JSON payload at {path}: {error}")
    };

    tracing::warn!(
        path = %path,
        error = %error,
        "JSON parsing error"
    );

    AppError::InvalidJson(message)
}

#[async_trait]
impl<S, T> FromRequest<S, axum::body::Body> for ValidatedJson<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(
        req: Request<axum::body::Body>,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        validate_content_type(&parts.headers)?;

        let req = Request::from_parts(parts, body);
        let body_bytes = to_bytes(req.into_body(), MAX_BODY_SIZE_BYTES)
            .await
            .map_err(|err| {
                if err.to_string().contains("length limit exceeded") {
                    tracing::warn!(
                        max_size = MAX_BODY_SIZE_BYTES,
                        "Request body exceeded size limit"
                    );
                    AppError::PayloadTooLarge
                } else {
                    tracing::warn!(
                        error = %err,
                        max_size = MAX_BODY_SIZE_BYTES,
                        "Failed to read request body"
                    );
                    AppError::InvalidJson(format!("failed to read request body: {err}"))
                }
            })?;

        let mut deserializer = Deserializer::from_slice(body_bytes.as_ref());
        let result = serde_path_to_error::deserialize(&mut deserializer).map_err(parsing_error)?;

        deserializer.end().map_err(|err| {
            tracing::warn!(
                error = %err,
                "Unexpected trailing data in JSON payload"
            );
            AppError::InvalidJson(format!("unexpected trailing data: {err}"))
        })?;

        Ok(ValidatedJson(result))
    }
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), AppError> {
    let value = headers.get(CONTENT_TYPE);

    if let Some(value) = value
        && let Ok(value) = value.to_str()
        && (value.starts_with("application/json") || value.ends_with("+json"))
    {
        return Ok(());
    }

    Err(invalid_content_type(value))
}
