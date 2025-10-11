use axum::{
    async_trait,
    extract::{FromRequest, Json, Request, rejection::JsonRejection as AxumJsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::{self, Deserializer, Value};

pub const MAX_BODY_SIZE_BYTES: usize = 64 * 1024; // 64 KiB upper bound for request bodies

#[derive(Debug)]
pub struct ValidatedJson<T>(pub T);

#[derive(Debug)]
pub struct JsonRejection {
    status: StatusCode,
    message: String,
}

impl JsonRejection {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn invalid_content_type(value: Option<&HeaderValue>) -> Self {
        let received = value
            .and_then(|val| val.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "missing".to_string());
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("expected application/json payload, received {received}"),
        )
    }

    fn parsing_error(err: serde_path_to_error::Error<serde_json::Error>) -> Self {
        let path = err.path().to_string();
        let error = err.into_inner();
        let message = if path.is_empty() {
            format!("failed to parse JSON payload: {error}")
        } else {
            format!("failed to parse JSON payload at {path}: {error}")
        };

        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn from_axum(rejection: AxumJsonRejection) -> Self {
        let status = rejection.status();
        let mut message = rejection.to_string();
        if message.len() > 512 {
            message.truncate(512);
        }

        Self::new(status, message)
    }
}

#[derive(serde::Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for JsonRejection {
    fn into_response(self) -> Response {
        let payload = axum::Json(ErrorBody {
            error: self.message.as_str(),
        });
        (self.status, payload).into_response()
    }
}

#[async_trait]
impl<S, T> FromRequest<S, axum::body::Body> for ValidatedJson<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = JsonRejection;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        validate_content_type(&parts.headers)?;

        let req = Request::from_parts(parts, body);
        let Json(raw_value) = Json::<Value>::from_request(req, state)
            .await
            .map_err(JsonRejection::from_axum)?;

        let serialized = serde_json::to_vec(&raw_value).map_err(|err| {
            JsonRejection::new(
                StatusCode::BAD_REQUEST,
                format!("failed to process JSON payload: {err}"),
            )
        })?;

        if serialized.len() > MAX_BODY_SIZE_BYTES {
            return Err(JsonRejection::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request payload exceeds {MAX_BODY_SIZE_BYTES} bytes"),
            ));
        }

        let mut deserializer = Deserializer::from_slice(&serialized);
        let result = serde_path_to_error::deserialize(&mut deserializer)
            .map_err(JsonRejection::parsing_error)?;

        deserializer.end().map_err(|err| {
            JsonRejection::new(
                StatusCode::BAD_REQUEST,
                format!("unexpected trailing data: {err}"),
            )
        })?;

        Ok(ValidatedJson(result))
    }
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), JsonRejection> {
    let value = headers.get(CONTENT_TYPE);

    if let Some(value) = value
        && let Ok(value) = value.to_str()
        && (value.starts_with("application/json") || value.ends_with("+json"))
    {
        return Ok(());
    }

    Err(JsonRejection::invalid_content_type(value))
}
