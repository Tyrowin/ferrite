use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode, header::HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::{DashMap, mapref::entry::Entry};
use serde::Serialize;
use thiserror::Error;

#[derive(Clone)]
pub struct RateLimiterState {
    max_requests: u32,
    window: Duration,
    buckets: Arc<DashMap<IpAddr, RateWindow>>,
}

impl RateLimiterState {
    pub fn new(calls: NonZeroU32, window: Duration) -> Self {
        Self {
            max_requests: calls.get(),
            window,
            buckets: Arc::new(DashMap::new()),
        }
    }

    fn register(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        match self.buckets.entry(ip) {
            Entry::Occupied(mut entry) => {
                let bucket = entry.get_mut();
                let elapsed = now.duration_since(bucket.started_at);

                if elapsed >= self.window {
                    bucket.started_at = now;
                    bucket.hits = 0;
                }

                if bucket.hits >= self.max_requests {
                    let retry_after = self
                        .window
                        .checked_sub(elapsed.min(self.window))
                        .unwrap_or_else(|| Duration::from_secs(0));
                    return Err(retry_after);
                }

                bucket.hits += 1;
                Ok(())
            }
            Entry::Vacant(entry) => {
                entry.insert(RateWindow {
                    started_at: now,
                    hits: 1,
                });
                Ok(())
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("too many requests, retry later")]
    TooManyRequests { retry_after: Option<Duration> },
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        let (message, retry_after_seconds) = match self {
            RateLimitError::TooManyRequests { retry_after } => (
                "too many requests, retry later".to_string(),
                retry_after.map(|duration| duration.as_secs().saturating_add(1)),
            ),
        };

        let payload = ErrorBody { error: message };

        let mut response = (StatusCode::TOO_MANY_REQUESTS, axum::Json(payload)).into_response();

        if let Some(seconds) = retry_after_seconds
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }

        response
    }
}

pub async fn enforce_rate_limit(
    State(state): State<RateLimiterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, RateLimitError> {
    let client_ip = select_client_ip(request.headers(), addr.ip());
    let now = Instant::now();

    if let Err(retry_after) = state.register(client_ip, now) {
        let retry_after = retry_after.max(Duration::from_secs(1));
        return Err(RateLimitError::TooManyRequests {
            retry_after: Some(retry_after),
        });
    }

    Ok(next.run(request).await)
}

fn select_client_ip(headers: &HeaderMap, fallback: IpAddr) -> IpAddr {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.split(',').next())
        .and_then(|ip| ip.trim().parse().ok());

    let real_ip = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|ip| ip.trim().parse().ok());

    forwarded.or(real_ip).unwrap_or(fallback)
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct RateWindow {
    started_at: Instant,
    hits: u32,
}
