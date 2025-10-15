use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};
use dashmap::{DashMap, mapref::entry::Entry};

use crate::errors::AppError;
use crate::logging::{SanitizedIpAddr, SecurityEvent};

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
                        .unwrap_or(Duration::from_secs(0));
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

pub async fn enforce_rate_limit(
    State(state): State<RateLimiterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let client_ip = select_client_ip(request.headers(), addr.ip());
    let now = Instant::now();

    if let Err(retry_after) = state.register(client_ip, now) {
        crate::log_security_event!(
            SecurityEvent::RateLimitExceeded,
            client_ip = %SanitizedIpAddr::new(client_ip),
            "Rate limit exceeded for client"
        );

        return Err(AppError::RateLimitExceeded { 
            retry_after: Some(retry_after.max(Duration::from_secs(1))) 
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

#[derive(Debug)]
struct RateWindow {
    started_at: Instant,
    hits: u32,
}
