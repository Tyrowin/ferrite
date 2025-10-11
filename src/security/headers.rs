use std::convert::Infallible;

use axum::{
    http::{HeaderValue, Request, header::HeaderName},
    middleware::Next,
    response::Response,
};

const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const REFERRER_POLICY: &str = "no-referrer";
const PERMISSIONS_POLICY: &str = "geolocation=(), microphone=(), camera=()";

pub async fn set_security_headers(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, Infallible> {
    let mut response = next.run(req).await;

    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static(REFERRER_POLICY),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("0"),
    );

    Ok(response)
}
