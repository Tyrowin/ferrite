use std::fmt;
use uuid::Uuid;

/// Sanitized wrapper for email addresses that masks the local part
#[derive(Debug, Clone)]
pub struct SanitizedEmail(String);

impl SanitizedEmail {
    pub fn new(email: impl Into<String>) -> Self {
        let email = email.into();
        Self(Self::sanitize(&email))
    }

    fn sanitize(email: &str) -> String {
        if let Some((local, domain)) = email.split_once('@') {
            let masked_local = if local.len() <= 2 {
                "*".repeat(local.len())
            } else {
                format!("{}***", &local[..1])
            };
            format!("{}@{}", masked_local, domain)
        } else {
            // Invalid email format, mask entirely
            "***@***".to_string()
        }
    }
}

impl fmt::Display for SanitizedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Sanitized wrapper for usernames that shows only first and last character
#[derive(Debug, Clone)]
pub struct SanitizedUsername(String);

impl SanitizedUsername {
    pub fn new(username: impl Into<String>) -> Self {
        let username = username.into();
        Self(Self::sanitize(&username))
    }

    fn sanitize(username: &str) -> String {
        let len = username.chars().count();
        if len <= 2 {
            "*".repeat(len)
        } else if len <= 4 {
            format!("{}***", username.chars().next().unwrap())
        } else {
            let first = username.chars().next().unwrap();
            let last = username.chars().last().unwrap();
            format!("{}***{}", first, last)
        }
    }
}

impl fmt::Display for SanitizedUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Wrapper for UUIDs that are safe to log
#[derive(Debug, Clone, Copy)]
pub struct LoggableUuid(pub Uuid);

impl fmt::Display for LoggableUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for LoggableUuid {
    fn from(uuid: Uuid) -> Self {
        LoggableUuid(uuid)
    }
}

/// Sanitized wrapper for IP addresses that masks the last octet
#[derive(Debug, Clone)]
pub struct SanitizedIpAddr(String);

impl SanitizedIpAddr {
    pub fn new(ip: impl fmt::Display) -> Self {
        Self(Self::sanitize(&ip.to_string()))
    }

    fn sanitize(ip: &str) -> String {
        // For IPv4, mask the last octet
        if let Some(last_dot) = ip.rfind('.') {
            format!("{}.***", &ip[..last_dot])
        } else if ip.contains(':') {
            // For IPv6, mask the last segment
            if let Some(last_colon) = ip.rfind(':') {
                format!("{}:****", &ip[..last_colon])
            } else {
                "***".to_string()
            }
        } else {
            "***".to_string()
        }
    }
}

impl fmt::Display for SanitizedIpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Security event types for structured logging
#[derive(Debug, Clone, Copy)]
pub enum SecurityEvent {
    LoginSuccess,
    LoginFailure,
    RegistrationSuccess,
    RegistrationFailure,
    TokenValidationFailure,
    TokenIssuedSuccessfully,
    UnauthorizedAccess,
    ForbiddenAccess,
    RateLimitExceeded,
    InvalidAuthHeader,
    MissingAuthHeader,
}

impl SecurityEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityEvent::LoginSuccess => "login_success",
            SecurityEvent::LoginFailure => "login_failure",
            SecurityEvent::RegistrationSuccess => "registration_success",
            SecurityEvent::RegistrationFailure => "registration_failure",
            SecurityEvent::TokenValidationFailure => "token_validation_failure",
            SecurityEvent::TokenIssuedSuccessfully => "token_issued",
            SecurityEvent::UnauthorizedAccess => "unauthorized_access",
            SecurityEvent::ForbiddenAccess => "forbidden_access",
            SecurityEvent::RateLimitExceeded => "rate_limit_exceeded",
            SecurityEvent::InvalidAuthHeader => "invalid_auth_header",
            SecurityEvent::MissingAuthHeader => "missing_auth_header",
        }
    }

    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            SecurityEvent::LoginFailure
                | SecurityEvent::TokenValidationFailure
                | SecurityEvent::UnauthorizedAccess
                | SecurityEvent::RateLimitExceeded
        )
    }
}

impl fmt::Display for SecurityEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Log a security event with sanitized context
#[macro_export]
macro_rules! log_security_event {
    ($event:expr, $($field:tt)*) => {
        if $event.is_critical() {
            tracing::warn!(
                security_event = %$event,
                event_type = "security",
                $($field)*
            );
        } else {
            tracing::info!(
                security_event = %$event,
                event_type = "security",
                $($field)*
            );
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_email() {
        assert_eq!(
            SanitizedEmail::new("user@example.com").to_string(),
            "u***@example.com"
        );
        assert_eq!(
            SanitizedEmail::new("ab@test.com").to_string(),
            "**@test.com"
        );
        assert_eq!(SanitizedEmail::new("a@test.com").to_string(), "*@test.com");
        assert_eq!(SanitizedEmail::new("invalid-email").to_string(), "***@***");
    }

    #[test]
    fn test_sanitize_username() {
        assert_eq!(SanitizedUsername::new("johndoe").to_string(), "j***e");
        assert_eq!(SanitizedUsername::new("ab").to_string(), "**");
        assert_eq!(SanitizedUsername::new("abc").to_string(), "a***");
        assert_eq!(SanitizedUsername::new("a").to_string(), "*");
    }

    #[test]
    fn test_sanitize_ipv4() {
        assert_eq!(
            SanitizedIpAddr::new("192.168.1.100").to_string(),
            "192.168.1.***"
        );
        assert_eq!(SanitizedIpAddr::new("10.0.0.1").to_string(), "10.0.0.***");
    }

    #[test]
    fn test_sanitize_ipv6() {
        assert_eq!(
            SanitizedIpAddr::new("2001:0db8:85a3:0000:0000:8a2e:0370:7334").to_string(),
            "2001:0db8:85a3:0000:0000:8a2e:0370:****"
        );
    }

    #[test]
    fn test_security_event_critical() {
        assert!(SecurityEvent::LoginFailure.is_critical());
        assert!(SecurityEvent::TokenValidationFailure.is_critical());
        assert!(!SecurityEvent::LoginSuccess.is_critical());
    }

    #[test]
    fn test_loggable_uuid() {
        let uuid = Uuid::new_v4();
        let loggable = LoggableUuid::from(uuid);
        assert_eq!(loggable.to_string(), uuid.to_string());
    }
}
