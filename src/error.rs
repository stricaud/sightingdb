use actix_web::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::db::NotFound;

/// Something a request asked for that we would not or could not do.
///
/// Each variant carries the HTTP status it should map to; the old code answered
/// `200 OK` for every one of these, which left clients parsing prose to find out
/// whether their request had worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The `_config` tree is server state and is not reachable over HTTP.
    ConfigNamespace,
    /// A write aimed at a namespace the database keeps for itself.
    InternalNamespace(String),
    /// A write aimed at a namespace this server does not store.
    NotStored(String),
    /// No such namespace, or no such value inside it.
    NotFound(NotFound),
    /// A write with nothing to record.
    EmptyValue,
    /// A timestamp that does not correspond to a representable instant.
    InvalidTimestamp(i64),
}

/// Error bodies that are a bare `{"message": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub message: String,
}

impl Message {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::ConfigNamespace => {
                write!(f, "No access to _config namespace from outside!")
            }
            ApiError::InternalNamespace(namespace) => write!(
                f,
                "'{namespace}' is an internal namespace and is not writable from outside."
            ),
            ApiError::NotStored(namespace) => write!(
                f,
                "This server does not store '{namespace}'. Its [storage] namespaces \
                 list says what it holds."
            ),
            ApiError::NotFound(nf) => write!(f, "{}", nf.error),
            ApiError::EmptyValue => write!(f, "Refusing to write an empty value."),
            ApiError::InvalidTimestamp(ts) => write!(f, "Timestamp out of range: {ts}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::ConfigNamespace | ApiError::InternalNamespace(_) => StatusCode::FORBIDDEN,
            // Not "forbidden" and not "missing": the request arrived somewhere
            // that cannot serve it. Once forwarding exists this is what a
            // router answers when no peer holds the namespace either, and it
            // has to stay distinguishable from a genuine 404 to be debuggable.
            ApiError::NotStored(_) => StatusCode::MISDIRECTED_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::EmptyValue | ApiError::InvalidTimestamp(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// The JSON body for this error. `NotFound` keeps its richer shape
    /// (`error`/`namespace`/`value`); everything else is a plain message.
    pub fn body(&self) -> serde_json::Value {
        match self {
            ApiError::NotFound(nf) => serde_json::json!(nf),
            ApiError::ConfigNamespace => {
                serde_json::json!(Message::new("No access to _config namespace from outside!"))
            }
            ApiError::InternalNamespace(_) | ApiError::NotStored(_) => {
                serde_json::json!(Message::new(self.to_string()))
            }
            ApiError::EmptyValue => {
                serde_json::json!(Message::new("Refusing to write an empty value."))
            }
            ApiError::InvalidTimestamp(ts) => {
                serde_json::json!(Message::new(format!("Timestamp out of range: {ts}")))
            }
        }
    }
}
