use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
    pub fn bad_gateway(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = json!({
            "code": self.status.as_u16() as i64,
            "message": self.message,
            "data": Value::Null
        });
        (self.status, Json(body)).into_response()
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self { AppError::bad_request(format!("JSON: {e}")) }
}
impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self { AppError::internal(format!("IO: {e}")) }
}
impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self { AppError::bad_gateway(format!("HTTP: {e}")) }
}
impl From<String> for AppError {
    fn from(e: String) -> Self { AppError::internal(e) }
}

pub type Result<T> = std::result::Result<T, AppError>;

/// Envelope shared by every REST and compatibility endpoint.
pub fn ok(data: impl Serialize) -> Json<Value> {
    Json(json!({
        "code": 0,
        "message": "ok",
        "data": serde_json::to_value(data).unwrap_or(Value::Null)
    }))
}

pub fn created(data: impl Serialize) -> (StatusCode, Json<Value>) {
    (StatusCode::CREATED, ok(data))
}

pub fn message(text: impl Into<String>) -> Json<Value> {
    Json(json!({ "code": 0, "message": text.into(), "data": Value::Null }))
}
