//! 平台中立的响应信封 + 错误类型（字节对齐 cmx-api-types 的 {code,msg,data}）。
//!
//! 与 cmx-rule-app::resp 同构：本 crate 不依赖 cmx-api-types，自持等价定义。
//! `AuthzError`：Business → HTTP 200 + code=1；NotFound → 404 + code=4；Internal → 500 + code=5。

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;

/// 统一响应信封。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResp<T> {
    pub code: u16,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> ApiResp<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: 0,
            msg: "success".to_string(),
            data: Some(data),
        }
    }
}

/// 平台中立错误。
#[derive(Debug, Clone)]
pub enum AuthzError {
    /// 业务错误（HTTP 200 + code=1）。
    Business(String),
    /// 资源不存在（HTTP 404 + code=4）。
    NotFound(String),
    /// 兜底内部错误（HTTP 500 + code=5）。
    Internal(String),
}

impl AuthzError {
    pub fn business(msg: impl Into<String>) -> Self {
        Self::Business(msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    fn code(&self) -> u16 {
        match self {
            Self::Business(_) => 1,
            Self::NotFound(_) => 4,
            Self::Internal(_) => 5,
        }
    }
    fn status(&self) -> StatusCode {
        match self {
            Self::Business(_) => StatusCode::OK,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    fn message(&self) -> &str {
        match self {
            Self::Business(m) | Self::NotFound(m) | Self::Internal(m) => m,
        }
    }
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}
impl std::error::Error for AuthzError {}

impl IntoResponse for AuthzError {
    fn into_response(self) -> Response {
        tracing::error!("{:<12} - AuthzError {self:?}", "ERROR");
        let status = self.status();
        let body = Json(json!({ "code": self.code(), "msg": self.message() }));
        (status, body).into_response()
    }
}

/// handler 结果别名。
pub type Result<T> = core::result::Result<T, AuthzError>;
