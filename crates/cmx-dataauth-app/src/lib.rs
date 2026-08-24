//! cmx-dataauth-app —— 数据权限引擎的**平台中立应用层**（一芯）。
//!
//! **一芯多壳**：handler 不绑 `State` 提取器，故 [`dataauth_routes::<S>()`] 对任意 state 泛型 `S` 成立
//! （独立壳 `cmx-dataauth-server` 用 `::<()>()`；未来平台壳可 `::<CmxAppState>()`）。

pub mod auth;
pub mod dashboard;
pub mod engine;
pub mod handlers;
pub mod resp;
pub mod tenancy;
pub mod tenant;

pub use auth::auth as auth_middleware;
pub use engine::{warm_store, DATAAUTH_DB_ID};
pub use resp::{ApiResp, AuthzError, Result};
pub use tenant::{current_tenant, current_user, identity_snapshot};

use axum::routing::{get, post};
use axum::Router;

/// 数据权限模块全部路由，前缀 `/dataauth/*`。对任意 state 泛型 `S` 成立。
pub fn dataauth_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().nest("/dataauth", routes_inner::<S>())
}

/// v1 正式契约前缀 `/dataauth/v1/*`。
pub fn dataauth_routes_v1<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().nest("/dataauth/v1", routes_inner::<S>())
}

fn routes_inner<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        // —— 核心：决策 / 编译 ——
        .route("/decide", post(handlers::decide))
        .route("/compile", post(handlers::compile))
        // —— 策略 CRUD ——
        .route(
            "/policies",
            get(handlers::list_policies).post(handlers::save_policy),
        )
        .route(
            "/policies/{id}",
            get(handlers::get_policy).delete(handlers::delete_policy),
        )
        // —— 授权 CRUD ——
        .route(
            "/grants",
            get(handlers::list_grants).post(handlers::save_grant),
        )
        .route("/grants/{id}", axum::routing::delete(handlers::delete_grant))
        // —— 关系元组（ReBAC）CRUD + lookup ——
        .route(
            "/relation-tuples",
            get(handlers::list_tuples).post(handlers::save_tuple),
        )
        .route(
            "/relation-tuples/lookup",
            get(handlers::lookup_resources),
        )
        .route(
            "/relation-tuples/{id}",
            axum::routing::delete(handlers::delete_tuple),
        )
        // —— 列脱敏规则 CRUD ——
        .route(
            "/mask-rules",
            get(handlers::list_mask_rules).post(handlers::save_mask_rule),
        )
        .route(
            "/mask-rules/{id}",
            axum::routing::delete(handlers::delete_mask_rule),
        )
        // —— 层级维度值 ——
        .route(
            "/dimensions/{dim_key}/values",
            get(handlers::list_dimension_values),
        )
        .route("/dimension-values", post(handlers::save_dimension_value))
        // —— 审计 / 大盘 ——
        .route("/audit-logs", get(handlers::list_audit))
        .route("/stats", get(handlers::stats))
}
