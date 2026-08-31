//! cmx-dataauth-app —— 数据权限引擎的**平台中立应用层**（一芯）。
//!
//! **一芯多壳**：handler 不绑 `State` 提取器，故 [`dataauth_routes::<S>()`] 对任意 state 泛型 `S` 成立
//! （独立壳 `cmx-dataauth-server` 用 `::<()>()`；未来平台壳可 `::<CmxAppState>()`）。

pub mod auth;
pub mod cache;
pub mod console;
pub mod dashboard;
pub mod engine;
pub mod handlers;
pub mod matcache;
pub mod openapi;
pub mod pep;
pub mod policy_source;
pub mod resp;
pub mod tenancy;
pub mod tenant;

pub use auth::auth as auth_middleware;
pub use engine::{warm_store, DATAAUTH_DB_ID};
pub use pep::{guard as pep_guard, DataScope, ResourceSpec};
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
        .merge(open_routes::<S>())
        .merge(admin_routes::<S>())
        // —— D6 演示：权限无感业务 handler（经 pep::guard 自动注入 DataScope）——
        .merge(demo_guarded_routes::<S>())
}

/// 数据面（面向业务调用者，认证后开放）：决策 / 编译 / 内存执行 / 前端查可见字典 / 大盘聚合。
/// 这些端点**不**挂管理员守卫 —— 业务系统代表终端用户调用。
fn open_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/decide", post(handlers::decide))
        .route("/compile", post(handlers::compile))
        .route("/enforce", post(handlers::enforce))
        // L3 物化缓存：前端查自身可见字典条目。
        .route("/dict/{dict_code}/permitted", get(handlers::dict_permitted))
        // 大盘聚合（计数，低敏），供根 / 监控页轮询。
        .route("/stats", get(handlers::stats))
}

/// 管理面（策略/授权/脱敏/维度/关系元组 CRUD + 审计 + 缓存刷新）：整组挂 `require_admin` 守卫。
/// off 模式放行（本地信任）；jwt/api-key 模式要求管理员角色，否则 403。
fn admin_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
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
        .route("/relation-tuples/lookup", get(handlers::lookup_resources))
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
        // —— L3 物化缓存失效（权限再分配后刷新）——
        .route("/dict/{dict_code}/refresh", post(handlers::dict_refresh))
        // —— RLS DDL 生成（防绕过纵深兜底）——
        .route("/rls/ddl", post(handlers::rls_ddl))
        // —— 审计（谁访问了什么，敏感）——
        .route("/audit-logs", get(handlers::list_audit))
        .route("/audit-logs/prune", post(handlers::prune_audit))
        // —— 治理：配置变更审计 · 决策解释 · 策略重叠分析 ——
        .route("/change-logs", get(handlers::list_changes))
        .route("/explain", post(handlers::explain))
        .route("/policies/overlap", get(handlers::policy_overlap))
        .layer(axum::middleware::from_fn(crate::auth::require_admin))
}

/// D6 演示路由：`GET /demo/vouchers`（读）与 `DELETE /demo/vouchers/{id}`（删）各挂 PEP 守卫层
/// （voucher，org→ou_id，owner/status 可过滤）。业务 handler 权限无感，只消费注入的 `DataScope`。
fn demo_guarded_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use cmx_dataauth_core::Action;
    let read_spec = pep::ResourceSpec::new("voucher", Action::Read)
        .dim("org", "ou_id")
        .cols(&["owner", "status"]);
    let del_spec = pep::ResourceSpec::new("voucher", Action::Delete)
        .dim("org", "ou_id")
        .cols(&["owner", "status"]);
    let read = Router::new()
        .route("/demo/vouchers", get(handlers::demo_vouchers))
        .layer(axum::middleware::from_fn(move |req, next| {
            let spec = read_spec.clone();
            async move { pep::guard(spec, req, next).await }
        }));
    let del = Router::new()
        .route(
            "/demo/vouchers/{id}",
            axum::routing::delete(handlers::demo_delete_voucher),
        )
        .layer(axum::middleware::from_fn(move |req, next| {
            let spec = del_spec.clone();
            async move { pep::guard(spec, req, next).await }
        }));
    read.merge(del)
}
