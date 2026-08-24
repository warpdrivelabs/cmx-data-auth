//! D6 —— PEP 中间件自动注入：业务 handler 对数据权限**无感**。
//!
//! 用法：给业务路由挂一层 `pep::guard(spec)`，声明该路由保护的资源（kind/action/列绑定）。中间件
//! 在请求进入 handler 前，读当前 task_local 主体 → `engine::decide` + 编译 SQL → 把
//! [`DataScope`]（whereSql + params + 脱敏义务）塞进请求扩展；Deny 直接 403 短路。业务 handler
//! 只需声明 `Extension<DataScope>`，把 `scope.where_sql`/`scope.params` 拼进自己的查询即可。
//!
//! 这样"决策/执行"对业务代码透明：handler 不 import 任何策略/授权概念，只消费一段 WHERE。

use crate::engine;
use crate::resp::AuthzError;
use crate::tenant::{current_roles, current_tenant, current_user};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cmx_dataauth_core::{Action, Obligation, Resource, Subject};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// 受保护资源声明（挂在路由上，供中间件构造 [`Resource`]）。
#[derive(Clone, Debug)]
pub struct ResourceSpec {
    pub kind: String,
    pub action: Action,
    /// 逻辑维度 → 物理列（如 `org → ou_id`）。
    pub dim_bindings: BTreeMap<String, String>,
    /// 可过滤列白名单。
    pub row_ctx: Vec<String>,
}

impl ResourceSpec {
    pub fn new(kind: impl Into<String>, action: Action) -> Self {
        Self {
            kind: kind.into(),
            action,
            dim_bindings: BTreeMap::new(),
            row_ctx: Vec::new(),
        }
    }
    pub fn dim(mut self, logical: impl Into<String>, physical: impl Into<String>) -> Self {
        self.dim_bindings.insert(logical.into(), physical.into());
        self
    }
    pub fn cols(mut self, cols: &[&str]) -> Self {
        self.row_ctx = cols.iter().map(|s| s.to_string()).collect();
        self
    }
    fn to_resource(&self) -> Resource {
        Resource {
            kind: self.kind.clone(),
            action: self.action,
            dim_bindings: self.dim_bindings.clone(),
            row_ctx: self.row_ctx.clone(),
        }
    }
}

/// 中间件注入进请求扩展的数据权限切面。业务 handler 经 `Extension<DataScope>` 取用。
#[derive(Clone, Debug)]
pub struct DataScope {
    /// `permit` | `permitWithConstraint`（Deny 已被中间件 403 短路，不会到 handler）。
    pub effect: String,
    /// 参数化 WHERE 片段（`permit` 全放行时为 `"TRUE"`）。
    pub where_sql: String,
    /// WHERE 的有序参数（`$1..$n`）。
    pub params: Vec<Value>,
    /// 列脱敏义务。
    pub obligations: Vec<Obligation>,
}

impl DataScope {
    /// 对一组行就地施加脱敏义务（handler 查完库后调用）。
    pub fn apply_masks(&self, rows: &mut [serde_json::Map<String, Value>]) {
        cmx_dataauth_core::apply_masks(rows, &self.obligations);
    }
}

/// 从 task_local 构造当前主体。
fn current_subject() -> Subject {
    Subject {
        tenant: current_tenant(),
        user_id: current_user().unwrap_or_default(),
        roles: current_roles(),
        dims: BTreeMap::new(),
        attrs: Value::Null,
    }
}

/// PEP 守卫中间件。挂在受保护业务路由上：
/// ```ignore
/// .route("/vouchers", get(list_vouchers))
/// .layer(axum::middleware::from_fn({
///     let spec = ResourceSpec::new("voucher", Action::Read).dim("org","ou_id").cols(&["owner","status"]);
///     move |req, next| pep::guard(spec.clone(), req, next)
/// }))
/// ```
pub async fn guard(spec: ResourceSpec, mut req: Request, next: Next) -> Response {
    let subject = current_subject();
    let resource = spec.to_resource();
    let decision = match engine::decide(&subject, &resource).await {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };
    // Deny → 403 短路，不进 handler。
    if matches!(decision.effect, cmx_dataauth_core::DecisionEffect::Deny) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "code": 403, "msg": "数据权限拒绝：无可见数据" })),
        )
            .into_response();
    }
    // 编译 SQL 切面。
    let compiled = match engine::compile(&decision, &resource, "sql") {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let where_sql = compiled
        .get("whereSql")
        .and_then(|v| v.as_str())
        .unwrap_or("TRUE")
        .to_string();
    let params = compiled
        .get("params")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let scope = DataScope {
        effect: format!("{:?}", decision.effect),
        where_sql,
        params,
        obligations: decision.obligations,
    };
    req.extensions_mut().insert(Arc::new(scope));
    next.run(req).await
}

/// handler 侧便捷：从请求扩展取注入的 [`DataScope`]（中间件未挂时报内部错）。
pub fn scope_from(ext: &axum::http::Extensions) -> Result<Arc<DataScope>, AuthzError> {
    ext.get::<Arc<DataScope>>()
        .cloned()
        .ok_or_else(|| AuthzError::internal("PEP 中间件未注入 DataScope（路由缺 pep::guard 层）"))
}
