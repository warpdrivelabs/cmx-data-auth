//! HTTP handler —— 自由 `async fn`，不绑 `State`（故路由对任意 `S` 泛型成立）。
//!
//! 端点：decide / compile · policy CRUD · grant CRUD · relation-tuple CRUD + lookup ·
//! mask-rule CRUD · dimension-value 列表/保存 · audit 列表 · stats。

use crate::engine;
use crate::resp::{ApiResp, AuthzError, Result};
use crate::tenant::current_tenant;
use axum::extract::{Path, Query};
use axum::Json;
use cmx_dataauth_core::{
    DataAuthStore, DimensionValue, Grant, MaskRule, PolicyDef, RelationTuple, Resource, Subject,
};
use serde::Deserialize;
use serde_json::{json, Value};

fn ok(v: Value) -> Result<Json<ApiResp<Value>>> {
    Ok(Json(ApiResp::ok(v)))
}

// ─────────────────── decide / compile ───────────────────

/// `POST /decide` body：`{ subject, resource }`。
#[derive(Deserialize)]
pub struct DecideReq {
    pub subject: Subject,
    pub resource: Resource,
}

pub async fn decide(Json(req): Json<DecideReq>) -> Result<Json<ApiResp<Value>>> {
    let d = engine::decide(&req.subject, &req.resource).await?;
    ok(serde_json::to_value(&d).unwrap_or(Value::Null))
}

/// `POST /compile` body：`{ subject, resource, backend }`。一步 decide + compile。
#[derive(Deserialize)]
pub struct CompileReq {
    pub subject: Subject,
    pub resource: Resource,
    #[serde(default)]
    pub backend: String,
}

pub async fn compile(Json(req): Json<CompileReq>) -> Result<Json<ApiResp<Value>>> {
    let d = engine::decide(&req.subject, &req.resource).await?;
    let compiled = engine::compile(&d, &req.resource, &req.backend)?;
    ok(json!({ "decision": d, "compiled": compiled }))
}

/// `GET /demo/vouchers` —— **D6 演示：权限无感的业务 handler**。
///
/// 它只声明消费中间件注入的 `DataScope`，完全不 import 任何策略/授权/维度概念。收到的
/// `scope.where_sql`/`scope.params` 已是数据权限编译好的下推片段，直接拼进自己的 SQL 即可。
/// 这里不连真库，只回显"业务 handler 会怎样用它"以证明接缝。
pub async fn demo_vouchers(req: axum::extract::Request) -> Result<Json<ApiResp<Value>>> {
    let scope = crate::pep::scope_from(req.extensions())?;
    let business_sql = format!(
        "SELECT id, ou_id, owner, status, amount FROM voucher WHERE {} ORDER BY biz_date DESC LIMIT 50",
        scope.where_sql
    );
    ok(json!({
        "note": "业务 handler 权限无感：仅消费中间件注入的 DataScope",
        "effect": scope.effect,
        "businessSql": business_sql,
        "scopeParams": scope.params,
        "obligations": scope.obligations,
    }))
}

/// `POST /enforce` body：`{ subject, resource, rows }`。
/// decide 后在内存里过滤 rows + 脱敏列（archetype-③，全程不碰 DB）。
#[derive(Deserialize)]
pub struct EnforceReq {
    pub subject: Subject,
    pub resource: Resource,
    #[serde(default)]
    pub rows: Vec<serde_json::Map<String, Value>>,
}

pub async fn enforce(Json(req): Json<EnforceReq>) -> Result<Json<ApiResp<Value>>> {
    let d = engine::decide(&req.subject, &req.resource).await?;
    let total = req.rows.len();
    let (kept, filtered) = engine::enforce(&d, req.rows)?;
    ok(json!({
        "effect": d.effect,
        "total": total,
        "kept": kept.len(),
        "filtered": filtered,
        "rows": kept,
        "obligations": d.obligations,
    }))
}

// ─────────────────── policy CRUD ───────────────────

pub async fn list_policies() -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let ps = engine::store()
        .list_policies(&t)
        .await
        .map_err(|e| AuthzError::internal(format!("列策略失败: {e}")))?;
    ok(json!(ps))
}

pub async fn get_policy(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let p = engine::store()
        .get_policy(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("取策略失败: {e}")))?
        .ok_or_else(|| AuthzError::not_found(format!("策略 {id} 不存在")))?;
    ok(json!(p))
}

pub async fn save_policy(Json(p): Json<PolicyDef>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let id = engine::store()
        .save_policy(&t, &p)
        .await
        .map_err(|e| AuthzError::internal(format!("存策略失败: {e}")))?;
    ok(json!({ "id": id }))
}

pub async fn delete_policy(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let n = engine::store()
        .delete_policy(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("删策略失败: {e}")))?;
    ok(json!({ "deleted": n }))
}

// ─────────────────── grant CRUD ───────────────────

pub async fn list_grants() -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let gs = engine::store()
        .list_grants(&t)
        .await
        .map_err(|e| AuthzError::internal(format!("列授权失败: {e}")))?;
    ok(json!(gs))
}

pub async fn save_grant(Json(g): Json<Grant>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let id = engine::store()
        .save_grant(&t, &g)
        .await
        .map_err(|e| AuthzError::internal(format!("存授权失败: {e}")))?;
    ok(json!({ "id": id }))
}

pub async fn delete_grant(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let n = engine::store()
        .delete_grant(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("删授权失败: {e}")))?;
    ok(json!({ "deleted": n }))
}

// ─────────────────── relation-tuple CRUD + lookup ───────────────────

pub async fn list_tuples() -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let ts = engine::store()
        .list_tuples(&t)
        .await
        .map_err(|e| AuthzError::internal(format!("列关系元组失败: {e}")))?;
    ok(json!(ts))
}

pub async fn save_tuple(Json(tp): Json<RelationTuple>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let id = engine::store()
        .save_tuple(&t, &tp)
        .await
        .map_err(|e| AuthzError::internal(format!("存关系元组失败: {e}")))?;
    ok(json!({ "id": id }))
}

pub async fn delete_tuple(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let n = engine::store()
        .delete_tuple(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("删关系元组失败: {e}")))?;
    ok(json!({ "deleted": n }))
}

/// `GET /relation-tuples/lookup?objectKind=&relation=&subjectKind=&subjectId=` → 对象 id 集。
#[derive(Deserialize)]
pub struct LookupQuery {
    #[serde(rename = "objectKind")]
    object_kind: String,
    relation: String,
    #[serde(rename = "subjectKind", default = "default_user")]
    subject_kind: String,
    #[serde(rename = "subjectId")]
    subject_id: String,
}

fn default_user() -> String {
    "user".to_string()
}

pub async fn lookup_resources(Query(q): Query<LookupQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let ids = engine::store()
        .lookup_resources(&t, &q.object_kind, &q.relation, &q.subject_kind, &q.subject_id)
        .await
        .map_err(|e| AuthzError::internal(format!("关系查询失败: {e}")))?;
    ok(json!({ "objectIds": ids }))
}

// ─────────────────── mask-rule CRUD ───────────────────

/// `GET /mask-rules?resourceKind=`。
#[derive(Deserialize)]
pub struct MaskQuery {
    #[serde(rename = "resourceKind", default)]
    resource_kind: String,
}

pub async fn list_mask_rules(Query(q): Query<MaskQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let ms = engine::store()
        .list_mask_rules(&t, &q.resource_kind)
        .await
        .map_err(|e| AuthzError::internal(format!("列脱敏规则失败: {e}")))?;
    ok(json!(ms))
}

pub async fn save_mask_rule(Json(m): Json<MaskRule>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let id = engine::store()
        .save_mask_rule(&t, &m)
        .await
        .map_err(|e| AuthzError::internal(format!("存脱敏规则失败: {e}")))?;
    ok(json!({ "id": id }))
}

pub async fn delete_mask_rule(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let n = engine::store()
        .delete_mask_rule(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("删脱敏规则失败: {e}")))?;
    ok(json!({ "deleted": n }))
}

// ─────────────────── dimension-value ───────────────────

/// `GET /dimensions/{dim_key}/values`。
pub async fn list_dimension_values(Path(dim_key): Path<String>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let vs = engine::store()
        .list_dimension_values(&t, &dim_key)
        .await
        .map_err(|e| AuthzError::internal(format!("列维度值失败: {e}")))?;
    ok(json!(vs))
}

pub async fn save_dimension_value(Json(dv): Json<DimensionValue>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    engine::store()
        .save_dimension_value(&t, &dv)
        .await
        .map_err(|e| AuthzError::internal(format!("存维度值失败: {e}")))?;
    ok(json!({ "ok": true }))
}

// ─────────────────── audit / stats ───────────────────

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

pub async fn list_audit(Query(q): Query<AuditQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let logs = engine::store()
        .list_audit(&t, q.limit)
        .await
        .map_err(|e| AuthzError::internal(format!("列审计失败: {e}")))?;
    ok(json!(logs))
}

/// `GET /stats` —— 大盘聚合（策略/授权/元组数量 + 最近审计条数）。
pub async fn stats() -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let st = engine::store();
    let policies = st.list_policies(&t).await.map(|v| v.len()).unwrap_or(0);
    let grants = st.list_grants(&t).await.map(|v| v.len()).unwrap_or(0);
    let tuples = st.list_tuples(&t).await.map(|v| v.len()).unwrap_or(0);
    let recent_audit = st.list_audit(&t, 20).await.map(|v| v.len()).unwrap_or(0);
    ok(json!({
        "policies": policies,
        "grants": grants,
        "tuples": tuples,
        "recentAudit": recent_audit,
    }))
}
