//! HTTP handler —— 自由 `async fn`，不绑 `State`（故路由对任意 `S` 泛型成立）。
//!
//! 端点：decide / compile · policy CRUD · grant CRUD · relation-tuple CRUD + lookup ·
//! mask-rule CRUD · dimension-value 列表/保存 · audit 列表 · stats。

use crate::engine;
use crate::resp::{ApiResp, AuthzError, Result};
use crate::tenant::{current_roles, current_tenant, current_user};
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

/// 记录一条配置变更审计（非致命：失败仅 warn，不阻断主流程）。
async fn record_change(entity_type: &str, op: &str, entity_id: impl std::fmt::Display, detail: Value) {
    let t = current_tenant();
    let log = cmx_dataauth_core::ChangeLog {
        id: uuid::Uuid::new_v4().to_string(),
        actor: current_user().unwrap_or_default(),
        op: op.to_string(),
        entity_type: entity_type.to_string(),
        entity_id: entity_id.to_string(),
        detail,
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = engine::store().append_change(&t, &log).await {
        tracing::warn!(error = %e, "配置变更审计写入失败（非致命）");
    }
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

/// `DELETE /demo/vouchers/{id}` —— **#4 演示：写/删侧权限无感**。
///
/// 与读侧同理，业务 handler 只消费中间件（`pep::guard`，Action::Delete）注入的 `DataScope`，把它拼进
/// 自己的 DELETE。约定：**scope 参数在前（`$1..$n`），handler 自有参数续号（`$n+1`）**，无需重排占位。
/// 删除后应校验影响行数——为 0 且 scope≠`TRUE` 即该行不在可见范围，视为越权（403/404）。这里不连真库，只回显。
pub async fn demo_delete_voucher(
    Path(id): Path<i64>,
    axum::Extension(scope): axum::Extension<std::sync::Arc<crate::pep::DataScope>>,
) -> Result<Json<ApiResp<Value>>> {
    let n = scope.params.len();
    let business_sql = format!(
        "DELETE FROM voucher WHERE ({}) AND id = ${} RETURNING id",
        scope.where_sql,
        n + 1
    );
    let mut params = scope.params.clone();
    params.push(json!(id));
    ok(json!({
        "note": "写/删同读：消费 DataScope 限定行集（scope 参数在前，自有参数续号）",
        "effect": scope.effect,
        "businessSql": business_sql,
        "params": params,
        "guard": "影响行数=0 且 scope≠TRUE → 该行不在可见范围，应视为 403/404（防越权删除）",
    }))
}

// ─────────────────── policy CRUD ───────────────────
/// 列表分页/检索通用查询：`?limit=&offset=&q=`。
#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default = "default_page_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
    #[serde(default)]
    q: Option<String>,
}

fn default_page_limit() -> i64 {
    50
}

/// 组装分页信封 `{ items, total, limit, offset }`。
fn page(items: Value, total: i64, p: &PageQuery) -> Value {
    json!({ "items": items, "total": total, "limit": p.limit.clamp(1, 500), "offset": p.offset.max(0) })
}

pub async fn list_policies(Query(p): Query<PageQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let st = engine::store();
    let items = st
        .list_policies(&t, p.limit, p.offset, p.q.as_deref())
        .await
        .map_err(|e| AuthzError::internal(format!("列策略失败: {e}")))?;
    let total = st
        .count_policies(&t, p.q.as_deref())
        .await
        .map_err(|e| AuthzError::internal(format!("计策略数失败: {e}")))?;
    ok(page(json!(items), total, &p))
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
    crate::cache::bump_generation();
    record_change("policy", "upsert", id, json!({ "name": p.name, "resourceKind": p.resource_kind, "action": p.action.as_str(), "effect": format!("{:?}", p.effect) })).await;
    ok(json!({ "id": id }))
}

pub async fn delete_policy(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let n = engine::store()
        .delete_policy(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("删策略失败: {e}")))?;
    crate::cache::bump_generation();
    record_change("policy", "delete", id, json!({})).await;
    ok(json!({ "deleted": n }))
}

// ─────────────────── grant CRUD ───────────────────

pub async fn list_grants(Query(p): Query<PageQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let st = engine::store();
    let items = st
        .list_grants(&t, p.limit, p.offset, p.q.as_deref())
        .await
        .map_err(|e| AuthzError::internal(format!("列授权失败: {e}")))?;
    let total = st
        .count_grants(&t, p.q.as_deref())
        .await
        .map_err(|e| AuthzError::internal(format!("计授权数失败: {e}")))?;
    ok(page(json!(items), total, &p))
}

pub async fn save_grant(Json(g): Json<Grant>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let id = engine::store()
        .save_grant(&t, &g)
        .await
        .map_err(|e| AuthzError::internal(format!("存授权失败: {e}")))?;
    // L3 物化缓存精准失效：该主体在此字典维度上的可见集需重算（"重分配即刷新"）。
    crate::matcache::invalidate_for_grant(&t, g.dim_key.as_deref(), &g.subject_type, &g.subject_id);
    crate::cache::bump_generation();
    record_change("grant", "upsert", id, json!({ "subjectType": g.subject_type, "subjectId": g.subject_id, "dimKey": g.dim_key, "dimValues": g.dim_values })).await;
    ok(json!({ "id": id }))
}

pub async fn delete_grant(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let st = engine::store();
    // 删前先取该授权的维度/主体，以便精准失效物化缓存（按 id 直取，避免全表扫）。
    let victim = st.get_grant(&t, id).await.ok().flatten();
    let n = st
        .delete_grant(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("删授权失败: {e}")))?;
    if let Some(g) = victim {
        crate::matcache::invalidate_for_grant(&t, g.dim_key.as_deref(), &g.subject_type, &g.subject_id);
    }
    crate::cache::bump_generation();
    record_change("grant", "delete", id, json!({})).await;
    ok(json!({ "deleted": n }))
}

// ─────────────────── relation-tuple CRUD + lookup ───────────────────

pub async fn list_tuples(Query(p): Query<PageQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let st = engine::store();
    let items = st
        .list_tuples(&t, p.limit, p.offset, p.q.as_deref())
        .await
        .map_err(|e| AuthzError::internal(format!("列关系元组失败: {e}")))?;
    let total = st
        .count_tuples(&t, p.q.as_deref())
        .await
        .map_err(|e| AuthzError::internal(format!("计关系元组数失败: {e}")))?;
    ok(page(json!(items), total, &p))
}

pub async fn save_tuple(Json(tp): Json<RelationTuple>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let id = engine::store()
        .save_tuple(&t, &tp)
        .await
        .map_err(|e| AuthzError::internal(format!("存关系元组失败: {e}")))?;
    crate::cache::bump_generation();
    record_change("relation_tuple", "upsert", id, json!({ "objectKind": tp.object_kind, "objectId": tp.object_id, "relation": tp.relation, "subjectKind": tp.subject_kind, "subjectId": tp.subject_id })).await;
    ok(json!({ "id": id }))
}

pub async fn delete_tuple(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let n = engine::store()
        .delete_tuple(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("删关系元组失败: {e}")))?;
    crate::cache::bump_generation();
    record_change("relation_tuple", "delete", id, json!({})).await;
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
    crate::cache::bump_generation();
    record_change("mask_rule", "upsert", id, json!({ "resourceKind": m.resource_kind, "column": m.column, "maskType": format!("{:?}", m.mask_type) })).await;
    ok(json!({ "id": id }))
}

pub async fn delete_mask_rule(Path(id): Path<i64>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let n = engine::store()
        .delete_mask_rule(&t, id)
        .await
        .map_err(|e| AuthzError::internal(format!("删脱敏规则失败: {e}")))?;
    crate::cache::bump_generation();
    record_change("mask_rule", "delete", id, json!({})).await;
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
    // 字典条目变化影响全量集与已物化集 → 失效该字典缓存。
    crate::matcache::invalidate(&t, &dv.dim_key, None);
    crate::cache::bump_generation();
    record_change("dimension_value", "upsert", format!("{}:{}", dv.dim_key, dv.dim_value), json!({ "dimKey": dv.dim_key, "dimValue": dv.dim_value, "parentValue": dv.parent_value })).await;
    ok(json!({ "ok": true }))
}

// ─────────────────── L3 物化权限集缓存（急切物化） ───────────────────

/// `GET /dict/{dictCode}/permitted[?userId=&roles=r1,r2]` —— 取当前主体在该字典上的可见条目。
/// 缓存优先（O(1) 直取）；未命中即物化。off 模式无身份时可用 query 覆写主体（便于测试/服务间调用）。
#[derive(Deserialize)]
pub struct PermittedQuery {
    #[serde(rename = "userId", default)]
    user_id: Option<String>,
    #[serde(default)]
    roles: Option<String>,
    #[serde(default)]
    orgs: Option<String>,
    #[serde(default)]
    posts: Option<String>,
}

/// 逗号分隔字符串 → 去空去空白的字符串列表。
fn csv(s: &Option<String>) -> Vec<String> {
    match s {
        Some(v) => v
            .split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect(),
        None => Vec::new(),
    }
}

pub async fn dict_permitted(
    Path(dict_code): Path<String>,
    Query(q): Query<PermittedQuery>,
) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let user = q.user_id.clone().or_else(current_user).unwrap_or_default();
    let roles: Vec<String> = match &q.roles {
        Some(_) => csv(&q.roles),
        None => current_roles(),
    };
    let orgs = csv(&q.orgs);
    let posts = csv(&q.posts);
    let p = crate::matcache::permitted_entries(&t, &dict_code, &user, &roles, &orgs, &posts).await?;
    ok(json!({
        "dictCode": dict_code,
        "fromCache": p.from_cache,
        "materializedAt": p.materialized_at,
        "count": p.entries.len(),
        "entries": p.entries,
    }))
}

/// `POST /dict/{dictCode}/refresh` body：`{ subjectType?, subjectId? }`。
/// 失效该字典的物化缓存（指定 principal 则只失效该键，否则整字典）。权限再分配后调用。
#[derive(Deserialize, Default)]
pub struct RefreshReq {
    #[serde(rename = "subjectType", default)]
    subject_type: Option<String>,
    #[serde(rename = "subjectId", default)]
    subject_id: Option<String>,
}

pub async fn dict_refresh(
    Path(dict_code): Path<String>,
    body: Option<Json<RefreshReq>>,
) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let n = match (req.subject_type.as_deref(), req.subject_id.as_deref()) {
        (Some(st), Some(si)) => crate::matcache::invalidate(&t, &dict_code, Some((st, si))),
        _ => crate::matcache::invalidate(&t, &dict_code, None),
    };
    ok(json!({ "dictCode": dict_code, "invalidated": n }))
}

// ─────────────────── RLS DDL 生成（防绕过纵深兜底） ───────────────────

/// `POST /rls/ddl` body：`{ table, dimColumn, guc?, policyName? }` → RLS DDL 语句 + set_config 示例。
/// 纯字符串生成（不碰 DB），供 DBA 审阅后执行。
#[derive(Deserialize)]
pub struct RlsReq {
    table: String,
    #[serde(rename = "dimColumn")]
    dim_column: String,
    #[serde(default)]
    guc: Option<String>,
    #[serde(rename = "policyName", default)]
    policy_name: Option<String>,
}

pub async fn rls_ddl(Json(req): Json<RlsReq>) -> Result<Json<ApiResp<Value>>> {
    let mut spec = cmx_dataauth_core::RlsSpec::new(req.table, req.dim_column);
    if let Some(g) = req.guc {
        spec = spec.with_guc(g);
    }
    if let Some(p) = req.policy_name {
        spec = spec.with_policy_name(p);
    }
    let ddl = cmx_dataauth_core::rls::generate(&spec).map_err(AuthzError::business)?;
    ok(json!({
        "ddl": ddl,
        "setScopeSql": cmx_dataauth_core::rls::set_scope_sql(&spec),
        "guc": spec.guc,
        "note": "应用层下推为主、RLS 兜底：应用须以非超级用户连库；事务开始用 setScopeSql 写入维度 scope（$1=逗号分隔ID）。GUC 未设→无行(fail-closed)。",
    }))
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

/// `POST /audit-logs/prune?beforeDays=90` —— 清理超保留期的审计（TTL）。
#[derive(Deserialize)]
pub struct PruneQuery {
    #[serde(rename = "beforeDays", default = "default_retention")]
    before_days: i64,
}

fn default_retention() -> i64 {
    90
}

pub async fn prune_audit(Query(q): Query<PruneQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let days = q.before_days.max(0);
    let before = chrono::Utc::now() - chrono::Duration::days(days);
    let n = engine::store()
        .prune_audit(&t, before)
        .await
        .map_err(|e| AuthzError::internal(format!("清理审计失败: {e}")))?;
    ok(json!({ "beforeDays": days, "prunedBefore": before.to_rfc3339(), "deleted": n }))
}

/// `GET /change-logs?limit=100` —— 配置变更审计（谁改了哪条策略/授权/…，#21）。
pub async fn list_changes(Query(q): Query<AuditQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let logs = engine::store()
        .list_changes(&t, q.limit)
        .await
        .map_err(|e| AuthzError::internal(format!("列变更审计失败: {e}")))?;
    ok(json!(logs))
}

/// `POST /explain` body：`{ subject, resource }` → 决策 + 人类可读解释（#19）。
pub async fn explain(Json(req): Json<DecideReq>) -> Result<Json<ApiResp<Value>>> {
    let d = engine::decide(&req.subject, &req.resource).await?;
    let mut reasons: Vec<String> = Vec::new();
    reasons.push(format!("最终效果：{:?}", d.effect));
    if d.trace.matched_policies.is_empty() {
        reasons.push("无匹配策略 → fail-closed 拒绝".into());
    } else {
        reasons.push(format!("命中策略：{}", d.trace.matched_policies.join("、")));
    }
    for (k, v) in &d.trace.expanded_dims {
        reasons.push(format!("维度 {k} 展开为 {} 个值", v.len()));
    }
    if !d.obligations.is_empty() {
        let cols: Vec<String> = d
            .obligations
            .iter()
            .map(|o| format!("{}({:?})", o.column, o.mask_type))
            .collect();
        reasons.push(format!("脱敏义务：{}", cols.join("、")));
    }
    reasons.extend(d.trace.notes.iter().cloned());
    ok(json!({ "decision": d, "explanation": reasons }))
}

/// `GET /policies/overlap?resourceKind=&action=read` —— 策略重叠/冲突分析（#19）。
#[derive(Deserialize)]
pub struct OverlapQuery {
    #[serde(rename = "resourceKind")]
    resource_kind: String,
    #[serde(default = "default_action")]
    action: String,
}

fn default_action() -> String {
    "read".to_string()
}

pub async fn policy_overlap(Query(q): Query<OverlapQuery>) -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    // 取该资源+动作的全部策略（大页足够，策略量小）。
    let all = engine::store()
        .list_policies(&t, 500, 0, None)
        .await
        .map_err(|e| AuthzError::internal(format!("列策略失败: {e}")))?;
    let matched: Vec<&PolicyDef> = all
        .iter()
        .filter(|p| p.resource_kind == q.resource_kind && p.action.as_str() == q.action)
        .collect();
    use cmx_dataauth_core::Effect;
    let permits = matched.iter().filter(|p| p.effect == Effect::Permit).count();
    let denies = matched.iter().filter(|p| p.effect == Effect::Deny).count();

    let mut findings: Vec<String> = Vec::new();
    if permits == 0 {
        findings.push("无放行策略 → 该资源恒拒绝（fail-closed）".into());
    }
    if permits > 1 {
        findings.push(format!("{permits} 条放行策略取并（可见集为各自之并）"));
    }
    if denies > 0 {
        findings.push(format!("{denies} 条 Deny 策略扣除行集"));
    }
    // Deny 约束为常量 True → 拒全部（盖过所有 permit）。
    for p in &matched {
        if p.effect == Effect::Deny && p.constraint_tpl == json!({"kind":"true"}) {
            findings.push(format!("策略「{}」Deny 约束=True → 拒全部（盖过所有放行）", p.name));
        }
    }
    // 重复约束（同 effect 下完全相同的 constraint_tpl）。
    let mut seen: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for p in &matched {
        let k = format!("{:?}|{}", p.effect, p.constraint_tpl);
        seen.entry(k).or_default().push(p.name.clone());
    }
    for names in seen.values() {
        if names.len() > 1 {
            findings.push(format!("重复约束：{}（可合并）", names.join("、")));
        }
    }
    if findings.is_empty() {
        findings.push("未发现明显重叠/冲突".into());
    }
    ok(json!({
        "resourceKind": q.resource_kind,
        "action": q.action,
        "policyCount": matched.len(),
        "permits": permits,
        "denies": denies,
        "findings": findings,
    }))
}

/// `GET /stats` —— 大盘聚合（策略/授权/元组数量 + 最近审计条数）。
pub async fn stats() -> Result<Json<ApiResp<Value>>> {
    let t = current_tenant();
    let st = engine::store();
    let policies = st.count_policies(&t, None).await.unwrap_or(0);
    let grants = st.count_grants(&t, None).await.unwrap_or(0);
    let tuples = st.count_tuples(&t, None).await.unwrap_or(0);
    let recent_audit = st.list_audit(&t, 20).await.map(|v| v.len()).unwrap_or(0);
    ok(json!({
        "policies": policies,
        "grants": grants,
        "tuples": tuples,
        "recentAudit": recent_audit,
        "matCacheEntries": crate::matcache::cache_size(),
        "decideCacheEntries": crate::cache::decide_cache_size(),
        "descCacheEntries": crate::cache::desc_cache_size(),
    }))
}
