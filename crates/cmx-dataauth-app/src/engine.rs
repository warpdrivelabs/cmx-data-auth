//! 数据权限编排（对标 cmx-rule-app::engine，但引擎无长驻状态，**无 poller**）。
//!
//! `decide()` 串起：装策略 + 授权 → 层级维度展开 → 部分求值（core::pdp）→ 解析 ReBAC 关系 →
//! FEEL 评脱敏义务 → 审计。`compile()` 把决策的残差约束编译到指定后端。

use chrono::Utc;
use cmx_dataauth_core::{
    apply_masks, compose, Constraint, ConstraintCompiler, DataAuthStore, Decision, DecisionEffect,
    DimensionExpander, EsCompiler, ExpandedDims, Obligation, PolicyDef, Resource,
    RowFilterCompiler, SqlCompiler, Subject,
};
use cmx_dataauth_store_pg::{PgDataAuthStore, PgDimensionExpander};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::resp::AuthzError;

/// 默认（single）租户库数据源 id。
pub const DATAAUTH_DB_ID: &str = crate::tenancy::DATAAUTH_DB_ID;

/// 取当前请求租户的存储（构造廉价，仅裹 db_id）。
pub fn store() -> PgDataAuthStore {
    PgDataAuthStore::new(crate::tenancy::current_db_id())
}

/// 取当前请求租户的维度展开器。
pub fn expander() -> PgDimensionExpander {
    PgDimensionExpander::new(crate::tenancy::current_db_id())
}

/// 启动钩子：建默认库表。非致命——失败只 warn。**不起后台线程**。
pub async fn warm_store() -> Result<(), String> {
    PgDataAuthStore::new(DATAAUTH_DB_ID)
        .ensure_schema()
        .await
        .map_err(|e| format!("建表失败: {e}"))?;
    tracing::info!(db = DATAAUTH_DB_ID, "✅ 数据权限存储 schema 就绪（无 poller，纯请求驱动）");
    Ok(())
}

/// 核心决策：`decide(Subject, Resource) → Decision`（残差约束 + 脱敏义务 + 轨迹）。
pub async fn decide(subject: &Subject, resource: &Resource) -> Result<Decision, AuthzError> {
    let tenant = if subject.tenant.is_empty() {
        crate::tenant::current_tenant()
    } else {
        subject.tenant.clone()
    };
    let st = store();

    // ① 装匹配策略。
    let policies: Vec<PolicyDef> = st
        .load_policies(&tenant, &resource.kind, resource.action.as_str())
        .await
        .map_err(|e| AuthzError::internal(format!("装载策略失败: {e}")))?;
    // D3：决策表源策略 → 求值降解为内联 Constraint 模板（core::pdp 无感）。
    let policies: Vec<PolicyDef> = policies
        .iter()
        .map(|p| crate::policy_source::resolve_policy(p, subject))
        .collect();

    // ② 装命中主体（USER + 每个 ROLE + 每个 ORG/POST）的授权。
    let mut subjects = vec![("USER".to_string(), subject.user_id.clone())];
    for r in &subject.roles {
        subjects.push(("ROLE".to_string(), r.clone()));
    }
    for o in &subject.orgs {
        subjects.push(("ORG".to_string(), o.clone()));
    }
    for p in &subject.posts {
        subjects.push(("POST".to_string(), p.clone()));
    }
    let grants = st
        .load_grants(&tenant, &subjects)
        .await
        .map_err(|e| AuthzError::internal(format!("装载授权失败: {e}")))?;

    // ③ 层级维度展开（每个 grant 的每个根值 → descendants）。
    let ex = expander();
    let mut expanded: ExpandedDims = BTreeMap::new();
    for g in &grants {
        // inherit=false 的授权只覆盖本节点，无需展开子孙（core::pdp 会按 inherit 只取根值）。
        if !g.inherit {
            continue;
        }
        let Some(dim_key) = &g.dim_key else { continue };
        for root in &g.dim_values {
            let root_s = match root {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let key = (dim_key.clone(), root_s.clone());
            if expanded.contains_key(&key) {
                continue;
            }
            let vals = ex
                .descendants(&tenant, dim_key, &root_s)
                .await
                .map_err(|e| AuthzError::internal(format!("维度展开失败: {e}")))?;
            expanded.insert(key, vals.into_iter().map(Value::String).collect());
        }
    }

    // ④ 部分求值。
    let mut decision = compose(subject, resource, &policies, &grants, &expanded);

    // ⑤ 解析 ReBAC 关系节点 → In。
    decision.constraint = resolve_relations(&decision.constraint, &st, &tenant, subject).await?;
    // 解析后若坍缩成 True/False 需同步 effect。
    decision.effect = match &decision.constraint {
        Constraint::True => DecisionEffect::Permit,
        Constraint::False => DecisionEffect::Deny,
        _ => DecisionEffect::PermitWithConstraint,
    };

    // ⑥ 脱敏义务（角色门 + FEEL 条件门）。
    if decision.effect != DecisionEffect::Deny {
        decision.obligations = build_obligations(&st, &tenant, resource, subject).await?;
    }

    // ⑦ 审计（非致命）。
    let audit = cmx_dataauth_core::AuditLog {
        id: uuid::Uuid::new_v4().to_string(),
        tenant: tenant.clone(),
        user_id: subject.user_id.clone(),
        resource_kind: resource.kind.clone(),
        action: resource.action.as_str().to_string(),
        effect: format!("{:?}", decision.effect),
        constraint_json: serde_json::to_value(&decision.constraint).unwrap_or(Value::Null),
        backend: None,
        created_at: Utc::now(),
    };
    if let Err(e) = st.append_audit(&tenant, &audit).await {
        tracing::warn!(error = %e, "决策审计写入失败（非致命）");
    }

    Ok(decision)
}

/// 递归把 `Relation{field,rel,subject}` 解析成 `In{field, lookup_resources(...)}`。
fn resolve_relations<'a>(
    c: &'a Constraint,
    st: &'a PgDataAuthStore,
    tenant: &'a str,
    subject: &'a Subject,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Constraint, AuthzError>> + Send + 'a>>
{
    Box::pin(async move {
        Ok(match c {
            Constraint::And { items } => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    out.push(resolve_relations(it, st, tenant, subject).await?);
                }
                Constraint::and(out)
            }
            Constraint::Or { items } => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    out.push(resolve_relations(it, st, tenant, subject).await?);
                }
                Constraint::or(out)
            }
            Constraint::Not { item } => {
                Constraint::not(resolve_relations(item, st, tenant, subject).await?)
            }
            Constraint::Relation { field, rel, subject: subj } => {
                // subject 占位 $user → 实际 user_id。
                let sid = if subj == "$user" {
                    subject.user_id.clone()
                } else {
                    subj.clone()
                };
                // object_kind 约定为 field 去掉 _id 后缀（voucher_id → voucher），否则用 field。
                let object_kind = field.strip_suffix("_id").unwrap_or(field);
                let ids = st
                    .lookup_resources(tenant, object_kind, rel, "user", &sid)
                    .await
                    .map_err(|e| AuthzError::internal(format!("关系查询失败: {e}")))?;
                Constraint::in_values(field.clone(), ids.into_iter().map(Value::String).collect())
            }
            other => other.clone(),
        })
    })
}

/// 装脱敏规则 → 过角色门 + FEEL 条件门 → 义务列表。
async fn build_obligations(
    st: &PgDataAuthStore,
    tenant: &str,
    resource: &Resource,
    subject: &Subject,
) -> Result<Vec<Obligation>, AuthzError> {
    let rules = st
        .list_mask_rules(tenant, &resource.kind)
        .await
        .map_err(|e| AuthzError::internal(format!("装载脱敏规则失败: {e}")))?;
    let ctx = json!({ "user": subject.attrs.clone() });
    let mut out = Vec::new();
    for m in rules {
        // 角色门：持有豁免角色 → 不脱敏。
        if let Some(role) = &m.min_role
            && subject.roles.iter().any(|r| r == role)
        {
            continue;
        }
        // FEEL 条件门：有条件时，仅当求值为真才脱敏；求值出错 → fail-safe 脱敏。
        if let Some(expr) = &m.condition_expr
            && !expr.trim().is_empty()
        {
            let masked = match cmx_rule_feel::eval_expression(expr, &ctx) {
                Ok(Value::Bool(b)) => b,
                Ok(_) => true,
                Err(_) => true,
            };
            if !masked {
                continue;
            }
        }
        out.push(Obligation {
            column: m.column.clone(),
            mask_type: m.mask_type,
            pattern: m.partial_pattern.clone(),
        });
    }
    Ok(out)
}

/// 把决策的残差约束编译到指定后端。`backend` ∈ `sql` | `rowfilter` | `es`。
pub fn compile(decision: &Decision, resource: &Resource, backend: &str) -> Result<Value, AuthzError> {
    match backend {
        "sql" | "" => {
            let mut map = BTreeMap::new();
            for (logical, phys) in &resource.dim_bindings {
                map.insert(logical.clone(), phys.clone());
            }
            let c = SqlCompiler::new(resource.allow_fields())
                .with_map(map)
                .compile(&decision.constraint)
                .map_err(|e| AuthzError::business(format!("SQL 编译失败: {e}")))?;
            Ok(json!({ "backend": "sql", "whereSql": c.sql, "params": c.params }))
        }
        "es" => {
            let q = EsCompiler
                .compile(&decision.constraint)
                .map_err(|e| AuthzError::business(format!("ES 编译失败: {e}")))?;
            Ok(json!({ "backend": "es", "query": q }))
        }
        "rowfilter" => {
            // 内存谓词是闭包，无法 JSON 序列化；此处仅校验可编译并回显约束。
            let _pred = RowFilterCompiler
                .compile(&decision.constraint)
                .map_err(|e| AuthzError::business(format!("内存谓词编译失败: {e}")))?;
            Ok(json!({
                "backend": "rowfilter",
                "ok": true,
                "note": "内存谓词为运行时闭包，仅在服务内可用",
                "constraint": serde_json::to_value(&decision.constraint).unwrap_or(Value::Null)
            }))
        }
        other => Err(AuthzError::business(format!("未知编译后端: {other}"))),
    }
}

/// 在内存里对调用方给的行集**就地执行**数据权限：同一约束 AST 编译成谓词过滤行 + 义务脱敏列。
///
/// 这是 archetype-③（拉取后过滤）的完整闭环，**全程不碰数据库** —— 证明"同一决策多点执行"：
/// 同一 `Decision.constraint` 既可 [`compile`] 成 SQL 下推，也可在此处过滤内存 DataSet / CSV / 跨库结果。
///
/// 返回 `(kept, filtered_count)`：保留并脱敏后的行 + 被过滤掉的行数。
pub fn enforce(
    decision: &Decision,
    rows: Vec<serde_json::Map<String, Value>>,
) -> Result<(Vec<serde_json::Map<String, Value>>, usize), AuthzError> {
    let total = rows.len();
    // Deny → 全部过滤（约束为 False，谓词恒假）。
    let pred = RowFilterCompiler
        .compile(&decision.constraint)
        .map_err(|e| AuthzError::business(format!("内存谓词编译失败: {e}")))?;
    let mut kept: Vec<serde_json::Map<String, Value>> =
        rows.into_iter().filter(|r| pred(r)).collect();
    let filtered = total - kept.len();
    apply_masks(&mut kept, &decision.obligations);
    Ok((kept, filtered))
}
