//! 部分求值 PDP —— 纯函数，零 IO。
//!
//! 把 `policies + grants + 已展开维度值集` 组合成最终残差约束。维度层级展开（descendants）、
//! Relation 解析、FEEL 脱敏条件门都在 app 层预处理后传入，故本模块可单测、可 wasm。
//!
//! **模板占位约定**（policy.constraint_tpl 里）：
//! - 维度占位：`{"kind":"in","field":"ou_id","values":["$dim:org"]}` → 替换为该主体在 `org` 维度
//!   被授值的下行闭包（跨相关 grant 取并）。无授值 → 空 `In` → 编译成 `FALSE`（fail-closed）。
//! - 标量占位：`"$user"` / `"$tenant"` → 主体 user_id / tenant。

use crate::def::{Effect, Grant, PolicyDef};
use crate::eval::{Decision, DecisionEffect, Trace};
use crate::ir::Constraint;
use crate::subject::{Resource, Subject};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// 拥有其一即全放行的超管角色名。
pub const SUPERADMIN_ROLES: &[&str] = &["superadmin", "SUPERADMIN", "admin", "ADMIN"];

/// 已展开维度值集：`(dim_key, root_value) -> descendants(含自身)`。
pub type ExpandedDims = BTreeMap<(String, String), Vec<Value>>;

/// 部分求值：组合出残差约束（obligations 由 app 层单独填充，此处恒为空）。
pub fn compose(
    subject: &Subject,
    resource: &Resource,
    policies: &[PolicyDef],
    grants: &[Grant],
    expanded: &ExpandedDims,
) -> Decision {
    let mut trace = Trace::default();

    // 超管短路。
    if subject
        .roles
        .iter()
        .any(|r| SUPERADMIN_ROLES.contains(&r.as_str()))
    {
        trace.notes.push("超管角色 → 全放行".into());
        return Decision {
            effect: DecisionEffect::Permit,
            constraint: Constraint::True,
            obligations: Vec::new(),
            trace,
        };
    }

    let action = resource.action.as_str();
    let mut per_policy: Vec<Constraint> = Vec::new();

    for p in policies {
        if p.resource_kind != resource.kind || p.action.as_str() != action {
            continue;
        }
        if p.effect == Effect::Deny {
            trace.matched_policies.push(format!("{}#deny", p.name));
            trace
                .notes
                .push(format!("命中 Deny 策略「{}」→ 拒绝", p.name));
            return Decision::deny_with(trace);
        }
        trace.matched_policies.push(p.name.clone());
        let related: Vec<&Grant> = grants
            .iter()
            .filter(|g| g.policy_id == p.id && subject_hit(subject, g))
            .collect();
        per_policy.push(instantiate(&p.constraint_tpl, &related, subject, expanded));
    }

    if per_policy.is_empty() {
        trace.notes.push("无匹配策略 → 拒绝".into());
        return Decision::deny_with(trace);
    }

    // 多策略取并（任一放行即可见）。
    let constraint = Constraint::or(per_policy);
    let effect = match constraint {
        Constraint::True => DecisionEffect::Permit,
        Constraint::False => DecisionEffect::Deny,
        _ => DecisionEffect::PermitWithConstraint,
    };
    trace.expanded_dims = expanded
        .iter()
        .map(|((k, _), v)| (k.clone(), v.clone()))
        .collect();
    Decision {
        effect,
        constraint,
        obligations: Vec::new(),
        trace,
    }
}

/// grant 主体是否命中当前主体。
pub fn subject_hit(subject: &Subject, g: &Grant) -> bool {
    match g.subject_type.to_uppercase().as_str() {
        "USER" => g.subject_id == subject.user_id,
        "ROLE" => subject.roles.iter().any(|r| r == &g.subject_id),
        _ => false, // ORG/POST：M1 暂不支持。
    }
}

/// 实例化 policy 的约束模板：反序列化 + 占位替换。
fn instantiate(tpl: &Value, related: &[&Grant], subject: &Subject, expanded: &ExpandedDims) -> Constraint {
    let base: Constraint = serde_json::from_value(tpl.clone()).unwrap_or(Constraint::False);
    subst(&base, related, subject, expanded)
}

fn subst(c: &Constraint, related: &[&Grant], subject: &Subject, expanded: &ExpandedDims) -> Constraint {
    match c {
        Constraint::And { items } => Constraint::and(
            items
                .iter()
                .map(|x| subst(x, related, subject, expanded))
                .collect(),
        ),
        Constraint::Or { items } => Constraint::or(
            items
                .iter()
                .map(|x| subst(x, related, subject, expanded))
                .collect(),
        ),
        Constraint::Not { item } => Constraint::not(subst(item, related, subject, expanded)),
        Constraint::In { field, values } => {
            if let Some(key) = dim_placeholder(values) {
                let vals = expand_for(&key, related, expanded);
                // 无授值 → 该维度分支恒不可命中 → False（AND 中坍缩整策略；OR 中被丢弃，保留其他分支如 public）。
                if vals.is_empty() {
                    Constraint::False
                } else {
                    Constraint::In {
                        field: field.clone(),
                        values: vals,
                    }
                }
            } else {
                Constraint::In {
                    field: field.clone(),
                    values: values.iter().map(|v| subst_scalar(v, subject)).collect(),
                }
            }
        }
        Constraint::Cmp { field, op, value } => Constraint::Cmp {
            field: field.clone(),
            op: *op,
            value: subst_scalar(value, subject),
        },
        Constraint::Between { field, lo, hi } => Constraint::Between {
            field: field.clone(),
            lo: subst_scalar(lo, subject),
            hi: subst_scalar(hi, subject),
        },
        other => other.clone(),
    }
}

/// `In.values == ["$dim:<key>"]` → Some(key)。
fn dim_placeholder(values: &[Value]) -> Option<String> {
    if values.len() == 1
        && let Value::String(s) = &values[0]
        && let Some(k) = s.strip_prefix("$dim:")
    {
        return Some(k.to_string());
    }
    None
}

/// 跨相关 grant，对某维度键取被授根值的下行闭包并集（去重，字符串化）。
fn expand_for(key: &str, related: &[&Grant], expanded: &ExpandedDims) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for g in related {
        if g.dim_key.as_deref() != Some(key) {
            continue;
        }
        for root in &g.dim_values {
            let root_s = value_to_string(root);
            let vals = expanded
                .get(&(key.to_string(), root_s.clone()))
                .cloned()
                .unwrap_or_else(|| vec![Value::String(root_s.clone())]);
            for v in vals {
                let s = value_to_string(&v);
                if seen.insert(s.clone()) {
                    out.push(Value::String(s));
                }
            }
        }
    }
    out
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn subst_scalar(v: &Value, subject: &Subject) -> Value {
    if let Value::String(s) = v {
        match s.as_str() {
            "$user" => return Value::String(subject.user_id.clone()),
            "$tenant" => return Value::String(subject.tenant.clone()),
            _ => {}
        }
    }
    v.clone()
}
