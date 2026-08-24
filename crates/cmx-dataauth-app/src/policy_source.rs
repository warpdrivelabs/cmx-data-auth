//! D3 —— 决策表作策略源。
//!
//! `source=decisionTable` 的策略，其 `constraint_tpl` 存 cmx-rulesengine 的 `DecisionBody` JSON。
//! 求值前，用主体事实（roles/dims/attrs + user/tenant）作为输入跑决策表，读输出列 `constraint`
//! （FEEL 输出，值为 Constraint 的 JSON 对象或 JSON 字符串），得到一个**内联 Constraint 模板**，
//! 再交给 core::pdp 的同一 subst 管道（仍支持 `$dim:*` / `$user` 占位）。
//!
//! 这样 `cmx-dataauth-core` 保持零 cmx-rule 依赖：决策表求值只在 app 层发生，产物退化为 D0 的内联模板。

use cmx_dataauth_core::{PolicyDef, PolicySource, Subject};
use cmx_rule_engine::evaluate;
use cmx_rule_model::{DecisionBody, DecisionDef, EvalContext};
use serde_json::{json, Value};

/// 决策表输出中承载约束 AST 的列名。
const CONSTRAINT_OUT: &str = "constraint";

/// 把主体投影成决策表输入事实：`{user, tenant, roles, dims, ...attrs}`。
fn subject_facts(subject: &Subject) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("user".into(), json!(subject.user_id));
    m.insert("tenant".into(), json!(subject.tenant));
    m.insert("roles".into(), json!(subject.roles));
    m.insert("dims".into(), json!(subject.dims));
    // attrs 顶层平铺（决策表输入表达式可直接写 `grade` / `region`）。
    if let Value::Object(attrs) = &subject.attrs {
        for (k, v) in attrs {
            m.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    Value::Object(m)
}

/// 若策略源为决策表，求值成内联 Constraint 模板并回填到 `constraint_tpl`；否则原样返回。
///
/// 求值失败 / 无 `constraint` 输出 / 输出非法 → 回退 `{"kind":"false"}`（fail-closed）。
pub fn resolve_policy(policy: &PolicyDef, subject: &Subject) -> PolicyDef {
    if policy.source != PolicySource::DecisionTable {
        return policy.clone();
    }
    let tpl = eval_table_to_constraint_tpl(&policy.constraint_tpl, subject)
        .unwrap_or_else(|note| {
            tracing::warn!(policy = %policy.name, note, "决策表策略求值失败，回退拒绝");
            json!({ "kind": "false" })
        });
    let mut out = policy.clone();
    out.source = PolicySource::Inline; // 已降解为内联模板。
    out.constraint_tpl = tpl;
    out
}

/// 跑决策表 → 取输出列 `constraint` → 归一成 Constraint 的 JSON 模板。
fn eval_table_to_constraint_tpl(body_json: &Value, subject: &Subject) -> Result<Value, String> {
    let body: DecisionBody = serde_json::from_value(body_json.clone())
        .map_err(|e| format!("决策体 JSON 非法: {e}"))?;
    let def = DecisionDef {
        key: "dataauth-policy".to_string(),
        name: "dataauth-policy".to_string(),
        version: 1,
        category_code: None,
        body,
    };
    let ctx = EvalContext::new(subject_facts(subject));
    let res = evaluate(&def, &ctx);
    // 失败归因：任一 trace 节点带 failure → 报错。
    if let Some(f) = res.trace.iter().find_map(|n| n.failure.clone()) {
        return Err(format!("决策表求值失败: {f}"));
    }
    extract_constraint(&res.output)
}

/// 从决策表输出对象里取 `constraint` 列（对象直用；字符串再解析一层 JSON）。
fn extract_constraint(output: &Value) -> Result<Value, String> {
    let raw = match output {
        Value::Object(m) => m.get(CONSTRAINT_OUT).cloned().ok_or_else(|| {
            format!("决策表输出缺 `{CONSTRAINT_OUT}` 列（现有键: {:?}）", m.keys().collect::<Vec<_>>())
        })?,
        // 无命中 → null；多命中数组 M1 暂不支持（应设 Unique/First 单命中）。
        Value::Null => return Err("决策表无命中（输出 null）".into()),
        other => return Err(format!("决策表输出非对象: {other}")),
    };
    match raw {
        Value::String(s) => serde_json::from_str::<Value>(&s)
            .map_err(|e| format!("`{CONSTRAINT_OUT}` 字符串非合法 JSON: {e}")),
        obj @ Value::Object(_) => Ok(obj),
        other => Err(format!("`{CONSTRAINT_OUT}` 须为对象或 JSON 字符串，实际: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subj() -> Subject {
        Subject {
            user_id: "u1".into(),
            roles: vec!["finance".into()],
            attrs: json!({ "grade": 7, "region": "east" }),
            ..Default::default()
        }
    }

    /// 决策表：region=east → In(ou_id, $dim:org)；否则 False。输出列为 JSON 字符串。
    fn region_table() -> Value {
        json!({
            "kind": "decisionTable",
            "hitPolicy": "F",
            "inputs": [{ "id":"i1", "label":"区域", "expression":"region" }],
            "outputs": [{ "id":"o1", "label":"约束", "name":"constraint" }],
            "rules": [
                { "id":"r1", "inputEntries":["\"east\""],
                  "outputEntries":["\"{\\\"kind\\\":\\\"in\\\",\\\"field\\\":\\\"ou_id\\\",\\\"values\\\":[\\\"$dim:org\\\"]}\""] },
                { "id":"r2", "inputEntries":["-"], "outputEntries":["\"{\\\"kind\\\":\\\"false\\\"}\""] }
            ]
        })
    }

    #[test]
    fn resolves_decision_table_to_inline() {
        let p = PolicyDef {
            id: 1,
            name: "region-scope".into(),
            resource_kind: "voucher".into(),
            action: cmx_dataauth_core::Action::Read,
            source: PolicySource::DecisionTable,
            constraint_tpl: region_table(),
            priority: 0,
            effect: cmx_dataauth_core::Effect::Permit,
        };
        let out = resolve_policy(&p, &subj());
        assert_eq!(out.source, PolicySource::Inline);
        assert_eq!(
            out.constraint_tpl,
            json!({"kind":"in","field":"ou_id","values":["$dim:org"]})
        );
    }

    #[test]
    fn non_east_region_gets_false() {
        let mut s = subj();
        s.attrs = json!({ "region": "west" });
        let p = PolicyDef {
            id: 1,
            name: "region-scope".into(),
            resource_kind: "voucher".into(),
            action: cmx_dataauth_core::Action::Read,
            source: PolicySource::DecisionTable,
            constraint_tpl: region_table(),
            priority: 0,
            effect: cmx_dataauth_core::Effect::Permit,
        };
        let out = resolve_policy(&p, &s);
        assert_eq!(out.constraint_tpl, json!({"kind":"false"}));
    }

    #[test]
    fn inline_policy_passthrough() {
        let p = PolicyDef {
            id: 1,
            name: "x".into(),
            resource_kind: "voucher".into(),
            action: cmx_dataauth_core::Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"true"}),
            priority: 0,
            effect: cmx_dataauth_core::Effect::Permit,
        };
        let out = resolve_policy(&p, &subj());
        assert_eq!(out.constraint_tpl, json!({"kind":"true"}));
    }
}
