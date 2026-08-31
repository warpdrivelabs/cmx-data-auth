//! cmx-dataauth-core —— 数据权限引擎的语义中立内核。
//!
//! 对外导出（稳定浅层 API）：
//! - 主体/资源：[`Subject`] / [`Resource`] / [`Action`]
//! - 约束 IR：[`Constraint`] / [`CmpOp`]
//! - 决策：[`Decision`] / [`DecisionEffect`] / [`Obligation`] / [`Trace`]
//! - 部分求值：[`compose`]（纯函数 PDP）
//! - 编译后端：[`ConstraintCompiler`] + [`SqlCompiler`] / [`RowFilterCompiler`] / [`EsCompiler`]
//! - 维度展开：[`DimensionExpander`] / [`MockDimensionExpander`]
//! - 契约：[`DataAuthStore`]（驱动无关持久化）
//! - DTO：[`PolicyDef`] / [`Grant`] / [`RelationTuple`] / [`MaskRule`] / [`DimensionValue`] / [`AuditLog`]
//!
//! 本 crate **不依赖任何数据库 / 任何 cmx-\* infra**，可 wasm / 嵌入式复用。

pub mod compiler;
pub mod def;
pub mod error;
pub mod eval;
pub mod expand;
pub mod ir;
pub mod mask;
pub mod pdp;
pub mod rls;
pub mod store;
pub mod subject;

pub use compiler::{
    ConstraintCompiler, EsCompiler, RowFilterCompiler, RowPredicate, SqlCompiler, SqlWhere,
};
pub use def::{
    AuditLog, DimensionValue, Effect, Grant, MaskRule, MaskType, PolicyDef, PolicySource,
    RelationTuple,
};
pub use error::{
    CompileError, CompileResult, Error, ExpandError, ExpandResult, Result, StoreError, StoreResult,
};
pub use eval::{Decision, DecisionEffect, Obligation, Trace};
pub use expand::{DimensionExpander, MockDimensionExpander, NoopExpander};
pub use ir::{CmpOp, Constraint};
pub use mask::{apply_masks, mask_value};
pub use pdp::{compose, ExpandedDims, SUPERADMIN_ROLES};
pub use rls::RlsSpec;
pub use store::DataAuthStore;
pub use subject::{Action, Resource, Subject};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    // ————————————————————— 约束 AST 智能构造 —————————————————————

    #[test]
    fn and_short_circuits_false() {
        let c = Constraint::and(vec![
            Constraint::True,
            Constraint::False,
            Constraint::cmp("x", CmpOp::Eq, json!(1)),
        ]);
        assert_eq!(c, Constraint::False);
    }

    #[test]
    fn and_drops_true_and_flattens() {
        let c = Constraint::and(vec![
            Constraint::True,
            Constraint::and(vec![
                Constraint::cmp("a", CmpOp::Eq, json!(1)),
                Constraint::cmp("b", CmpOp::Eq, json!(2)),
            ]),
        ]);
        // 摊平嵌套 And + 丢弃 True → 二元 And。
        match c {
            Constraint::And { items } => assert_eq!(items.len(), 2),
            other => panic!("期望 And，实际 {other:?}"),
        }
    }

    #[test]
    fn and_single_unwraps() {
        let leaf = Constraint::cmp("a", CmpOp::Eq, json!(1));
        let c = Constraint::and(vec![Constraint::True, leaf.clone()]);
        assert_eq!(c, leaf);
    }

    #[test]
    fn or_short_circuits_true() {
        let c = Constraint::or(vec![Constraint::False, Constraint::True]);
        assert_eq!(c, Constraint::True);
    }

    #[test]
    fn or_drops_false() {
        let leaf = Constraint::cmp("a", CmpOp::Eq, json!(1));
        let c = Constraint::or(vec![Constraint::False, leaf.clone(), Constraint::False]);
        assert_eq!(c, leaf);
    }

    #[test]
    fn not_double_negation() {
        let leaf = Constraint::cmp("a", CmpOp::Eq, json!(1));
        assert_eq!(Constraint::not(Constraint::not(leaf.clone())), leaf);
        assert_eq!(Constraint::not(Constraint::True), Constraint::False);
    }

    #[test]
    fn constraint_serde_roundtrip() {
        let c = Constraint::and(vec![
            Constraint::in_values("ou_id", vec![json!("1001")]),
            Constraint::cmp("owner", CmpOp::Eq, json!("u42")),
        ]);
        let s = serde_json::to_value(&c).unwrap();
        let back: Constraint = serde_json::from_value(s).unwrap();
        assert_eq!(c, back);
    }

    // ————————————————————— SqlCompiler —————————————————————

    fn sql(allow: &[&str], c: &Constraint) -> CompileResult<SqlWhere> {
        SqlCompiler::new(allow.iter().map(|s| s.to_string())).compile(c)
    }

    #[test]
    fn sql_in_parameterized() {
        let c = Constraint::in_values("ou_id", vec![json!("1001"), json!("1002")]);
        let out = sql(&["ou_id"], &c).unwrap();
        assert_eq!(out.sql, "ou_id IN ($1, $2)");
        assert_eq!(out.params, vec![json!("1001"), json!("1002")]);
    }

    #[test]
    fn sql_and_or_nesting() {
        let c = Constraint::and(vec![
            Constraint::in_values("ou_id", vec![json!(1), json!(2)]),
            Constraint::or(vec![
                Constraint::cmp("owner", CmpOp::Eq, json!("u42")),
                Constraint::cmp("status", CmpOp::Eq, json!("public")),
            ]),
        ]);
        let out = sql(&["ou_id", "owner", "status"], &c).unwrap();
        assert_eq!(
            out.sql,
            "(ou_id IN ($1, $2)) AND ((owner = $3) OR (status = $4))"
        );
        assert_eq!(
            out.params,
            vec![json!(1), json!(2), json!("u42"), json!("public")]
        );
    }

    #[test]
    fn sql_unknown_field_rejected() {
        let c = Constraint::cmp("secret_col", CmpOp::Eq, json!(1));
        let e = sql(&["ou_id"], &c).unwrap_err();
        assert!(matches!(e, CompileError::UnknownField(f) if f == "secret_col"));
    }

    #[test]
    fn sql_empty_in_is_false() {
        let c = Constraint::in_values("ou_id", vec![]);
        let out = sql(&["ou_id"], &c).unwrap();
        assert_eq!(out.sql, "FALSE");
        assert!(out.params.is_empty());
    }

    #[test]
    fn sql_between() {
        let c = Constraint::Between {
            field: "amount".into(),
            lo: json!(0),
            hi: json!(5000),
        };
        let out = sql(&["amount"], &c).unwrap();
        assert_eq!(out.sql, "amount BETWEEN $1 AND $2");
        assert_eq!(out.params, vec![json!(0), json!(5000)]);
    }

    #[test]
    fn sql_cmp_ops() {
        let out = sql(&["a"], &Constraint::cmp("a", CmpOp::Ne, json!(1))).unwrap();
        assert_eq!(out.sql, "a <> $1");
        let out = sql(&["a"], &Constraint::cmp("a", CmpOp::Like, json!("x%"))).unwrap();
        assert_eq!(out.sql, "a LIKE $1");
    }

    #[test]
    fn sql_relation_unresolved_errors() {
        let c = Constraint::Relation {
            field: "id".into(),
            rel: "viewer".into(),
            subject: "u42".into(),
        };
        let e = sql(&["id"], &c).unwrap_err();
        assert!(matches!(e, CompileError::UnresolvedRelation(_)));
    }

    #[test]
    fn sql_start_at_offset() {
        let c = Constraint::cmp("owner", CmpOp::Eq, json!("u42"));
        let out = SqlCompiler::new(vec!["owner".to_string()])
            .start_at(5)
            .compile(&c)
            .unwrap();
        assert_eq!(out.sql, "owner = $5");
    }

    #[test]
    fn sql_field_mapping() {
        let mut m = BTreeMap::new();
        m.insert("org".to_string(), "ou_id".to_string());
        let c = Constraint::in_values("org", vec![json!("1001")]);
        let out = SqlCompiler::new(Vec::<String>::new())
            .with_map(m)
            .compile(&c)
            .unwrap();
        assert_eq!(out.sql, "ou_id IN ($1)");
    }

    // ————————————————————— RowFilterCompiler —————————————————————

    fn row(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn rowfilter_in() {
        let pred = RowFilterCompiler
            .compile(&Constraint::in_values("org", vec![json!("1001"), json!("1002")]))
            .unwrap();
        assert!(pred(&row(json!({"org":"1001"}))));
        assert!(!pred(&row(json!({"org":"9999"}))));
    }

    #[test]
    fn rowfilter_cmp_numeric() {
        let pred = RowFilterCompiler
            .compile(&Constraint::cmp("amount", CmpOp::Gt, json!(100)))
            .unwrap();
        assert!(pred(&row(json!({"amount":150}))));
        assert!(!pred(&row(json!({"amount":50}))));
    }

    #[test]
    fn rowfilter_like() {
        let pred = RowFilterCompiler
            .compile(&Constraint::cmp("name", CmpOp::Like, json!("张%")))
            .unwrap();
        assert!(pred(&row(json!({"name":"张三"}))));
        assert!(!pred(&row(json!({"name":"李四"}))));
    }

    #[test]
    fn rowfilter_and_or() {
        let c = Constraint::or(vec![
            Constraint::cmp("owner", CmpOp::Eq, json!("u42")),
            Constraint::cmp("status", CmpOp::Eq, json!("public")),
        ]);
        let pred = RowFilterCompiler.compile(&c).unwrap();
        assert!(pred(&row(json!({"owner":"u42","status":"draft"}))));
        assert!(pred(&row(json!({"owner":"x","status":"public"}))));
        assert!(!pred(&row(json!({"owner":"x","status":"draft"}))));
    }

    #[test]
    fn rowfilter_between() {
        let pred = RowFilterCompiler
            .compile(&Constraint::Between {
                field: "amount".into(),
                lo: json!(0),
                hi: json!(100),
            })
            .unwrap();
        assert!(pred(&row(json!({"amount":50}))));
        assert!(!pred(&row(json!({"amount":150}))));
    }

    // ————————————————————— EsCompiler —————————————————————

    #[test]
    fn es_in_terms() {
        let v = EsCompiler
            .compile(&Constraint::in_values("ou_id", vec![json!("1001")]))
            .unwrap();
        assert_eq!(v, json!({"terms":{"ou_id":["1001"]}}));
    }

    #[test]
    fn es_cmp_and_range() {
        let v = EsCompiler
            .compile(&Constraint::cmp("status", CmpOp::Eq, json!("public")))
            .unwrap();
        assert_eq!(v, json!({"term":{"status":"public"}}));
        let v2 = EsCompiler
            .compile(&Constraint::cmp("amount", CmpOp::Ge, json!(100)))
            .unwrap();
        assert_eq!(v2, json!({"range":{"amount":{"gte":100}}}));
    }

    // ————————————————————— compose（部分求值 PDP）—————————————————————

    fn voucher_read() -> Resource {
        Resource {
            kind: "voucher".into(),
            action: Action::Read,
            ..Default::default()
        }
    }

    #[test]
    fn compose_superadmin_permit_all() {
        let subj = Subject {
            tenant: "t".into(),
            user_id: "u1".into(),
            roles: vec!["admin".into()],
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[], &[], &ExpandedDims::new());
        assert_eq!(d.effect, DecisionEffect::Permit);
        assert_eq!(d.constraint, Constraint::True);
    }

    #[test]
    fn compose_no_policy_denies() {
        let subj = Subject {
            user_id: "u1".into(),
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[], &[], &ExpandedDims::new());
        assert_eq!(d.effect, DecisionEffect::Deny);
        assert_eq!(d.constraint, Constraint::False);
    }

    #[test]
    fn compose_dim_expansion() {
        let policy = PolicyDef {
            id: 1,
            name: "org-scope".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"in","field":"ou_id","values":["$dim:org"]}),
            priority: 0,
            effect: Effect::Permit,
        };
        let grant = Grant {
            id: 1,
            policy_id: 1,
            subject_type: "USER".into(),
            subject_id: "u1".into(),
            dim_key: Some("org".into()),
            dim_values: vec![json!("1001")],
            inherit: true,
        };
        let mut expanded = ExpandedDims::new();
        expanded.insert(
            ("org".into(), "1001".into()),
            vec![json!("1001"), json!("100101"), json!("100102")],
        );
        let subj = Subject {
            user_id: "u1".into(),
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[policy], &[grant], &expanded);
        assert_eq!(d.effect, DecisionEffect::PermitWithConstraint);
        assert_eq!(
            d.constraint,
            Constraint::In {
                field: "ou_id".into(),
                values: vec![json!("1001"), json!("100101"), json!("100102")],
            }
        );
    }

    #[test]
    fn compose_inherit_false_only_self() {
        // inherit=false：即便 expanded 里有下行闭包，也只授根节点本身（不下钻子孙）。
        let policy = PolicyDef {
            id: 1,
            name: "org-scope".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"in","field":"ou_id","values":["$dim:org"]}),
            priority: 0,
            effect: Effect::Permit,
        };
        let grant = Grant {
            id: 1,
            policy_id: 1,
            subject_type: "USER".into(),
            subject_id: "u1".into(),
            dim_key: Some("org".into()),
            dim_values: vec![json!("1001")],
            inherit: false,
        };
        let mut expanded = ExpandedDims::new();
        expanded.insert(
            ("org".into(), "1001".into()),
            vec![json!("1001"), json!("100101"), json!("100102")],
        );
        let subj = Subject {
            user_id: "u1".into(),
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[policy], &[grant], &expanded);
        assert_eq!(
            d.constraint,
            Constraint::In {
                field: "ou_id".into(),
                values: vec![json!("1001")], // 只有根，无 100101/100102。
            }
        );
    }

    #[test]
    fn compose_user_placeholder() {
        let policy = PolicyDef {
            id: 1,
            name: "own".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"cmp","field":"owner","op":"eq","value":"$user"}),
            priority: 0,
            effect: Effect::Permit,
        };
        let grant = Grant {
            id: 1,
            policy_id: 1,
            subject_type: "USER".into(),
            subject_id: "u42".into(),
            dim_key: None,
            dim_values: vec![],
            inherit: true,
        };
        let subj = Subject {
            user_id: "u42".into(),
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[policy], &[grant], &ExpandedDims::new());
        assert_eq!(
            d.constraint,
            Constraint::Cmp {
                field: "owner".into(),
                op: CmpOp::Eq,
                value: json!("u42"),
            }
        );
    }

    #[test]
    fn compose_empty_dim_grant_denies() {
        // 用户命中策略但在该维度无授值 → In($dim) 坍缩 False → AND 整策略 False → Deny。
        let policy = PolicyDef {
            id: 1,
            name: "org-scope".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"and","items":[
                {"kind":"in","field":"ou_id","values":["$dim:org"]},
                {"kind":"cmp","field":"owner","op":"eq","value":"$user"}
            ]}),
            priority: 0,
            effect: Effect::Permit,
        };
        // grant 命中主体但 dim_values 空。
        let grant = Grant {
            id: 1,
            policy_id: 1,
            subject_type: "USER".into(),
            subject_id: "u1".into(),
            dim_key: Some("org".into()),
            dim_values: vec![],
            inherit: true,
        };
        let subj = Subject {
            user_id: "u1".into(),
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[policy], &[grant], &ExpandedDims::new());
        assert_eq!(d.effect, DecisionEffect::Deny);
        assert_eq!(d.constraint, Constraint::False);
    }

    #[test]
    fn compose_deny_only_denies() {
        // 只有 Deny 策略、无放行策略 → 拒绝（Deny 不单独授予可见性）。
        let deny = PolicyDef {
            id: 2,
            name: "blk".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"true"}),
            priority: 100,
            effect: Effect::Deny,
        };
        let subj = Subject {
            user_id: "u1".into(),
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[deny], &[], &ExpandedDims::new());
        assert_eq!(d.effect, DecisionEffect::Deny);
    }

    #[test]
    fn compose_conditional_deny_subtracts_rows() {
        // 放行全部 + Deny 谓词（amount>100万）→ 可见 = True AND NOT(amount>100万) = NOT(amount>100万)。
        let permit = PolicyDef {
            id: 1,
            name: "all".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"true"}),
            priority: 0,
            effect: Effect::Permit,
        };
        let deny = PolicyDef {
            id: 2,
            name: "no-big".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"cmp","field":"amount","op":"gt","value":1000000}),
            priority: 10,
            effect: Effect::Deny,
        };
        let subj = Subject {
            user_id: "u1".into(),
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[permit, deny], &[], &ExpandedDims::new());
        assert_eq!(d.effect, DecisionEffect::PermitWithConstraint);
        assert_eq!(
            d.constraint,
            Constraint::not(Constraint::cmp("amount", CmpOp::Gt, json!(1000000)))
        );
    }

    #[test]
    fn compose_deny_all_beats_permit() {
        // Deny 约束 True（拒全部）→ permit AND NOT(True) = False → Deny。
        let permit = PolicyDef {
            id: 1,
            name: "scope".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"in","field":"ou_id","values":["1001"]}),
            priority: 0,
            effect: Effect::Permit,
        };
        let deny = PolicyDef {
            id: 2,
            name: "block-all".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"true"}),
            priority: 100,
            effect: Effect::Deny,
        };
        let subj = Subject {
            user_id: "u1".into(),
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[permit, deny], &[], &ExpandedDims::new());
        assert_eq!(d.effect, DecisionEffect::Deny);
        assert_eq!(d.constraint, Constraint::False);
    }

    #[test]
    fn compose_org_subject_hit() {
        // ORG 主体：grant(subject_type=ORG,1001) 命中 subject.orgs=[1001]。
        let policy = PolicyDef {
            id: 1,
            name: "org-scope".into(),
            resource_kind: "voucher".into(),
            action: Action::Read,
            source: PolicySource::Inline,
            constraint_tpl: json!({"kind":"in","field":"ou_id","values":["$dim:org"]}),
            priority: 0,
            effect: Effect::Permit,
        };
        let grant = Grant {
            id: 1,
            policy_id: 1,
            subject_type: "ORG".into(),
            subject_id: "1001".into(),
            dim_key: Some("org".into()),
            dim_values: vec![json!("1001")],
            inherit: true,
        };
        let mut expanded = ExpandedDims::new();
        expanded.insert(
            ("org".into(), "1001".into()),
            vec![json!("1001"), json!("100101")],
        );
        let subj = Subject {
            user_id: "u1".into(),
            orgs: vec!["1001".into()],
            ..Default::default()
        };
        let d = compose(&subj, &voucher_read(), &[policy], &[grant], &expanded);
        assert_eq!(
            d.constraint,
            Constraint::In {
                field: "ou_id".into(),
                values: vec![json!("1001"), json!("100101")],
            }
        );
    }

    // ————————————————————— 维度展开 —————————————————————

    #[tokio::test]
    async fn expander_mock_adds_self() {
        let ex = MockDimensionExpander::new().with("1001", vec!["100101".into(), "100102".into()]);
        let d = ex.descendants("t", "org", "1001").await.unwrap();
        assert!(d.contains(&"1001".to_string()));
        assert!(d.contains(&"100101".to_string()));
        assert_eq!(d.len(), 3);
    }
}
