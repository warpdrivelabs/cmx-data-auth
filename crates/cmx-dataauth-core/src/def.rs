//! 持久化 / 传输 DTO —— 策略、授权、关系元组、脱敏规则、维度值、审计。

use crate::subject::Action;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 策略效果。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Effect {
    #[default]
    Permit,
    Deny,
}

/// 策略约束来源（D3）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicySource {
    /// 内联：`constraint_tpl` 直接是 Constraint AST 模板（默认，D0-D2/D5）。
    #[default]
    Inline,
    /// 决策表：`constraint_tpl` 是 cmx-rulesengine 的 DecisionBody JSON；求值输出列 `constraint`
    /// 产出 Constraint（可含 `$dim:*`/`$user` 占位），再走同一 subst 管道。
    DecisionTable,
}

/// 策略定义（落 `cmx_dataauth_policy`）。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDef {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    pub resource_kind: String,
    #[serde(default)]
    pub action: Action,
    /// 约束来源。`inline`（默认）→ `constraint_tpl` 为 Constraint AST；`decisionTable` →
    /// `constraint_tpl` 为决策表 DecisionBody JSON（app 层求值成 Constraint）。
    #[serde(default)]
    pub source: PolicySource,
    /// `source=inline`：约束 AST **模板**（`Constraint` 的 JSON；可含维度占位
    /// `{"kind":"in","field":"ou_id","values":["$dim:org"]}` 与标量占位 `"$user"`）。
    /// `source=decisionTable`：决策表 DecisionBody JSON。均落 `constraint_json` 列。
    pub constraint_tpl: Value,
    /// 求值顺序权重（越大越先）。策略组合是**集合式**（放行取并、再扣除 Deny 行集），故 priority
    /// **不做覆盖裁决**——它只决定遍历/编译顺序（高优先条件在生成 SQL 中靠前）与 trace 可读性。
    /// 需要"高优先直接拒绝"时，用一条 Deny 策略（其约束 = 被拒行集，`True`=拒全部）表达。
    #[serde(default)]
    pub priority: i32,
    /// `permit`：约束描述**可见行集**（多放行取并）。`deny`：约束描述**被拒行集**
    /// （`True`=拒全部、`False`=不拒、谓词=拒该子集），最终可见 = 放行 AND NOT(拒绝并)。
    #[serde(default)]
    pub effect: Effect,
}

/// 授权：把策略绑到主体 + 维度值集（落 `cmx_dataauth_grant`）。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    #[serde(default)]
    pub id: i64,
    pub policy_id: i64,
    /// `ROLE` | `USER` | `ORG` | `POST`。
    pub subject_type: String,
    pub subject_id: String,
    /// 维度键（`org`/`proj`/`cost_center`）；None = 无维度约束。
    #[serde(default)]
    pub dim_key: Option<String>,
    /// 该主体在此维度上被授的**根值**（层级展开前）。
    #[serde(default)]
    pub dim_values: Vec<Value>,
    #[serde(default = "default_true")]
    pub inherit: bool,
}

fn default_true() -> bool {
    true
}

/// ReBAC 关系元组（落 `cmx_dataauth_relation_tuple`）：`object_kind:object_id #relation @ subject_kind:subject_id`。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationTuple {
    #[serde(default)]
    pub id: i64,
    pub object_kind: String,
    pub object_id: String,
    pub relation: String,
    pub subject_kind: String,
    pub subject_id: String,
}

/// 脱敏类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MaskType {
    /// 完整遮蔽（值 → `****`）。
    Full,
    /// 部分脱敏（按 `partial_pattern`）。
    Partial,
    /// 不可逆哈希 / 令牌化。
    Hash,
    /// 列隐藏：从投影中**移除该列**（区别于脱敏——不是 `****` 而是列不存在）。
    Hide,
}

/// 列脱敏规则（落 `cmx_dataauth_mask_rule`）。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaskRule {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub resource_kind: String,
    pub column: String,
    pub mask_type: MaskType,
    /// 部分脱敏模式，如 `"131****8800"`。
    #[serde(default)]
    pub partial_pattern: Option<String>,
    /// FEEL 条件（如 `user.grade < 5`）；None = 恒脱敏。app 层用 cmx-rule-feel 评估。
    #[serde(default)]
    pub condition_expr: Option<String>,
    /// 豁免角色：主体持有此角色则**不**脱敏。
    #[serde(default)]
    pub min_role: Option<String>,
}

/// 层级维度值（落 `cmx_dataauth_dimension_value`）—— descendants 展开的数据源。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DimensionValue {
    pub dim_key: String,
    pub dim_value: String,
    #[serde(default)]
    pub parent_value: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub depth: i32,
}

/// 决策审计（落 `cmx_dataauth_audit_log`）。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLog {
    pub id: String,
    pub tenant: String,
    pub user_id: String,
    pub resource_kind: String,
    pub action: String,
    pub effect: String,
    pub constraint_json: Value,
    #[serde(default)]
    pub backend: Option<String>,
    pub created_at: DateTime<Utc>,
}
