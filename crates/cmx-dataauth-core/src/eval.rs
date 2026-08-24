//! 决策结果 —— PDP 的输出：效果 + 残差约束 + 义务（脱敏） + 审计轨迹。

use crate::def::MaskType;
use crate::ir::Constraint;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// 决策效果。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DecisionEffect {
    /// 无条件放行（约束 = True）。
    Permit,
    /// 带残差约束放行。
    PermitWithConstraint,
    /// 拒绝（约束 = False）。
    Deny,
}

/// 义务：列脱敏。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Obligation {
    pub column: String,
    pub mask_type: MaskType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

/// 决策轨迹（可解释性 / 审计）。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trace {
    #[serde(default)]
    pub matched_policies: Vec<String>,
    #[serde(default)]
    pub expanded_dims: BTreeMap<String, Vec<Value>>,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// 决策结果。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub effect: DecisionEffect,
    pub constraint: Constraint,
    #[serde(default)]
    pub obligations: Vec<Obligation>,
    #[serde(default)]
    pub trace: Trace,
}

impl Decision {
    /// 全放行（约束 True）。
    pub fn permit_all() -> Self {
        Decision {
            effect: DecisionEffect::Permit,
            constraint: Constraint::True,
            obligations: Vec::new(),
            trace: Trace::default(),
        }
    }

    /// 全拒绝（约束 False）。
    pub fn deny() -> Self {
        Self::deny_with(Trace::default())
    }

    /// 带轨迹的全拒绝。
    pub fn deny_with(trace: Trace) -> Self {
        Decision {
            effect: DecisionEffect::Deny,
            constraint: Constraint::False,
            obligations: Vec::new(),
            trace,
        }
    }
}
