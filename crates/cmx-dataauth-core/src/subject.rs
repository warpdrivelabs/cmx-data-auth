//! 主体上下文与资源描述符 —— `decide(Subject, Resource)` 的两个输入。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// 资源动作。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    #[default]
    Read,
    Write,
    Delete,
    Export,
}

impl Action {
    /// camelCase 字面量（与序列化一致），供与 policy.action 字符串比对。
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Delete => "delete",
            Action::Export => "export",
        }
    }
}

/// 主体上下文：谁在访问。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    #[serde(default)]
    pub tenant: String,
    pub user_id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    /// 主体在各维度上被授予的**根值集**（如 `org -> ["1001","1002"]`）。层级展开在 app 层完成。
    #[serde(default)]
    pub dims: BTreeMap<String, Vec<Value>>,
    /// 任意属性（供 FEEL 脱敏条件用，如 `{ "grade": 7, "region": "east" }`）。
    #[serde(default)]
    pub attrs: Value,
}

/// 资源描述符：访问什么。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub kind: String,
    #[serde(default)]
    pub action: Action,
    /// 逻辑维度 → 物理列名（如 `org -> ou_id`）。
    #[serde(default)]
    pub dim_bindings: BTreeMap<String, String>,
    /// 本资源可参与过滤的列白名单（如 `["owner","status","amount"]`）—— SqlCompiler 防注入依据之一。
    #[serde(default)]
    pub row_ctx: Vec<String>,
}

impl Resource {
    /// 编译白名单 = 维度绑定的物理列 ∪ row_ctx。
    pub fn allow_fields(&self) -> Vec<String> {
        let mut out: Vec<String> = self.dim_bindings.values().cloned().collect();
        out.extend(self.row_ctx.iter().cloned());
        out.sort();
        out.dedup();
        out
    }
}
