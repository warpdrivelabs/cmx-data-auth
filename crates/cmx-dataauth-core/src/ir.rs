//! 约束 AST —— 四种权限范型（维度 scope / 属性条件 / 关系 ReBAC / 区间）的公共"残差"表示。
//!
//! 这是本引擎的**稳定中间表示（IR）**：PDP 部分求值吐出它，多个 PEP 后端各自把它编译成
//! SQL WHERE / 内存谓词 / ES 查询。它可序列化为 JSON（`constraint_json` 落库形态），也可由
//! 外部规则引擎（决策表）产出。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 比较算子。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Like,
}

impl CmpOp {
    /// SQL 算子字面量。
    pub fn sql(self) -> &'static str {
        match self {
            CmpOp::Eq => "=",
            CmpOp::Ne => "<>",
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
            CmpOp::Like => "LIKE",
        }
    }
}

/// 约束节点。内部标签 `kind`（camelCase）序列化为干净 JSON，如 `{"kind":"in","field":"ou_id","values":[..]}`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Constraint {
    /// 全放行（超管 / 无限制）。
    True,
    /// 全拒绝（无授权 / 空集）。
    False,
    /// 布尔与。
    And { items: Vec<Constraint> },
    /// 布尔或。
    Or { items: Vec<Constraint> },
    /// 布尔非。
    Not { item: Box<Constraint> },
    /// 二元比较：`field op value`。
    Cmp { field: String, op: CmpOp, value: Value },
    /// 集合成员：`field IN (values)` —— 维度权限 / 层级展开的落点。
    In { field: String, values: Vec<Value> },
    /// 区间：`field BETWEEN lo AND hi`。
    Between { field: String, lo: Value, hi: Value },
    /// 关系（ReBAC 桥）：编译前须经 `lookup_resources` 解析成 `In`。
    Relation {
        field: String,
        rel: String,
        subject: String,
    },
}

impl Constraint {
    /// 构造 `field op value`。
    pub fn cmp(field: impl Into<String>, op: CmpOp, value: Value) -> Self {
        Constraint::Cmp {
            field: field.into(),
            op,
            value,
        }
    }

    /// 构造 `field IN (values)`。
    pub fn in_values(field: impl Into<String>, values: Vec<Value>) -> Self {
        Constraint::In {
            field: field.into(),
            values,
        }
    }

    /// 布尔与智能构造：摊平嵌套 `And`、丢弃 `True`、任一 `False` → `False`、单元素解包、空 → `True`。
    pub fn and(items: Vec<Constraint>) -> Self {
        let mut flat = Vec::new();
        for c in items {
            match c {
                Constraint::True => {}
                Constraint::False => return Constraint::False,
                Constraint::And { items } => flat.extend(items),
                other => flat.push(other),
            }
        }
        match flat.len() {
            0 => Constraint::True,
            1 => flat.pop().unwrap(),
            _ => Constraint::And { items: flat },
        }
    }

    /// 布尔或智能构造：摊平嵌套 `Or`、丢弃 `False`、任一 `True` → `True`、单元素解包、空 → `False`。
    pub fn or(items: Vec<Constraint>) -> Self {
        let mut flat = Vec::new();
        for c in items {
            match c {
                Constraint::False => {}
                Constraint::True => return Constraint::True,
                Constraint::Or { items } => flat.extend(items),
                other => flat.push(other),
            }
        }
        match flat.len() {
            0 => Constraint::False,
            1 => flat.pop().unwrap(),
            _ => Constraint::Or { items: flat },
        }
    }

    /// 布尔非智能构造：常量翻转、双非消解。
    #[allow(clippy::should_implement_trait)] // 与 and/or 同族的智能构造器，非 std::ops::Not。
    pub fn not(item: Constraint) -> Self {
        match item {
            Constraint::True => Constraint::False,
            Constraint::False => Constraint::True,
            Constraint::Not { item } => *item,
            other => Constraint::Not {
                item: Box::new(other),
            },
        }
    }

    /// 是否常量约束（编译无需绑定任何字段）。
    pub fn is_const(&self) -> bool {
        matches!(self, Constraint::True | Constraint::False)
    }
}
