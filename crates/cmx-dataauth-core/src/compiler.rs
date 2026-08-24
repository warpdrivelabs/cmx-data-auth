//! PEP 编译后端 —— 把约束 AST 编译到具体查询语言/形态。同一 AST 可被多后端编译。
//!
//! - [`SqlCompiler`] → 参数化 `WHERE` 片段 + 有序参数（下推 PG，可分页/聚合）。
//! - [`RowFilterCompiler`] → 内存谓词闭包（cmx-rowsource / 跨库 DataSet 后过滤）。
//! - [`EsCompiler`] → ElasticSearch Query DSL（JSON）。

use crate::error::{CompileError, CompileResult};
use crate::ir::{CmpOp, Constraint};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// 编译后端契约。
pub trait ConstraintCompiler {
    type Output;
    fn compile(&self, c: &Constraint) -> CompileResult<Self::Output>;
}

// ═══════════════════════════ SQL 后端 ═══════════════════════════

/// SQL 下推编译结果：参数化 WHERE 片段 + 按 `$1..$n` 顺序的参数。
#[derive(Clone, Debug, PartialEq)]
pub struct SqlWhere {
    pub sql: String,
    pub params: Vec<Value>,
}

/// SQL 编译器：约束 AST → 参数化 WHERE。
///
/// **防注入硬门**：字段名只允许来自 `allow`（资源白名单），值永远走占位参数 `$n`、绝不拼进 SQL 串。
pub struct SqlCompiler {
    allow: BTreeSet<String>,
    map: BTreeMap<String, String>,
    start: usize,
}

impl SqlCompiler {
    /// 用允许的**物理**字段名白名单构造。
    pub fn new(allow: impl IntoIterator<Item = String>) -> Self {
        Self {
            allow: allow.into_iter().collect(),
            map: BTreeMap::new(),
            start: 1,
        }
    }

    /// 追加逻辑字段 → 物理列映射（逻辑名也纳入白名单）。
    pub fn with_map(mut self, map: BTreeMap<String, String>) -> Self {
        for (k, v) in &map {
            self.allow.insert(k.clone());
            self.allow.insert(v.clone());
        }
        self.map = map;
        self
    }

    /// 参数起始序号（拼进更大 SQL 时右移，默认 1）。
    pub fn start_at(mut self, n: usize) -> Self {
        self.start = n.max(1);
        self
    }

    fn phys(&self, field: &str) -> CompileResult<String> {
        if let Some(p) = self.map.get(field) {
            return Ok(p.clone());
        }
        if self.allow.contains(field) {
            return Ok(field.to_string());
        }
        Err(CompileError::UnknownField(field.to_string()))
    }
}

impl ConstraintCompiler for SqlCompiler {
    type Output = SqlWhere;
    fn compile(&self, c: &Constraint) -> CompileResult<SqlWhere> {
        let mut params = Vec::new();
        let mut n = self.start;
        let sql = self.emit(c, &mut params, &mut n)?;
        Ok(SqlWhere { sql, params })
    }
}

impl SqlCompiler {
    fn emit(&self, c: &Constraint, params: &mut Vec<Value>, n: &mut usize) -> CompileResult<String> {
        Ok(match c {
            Constraint::True => "TRUE".to_string(),
            Constraint::False => "FALSE".to_string(),
            Constraint::And { items } => self.join(items, " AND ", params, n)?,
            Constraint::Or { items } => self.join(items, " OR ", params, n)?,
            Constraint::Not { item } => format!("NOT ({})", self.emit(item, params, n)?),
            Constraint::Cmp { field, op, value } => {
                let col = self.phys(field)?;
                params.push(value.clone());
                let p = *n;
                *n += 1;
                format!("{col} {} ${p}", op.sql())
            }
            Constraint::In { field, values } => {
                let col = self.phys(field)?;
                if values.is_empty() {
                    "FALSE".to_string() // 空集 = 恒不可命中。
                } else {
                    let mut ph = Vec::with_capacity(values.len());
                    for v in values {
                        params.push(v.clone());
                        ph.push(format!("${}", *n));
                        *n += 1;
                    }
                    format!("{col} IN ({})", ph.join(", "))
                }
            }
            Constraint::Between { field, lo, hi } => {
                let col = self.phys(field)?;
                params.push(lo.clone());
                let a = *n;
                *n += 1;
                params.push(hi.clone());
                let b = *n;
                *n += 1;
                format!("{col} BETWEEN ${a} AND ${b}")
            }
            Constraint::Relation { field, .. } => {
                return Err(CompileError::UnresolvedRelation(field.clone()));
            }
        })
    }

    fn join(
        &self,
        items: &[Constraint],
        sep: &str,
        params: &mut Vec<Value>,
        n: &mut usize,
    ) -> CompileResult<String> {
        if items.is_empty() {
            return Ok("TRUE".to_string());
        }
        let mut parts = Vec::with_capacity(items.len());
        for it in items {
            parts.push(format!("({})", self.emit(it, params, n)?));
        }
        Ok(parts.join(sep))
    }
}

// ═══════════════════════════ 内存谓词后端 ═══════════════════════════

/// 一行数据的类型（JSON 对象）。
pub type RowPredicate = Box<dyn Fn(&serde_json::Map<String, Value>) -> bool + Send + Sync>;

/// 内存谓词编译器：约束 AST → 对一行判真的闭包。用于 cmx-rowsource / 跨库 DataSet 后过滤。
pub struct RowFilterCompiler;

impl ConstraintCompiler for RowFilterCompiler {
    type Output = RowPredicate;
    fn compile(&self, c: &Constraint) -> CompileResult<RowPredicate> {
        if let Some(f) = first_relation(c) {
            return Err(CompileError::UnresolvedRelation(f));
        }
        Ok(build_pred(c))
    }
}

fn build_pred(c: &Constraint) -> RowPredicate {
    match c.clone() {
        Constraint::True => Box::new(|_| true),
        Constraint::False => Box::new(|_| false),
        Constraint::Not { item } => {
            let p = build_pred(&item);
            Box::new(move |r| !p(r))
        }
        Constraint::And { items } => {
            let ps: Vec<RowPredicate> = items.iter().map(build_pred).collect();
            Box::new(move |r| ps.iter().all(|p| p(r)))
        }
        Constraint::Or { items } => {
            let ps: Vec<RowPredicate> = items.iter().map(build_pred).collect();
            Box::new(move |r| ps.iter().any(|p| p(r)))
        }
        Constraint::In { field, values } => Box::new(move |r| {
            r.get(&field)
                .map(|v| values.iter().any(|x| json_eq(x, v)))
                .unwrap_or(false)
        }),
        Constraint::Cmp { field, op, value } => Box::new(move |r| {
            r.get(&field).map(|v| cmp_apply(op, v, &value)).unwrap_or(false)
        }),
        Constraint::Between { field, lo, hi } => Box::new(move |r| {
            r.get(&field)
                .and_then(num)
                .zip(num(&lo))
                .zip(num(&hi))
                .map(|((x, l), h)| x >= l && x <= h)
                .unwrap_or(false)
        }),
        Constraint::Relation { .. } => Box::new(|_| false), // 入口已拦截。
    }
}

fn json_eq(a: &Value, b: &Value) -> bool {
    if let (Some(x), Some(y)) = (num(a), num(b)) {
        return (x - y).abs() < f64::EPSILON;
    }
    a == b
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn cmp_apply(op: CmpOp, left: &Value, right: &Value) -> bool {
    match op {
        CmpOp::Eq => json_eq(left, right),
        CmpOp::Ne => !json_eq(left, right),
        CmpOp::Like => match (left, right) {
            (Value::String(l), Value::String(r)) => like(l, r),
            _ => false,
        },
        CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => {
            if let (Some(x), Some(y)) = (num(left), num(right)) {
                match op {
                    CmpOp::Lt => x < y,
                    CmpOp::Le => x <= y,
                    CmpOp::Gt => x > y,
                    CmpOp::Ge => x >= y,
                    _ => unreachable!(),
                }
            } else if let (Value::String(l), Value::String(r)) = (left, right) {
                match op {
                    CmpOp::Lt => l < r,
                    CmpOp::Le => l <= r,
                    CmpOp::Gt => l > r,
                    CmpOp::Ge => l >= r,
                    _ => unreachable!(),
                }
            } else {
                false
            }
        }
    }
}

/// SQL LIKE 通配匹配（`%`=任意串，`_`=任意单字符），经典 DP，无需 regex crate。
fn like(s: &str, pat: &str) -> bool {
    let s: Vec<char> = s.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    let (m, n) = (s.len(), p.len());
    let mut dp = vec![vec![false; n + 1]; m + 1];
    dp[0][0] = true;
    for j in 1..=n {
        if p[j - 1] == '%' {
            dp[0][j] = dp[0][j - 1];
        }
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = match p[j - 1] {
                '%' => dp[i - 1][j] || dp[i][j - 1],
                '_' => dp[i - 1][j - 1],
                c => dp[i - 1][j - 1] && s[i - 1] == c,
            };
        }
    }
    dp[m][n]
}

// ═══════════════════════════ ElasticSearch 后端 ═══════════════════════════

/// ES 编译器：约束 AST → ES Query DSL（bool/term/terms/range/wildcard）。
pub struct EsCompiler;

impl ConstraintCompiler for EsCompiler {
    type Output = Value;
    fn compile(&self, c: &Constraint) -> CompileResult<Value> {
        if let Some(f) = first_relation(c) {
            return Err(CompileError::UnresolvedRelation(f));
        }
        Ok(es(c))
    }
}

/// 单键对象 `{ field: inner }`（serde_json `json!` 不支持动态 key，故显式构造）。
fn obj(field: &str, inner: Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(field.to_string(), inner);
    Value::Object(m)
}

fn es(c: &Constraint) -> Value {
    match c {
        Constraint::True => json!({ "match_all": {} }),
        Constraint::False => json!({ "match_none": {} }),
        Constraint::And { items } => {
            json!({ "bool": { "filter": items.iter().map(es).collect::<Vec<_>>() } })
        }
        Constraint::Or { items } => json!({ "bool": {
            "should": items.iter().map(es).collect::<Vec<_>>(),
            "minimum_should_match": 1
        }}),
        Constraint::Not { item } => json!({ "bool": { "must_not": [ es(item) ] } }),
        Constraint::In { field, values } => json!({ "terms": obj(field, json!(values)) }),
        Constraint::Cmp { field, op, value } => match op {
            CmpOp::Eq => json!({ "term": obj(field, value.clone()) }),
            CmpOp::Ne => json!({ "bool": { "must_not": [ { "term": obj(field, value.clone()) } ] } }),
            CmpOp::Lt => json!({ "range": obj(field, json!({ "lt": value })) }),
            CmpOp::Le => json!({ "range": obj(field, json!({ "lte": value })) }),
            CmpOp::Gt => json!({ "range": obj(field, json!({ "gt": value })) }),
            CmpOp::Ge => json!({ "range": obj(field, json!({ "gte": value })) }),
            CmpOp::Like => json!({ "wildcard": obj(field, like_to_wildcard(value)) }),
        },
        Constraint::Between { field, lo, hi } => {
            json!({ "range": obj(field, json!({ "gte": lo, "lte": hi })) })
        }
        Constraint::Relation { .. } => json!({ "match_none": {} }),
    }
}

fn like_to_wildcard(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(s.replace('%', "*").replace('_', "?")),
        other => other.clone(),
    }
}

// ═══════════════════════════ 共用 ═══════════════════════════

/// 找到第一个未解析的 `Relation`（编译前的合法性检查）。
fn first_relation(c: &Constraint) -> Option<String> {
    match c {
        Constraint::Relation { field, .. } => Some(field.clone()),
        Constraint::Not { item } => first_relation(item),
        Constraint::And { items } | Constraint::Or { items } => items.iter().find_map(first_relation),
        _ => None,
    }
}
