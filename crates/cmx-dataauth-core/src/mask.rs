//! 义务执行器 —— 在投影层对行数据施加列脱敏（FULL / PARTIAL / HASH）。
//!
//! 与行过滤正交：行过滤决定"哪些行可见"，脱敏决定"某列如何呈现"。此处只改**呈现值**，不碰
//! 数据库存储的原值。配合 [`crate::compiler::RowFilterCompiler`] 构成 archetype-③（拉取后过滤）
//! 的完整闭环：同一约束 AST 既能编译成 SQL 下推，也能在内存里过滤 + 脱敏。

use crate::def::MaskType;
use crate::eval::Obligation;
use serde_json::Value;

/// 对单个值施加脱敏。非字符串值先转其字符串表示再脱敏（脱敏结果恒为字符串）。
pub fn mask_value(v: &Value, mask_type: MaskType, pattern: Option<&str>) -> Value {
    let s = match v {
        Value::Null => return Value::Null, // 空值不脱敏（无信息可泄露）。
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    Value::String(match mask_type {
        MaskType::Full => "****".to_string(),
        MaskType::Partial => partial(&s, pattern),
        MaskType::Hash => hash_token(&s),
    })
}

/// 部分脱敏：保留首尾、中间打码。
///
/// pattern 语义：形如 `{h}...{t}`（如 `{3}****{4}`）取保留头 h / 尾 t；否则默认头 3 尾 4。
/// 串长不足保留位数时全遮蔽。
fn partial(s: &str, pattern: Option<&str>) -> String {
    let (head, tail) = parse_keep(pattern).unwrap_or((3, 4));
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n <= head + tail {
        return "*".repeat(n.max(1));
    }
    let h: String = chars[..head].iter().collect();
    let t: String = chars[n - tail..].iter().collect();
    format!("{h}{}{t}", "*".repeat(n - head - tail))
}

/// 从 `{h}...{t}` 模式抽取保留头/尾位数（无 crate 依赖，手工解析）。
fn parse_keep(pattern: Option<&str>) -> Option<(usize, usize)> {
    let p = pattern?;
    let head = between_braces(p, 0)?;
    let (h, next) = head;
    let tail = between_braces(p, next)?;
    Some((h, tail.0))
}

/// 从 `from` 起找下一个 `{数字}`，返回 (数字, 闭括号后位置)。
fn between_braces(p: &str, from: usize) -> Option<(usize, usize)> {
    let lb = p[from..].find('{')? + from;
    let rb = p[lb..].find('}')? + lb;
    let num: usize = p[lb + 1..rb].parse().ok()?;
    Some((num, rb + 1))
}

/// 不可逆令牌化（M1：非加密稳定哈希；生产应换 HMAC-SHA256 + 密钥）。
fn hash_token(s: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("tok_{:016x}", h.finish())
}

/// 按义务列表对一组行（JSON 对象）逐列脱敏（就地修改）。
pub fn apply_masks(rows: &mut [serde_json::Map<String, Value>], obligations: &[Obligation]) {
    if obligations.is_empty() {
        return;
    }
    for row in rows.iter_mut() {
        for ob in obligations {
            if let Some(v) = row.get(&ob.column) {
                let masked = mask_value(v, ob.mask_type, ob.pattern.as_deref());
                row.insert(ob.column.clone(), masked);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mask_full() {
        assert_eq!(mask_value(&json!("secret"), MaskType::Full, None), json!("****"));
        assert_eq!(mask_value(&json!(12345), MaskType::Full, None), json!("****"));
        assert_eq!(mask_value(&Value::Null, MaskType::Full, None), Value::Null);
    }

    #[test]
    fn mask_partial_default() {
        // 默认头 3 尾 4。
        assert_eq!(
            mask_value(&json!("13812345678"), MaskType::Partial, None),
            json!("138****5678")
        );
    }

    #[test]
    fn mask_partial_pattern() {
        // {2}...{2} → 头 2 尾 2。
        assert_eq!(
            mask_value(&json!("abcdef"), MaskType::Partial, Some("{2}**{2}")),
            json!("ab**ef")
        );
    }

    #[test]
    fn mask_partial_too_short() {
        assert_eq!(
            mask_value(&json!("ab"), MaskType::Partial, None),
            json!("**")
        );
    }

    #[test]
    fn mask_hash_deterministic() {
        let a = mask_value(&json!("100000"), MaskType::Hash, None);
        let b = mask_value(&json!("100000"), MaskType::Hash, None);
        assert_eq!(a, b);
        assert!(a.as_str().unwrap().starts_with("tok_"));
        assert_ne!(a, mask_value(&json!("200000"), MaskType::Hash, None));
    }

    #[test]
    fn apply_masks_over_rows() {
        let obs = vec![
            Obligation { column: "salary".into(), mask_type: MaskType::Full, pattern: None },
            Obligation {
                column: "phone".into(),
                mask_type: MaskType::Partial,
                pattern: Some("{3}****{4}".into()),
            },
        ];
        let mut rows = vec![
            json!({"name":"张三","salary":9000,"phone":"13812345678"})
                .as_object()
                .unwrap()
                .clone(),
        ];
        apply_masks(&mut rows, &obs);
        assert_eq!(rows[0]["salary"], json!("****"));
        assert_eq!(rows[0]["phone"], json!("138****5678"));
        assert_eq!(rows[0]["name"], json!("张三")); // 未列入义务 → 不动。
    }
}
