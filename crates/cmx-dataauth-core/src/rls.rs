//! PG Row-Level Security（RLS）DDL 生成 —— 防绕过纵深兜底。
//!
//! 应用层 WHERE 下推是主力；RLS 是"即便调用方漏拼 WHERE 也拦得住"的数据库层兜底。做法：目标表启用
//! RLS + 一条按**会话 GUC** 过滤维度列的策略；应用在事务开始 `set_config(guc, scope_ids, true)` 把
//! decide 出的维度 ID 集写进会话，RLS 据此过滤。GUC 未设置 → 无行可见（**fail-closed**）。
//!
//! 约束与边界：
//! - RLS 对 `BYPASSRLS` 角色（含超级用户）**无效**——应用须以**非超级用户**连库，兜底方生效（故加 `FORCE`）。
//! - 本兜底为**维度级**粗过滤（覆盖最主要的跨组织越权风险）；完整残差（owner/status/ReBAC）仍靠应用层下推。
//! - 生成物供 DBA 审阅后执行（本模块只产字符串，不碰 DB）。

/// RLS 生成规格。
#[derive(Clone, Debug)]
pub struct RlsSpec {
    /// 物理表名（可 `schema.table`）。
    pub table: String,
    /// 维度物理列（如 `ou_id`）。
    pub dim_column: String,
    /// 会话 GUC 名（默认 `dataauth.<table>_scope`）。
    pub guc: String,
    /// 策略名（默认 `dataauth_<table>`）。
    pub policy_name: String,
    /// 维护旁路 GUC：`SET dataauth.bypass='on'` 时放行（供迁移/管理流程）。
    pub bypass_guc: String,
}

impl RlsSpec {
    pub fn new(table: impl Into<String>, dim_column: impl Into<String>) -> Self {
        let table = table.into();
        // 策略名取表的最后一段（去 schema）以避免非法字符。
        let base = table.rsplit('.').next().unwrap_or(&table).to_string();
        Self {
            guc: format!("dataauth.{base}_scope"),
            policy_name: format!("dataauth_{base}"),
            bypass_guc: "dataauth.bypass".to_string(),
            table,
            dim_column: dim_column.into(),
        }
    }
    pub fn with_guc(mut self, g: impl Into<String>) -> Self {
        self.guc = g.into();
        self
    }
    pub fn with_policy_name(mut self, p: impl Into<String>) -> Self {
        self.policy_name = p.into();
        self
    }
}

/// 生成幂等 RLS DDL 语句序列（校验标识符防注入）。
pub fn generate(spec: &RlsSpec) -> Result<Vec<String>, String> {
    for (label, v) in [
        ("table", &spec.table),
        ("dim_column", &spec.dim_column),
        ("policy_name", &spec.policy_name),
        ("guc", &spec.guc),
        ("bypass_guc", &spec.bypass_guc),
    ] {
        if !valid_ident(v) {
            return Err(format!("非法标识符 {label}: {v}"));
        }
    }
    let RlsSpec {
        table,
        dim_column,
        guc,
        policy_name,
        bypass_guc,
    } = spec;
    Ok(vec![
        format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"),
        format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"),
        format!("DROP POLICY IF EXISTS {policy_name} ON {table};"),
        format!(
            "CREATE POLICY {policy_name} ON {table} USING (\n  \
             current_setting('{bypass_guc}', true) = 'on'\n  \
             OR {dim_column}::text = ANY (string_to_array(current_setting('{guc}', true), ','))\n);"
        ),
    ])
}

/// 应用在事务开始设置会话维度 scope 的 SQL：`set_config` 便于参数化（`$1` = 逗号分隔 ID 集）。
pub fn set_scope_sql(spec: &RlsSpec) -> String {
    format!("SELECT set_config('{}', $1, true)", spec.guc)
}

/// 合法标识符：允许 `schema.name`（≤2 段），每段 `[A-Za-z_][A-Za-z0-9_]*`。GUC（含一个点）亦适用。
fn valid_ident(s: &str) -> bool {
    let segs: Vec<&str> = s.split('.').collect();
    if segs.is_empty() || segs.len() > 2 {
        return false;
    }
    segs.iter().all(|seg| {
        let mut c = seg.chars();
        matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
            && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dimension_backstop() {
        let ddl = generate(&RlsSpec::new("voucher", "ou_id")).unwrap();
        let all = ddl.join("\n");
        assert!(all.contains("ALTER TABLE voucher ENABLE ROW LEVEL SECURITY;"));
        assert!(all.contains("FORCE ROW LEVEL SECURITY"));
        assert!(all.contains("CREATE POLICY dataauth_voucher ON voucher"));
        assert!(all.contains("current_setting('dataauth.voucher_scope', true)"));
        assert!(all.contains("ou_id::text = ANY (string_to_array"));
        assert!(all.contains("current_setting('dataauth.bypass', true) = 'on'"));
        assert_eq!(
            set_scope_sql(&RlsSpec::new("voucher", "ou_id")),
            "SELECT set_config('dataauth.voucher_scope', $1, true)"
        );
    }

    #[test]
    fn rejects_injection_ident() {
        let mut spec = RlsSpec::new("voucher", "ou_id");
        spec.table = "voucher; DROP TABLE x".into();
        assert!(generate(&spec).is_err());
        let mut spec2 = RlsSpec::new("voucher", "ou_id");
        spec2.dim_column = "ou_id) OR (1=1".into();
        assert!(generate(&spec2).is_err());
    }

    #[test]
    fn schema_qualified_table_ok() {
        let ddl = generate(&RlsSpec::new("public.voucher", "ou_id")).unwrap();
        assert!(ddl.join("\n").contains("CREATE POLICY dataauth_voucher ON public.voucher"));
    }
}
