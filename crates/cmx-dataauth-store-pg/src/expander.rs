//! 层级维度展开器 —— `WITH RECURSIVE` 求某维度值的下行闭包（含自身）。

use async_trait::async_trait;
use cmx_core::model::cell::DataValue;
use cmx_database_pg::{query_sql_with_params, SqlParams};
use cmx_dataauth_core::{DimensionExpander, ExpandError, ExpandResult};

/// PG 维度展开器：对 `cmx_dataauth_dimension_value(dim_value, parent_value)` 递归求子树。
#[derive(Clone)]
pub struct PgDimensionExpander {
    db_id: String,
}

impl PgDimensionExpander {
    pub fn new(db_id: impl Into<String>) -> Self {
        Self { db_id: db_id.into() }
    }
}

#[async_trait]
impl DimensionExpander for PgDimensionExpander {
    async fn descendants(&self, _tenant: &str, dim_key: &str, value: &str) -> ExpandResult<Vec<String>> {
        let sql = "WITH RECURSIVE sub AS ( \
                     SELECT dim_value FROM cmx_dataauth_dimension_value \
                       WHERE dim_key = $1 AND dim_value = $2 \
                     UNION ALL \
                     SELECT d.dim_value FROM cmx_dataauth_dimension_value d \
                       JOIN sub ON d.parent_value = sub.dim_value AND d.dim_key = $1 \
                   ) SELECT dim_value FROM sub";
        let params = vec![
            DataValue::String(dim_key.to_string()),
            DataValue::String(value.to_string()),
        ];
        let ds = query_sql_with_params(&self.db_id, None, sql, SqlParams::DataValues(params), "dataauth_descendants")
            .await
            .map_err(|e| ExpandError::Backend(format!("维度递归查询失败: {e}")))?;
        let schema = ds.schema.as_ref();
        let mut out: Vec<String> = ds
            .iter()
            .filter_map(|r| match r.get_by_name(schema, "dim_value") {
                Some(DataValue::String(s)) => Some(s.clone()),
                Some(DataValue::ShortStr(s)) | Some(DataValue::LongStr(s)) => Some(s.to_string()),
                _ => None,
            })
            .collect();
        // 维度树未登记该值时，闭包为空 → 至少含自身（fail-safe：仅授权自身节点）。
        if !out.iter().any(|x| x == value) {
            out.push(value.to_string());
        }
        Ok(out)
    }
}
