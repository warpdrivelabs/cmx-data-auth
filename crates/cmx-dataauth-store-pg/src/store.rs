//! [`DataAuthStore`] 的 tokio-postgres 实现。
//!
//! 严格类型纪律（对齐 rule/flow store-pg）：jsonb 列写 `DataValue::Json(String)`、读回同样；
//! TIMESTAMPTZ 用 `DataValue::DateTime`；文本 `DataValue::String`；整数 `DataValue::Int`；
//! 参数统一走 `SqlParams::DataValues`（顺序对应 `$1..$n`）。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cmx_core::model::cell::DataValue;
use cmx_core::model::data::dataset::{DataSet, Row, Schema};
use cmx_database_pg::{execute_sql, execute_sql_with_params, query_sql_with_params, SqlParams};
use cmx_dataauth_core::{
    AuditLog, DataAuthStore, DimensionValue, Effect, Grant, MaskRule, MaskType, PolicyDef,
    RelationTuple, StoreError, StoreResult,
};
use serde_json::Value;

/// PG 数据权限存储。`db_id` 指向已注册数据源（多租户下按租户派生）。
#[derive(Clone)]
pub struct PgDataAuthStore {
    db_id: String,
}

impl PgDataAuthStore {
    pub fn new(db_id: impl Into<String>) -> Self {
        Self { db_id: db_id.into() }
    }

    /// 幂等建表（启动钩子调用）。
    pub async fn ensure_schema(&self) -> StoreResult<()> {
        for stmt in crate::ddl::DDL_STATEMENTS {
            execute_sql(&self.db_id, None, stmt)
                .await
                .map_err(|e| StoreError::Backend(format!("建表失败: {e}")))?;
        }
        Ok(())
    }

    async fn exec(&self, sql: &str, params: Vec<DataValue>) -> StoreResult<u64> {
        execute_sql_with_params(&self.db_id, None, sql, SqlParams::DataValues(params))
            .await
            .map_err(|e| StoreError::Backend(format!("执行失败: {e}")))
    }

    async fn query(&self, sql: &str, params: Vec<DataValue>, ds_id: &str) -> StoreResult<DataSet> {
        query_sql_with_params(&self.db_id, None, sql, SqlParams::DataValues(params), ds_id)
            .await
            .map_err(|e| StoreError::Backend(format!("查询失败: {e}")))
    }

    /// INSERT ... RETURNING id 取铸号（GENERATED IDENTITY）。
    async fn insert_returning_id(&self, sql: &str, params: Vec<DataValue>) -> StoreResult<i64> {
        let ds = self.query(sql, params, "dataauth_ins_id").await?;
        Ok(ds
            .iter()
            .next()
            .map(|r| get_i64(r, ds.schema.as_ref(), "id"))
            .unwrap_or(0))
    }
}

#[async_trait]
impl DataAuthStore for PgDataAuthStore {
    // ─────────────────── 策略 ───────────────────

    async fn list_policies(&self, _tenant: &str) -> StoreResult<Vec<PolicyDef>> {
        let ds = self
            .query(
                "SELECT id, name, resource_kind, action, constraint_json, priority, effect \
                 FROM cmx_dataauth_policy ORDER BY priority DESC, id",
                vec![],
                "dataauth_policy_list",
            )
            .await?;
        rows_to_policies(&ds)
    }

    async fn get_policy(&self, _tenant: &str, id: i64) -> StoreResult<Option<PolicyDef>> {
        let ds = self
            .query(
                "SELECT id, name, resource_kind, action, constraint_json, priority, effect \
                 FROM cmx_dataauth_policy WHERE id = $1",
                vec![DataValue::Int(id)],
                "dataauth_policy_one",
            )
            .await?;
        Ok(rows_to_policies(&ds)?.into_iter().next())
    }

    async fn load_policies(
        &self,
        _tenant: &str,
        resource_kind: &str,
        action: &str,
    ) -> StoreResult<Vec<PolicyDef>> {
        let ds = self
            .query(
                "SELECT id, name, resource_kind, action, constraint_json, priority, effect \
                 FROM cmx_dataauth_policy \
                 WHERE enabled = TRUE AND resource_kind = $1 AND action = $2 \
                 ORDER BY priority DESC, id",
                vec![
                    DataValue::String(resource_kind.to_string()),
                    DataValue::String(action.to_string()),
                ],
                "dataauth_policy_load",
            )
            .await?;
        rows_to_policies(&ds)
    }

    async fn save_policy(&self, _tenant: &str, p: &PolicyDef) -> StoreResult<i64> {
        let now = Utc::now();
        let cj = DataValue::Json(p.constraint_tpl.to_string());
        let eff = effect_str(p.effect);
        if p.id == 0 {
            self.insert_returning_id(
                "INSERT INTO cmx_dataauth_policy \
                 (name, resource_kind, action, constraint_json, priority, effect, enabled, created_at, updated_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7,$7) RETURNING id",
                vec![
                    DataValue::String(p.name.clone()),
                    DataValue::String(p.resource_kind.clone()),
                    DataValue::String(p.action.as_str().to_string()),
                    cj,
                    DataValue::Int(p.priority as i64),
                    DataValue::String(eff),
                    DataValue::DateTime(now),
                ],
            )
            .await
        } else {
            self.exec(
                "UPDATE cmx_dataauth_policy SET name=$2, resource_kind=$3, action=$4, \
                 constraint_json=$5, priority=$6, effect=$7, updated_at=$8 WHERE id=$1",
                vec![
                    DataValue::Int(p.id),
                    DataValue::String(p.name.clone()),
                    DataValue::String(p.resource_kind.clone()),
                    DataValue::String(p.action.as_str().to_string()),
                    cj,
                    DataValue::Int(p.priority as i64),
                    DataValue::String(eff),
                    DataValue::DateTime(now),
                ],
            )
            .await?;
            Ok(p.id)
        }
    }

    async fn delete_policy(&self, _tenant: &str, id: i64) -> StoreResult<u64> {
        self.exec(
            "DELETE FROM cmx_dataauth_policy WHERE id = $1",
            vec![DataValue::Int(id)],
        )
        .await
    }

    // ─────────────────── 授权 ───────────────────

    async fn list_grants(&self, _tenant: &str) -> StoreResult<Vec<Grant>> {
        let ds = self
            .query(
                "SELECT id, policy_id, subject_type, subject_id, dim_key, dim_values, inherit \
                 FROM cmx_dataauth_grant ORDER BY id",
                vec![],
                "dataauth_grant_list",
            )
            .await?;
        rows_to_grants(&ds)
    }

    async fn load_grants(
        &self,
        _tenant: &str,
        subjects: &[(String, String)],
    ) -> StoreResult<Vec<Grant>> {
        if subjects.is_empty() {
            return Ok(Vec::new());
        }
        // 动态 (type,id) OR 组，参数化。
        let mut clauses = Vec::new();
        let mut params = Vec::new();
        let mut n = 1;
        for (t, i) in subjects {
            clauses.push(format!("(subject_type = ${} AND subject_id = ${})", n, n + 1));
            params.push(DataValue::String(t.clone()));
            params.push(DataValue::String(i.clone()));
            n += 2;
        }
        let sql = format!(
            "SELECT id, policy_id, subject_type, subject_id, dim_key, dim_values, inherit \
             FROM cmx_dataauth_grant WHERE {}",
            clauses.join(" OR ")
        );
        let ds = self.query(&sql, params, "dataauth_grant_load").await?;
        rows_to_grants(&ds)
    }

    async fn save_grant(&self, _tenant: &str, g: &Grant) -> StoreResult<i64> {
        let now = Utc::now();
        let dv = DataValue::Json(Value::Array(g.dim_values.clone()).to_string());
        if g.id == 0 {
            self.insert_returning_id(
                "INSERT INTO cmx_dataauth_grant \
                 (policy_id, subject_type, subject_id, dim_key, dim_values, inherit, created_at, updated_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$7) RETURNING id",
                vec![
                    DataValue::Int(g.policy_id),
                    DataValue::String(g.subject_type.clone()),
                    DataValue::String(g.subject_id.clone()),
                    opt_str(&g.dim_key),
                    dv,
                    DataValue::Bool(g.inherit),
                    DataValue::DateTime(now),
                ],
            )
            .await
        } else {
            self.exec(
                "UPDATE cmx_dataauth_grant SET policy_id=$2, subject_type=$3, subject_id=$4, \
                 dim_key=$5, dim_values=$6, inherit=$7, updated_at=$8 WHERE id=$1",
                vec![
                    DataValue::Int(g.id),
                    DataValue::Int(g.policy_id),
                    DataValue::String(g.subject_type.clone()),
                    DataValue::String(g.subject_id.clone()),
                    opt_str(&g.dim_key),
                    dv,
                    DataValue::Bool(g.inherit),
                    DataValue::DateTime(now),
                ],
            )
            .await?;
            Ok(g.id)
        }
    }

    async fn delete_grant(&self, _tenant: &str, id: i64) -> StoreResult<u64> {
        self.exec(
            "DELETE FROM cmx_dataauth_grant WHERE id = $1",
            vec![DataValue::Int(id)],
        )
        .await
    }

    // ─────────────────── 关系元组（ReBAC） ───────────────────

    async fn list_tuples(&self, _tenant: &str) -> StoreResult<Vec<RelationTuple>> {
        let ds = self
            .query(
                "SELECT id, object_kind, object_id, relation, subject_kind, subject_id \
                 FROM cmx_dataauth_relation_tuple ORDER BY id",
                vec![],
                "dataauth_tuple_list",
            )
            .await?;
        rows_to_tuples(&ds)
    }

    async fn lookup_resources(
        &self,
        _tenant: &str,
        object_kind: &str,
        relation: &str,
        subject_kind: &str,
        subject_id: &str,
    ) -> StoreResult<Vec<String>> {
        let ds = self
            .query(
                "SELECT object_id FROM cmx_dataauth_relation_tuple \
                 WHERE object_kind=$1 AND relation=$2 AND subject_kind=$3 AND subject_id=$4",
                vec![
                    DataValue::String(object_kind.to_string()),
                    DataValue::String(relation.to_string()),
                    DataValue::String(subject_kind.to_string()),
                    DataValue::String(subject_id.to_string()),
                ],
                "dataauth_lookup",
            )
            .await?;
        let schema = ds.schema.as_ref();
        Ok(ds
            .iter()
            .filter_map(|r| get_opt_string(r, schema, "object_id"))
            .collect())
    }

    async fn save_tuple(&self, _tenant: &str, t: &RelationTuple) -> StoreResult<i64> {
        let now = Utc::now();
        if t.id == 0 {
            self.insert_returning_id(
                "INSERT INTO cmx_dataauth_relation_tuple \
                 (object_kind, object_id, relation, subject_kind, subject_id, created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
                vec![
                    DataValue::String(t.object_kind.clone()),
                    DataValue::String(t.object_id.clone()),
                    DataValue::String(t.relation.clone()),
                    DataValue::String(t.subject_kind.clone()),
                    DataValue::String(t.subject_id.clone()),
                    DataValue::DateTime(now),
                ],
            )
            .await
        } else {
            self.exec(
                "UPDATE cmx_dataauth_relation_tuple SET object_kind=$2, object_id=$3, relation=$4, \
                 subject_kind=$5, subject_id=$6 WHERE id=$1",
                vec![
                    DataValue::Int(t.id),
                    DataValue::String(t.object_kind.clone()),
                    DataValue::String(t.object_id.clone()),
                    DataValue::String(t.relation.clone()),
                    DataValue::String(t.subject_kind.clone()),
                    DataValue::String(t.subject_id.clone()),
                ],
            )
            .await?;
            Ok(t.id)
        }
    }

    async fn delete_tuple(&self, _tenant: &str, id: i64) -> StoreResult<u64> {
        self.exec(
            "DELETE FROM cmx_dataauth_relation_tuple WHERE id = $1",
            vec![DataValue::Int(id)],
        )
        .await
    }

    // ─────────────────── 列脱敏规则 ───────────────────

    async fn list_mask_rules(&self, _tenant: &str, resource_kind: &str) -> StoreResult<Vec<MaskRule>> {
        let ds = self
            .query(
                "SELECT id, resource_kind, column_name, mask_type, partial_pattern, condition_expr, min_role \
                 FROM cmx_dataauth_mask_rule WHERE resource_kind = $1 ORDER BY id",
                vec![DataValue::String(resource_kind.to_string())],
                "dataauth_mask_list",
            )
            .await?;
        rows_to_masks(&ds)
    }

    async fn save_mask_rule(&self, _tenant: &str, m: &MaskRule) -> StoreResult<i64> {
        let now = Utc::now();
        if m.id == 0 {
            self.insert_returning_id(
                "INSERT INTO cmx_dataauth_mask_rule \
                 (resource_kind, column_name, mask_type, partial_pattern, condition_expr, min_role, created_at, updated_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$7) RETURNING id",
                vec![
                    DataValue::String(m.resource_kind.clone()),
                    DataValue::String(m.column.clone()),
                    DataValue::String(mask_type_str(m.mask_type)),
                    opt_str(&m.partial_pattern),
                    opt_str(&m.condition_expr),
                    opt_str(&m.min_role),
                    DataValue::DateTime(now),
                ],
            )
            .await
        } else {
            self.exec(
                "UPDATE cmx_dataauth_mask_rule SET resource_kind=$2, column_name=$3, mask_type=$4, \
                 partial_pattern=$5, condition_expr=$6, min_role=$7, updated_at=$8 WHERE id=$1",
                vec![
                    DataValue::Int(m.id),
                    DataValue::String(m.resource_kind.clone()),
                    DataValue::String(m.column.clone()),
                    DataValue::String(mask_type_str(m.mask_type)),
                    opt_str(&m.partial_pattern),
                    opt_str(&m.condition_expr),
                    opt_str(&m.min_role),
                    DataValue::DateTime(now),
                ],
            )
            .await?;
            Ok(m.id)
        }
    }

    async fn delete_mask_rule(&self, _tenant: &str, id: i64) -> StoreResult<u64> {
        self.exec(
            "DELETE FROM cmx_dataauth_mask_rule WHERE id = $1",
            vec![DataValue::Int(id)],
        )
        .await
    }

    // ─────────────────── 层级维度值 ───────────────────

    async fn list_dimension_values(
        &self,
        _tenant: &str,
        dim_key: &str,
    ) -> StoreResult<Vec<DimensionValue>> {
        let ds = self
            .query(
                "SELECT dim_key, dim_value, parent_value, label, depth \
                 FROM cmx_dataauth_dimension_value WHERE dim_key = $1 ORDER BY depth, dim_value",
                vec![DataValue::String(dim_key.to_string())],
                "dataauth_dimval_list",
            )
            .await?;
        let schema = ds.schema.as_ref();
        let mut out = Vec::new();
        for r in ds.iter() {
            out.push(DimensionValue {
                dim_key: get_string(r, schema, "dim_key")?,
                dim_value: get_string(r, schema, "dim_value")?,
                parent_value: get_opt_string(r, schema, "parent_value"),
                label: get_opt_string(r, schema, "label"),
                depth: get_i64(r, schema, "depth") as i32,
            });
        }
        Ok(out)
    }

    async fn save_dimension_value(&self, _tenant: &str, dv: &DimensionValue) -> StoreResult<()> {
        self.exec(
            "INSERT INTO cmx_dataauth_dimension_value (dim_key, dim_value, parent_value, label, depth) \
             VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT (dim_key, dim_value) DO UPDATE SET parent_value=EXCLUDED.parent_value, \
             label=EXCLUDED.label, depth=EXCLUDED.depth",
            vec![
                DataValue::String(dv.dim_key.clone()),
                DataValue::String(dv.dim_value.clone()),
                opt_str(&dv.parent_value),
                opt_str(&dv.label),
                DataValue::Int(dv.depth as i64),
            ],
        )
        .await?;
        Ok(())
    }

    // ─────────────────── 审计 ───────────────────

    async fn append_audit(&self, _tenant: &str, log: &AuditLog) -> StoreResult<()> {
        self.exec(
            "INSERT INTO cmx_dataauth_audit_log \
             (id, user_id, resource_kind, action, effect, constraint_json, backend, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            vec![
                DataValue::String(log.id.clone()),
                DataValue::String(log.user_id.clone()),
                DataValue::String(log.resource_kind.clone()),
                DataValue::String(log.action.clone()),
                DataValue::String(log.effect.clone()),
                DataValue::Json(log.constraint_json.to_string()),
                opt_str(&log.backend),
                DataValue::DateTime(log.created_at),
            ],
        )
        .await?;
        Ok(())
    }

    async fn list_audit(&self, _tenant: &str, limit: i64) -> StoreResult<Vec<AuditLog>> {
        let ds = self
            .query(
                "SELECT id, user_id, resource_kind, action, effect, constraint_json, backend, created_at \
                 FROM cmx_dataauth_audit_log ORDER BY created_at DESC LIMIT $1",
                vec![DataValue::Int(limit.clamp(1, 1000))],
                "dataauth_audit_list",
            )
            .await?;
        let schema = ds.schema.as_ref();
        let mut out = Vec::new();
        for r in ds.iter() {
            out.push(AuditLog {
                id: get_string(r, schema, "id")?,
                tenant: String::new(),
                user_id: get_opt_string(r, schema, "user_id").unwrap_or_default(),
                resource_kind: get_opt_string(r, schema, "resource_kind").unwrap_or_default(),
                action: get_opt_string(r, schema, "action").unwrap_or_default(),
                effect: get_opt_string(r, schema, "effect").unwrap_or_default(),
                constraint_json: get_json(r, schema, "constraint_json").unwrap_or(Value::Null),
                backend: get_opt_string(r, schema, "backend"),
                created_at: get_opt_ts(r, schema, "created_at").unwrap_or_else(Utc::now),
            });
        }
        Ok(out)
    }
}

// ————————————————————————— 组装 / 取值助手 —————————————————————————

fn rows_to_policies(ds: &DataSet) -> StoreResult<Vec<PolicyDef>> {
    let schema = ds.schema.as_ref();
    let mut out = Vec::new();
    for r in ds.iter() {
        out.push(PolicyDef {
            id: get_i64(r, schema, "id"),
            name: get_opt_string(r, schema, "name").unwrap_or_default(),
            resource_kind: get_string(r, schema, "resource_kind")?,
            action: parse_action(&get_opt_string(r, schema, "action").unwrap_or_default()),
            constraint_tpl: get_json(r, schema, "constraint_json")?,
            priority: get_i64(r, schema, "priority") as i32,
            effect: parse_effect(&get_opt_string(r, schema, "effect").unwrap_or_default()),
        });
    }
    Ok(out)
}

fn rows_to_grants(ds: &DataSet) -> StoreResult<Vec<Grant>> {
    let schema = ds.schema.as_ref();
    let mut out = Vec::new();
    for r in ds.iter() {
        let dim_values = match get_json(r, schema, "dim_values") {
            Ok(Value::Array(a)) => a,
            _ => Vec::new(),
        };
        out.push(Grant {
            id: get_i64(r, schema, "id"),
            policy_id: get_i64(r, schema, "policy_id"),
            subject_type: get_string(r, schema, "subject_type")?,
            subject_id: get_string(r, schema, "subject_id")?,
            dim_key: get_opt_string(r, schema, "dim_key"),
            dim_values,
            inherit: get_bool(r, schema, "inherit"),
        });
    }
    Ok(out)
}

fn rows_to_tuples(ds: &DataSet) -> StoreResult<Vec<RelationTuple>> {
    let schema = ds.schema.as_ref();
    let mut out = Vec::new();
    for r in ds.iter() {
        out.push(RelationTuple {
            id: get_i64(r, schema, "id"),
            object_kind: get_string(r, schema, "object_kind")?,
            object_id: get_string(r, schema, "object_id")?,
            relation: get_string(r, schema, "relation")?,
            subject_kind: get_string(r, schema, "subject_kind")?,
            subject_id: get_string(r, schema, "subject_id")?,
        });
    }
    Ok(out)
}

fn rows_to_masks(ds: &DataSet) -> StoreResult<Vec<MaskRule>> {
    let schema = ds.schema.as_ref();
    let mut out = Vec::new();
    for r in ds.iter() {
        out.push(MaskRule {
            id: get_i64(r, schema, "id"),
            resource_kind: get_opt_string(r, schema, "resource_kind").unwrap_or_default(),
            column: get_string(r, schema, "column_name")?,
            mask_type: parse_mask_type(&get_opt_string(r, schema, "mask_type").unwrap_or_default()),
            partial_pattern: get_opt_string(r, schema, "partial_pattern"),
            condition_expr: get_opt_string(r, schema, "condition_expr"),
            min_role: get_opt_string(r, schema, "min_role"),
        });
    }
    Ok(out)
}

fn effect_str(e: Effect) -> String {
    match e {
        Effect::Permit => "permit",
        Effect::Deny => "deny",
    }
    .to_string()
}

fn parse_effect(s: &str) -> Effect {
    if s.eq_ignore_ascii_case("deny") {
        Effect::Deny
    } else {
        Effect::Permit
    }
}

fn parse_action(s: &str) -> cmx_dataauth_core::Action {
    use cmx_dataauth_core::Action;
    match s.to_ascii_lowercase().as_str() {
        "write" => Action::Write,
        "delete" => Action::Delete,
        "export" => Action::Export,
        _ => Action::Read,
    }
}

fn mask_type_str(m: MaskType) -> String {
    match m {
        MaskType::Full => "FULL",
        MaskType::Partial => "PARTIAL",
        MaskType::Hash => "HASH",
    }
    .to_string()
}

fn parse_mask_type(s: &str) -> MaskType {
    match s.to_ascii_uppercase().as_str() {
        "PARTIAL" => MaskType::Partial,
        "HASH" => MaskType::Hash,
        _ => MaskType::Full,
    }
}

fn opt_str(v: &Option<String>) -> DataValue {
    match v {
        Some(s) => DataValue::String(s.clone()),
        None => DataValue::Null,
    }
}

fn get_string(row: &Row, schema: &Schema, col: &str) -> StoreResult<String> {
    match row.get_by_name(schema, col) {
        Some(DataValue::String(s)) => Ok(s.clone()),
        Some(DataValue::ShortStr(s)) | Some(DataValue::LongStr(s)) => Ok(s.to_string()),
        other => Err(StoreError::Backend(format!("列 {col} 期望文本，实际 {other:?}"))),
    }
}

fn get_opt_string(row: &Row, schema: &Schema, col: &str) -> Option<String> {
    match row.get_by_name(schema, col) {
        Some(DataValue::String(s)) => Some(s.clone()),
        Some(DataValue::ShortStr(s)) | Some(DataValue::LongStr(s)) => Some(s.to_string()),
        _ => None,
    }
}

fn get_bool(row: &Row, schema: &Schema, col: &str) -> bool {
    matches!(row.get_by_name(schema, col), Some(DataValue::Bool(true)))
}

fn get_i64(row: &Row, schema: &Schema, col: &str) -> i64 {
    match row.get_by_name(schema, col) {
        Some(DataValue::Int(v)) => *v,
        _ => 0,
    }
}

fn get_opt_ts(row: &Row, schema: &Schema, col: &str) -> Option<DateTime<Utc>> {
    match row.get_by_name(schema, col) {
        Some(DataValue::DateTime(dt)) => Some(*dt),
        _ => None,
    }
}

fn get_json(row: &Row, schema: &Schema, col: &str) -> StoreResult<Value> {
    match row.get_by_name(schema, col) {
        Some(DataValue::Json(s)) => serde_json::from_str(s)
            .map_err(|e| StoreError::Backend(format!("解析 {col} jsonb 失败: {e}"))),
        Some(DataValue::String(s)) => serde_json::from_str(s)
            .map_err(|e| StoreError::Backend(format!("解析 {col} 字符串为 json 失败: {e}"))),
        other => Err(StoreError::Backend(format!("列 {col} 期望 jsonb，实际 {other:?}"))),
    }
}
