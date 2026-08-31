//! 驱动无关的持久化契约。方法均按 `tenant` 作用（db-per-tenant 下传 `"default"`）。

use crate::def::{AuditLog, ChangeLog, DimensionValue, Grant, MaskRule, PolicyDef, RelationTuple};
use crate::error::StoreResult;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// 数据权限存储：策略 / 授权 / 关系元组 / 脱敏规则 / 维度值 / 审计。
#[async_trait]
pub trait DataAuthStore: Send + Sync {
    // —— 策略 ——
    /// 分页列策略；`q` 按 name 模糊过滤（None=不过滤）。
    async fn list_policies(
        &self,
        tenant: &str,
        limit: i64,
        offset: i64,
        q: Option<&str>,
    ) -> StoreResult<Vec<PolicyDef>>;
    async fn count_policies(&self, tenant: &str, q: Option<&str>) -> StoreResult<i64>;
    async fn get_policy(&self, tenant: &str, id: i64) -> StoreResult<Option<PolicyDef>>;
    /// 求值热路径：取匹配 `(resource_kind, action)` 的启用策略。
    async fn load_policies(
        &self,
        tenant: &str,
        resource_kind: &str,
        action: &str,
    ) -> StoreResult<Vec<PolicyDef>>;
    /// upsert；`id==0` 时由后端铸号，返回策略 id。
    async fn save_policy(&self, tenant: &str, policy: &PolicyDef) -> StoreResult<i64>;
    async fn delete_policy(&self, tenant: &str, id: i64) -> StoreResult<u64>;

    // —— 授权 ——
    /// 分页列授权；`q` 按 subject_id 模糊过滤。
    async fn list_grants(
        &self,
        tenant: &str,
        limit: i64,
        offset: i64,
        q: Option<&str>,
    ) -> StoreResult<Vec<Grant>>;
    async fn count_grants(&self, tenant: &str, q: Option<&str>) -> StoreResult<i64>;
    async fn get_grant(&self, tenant: &str, id: i64) -> StoreResult<Option<Grant>>;
    /// 求值热路径：取命中给定主体（`(subject_type, subject_id)` 列表）的授权。
    async fn load_grants(
        &self,
        tenant: &str,
        subjects: &[(String, String)],
    ) -> StoreResult<Vec<Grant>>;
    async fn save_grant(&self, tenant: &str, grant: &Grant) -> StoreResult<i64>;
    async fn delete_grant(&self, tenant: &str, id: i64) -> StoreResult<u64>;

    // —— 关系元组（ReBAC）——
    /// 分页列关系元组；`q` 按 object_id/subject_id 模糊过滤。
    async fn list_tuples(
        &self,
        tenant: &str,
        limit: i64,
        offset: i64,
        q: Option<&str>,
    ) -> StoreResult<Vec<RelationTuple>>;
    async fn count_tuples(&self, tenant: &str, q: Option<&str>) -> StoreResult<i64>;
    /// `LookupResources`：某主体在某关系下可及的对象 id 集（含 group 多跳闭包）。
    async fn lookup_resources(
        &self,
        tenant: &str,
        object_kind: &str,
        relation: &str,
        subject_kind: &str,
        subject_id: &str,
    ) -> StoreResult<Vec<String>>;
    async fn save_tuple(&self, tenant: &str, tuple: &RelationTuple) -> StoreResult<i64>;
    async fn delete_tuple(&self, tenant: &str, id: i64) -> StoreResult<u64>;

    // —— 列脱敏规则 ——
    async fn list_mask_rules(&self, tenant: &str, resource_kind: &str) -> StoreResult<Vec<MaskRule>>;
    async fn save_mask_rule(&self, tenant: &str, rule: &MaskRule) -> StoreResult<i64>;
    async fn delete_mask_rule(&self, tenant: &str, id: i64) -> StoreResult<u64>;

    // —— 层级维度值 ——
    async fn list_dimension_values(
        &self,
        tenant: &str,
        dim_key: &str,
    ) -> StoreResult<Vec<DimensionValue>>;
    async fn save_dimension_value(&self, tenant: &str, dv: &DimensionValue) -> StoreResult<()>;

    // —— 审计 ——
    async fn append_audit(&self, tenant: &str, log: &AuditLog) -> StoreResult<()>;
    async fn list_audit(&self, tenant: &str, limit: i64) -> StoreResult<Vec<AuditLog>>;
    /// 清理 `created_at < before` 的审计（保留期/TTL）。返回删除条数。
    async fn prune_audit(&self, tenant: &str, before: DateTime<Utc>) -> StoreResult<u64>;

    // —— 配置变更审计 ——
    async fn append_change(&self, tenant: &str, log: &ChangeLog) -> StoreResult<()>;
    async fn list_changes(&self, tenant: &str, limit: i64) -> StoreResult<Vec<ChangeLog>>;
}
