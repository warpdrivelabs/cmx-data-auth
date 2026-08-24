//! 驱动无关的持久化契约。方法均按 `tenant` 作用（db-per-tenant 下传 `"default"`）。

use crate::def::{AuditLog, DimensionValue, Grant, MaskRule, PolicyDef, RelationTuple};
use crate::error::StoreResult;
use async_trait::async_trait;

/// 数据权限存储：策略 / 授权 / 关系元组 / 脱敏规则 / 维度值 / 审计。
#[async_trait]
pub trait DataAuthStore: Send + Sync {
    // —— 策略 ——
    async fn list_policies(&self, tenant: &str) -> StoreResult<Vec<PolicyDef>>;
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
    async fn list_grants(&self, tenant: &str) -> StoreResult<Vec<Grant>>;
    /// 求值热路径：取命中给定主体（`(subject_type, subject_id)` 列表）的授权。
    async fn load_grants(
        &self,
        tenant: &str,
        subjects: &[(String, String)],
    ) -> StoreResult<Vec<Grant>>;
    async fn save_grant(&self, tenant: &str, grant: &Grant) -> StoreResult<i64>;
    async fn delete_grant(&self, tenant: &str, id: i64) -> StoreResult<u64>;

    // —— 关系元组（ReBAC）——
    async fn list_tuples(&self, tenant: &str) -> StoreResult<Vec<RelationTuple>>;
    /// `LookupResources`：某主体在某关系下可及的对象 id 集。
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
}
