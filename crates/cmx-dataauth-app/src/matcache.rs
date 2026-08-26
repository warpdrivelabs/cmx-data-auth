//! L3 物化权限集缓存 —— 急切物化，空间换时间。
//!
//! 对**枚举可穷尽的简单字典**（组织机构、成本中心、项目…），把"某主体在该字典上可见哪些条目"预
//! 计算成条目集合、直接缓存；前端查字典时 O(1) 取集、可不碰库；权限**再分配**时刷新对应键。
//!
//! 缓存按 principal 分桶（键 = `(tenant, dictCode, subjectType, subjectId)`），用户有效可见集 =
//! `cache[user:自身] ∪ cache[role:各角色]`（去重）。给某角色重分配只失效一个键，其全体成员下次
//! 查询自动取到最新。载体 M1 为进程内 `OnceLock<Mutex<HashMap>>`；生产可换 Redis。

use crate::engine;
use crate::resp::AuthzError;
use chrono::{DateTime, Utc};
use cmx_dataauth_core::{DataAuthStore, DimensionExpander, DimensionValue, SUPERADMIN_ROLES};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

/// 缓存键：(tenant, dictCode, subjectType, subjectId)。
type Key = (String, String, String, String);

/// 授"全部"的通配根值（grant.dim_values 含它 → 物化为全量字典）。
const ALL: &str = "*";
/// 超管的特殊 principal（物化为全量字典）。
const SUPER: (&str, &str) = ("SUPER", "*");

#[derive(Clone)]
struct CacheEntry {
    values: Arc<Vec<DimensionValue>>,
    at: DateTime<Utc>,
}

static CACHE: OnceLock<Mutex<HashMap<Key, CacheEntry>>> = OnceLock::new();
fn cache() -> &'static Mutex<HashMap<Key, CacheEntry>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 查询结果。
pub struct Permitted {
    pub entries: Vec<DimensionValue>,
    /// 本次查询涉及的 principal 是否**全部**命中缓存（全命中 = 未触发任何物化）。
    pub from_cache: bool,
    /// 参与本次查询的各 principal 缓存中，最早的物化时刻（前端可据此判新鲜度）。None = 无缓存。
    pub materialized_at: Option<DateTime<Utc>>,
}

/// 查询主体在某字典上的可见条目（缓存优先；未命中即物化并落缓存）。
pub async fn permitted_entries(
    tenant: &str,
    dict_code: &str,
    user_id: &str,
    roles: &[String],
) -> Result<Permitted, AuthzError> {
    // 超管 → 全量（物化到特殊 principal，同样享缓存）。
    if roles.iter().any(|r| SUPERADMIN_ROLES.contains(&r.as_str())) {
        let (v, hit, at) = get_or_materialize(tenant, dict_code, SUPER.0, SUPER.1).await?;
        return Ok(Permitted {
            entries: (*v).clone(),
            from_cache: hit,
            materialized_at: Some(at),
        });
    }

    let mut principals: Vec<(String, String)> = Vec::new();
    if !user_id.is_empty() {
        principals.push(("USER".into(), user_id.to_string()));
    }
    for r in roles {
        principals.push(("ROLE".into(), r.clone()));
    }

    let mut all_hit = true;
    let mut oldest: Option<DateTime<Utc>> = None;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<DimensionValue> = Vec::new();
    for (st, si) in &principals {
        let (v, hit, at) = get_or_materialize(tenant, dict_code, st, si).await?;
        all_hit &= hit;
        oldest = Some(oldest.map_or(at, |o| o.min(at)));
        for e in v.iter() {
            if seen.insert(e.dim_value.clone()) {
                out.push(e.clone());
            }
        }
    }
    Ok(Permitted {
        entries: out,
        from_cache: all_hit,
        materialized_at: oldest,
    })
}

/// 取或物化一个 principal 的可见集。返回 (集合, 是否缓存命中, 物化时刻)。
async fn get_or_materialize(
    tenant: &str,
    dict_code: &str,
    stype: &str,
    sid: &str,
) -> Result<(Arc<Vec<DimensionValue>>, bool, DateTime<Utc>), AuthzError> {
    let key = (
        tenant.to_string(),
        dict_code.to_string(),
        stype.to_string(),
        sid.to_string(),
    );
    if let Some(e) = cache().lock().unwrap().get(&key) {
        return Ok((e.values.clone(), true, e.at));
    }
    let values = Arc::new(materialize(tenant, dict_code, stype, sid).await?);
    let at = Utc::now();
    cache().lock().unwrap().insert(
        key,
        CacheEntry {
            values: values.clone(),
            at,
        },
    );
    Ok((values, false, at))
}

/// 物化一个 principal 的可见集：该 principal 被授的字典维度根 → descendants 并集 → 过滤全量字典。
async fn materialize(
    tenant: &str,
    dict_code: &str,
    stype: &str,
    sid: &str,
) -> Result<Vec<DimensionValue>, AuthzError> {
    let st = engine::store();
    let all = st
        .list_dimension_values(tenant, dict_code)
        .await
        .map_err(|e| AuthzError::internal(format!("装载字典条目失败: {e}")))?;

    // 超管特殊 principal → 全量。
    if stype == SUPER.0 {
        return Ok(all);
    }

    let grants = st
        .load_grants(tenant, &[(stype.to_string(), sid.to_string())])
        .await
        .map_err(|e| AuthzError::internal(format!("装载授权失败: {e}")))?;

    let ex = engine::expander();
    let mut permitted: BTreeSet<String> = BTreeSet::new();
    for g in &grants {
        if g.dim_key.as_deref() != Some(dict_code) {
            continue;
        }
        for root in &g.dim_values {
            let rs = match root {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if rs == ALL {
                return Ok(all); // 授"全部" → 全量字典。
            }
            let desc = ex
                .descendants(tenant, dict_code, &rs)
                .await
                .map_err(|e| AuthzError::internal(format!("维度展开失败: {e}")))?;
            permitted.extend(desc);
        }
    }

    Ok(all
        .into_iter()
        .filter(|e| permitted.contains(&e.dim_value))
        .collect())
}

/// 失效缓存：`principal=None` → 该字典全部 principal 键；`Some((type,id))` → 仅该 principal。
/// 返回失效的键数。权限再分配时调用（"刷新缓冲"）。
pub fn invalidate(tenant: &str, dict_code: &str, principal: Option<(&str, &str)>) -> usize {
    let mut c = cache().lock().unwrap();
    let before = c.len();
    c.retain(|(t, d, st, si), _| {
        if t != tenant || d != dict_code {
            return true; // 其它租户/字典不动。
        }
        match principal {
            Some((pt, pi)) => !(st == pt && si == pi), // 保留非目标 principal。
            None => false,                              // 该字典全清。
        }
    });
    before - c.len()
}

/// 授权变更时的精准失效：按 grant 的字典维度 + 主体失效对应键（外加超管键，因全量可能变）。
pub fn invalidate_for_grant(tenant: &str, dim_key: Option<&str>, subject_type: &str, subject_id: &str) {
    let Some(dict) = dim_key else { return };
    invalidate(tenant, dict, Some((subject_type, subject_id)));
    // 字典条目本身变化会影响超管全量集与"授全部"者；一并失效该字典的 SUPER 键。
    invalidate(tenant, dict, Some((SUPER.0, SUPER.1)));
}

/// 缓存条目数（大盘/诊断用）。
pub fn cache_size() -> usize {
    cache().lock().unwrap().len()
}

/// 清空全部缓存（测试/运维兜底）。
pub fn clear() -> usize {
    let mut c = cache().lock().unwrap();
    let n = c.len();
    c.clear();
    n
}
