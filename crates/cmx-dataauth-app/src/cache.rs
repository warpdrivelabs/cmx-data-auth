//! L1 进程内缓存：decide 决策缓存（#12）+ descendants 展开记忆（#15）。读多写少。
//!
//! **失效模型**：任一配置写（策略/授权/脱敏/元组/维度）调 [`bump_generation`] → 全局 generation 自增
//! 并清空两缓存（fail-fresh，写后立即新鲜）。另加 TTL 兜底多实例（他机改动本机不知，TTL 秒后自然过期）。
//! 生产可换 Redis + pub/sub 失效。
//!
//! - **decide 缓存**默认**关闭**（`DATAAUTH_DECIDE_CACHE_TTL_SECS=0`），显式开启；命中仍写审计（不漏审计）。
//! - **descendants 缓存**默认**开启**（`DATAAUTH_DESC_CACHE_TTL_SECS`，默认 60s，0 关闭）；维度树少变，收益稳。

use cmx_dataauth_core::{Decision, Resource, Subject};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

static GEN: AtomicU64 = AtomicU64::new(0);

/// 配置写后调用：generation 自增 + 清空两缓存（整体作废）。
pub fn bump_generation() {
    GEN.fetch_add(1, Ordering::Relaxed);
    if let Some(m) = DECIDE.get() {
        m.lock().unwrap().clear();
    }
    if let Some(m) = DESC.get() {
        m.lock().unwrap().clear();
    }
}

fn generation() -> u64 {
    GEN.load(Ordering::Relaxed)
}

fn env_secs(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

// ─────────────────── decide 决策缓存（#12，默认关闭）───────────────────

struct DecideEntry {
    decision: Decision,
    at: Instant,
    gen_id: u64,
}

static DECIDE: OnceLock<Mutex<HashMap<u64, DecideEntry>>> = OnceLock::new();
fn decide_map() -> &'static Mutex<HashMap<u64, DecideEntry>> {
    DECIDE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn decide_ttl() -> Option<Duration> {
    let secs = env_secs("DATAAUTH_DECIDE_CACHE_TTL_SECS", 0);
    (secs > 0).then(|| Duration::from_secs(secs))
}

fn decide_key(tenant: &str, subject: &Subject, resource: &Resource) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tenant.hash(&mut h);
    serde_json::to_string(subject).unwrap_or_default().hash(&mut h);
    serde_json::to_string(resource).unwrap_or_default().hash(&mut h);
    h.finish()
}

/// 命中返回克隆的 Decision（缓存关闭 / 未命中 / 过期 / generation 变 → None）。
pub fn decide_get(tenant: &str, subject: &Subject, resource: &Resource) -> Option<Decision> {
    let ttl = decide_ttl()?;
    let k = decide_key(tenant, subject, resource);
    let g = generation();
    let m = decide_map().lock().unwrap();
    let e = m.get(&k)?;
    (e.gen_id == g && e.at.elapsed() < ttl).then(|| e.decision.clone())
}

pub fn decide_put(tenant: &str, subject: &Subject, resource: &Resource, d: &Decision) {
    if decide_ttl().is_none() {
        return;
    }
    let k = decide_key(tenant, subject, resource);
    decide_map().lock().unwrap().insert(
        k,
        DecideEntry {
            decision: d.clone(),
            at: Instant::now(),
            gen_id: generation(),
        },
    );
}

pub fn decide_cache_size() -> usize {
    DECIDE.get().map(|m| m.lock().unwrap().len()).unwrap_or(0)
}

// ─────────────────── descendants 展开记忆（#15，默认开启）───────────────────

struct DescEntry {
    vals: Vec<String>,
    at: Instant,
    gen_id: u64,
}

static DESC: OnceLock<Mutex<DescMap>> = OnceLock::new();
type DescMap = HashMap<(String, String, String), DescEntry>;
fn desc_map() -> &'static Mutex<DescMap> {
    DESC.get_or_init(|| Mutex::new(HashMap::new()))
}

fn desc_ttl() -> Option<Duration> {
    let secs = env_secs("DATAAUTH_DESC_CACHE_TTL_SECS", 60);
    (secs > 0).then(|| Duration::from_secs(secs))
}

pub fn desc_get(tenant: &str, dim_key: &str, root: &str) -> Option<Vec<String>> {
    let ttl = desc_ttl()?;
    let g = generation();
    let m = desc_map().lock().unwrap();
    let e = m.get(&(tenant.to_string(), dim_key.to_string(), root.to_string()))?;
    (e.gen_id == g && e.at.elapsed() < ttl).then(|| e.vals.clone())
}

pub fn desc_put(tenant: &str, dim_key: &str, root: &str, vals: &[String]) {
    if desc_ttl().is_none() {
        return;
    }
    desc_map().lock().unwrap().insert(
        (tenant.to_string(), dim_key.to_string(), root.to_string()),
        DescEntry {
            vals: vals.to_vec(),
            at: Instant::now(),
            gen_id: generation(),
        },
    );
}

pub fn desc_cache_size() -> usize {
    DESC.get().map(|m| m.lock().unwrap().len()).unwrap_or(0)
}
