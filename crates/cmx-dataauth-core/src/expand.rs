//! 维度展开器 —— 把一个维度**根值**展开为其下行闭包（含自身的全部子孙），供 `In` 下推。
//!
//! 注意方向：数据权限需要**向下**闭包（org → 全部子组织），与 cmx-flow 的 `DimensionResolver`
//! （向上取 ancestors）方向相反，故本 crate 自定义此 trait。

use crate::error::ExpandResult;
use async_trait::async_trait;
use std::collections::HashMap;

/// 维度展开契约。
#[async_trait]
pub trait DimensionExpander: Send + Sync {
    /// 返回 `value` 在 `dim_key` 维度下的全部子孙（**含自身**）。平级维度返回 `[value]`。
    async fn descendants(&self, tenant: &str, dim_key: &str, value: &str) -> ExpandResult<Vec<String>>;
}

/// 不展开：原样返回根值（平级 / 无层级维度）。
pub struct NoopExpander;

#[async_trait]
impl DimensionExpander for NoopExpander {
    async fn descendants(&self, _tenant: &str, _dim_key: &str, value: &str) -> ExpandResult<Vec<String>> {
        Ok(vec![value.to_string()])
    }
}

/// 测试用内存展开器：`value -> 子孙集`（未含自身时自动补齐）。
#[derive(Default, Clone)]
pub struct MockDimensionExpander {
    map: HashMap<String, Vec<String>>,
}

impl MockDimensionExpander {
    pub fn new() -> Self {
        Self::default()
    }

    /// 链式登记一个根值 → 子孙集。
    pub fn with(mut self, value: impl Into<String>, descendants: Vec<String>) -> Self {
        self.map.insert(value.into(), descendants);
        self
    }
}

#[async_trait]
impl DimensionExpander for MockDimensionExpander {
    async fn descendants(&self, _tenant: &str, _dim_key: &str, value: &str) -> ExpandResult<Vec<String>> {
        let mut out = self.map.get(value).cloned().unwrap_or_default();
        if !out.iter().any(|x| x == value) {
            out.push(value.to_string());
        }
        Ok(out)
    }
}
