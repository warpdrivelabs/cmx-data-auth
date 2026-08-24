//! 内核错误类型。决策错误 / 存储错误 / 编译错误 / 维度展开错误 —— 各自独立类型（对齐 rule-model）。

use thiserror::Error;

/// 内核逻辑错误（策略装配 / 求值）。
#[derive(Debug, Error)]
pub enum Error {
    #[error("策略错误: {0}")]
    Policy(String),
    #[error("求值错误: {0}")]
    Eval(String),
}
pub type Result<T> = core::result::Result<T, Error>;

/// 存储后端错误（驱动无关）。
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("存储后端错误: {0}")]
    Backend(String),
    #[error("未找到: {0}")]
    NotFound(String),
}
pub type StoreResult<T> = core::result::Result<T, StoreError>;

/// 约束编译错误（PEP 后端）。
#[derive(Debug, Error)]
pub enum CompileError {
    /// 字段不在资源白名单（`dim_bindings` 物理列 ∪ `row_ctx`）—— **防注入硬门**。
    #[error("未知字段（不在资源白名单，拒绝编译）: {0}")]
    UnknownField(String),
    /// 关系约束（ReBAC）未先经 `lookup_resources` 解析成 `In`。
    #[error("未解析的关系约束（Relation 须先化为 In）: field={0}")]
    UnresolvedRelation(String),
}
pub type CompileResult<T> = core::result::Result<T, CompileError>;

/// 维度展开错误。
#[derive(Debug, Error)]
pub enum ExpandError {
    #[error("维度展开失败: {0}")]
    Backend(String),
}
pub type ExpandResult<T> = core::result::Result<T, ExpandError>;
