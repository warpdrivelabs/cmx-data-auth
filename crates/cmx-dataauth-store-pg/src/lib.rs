//! cmx-dataauth-store-pg —— [`cmx_dataauth_core::DataAuthStore`] 的 tokio-postgres 实现 + 层级维度展开器。

pub mod ddl;
pub mod expander;
pub mod store;

pub use expander::PgDimensionExpander;
pub use store::PgDataAuthStore;
