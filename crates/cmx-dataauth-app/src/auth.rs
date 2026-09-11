//! 认证中间件（off / jwt / api-key），建租户 scope。镜像 cmx-rule-app::auth。
//!
//! 配置经全局 `ConfigManager` 读 `[auth]` 段（toml ← env `AUTH__*` 覆盖，`__`→`.` 约定）：
//! - `auth.mode=off`（默认）：不校验，建 `default` 租户 scope 放行 —— 单租户零回归。
//! - `auth.mode=jwt`：验 Bearer JWT（HS256），解 tenant/user/roles claim；缺/坏 → 401。
//! - API Key（`auth.api_keys=key:tenant,...`）：`X-API-Key` 命中 → 服务身份，租户取 key 绑定。
//!
//! 启动期 [`auth_config_warmup`] 对 `auth.mode` fail-fast（缺失/非法即中止），由 server datasources 钩子调用。

use crate::tenant::{scope, TenantCtx};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

/// 认证配置（每请求从 ConfigManager 读 `auth.*`）。
struct AuthConfig {
    mode: String,
    jwt_secret: String,
    tenant_claim: String,
    roles_claim: String,
    api_keys: Vec<(String, String)>, // (key, tenant)
    allowed_tenants: Vec<String>,    // 空 = 不限制；非空 = JWT tenant claim 白名单。
    admin_roles: Vec<String>,        // 可管理"管理面"（策略/授权/脱敏/维度 CRUD）的角色。
}

impl AuthConfig {
    /// 从全局 ConfigManager 读 `[auth]` 段（env `AUTH__*` 覆盖）。默认值与迁移前 env 版逐一对齐。
    fn from_config() -> Self {
        let get = |key: &str| {
            cmx_utils::ConfigManager::try_global()
                .and_then(|cm| cm.get_string(key).ok())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let csv = |key: &str, default: &str| -> Vec<String> {
            get(key)
                .unwrap_or_else(|| default.to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let api_keys = get("auth.api_keys")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .filter_map(|pair| {
                let (k, t) = pair.split_once(':')?;
                Some((k.trim().to_string(), t.trim().to_string()))
            })
            .collect();
        Self {
            mode: get("auth.mode").unwrap_or_else(|| "off".to_string()),
            jwt_secret: get("auth.jwt_secret").unwrap_or_else(|| "change-me".to_string()),
            tenant_claim: get("auth.jwt_tenant_claim").unwrap_or_else(|| "tenant".to_string()),
            roles_claim: get("auth.jwt_roles_claim").unwrap_or_else(|| "roles".to_string()),
            api_keys,
            allowed_tenants: csv("auth.allowed_tenants", ""),
            admin_roles: csv("auth.admin_roles", "superadmin,admin,dataauth-admin"),
        }
    }
}

/// 启动期认证配置预热（fail-fast）：校验 `auth.mode` ∈ {off,jwt}，缺失/非法即 panic 中止启动
/// （仿 engine-kit `auth_config_warmup`；缺失通常意味 CONFIG_FILE 未指向 data-auth-server.toml）。
/// 由 server 的 datasources 钩子在建池前调用。
pub fn auth_config_warmup() {
    let raw = cmx_utils::ConfigManager::try_global()
        .and_then(|cm| cm.get_string("auth.mode").ok())
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty());
    match raw.as_deref() {
        Some("off") => warn_off_once(),
        Some("jwt") => tracing::info!("✅ 数据权限认证模式 = jwt"),
        other => panic!(
            "auth.mode 配置缺失或非法（当前值: {other:?}），须为 off | jwt——\
             检查 [auth] mode（或 env AUTH__MODE）、及 CONFIG_FILE 是否指向 data-auth-server.toml"
        ),
    }
}

/// JWT claim（宽松：tenant/roles 键名可配，故用 Value 二次取）。
#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Value,
}

/// 认证中间件。建租户 scope + 确保租户库就绪后放行；失败返 401。
pub async fn auth(req: Request, next: Next) -> Response {
    let cfg = AuthConfig::from_config();

    if cfg.mode == "off" {
        warn_off_once();
        return scoped_run(TenantCtx::new(crate::tenant::DEFAULT_TENANT), req, next).await;
    }

    if let Some(key) = req.headers().get("X-API-Key").and_then(|v| v.to_str().ok()) {
        if let Some((_, tenant)) = cfg.api_keys.iter().find(|(k, _)| k == key) {
            let ctx = TenantCtx::new(tenant.clone()).with_roles(vec!["service".into()]);
            return scoped_run(ctx, req, next).await;
        }
        return unauthorized("无效 API Key");
    }

    if cfg.mode == "jwt" {
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let Some(token) = token else {
            return unauthorized("缺少 Bearer 令牌");
        };
        match decode_claims(token, &cfg) {
            Ok(ctx) => scoped_run(ctx, req, next).await,
            Err(msg) => unauthorized(&msg),
        }
    } else {
        unauthorized("未知认证模式")
    }
}

async fn scoped_run(ctx: TenantCtx, req: Request, next: Next) -> Response {
    scope(ctx, async move {
        crate::tenancy::ensure_current_ready().await;
        next.run(req).await
    })
    .await
}

fn decode_claims(token: &str, cfg: &AuthConfig) -> Result<TenantCtx, String> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    // 拒绝默认/空密钥：防止用出厂密钥签发的令牌通过（fail-closed）。
    if cfg.jwt_secret.trim().is_empty() || cfg.jwt_secret == "change-me" {
        return Err("JWT 密钥未配置（拒绝默认/空密钥），请设置 DATAAUTH_JWT_SECRET".into());
    }
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true; // 校验过期
    validation.set_required_spec_claims(&["exp"]); // 强制携带 exp（拒绝无期令牌）
    validation.leeway = 30;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| format!("令牌验签失败: {e}"))?;

    let claims = data.claims;
    let tenant = claims
        .extra
        .get(&cfg.tenant_claim)
        .and_then(|v| v.as_str())
        .unwrap_or(crate::tenant::DEFAULT_TENANT)
        .to_string();
    // 租户白名单（配置了 DATAAUTH_ALLOWED_TENANTS 才校验）。
    if !cfg.allowed_tenants.is_empty() && !cfg.allowed_tenants.contains(&tenant) {
        return Err(format!("租户 {tenant} 不在允许集"));
    }
    let roles = claims
        .extra
        .get(&cfg.roles_claim)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    Ok(TenantCtx::new(tenant).with_user(claims.sub).with_roles(roles))
}

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "code": 401, "msg": msg })),
    )
        .into_response()
}

/// 管理面守卫：保护策略/授权/脱敏/维度/关系元组的写读端点（"谁能治理治理者"）。
///
/// - `off` 模式：本地信任，放行（含 CRUD）—— 保持零回归，生产须禁 off。
/// - `jwt`/`api-key` 模式：要求主体持有管理员角色（`auth.admin_roles`，默认
///   `superadmin,admin,dataauth-admin`），否则 403。数据面端点（decide/compile/enforce）不挂本守卫。
///
/// 注意：管理员角色 ⊇ 决策超管（[`cmx_dataauth_core::SUPERADMIN_ROLES`]）但不等价 —— `dataauth-admin`
/// 可管理配置，却不会让 `decide` 短路成"看全部数据"。
pub async fn require_admin(req: Request, next: Next) -> Response {
    let cfg = AuthConfig::from_config();
    if cfg.mode == "off" {
        return next.run(req).await;
    }
    let roles = crate::tenant::current_roles();
    let is_admin = roles.iter().any(|r| cfg.admin_roles.iter().any(|a| a == r));
    if is_admin {
        next.run(req).await
    } else {
        (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "code": 403, "msg": "需要管理员角色（数据权限管理面）" })),
        )
            .into_response()
    }
}

/// off 模式仅告警一次：提醒生产不应关闭认证。
fn warn_off_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tracing::warn!(
            "⚠️ DATAAUTH_AUTH_MODE=off —— 认证与管理面鉴权全部关闭（本地信任）。生产环境请设为 jwt/api-key。"
        );
    });
}
