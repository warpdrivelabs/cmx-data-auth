//! 认证中间件（off / jwt / api-key），建租户 scope。镜像 cmx-rule-app::auth。
//!
//! - `DATAAUTH_AUTH_MODE=off`（默认）：不校验，建 `default` 租户 scope 放行 —— 单租户零回归。
//! - `DATAAUTH_AUTH_MODE=jwt`：验 Bearer JWT（HS256），解 tenant/user/roles claim；缺/坏 → 401。
//! - API Key（`DATAAUTH_API_KEYS=key:tenant,...`）：`X-API-Key` 命中 → 服务身份，租户取 key 绑定。

use crate::tenant::{scope, TenantCtx};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

/// 认证配置（懒读环境变量）。
struct AuthConfig {
    mode: String,
    jwt_secret: String,
    tenant_claim: String,
    roles_claim: String,
    api_keys: Vec<(String, String)>, // (key, tenant)
}

impl AuthConfig {
    fn from_env() -> Self {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let api_keys = env("DATAAUTH_API_KEYS", "")
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .filter_map(|pair| {
                let (k, t) = pair.split_once(':')?;
                Some((k.trim().to_string(), t.trim().to_string()))
            })
            .collect();
        Self {
            mode: env("DATAAUTH_AUTH_MODE", "off"),
            jwt_secret: env("DATAAUTH_JWT_SECRET", "change-me"),
            tenant_claim: env("DATAAUTH_JWT_TENANT_CLAIM", "tenant"),
            roles_claim: env("DATAAUTH_JWT_ROLES_CLAIM", "roles"),
            api_keys,
        }
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
    let cfg = AuthConfig::from_env();

    if cfg.mode == "off" {
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
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
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
