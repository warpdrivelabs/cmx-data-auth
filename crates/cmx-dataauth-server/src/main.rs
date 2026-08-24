/*
 * cmx-dataauth 独立数据权限引擎微服务 HTTP 服务器。
 *
 * 采用通用骨架 cmx-web-chassis：main 只填 ServiceSpec —— dataauth 路由 + 两个启动钩子（注册数据源、
 * 建表预热）+ 专属 banner/配色，交 chassis::run 装配。零 cmx-api 依赖。
 *
 * 与 rule-server 一致：**无定时器 poller**（数据权限决策无长驻实例）—— 钩子②只建表预热，纯请求驱动。
 *
 * 配置（chassis 框架级用 DATAAUTH_ 前缀；专属用各自变量）：
 *   DATAAUTH_HOST / DATAAUTH_PORT（默认 0.0.0.0:8096）/ DATAAUTH_LOG_DIR / DATAAUTH_LOG_LEVEL / DATAAUTH_CONFIG(toml)
 *   DATAAUTH_PG_URL（数据源）/ DATAAUTH_AUTH_MODE / DATAAUTH_JWT_* / DATAAUTH_API_KEYS / DATAAUTH_TENANCY
 *
 * 用法：
 *   DATAAUTH_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/fico cargo run -p cmx-dataauth-server
 *   curl -XPOST http://127.0.0.1:8096/api/dataauth/v1/decide -d '{"subject":{...},"resource":{...}}'
 */

use cmx_database_pg::{DbConfig, DbType};
use cmx_dataauth_app::{dataauth_routes, dataauth_routes_v1, warm_store, DATAAUTH_DB_ID};
use cmx_web_chassis::{run, BannerSpec, ChassisConfig, ServiceSpec};

/// 专属字符画（MEGA DATA-AUTH）。
const DATAAUTH_ART: &str = r#"
██████╗  █████╗ ████████╗ █████╗    ██████╗ ██╗   ██╗████████╗██╗  ██╗
██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗   ██╔══██╗██║   ██║╚══██╔══╝██║  ██║
██║  ██║███████║   ██║   ███████║   ██████╔╝██║   ██║   ██║   ███████║
██║  ██║██╔══██║   ██║   ██╔══██║   ██╔══██╗██║   ██║   ██║   ██╔══██║
██████╔╝██║  ██║   ██║   ██║  ██║   ██║  ██║╚██████╔╝   ██║   ██║  ██║
╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
"#;

/// data-auth-server.toml 的 [auth]/[datasource] 段（全可选）。
#[derive(serde::Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    auth: AuthSection,
    #[serde(default)]
    datasource: DatasourceSection,
}

#[derive(serde::Deserialize, Default)]
struct AuthSection {
    mode: Option<String>,
    jwt_secret: Option<String>,
    jwt_tenant_claim: Option<String>,
    jwt_roles_claim: Option<String>,
    api_keys: Option<String>,
    tenancy: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct DatasourceSection {
    dataauth_pg_url: Option<String>,
}

/// 读 toml 的 [auth]/[datasource] 段 → 注入 DATAAUTH_* 环境变量（env 未设时；env 优先）。
fn apply_toml_env() {
    let path = std::env::var("CONFIG_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("DATAAUTH_CONFIG").ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "data-auth-server.toml".to_string());
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let file: FileConfig = match toml::from_str(&text) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "data-auth-server.toml 解析失败，回退环境变量");
            return;
        }
    };
    let set_if_absent = |key: &str, val: &Option<String>| {
        if let Some(v) = val
            && !v.trim().is_empty()
            && std::env::var(key).is_err()
        {
            // SAFETY: 启动早期、单线程、任何请求前设置进程环境变量。
            unsafe { std::env::set_var(key, v) }
        }
    };
    set_if_absent("DATAAUTH_AUTH_MODE", &file.auth.mode);
    set_if_absent("DATAAUTH_JWT_SECRET", &file.auth.jwt_secret);
    set_if_absent("DATAAUTH_JWT_TENANT_CLAIM", &file.auth.jwt_tenant_claim);
    set_if_absent("DATAAUTH_JWT_ROLES_CLAIM", &file.auth.jwt_roles_claim);
    set_if_absent("DATAAUTH_API_KEYS", &file.auth.api_keys);
    set_if_absent("DATAAUTH_TENANCY", &file.auth.tenancy);
    set_if_absent("DATAAUTH_PG_URL", &file.datasource.dataauth_pg_url);
}

#[tokio::main]
async fn main() -> cmx_web_chassis::Result<()> {
    dotenvy::dotenv().ok();
    if let Err(e) = cmx_service_base::init_config_manager() {
        tracing::warn!(error = %e, "全局 ConfigManager 初始化失败，回退 env/默认兜底");
    }

    let mut cfg = ChassisConfig::load("dataauth", "data-auth-server.toml");
    apply_toml_env();
    if std::env::var("DATAAUTH_PORT").is_err() && cfg.port == 8080 {
        cfg.port = 8096; // dataauth 默认端口（避开平台 8080 / flow 8091 / report 8092 / model 8093 / rule 8094 / mdm 8095）。
    }

    let banner = BannerSpec::defaults("dataauth")
        .art(DATAAUTH_ART)
        .tagline("  MEGA Data-Auth · 数据权限引擎微服务 · cmx-web-chassis ")
        .stops(vec![(99, 102, 241), (34, 211, 238), (16, 185, 129)]);

    // 路由：v1 正式契约 + 旧前缀，经认证中间件。
    let authed = dataauth_routes_v1::<()>()
        .merge(dataauth_routes::<()>())
        .layer(axum::middleware::from_fn(cmx_web_monitor::observe))
        .layer(axum::middleware::from_fn(cmx_dataauth_app::auth_middleware));
    let api_router = axum::Router::new().merge(authed);
    let app_router = axum::Router::new()
        // 根 → 监控大盘（免认证，轮询 /api/dataauth/v1/stats）。
        .route("/", axum::routing::get(cmx_dataauth_app::dashboard::dashboard))
        .nest("/api", api_router);

    // 技术监控（/_mon）。
    cmx_web_monitor::set_service_name("cmx-dataauth 数据权限引擎");
    cmx_web_monitor::set_identity_provider(cmx_dataauth_app::identity_snapshot);
    cmx_web_monitor::set_topology_provider(|| {
        vec![cmx_web_monitor::ServiceDep {
            key: "dataauth".into(),
            label: "数据权限引擎".into(),
            mode: "embedded".into(),
            target: None,
            proxiable: true,
        }]
    });

    let spec = ServiceSpec::<()>::new("dataauth", cfg)
        .banner(banner)
        .nest_api(false) // 已自行 nest /api，让根大盘 / 逃出 /api。
        .router(app_router)
        .state(())
        // 钩子① 注册数据源（db_id 对齐 DATAAUTH_DB_ID）。
        .init("datasources", |_meta| {
            Box::pin(async {
                let url = std::env::var("DATAAUTH_PG_URL").unwrap_or_else(|_| {
                    "postgres://postgres:postgres@127.0.0.1:5432/fico".to_string()
                });
                cmx_service_base::register_pg_datasources(&[dataauth_db_config(DATAAUTH_DB_ID, &url)])
                    .await
                    .map_err(|e| anyhow::anyhow!("注册数据源失败: {e}"))?;
                tracing::info!(db = DATAAUTH_DB_ID, "✅ 数据源已注册");
                Ok(())
            })
        })
        // 钩子② 建表预热（**无 poller**）。非致命：DB/schema 不可用只 warn，服务仍起。
        .init("store", |_meta| {
            Box::pin(async {
                if let Err(e) = warm_store().await {
                    tracing::warn!(error = %e, "数据权限存储初始化失败（DB/schema 不可用？端点将返错）");
                }
                Ok(())
            })
        });

    run(spec).await
}

/// 构造 dataauth PG 数据源配置（url 从 env 来）。
fn dataauth_db_config(db_id: &str, url: &str) -> DbConfig {
    DbConfig {
        db_type: DbType::Postgres,
        db_url: url.to_string(),
        db_id: db_id.to_string(),
        db_name: None,
        db_schema: Some("public".to_string()),
        default: true,
        pool_config: Default::default(),
        health_check_interval: 60,
        health_check_timeout: 5,
        domain_code: None,
        application_code: None,
        module_code: None,
        source_type: Some("default".to_string()),
    }
}
