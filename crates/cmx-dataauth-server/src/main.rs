/*
 * cmx-dataauth 独立数据权限引擎微服务 HTTP 服务器。
 *
 * 采用通用骨架 cmx-web-chassis + 统一启动契约（与 rule/report/flow/model/mdm/onto 逐一对齐）：
 *   dotenvy(.env 提供 CONFIG_FILE) → init_infra（装配全局 ConfigManager：CONFIG_FILE toml + env
 *   + 可选 Nacos）→ ChassisConfig::load（只吃 [server]）→ 两个 .init 钩子（datasources / store）
 *   → run → shutdown_infra。零 cmx-api 依赖。
 *
 * 与 rule-server 一致：**无定时器 poller**（数据权限决策无长驻实例）—— 钩子②只建表预热，纯请求驱动。
 *
 * 配置（统一 toml-first；见 data-auth-server.toml）：
 *   [server] host/port/log_dir/log_level/graceful_timeout_secs（默认 0.0.0.0:8098；env 覆盖 SERVER__*）
 *   [[databases]] 标准数据源段（db_id = DATAAUTH_DB_ID = "dataauth_pg"，default=true；缺段启动失败）
 *   [auth] mode / jwt_secret / jwt claim / api_keys / tenancy / admin_roles / allowed_tenants（ConfigManager 直读 auth.*，env AUTH__* 覆盖）
 *   业务专属旋钮仍走 env（DATAAUTH_DECIDE_CACHE_TTL_SECS / DATAAUTH_DESC_CACHE_TTL_SECS / DATAAUTH_TENANT_DB_URL_TEMPLATE）
 *
 * 用法：
 *   ./dataauth.sh                                   # 读 data-auth-server.toml（本地库，off 模式）
 *   AUTH__MODE=jwt AUTH__JWT_SECRET=... ./dataauth.sh # jwt 模式（env 覆盖）
 *   curl -XPOST http://127.0.0.1:8098/api/dataauth/v1/decide -d '{"subject":{...},"resource":{...}}'
 */

use cmx_dataauth_app::{
    auth_config_warmup, dataauth_routes, dataauth_routes_v1, warm_store, DATAAUTH_DB_ID,
};
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

#[tokio::main]
async fn main() -> cmx_web_chassis::Result<()> {
    dotenvy::dotenv().ok();
    // 统一基础设施装配（与 rule/report/flow 同一制度）：CONFIG_FILE toml ← 可选 Nacos ← env 三源
    // ConfigManager + 注册中心/配置中心客户端。默认 Nacos 关闭时走 Mock（纯本地 toml+env，行为与
    // 接入前一致）；开启后 create 阶段强依赖 Nacos 可达，失败即中止启动。
    cmx_service_base::init_infra()
        .await
        .map_err(|e| cmx_web_chassis::ChassisError::Config(format!("基础设施初始化失败: {e}")))?;

    let mut cfg = ChassisConfig::load("dataauth", "data-auth-server.toml");
    if std::env::var("SERVER__PORT").is_err() && cfg.port == 8080 {
        cfg.port = 8098; // dataauth 默认端口（避开平台 8080 / flow 8091 / report 8092 / model 8093 / rule 8094 / mdm 8095 / meta 8096 / onto 8097）。
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
    let api_router = axum::Router::new()
        .merge(authed)
        // 公开契约（免认证，挂认证之外）：OpenAPI JSON 供 Swagger/门户消费。
        .route(
            "/dataauth/v1/openapi.json",
            axum::routing::get(cmx_dataauth_app::openapi::openapi_json),
        );
    let app_router = axum::Router::new()
        // 根 → 监控大盘（免认证，轮询 /api/dataauth/v1/stats）。
        .route("/", axum::routing::get(cmx_dataauth_app::dashboard::dashboard))
        // 管理工作台（#17）+ Swagger UI（#18）——免认证静态页；门户可反代。
        .route("/console", axum::routing::get(cmx_dataauth_app::console::console))
        .route("/swagger", axum::routing::get(cmx_dataauth_app::openapi::swagger))
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
        // 钩子① 注册数据源（[[databases]] 配置驱动；auth.mode fail-fast）。
        .init("datasources", |_meta| {
            // auth.mode 缺失/非法在启动期即失败（fail-fast），而非等首个请求。
            auth_config_warmup();
            Box::pin(async {
                let base = cmx_service_base::BaseConfig::from_config_manager()
                    .map_err(|e| anyhow::anyhow!("读取 [[databases]] 配置失败: {e}"))?;
                cmx_service_base::validate_databases(
                    &base.databases,
                    &cmx_service_base::DatasourceRules {
                        required_db_ids: &[DATAAUTH_DB_ID],
                        ..Default::default()
                    },
                )
                .map_err(|e| {
                    anyhow::anyhow!("数据源校验失败（需 db_id=\"{DATAAUTH_DB_ID}\" 的 [[databases]] 段）: {e}")
                })?;
                let ids: Vec<&str> = base.databases.iter().map(|d| d.db_id.as_str()).collect();
                cmx_service_base::register_pg_datasources(&base.databases)
                    .await
                    .map_err(|e| anyhow::anyhow!("注册数据源失败: {e}"))?;
                tracing::info!(databases = ?ids, "✅ 数据权限引擎 tokio-pg 数据源已注册（[[databases]] 配置驱动）");
                Ok(())
            })
        })
        // 钩子② 建表预热（**无 poller**）。致命：DB/schema 不可用即中止启动（对齐 rule/report）。
        .init("store", |_meta| {
            Box::pin(async {
                warm_store()
                    .await
                    .map_err(|e| anyhow::anyhow!("数据权限存储初始化失败: {e}"))?;
                Ok(())
            })
        });

    // 收尾：serve 结束后一定注销注册中心实例（不用 `?`，保证 shutdown 必达）。
    let result = run(spec).await;
    cmx_service_base::shutdown_infra().await;
    result
}
