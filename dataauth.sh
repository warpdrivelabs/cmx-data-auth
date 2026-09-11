#!/usr/bin/env bash
#
# 启动数据权限引擎微服务（MEGA DATA-AUTH · :8098）。
#
# 统一启动契约（门户/流程/报表/主数据/规则/本体各服务同一套）：
#   1) cd 到本 workspace 根（*-server.toml 的相对路径基准）
#   2) export CONFIG_FILE → ConfigManager 与 chassis 同源读取该 toml（[server]/[[databases]]/[auth]）
#   3) cargo run 对应 bin
#
# 用法：
#   ./dataauth.sh                 # 开发模式（debug，读 data-auth-server.toml：本地库 + off 模式）
#   ./dataauth.sh --release       # 发布模式（透传给 cargo run）
#   CONFIG_FILE=data-auth-server-dev.toml ./dataauth.sh   # 切 dev 库
#   AUTH__MODE=jwt AUTH__JWT_SECRET=<秘钥> ./dataauth.sh  # jwt 模式（env 覆盖 [auth]）
#
# 依赖：PostgreSQL（含 dataauth 策略/授权/维度/元组/审计等表，首启自动建）。
# 起后访问：
#   http://127.0.0.1:8098/                          数据权限工作台监控大盘
#   http://127.0.0.1:8098/console                   管理工作台
#   http://127.0.0.1:8098/swagger                   Swagger UI
#   http://127.0.0.1:8098/api/dataauth/v1/stats     引擎聚合
#   http://127.0.0.1:8098/_mon                      技术监控
set -euo pipefail
cd "$(dirname "$0")"
export CONFIG_FILE="${CONFIG_FILE:-data-auth-server.toml}"
exec cargo run -p cmx-dataauth-server "$@"
