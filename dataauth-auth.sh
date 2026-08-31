#!/usr/bin/env bash
# cmx-dataauth P0 认证/管理面冒烟（须以 jwt 模式起服务）：
#   DATAAUTH_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/fico \
#     DATAAUTH_AUTH_MODE=jwt DATAAUTH_JWT_SECRET=test-secret SERVER__PORT=8096 \
#     cargo run -p cmx-dataauth-server &
#   ./dataauth-auth.sh
#
# 覆盖 P0：#1 管理面守卫（非管理员写→403、管理员读→200）· #2 JWT 校验 exp（无 exp→401、
# 默认密钥→拒）· #4 写/删执行接缝（DELETE 注入 scoped WHERE）· 数据面读 PEP 注入。
set -euo pipefail
B="${DATAAUTH_BASE:-http://127.0.0.1:8096/api/dataauth/v1}"
SECRET="${DATAAUTH_JWT_SECRET:-test-secret}"
pass=0; fail=0
chk() { if [[ "$3" == *"$2"* ]]; then echo "  ✅ $1"; pass=$((pass+1)); else echo "  ❌ $1"; echo "     期望含: $2"; echo "     实际: $3"; fail=$((fail+1)); fi; }
J='content-type: application/json'

# mktok <sub> <roles_csv> <exp:1/0> [secret]
mktok() {
  python3 - "$1" "$2" "$3" "${4:-$SECRET}" <<'PY'
import hmac,hashlib,base64,json,sys,time
sub,roles_csv,exp_flag,secret=sys.argv[1:5]
b=lambda x:base64.urlsafe_b64encode(x).rstrip(b"=").decode()
payload={"sub":sub,"tenant":"default","roles":[r for r in roles_csv.split(",") if r]}
if exp_flag=="1": payload["exp"]=int(time.time())+3600
h=b(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
p=b(json.dumps(payload).encode())
s=b(hmac.new(secret.encode(),f"{h}.{p}".encode(),hashlib.sha256).digest())
print(f"{h}.{p}.{s}")
PY
}
AH() { echo "Authorization: Bearer $1"; }

ADMIN=$(mktok admin dataauth-admin 1)     # 管理员（可管理面，但非决策超管）
BIZ=$(mktok biz1 "" 1)                      # 业务用户（数据面，无管理权）
NOEXP=$(mktok biz1 dataauth-admin 0)        # 无 exp（应被拒）
BADSECRET=$(mktok admin dataauth-admin 1 wrong-secret)  # 错误密钥（应被拒）

echo "== 0. 维度树 + 管理员 seed voucher 读/删策略与授权 =="
for row in '1001||' '100101|上海|1001' '100102|杭州|1001'; do
  IFS='|' read -r v l p <<< "$row"
  curl -s -XPOST $B/dimension-values -H "$J" -H "$(AH "$ADMIN")" -d "{\"dimKey\":\"org\",\"dimValue\":\"$v\",\"label\":\"$l\",\"parentValue\":\"$p\"}" >/dev/null
done
PR=$(curl -s -XPOST $B/policies -H "$J" -H "$(AH "$ADMIN")" -d '{"name":"pep-read","resourceKind":"voucher","action":"read","effect":"permit","constraintTpl":{"kind":"in","field":"ou_id","values":["$dim:org"]}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
PD=$(curl -s -XPOST $B/policies -H "$J" -H "$(AH "$ADMIN")" -d '{"name":"pep-del","resourceKind":"voucher","action":"delete","effect":"permit","constraintTpl":{"kind":"in","field":"ou_id","values":["$dim:org"]}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
curl -s -XPOST $B/grants -H "$J" -H "$(AH "$ADMIN")" -d "{\"policyId\":$PR,\"subjectType\":\"USER\",\"subjectId\":\"biz1\",\"dimKey\":\"org\",\"dimValues\":[\"1001\"]}" >/dev/null
curl -s -XPOST $B/grants -H "$J" -H "$(AH "$ADMIN")" -d "{\"policyId\":$PD,\"subjectType\":\"USER\",\"subjectId\":\"biz1\",\"dimKey\":\"org\",\"dimValues\":[\"1001\"]}" >/dev/null
echo "  seeded read=$PR del=$PD"

echo "== 1. #1 管理面守卫 =="
FORB=$(curl -s -o /dev/null -w "%{http_code}" -XPOST $B/policies -H "$J" -H "$(AH "$BIZ")" -d '{"name":"x","resourceKind":"y","action":"read","constraintTpl":{"kind":"true"}}')
chk "非管理员写管理面 → 403" "403" "$FORB"
ADMOK=$(curl -s -o /dev/null -w "%{http_code}" "$B/policies" -H "$(AH "$ADMIN")")
chk "管理员读管理面 → 200" "200" "$ADMOK"
DATAOK=$(curl -s -o /dev/null -w "%{http_code}" -XPOST $B/decide -H "$J" -H "$(AH "$BIZ")" -d '{"subject":{"userId":"biz1"},"resource":{"kind":"voucher","action":"read","dimBindings":{"org":"ou_id"}}}')
chk "非管理员仍可用数据面 /decide → 200" "200" "$DATAOK"

echo "== 2. #2 JWT 校验 =="
UNAUTH=$(curl -s -o /dev/null -w "%{http_code}" "$B/stats" -H "$(AH "$NOEXP")")
chk "无 exp 令牌 → 401" "401" "$UNAUTH"
BADSEC=$(curl -s -o /dev/null -w "%{http_code}" "$B/stats" -H "$(AH "$BADSECRET")")
chk "错误密钥令牌 → 401" "401" "$BADSEC"
NOTOK=$(curl -s -o /dev/null -w "%{http_code}" "$B/stats")
chk "无令牌 → 401" "401" "$NOTOK"

echo "== 3. 数据面 PEP 读注入（#5 接缝的读侧）=="
DEMO=$(curl -s "$B/demo/vouchers" -H "$(AH "$BIZ")")
chk "读 demo 注入 scoped WHERE" "WHERE ou_id IN" "$DEMO"

echo "== 4. #4 写/删执行接缝 =="
DEL=$(curl -s -XDELETE "$B/demo/vouchers/7" -H "$(AH "$BIZ")")
chk "删 demo 注入 scoped DELETE" "DELETE FROM voucher WHERE" "$DEL"
chk "删 demo scope 参数在前(含 businessSql)" '"businessSql"' "$DEL"
# 无删权用户（未授 voucher/delete）→ guard 403。
BIZ2=$(mktok biz2 "" 1)
DELF=$(curl -s -o /dev/null -w "%{http_code}" -XDELETE "$B/demo/vouchers/7" -H "$(AH "$BIZ2")")
chk "无删权用户 → 403 短路" "403" "$DELF"

echo
echo "==== 通过 $pass · 失败 $fail ===="
[[ $fail -eq 0 ]]
