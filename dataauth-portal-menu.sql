-- 数据权限引擎（cmx-data-auth）门户菜单/模块登记。
-- ============================================================================
-- 幂等（可重复执行）。在**门户库**（portal 的 cmx 库）执行，非本引擎的 fico 库。
-- 前置：门户已配 [center_client.services].dataauth = { url = "http://127.0.0.1:8098" }
--       （反代壳 cmx-dataauth-proxy 已把 /api/dataauth/* 与 /console 接进平台）。
--
-- 关键契约（经前端运行时代码核实，非猜测）：
--   · 门户 SPA **忽略 open_type 列**（仅编辑器用）；开什么完全看 definition JSONB。
--   · 独立 URL 页（如反代的 /console）经**四区工作台里的 iframe 视图**加载：
--     URL 必须落在 definition.workspace.content.views[].data.src（type:"iframe"）。
--   · 仅 definition 的 workspace/dialogspace/expanded/type 抵达前端；path/component/open_type 列不抵达。
--   · 菜单节点须为**叶子**（leaf=1）才可打开（非叶子只展开/折叠）。
--   · 查询按 (domain_code, application_code, module_code) 过滤 → 三者须与目标菜单组一致。
-- ============================================================================

-- 1) 模块登记（DAM 注册表；与 mdm 同域应用 basic.dataplatform）。
INSERT INTO cmx_module (id, code, domain_code, application_code, name, title, icon, description,
 tags, resource_root, manifest_path, status, archived, sort_order)
VALUES
    ('basic_dataplatform_dataauth', 'dataauth', 'basic', 'dataplatform',
 '数据权限', '企业数据权限引擎', 'shield',
 '数据权限引擎（PDP/PEP 解耦，约束 AST，行级/列级）：策略/授权/脱敏/维度/关系元组/决策解释/审计。',
 '["basic.dataplatform.dataauth","dataauth"]', 'basic/dataplatform/dataauth',
 'modules/basic/dataplatform/dataauth/module.json', 1, 0, 10)
ON CONFLICT (id) DO UPDATE SET
    code = EXCLUDED.code, domain_code = EXCLUDED.domain_code, application_code = EXCLUDED.application_code,
    name = EXCLUDED.name, title = EXCLUDED.title, icon = EXCLUDED.icon, description = EXCLUDED.description,
    tags = EXCLUDED.tags, resource_root = EXCLUDED.resource_root, manifest_path = EXCLUDED.manifest_path,
    status = EXCLUDED.status, archived = EXCLUDED.archived, sort_order = EXCLUDED.sort_order;

-- 2) 菜单：父分组（数据权限）+ 叶子（管理工作台 → iframe /console）。
--    定位组 (basic, dataplatform, dataauth)。id 用固定大整数（雪花风格，避免与现有冲突）。
INSERT INTO cmx_menu (id, code, name, icon, fun_code, sort_order, definition, domain_code, application_code, module_code, parent_id, parent_code, depth, leaf, code_path, id_path, visible, status, open_type, archived, create_time, update_time)
VALUES ('7501000000000000001', 'dataauth', '数据权限', 'shield', NULL, 1,
 '{"caption":"数据权限","expanded":true,"name":"dataauth"}'::jsonb,
 'basic', 'dataplatform', 'dataauth', NULL, NULL, 1, 0, '/dataauth', '/7501000000000000001', 1, 1, 0, 0, now(), now())
ON CONFLICT (code) WHERE archived = 0 DO NOTHING;

INSERT INTO cmx_menu (id, code, name, icon, fun_code, sort_order, definition, domain_code, application_code, module_code, parent_id, parent_code, depth, leaf, code_path, id_path, visible, status, open_type, archived, create_time, update_time)
VALUES ('7501000000000000002', 'dataauth-console', '管理工作台', 'tabler-outline/adjustments-cog', NULL, 1,
 '{"caption":"数据权限管理工作台","workspace":{"content":{"caption":"数据权限管理工作台","icon":"tabler-outline/adjustments-cog","views":[{"tabLabel":"工作台","icon":"tabler-outline/adjustments-cog","type":"iframe","data":{"src":"/console","title":"数据权限工作台"}}]}},"name":"dataauth-console"}'::jsonb,
 'basic', 'dataplatform', 'dataauth', '7501000000000000001', 'dataauth', 2, 1, '/dataauth/dataauth-console', '/7501000000000000001/7501000000000000002', 1, 1, 0, 0, now(), now())
ON CONFLICT (code) WHERE archived = 0 DO NOTHING;

-- 3)（可选）API 文档叶子：Swagger UI 同样经反代（若门户也反代 /swagger 则可加；当前只反代 /console 与 /api/dataauth/*）。
