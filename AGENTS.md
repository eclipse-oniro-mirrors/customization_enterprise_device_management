# enterprise_device_management 技术文档

## 第一部分：项目全景图

| 目录 | 职责 | 核心文件 |
|------|------|----------|
| `common/` | 公共基础模块 | EdmUtils, EdmLog, EdmBundleManagerImpl |
| `etc/` | 系统配置和启动脚本 | init/, param/ |
| `framework/` | 框架扩展模块 | extension/ |
| `interfaces/` | 对外接口层（NAPI/内部API） | AdminManagerAddon, IPlugin, IPolicySerializer |
| `sa_profile/` | 系统能力配置 | 1601.json |
| `services/edm/` | EDM主服务实现 | EnterpriseDeviceMgrAbility, AdminManager, PolicyManager, PluginManager |
| `services/edm/src/event_management/` | 事件管理与分发 | EventSubscriptionManager, MdmEventRelayer, PluginEventRouter |
| `services/edm_plugin/` | 策略插件实现 | 130+ 插件类 |
| `test/` | 测试代码 | unittest/, fuzztest/ |

### 高频变更文件

| 文件/目录 | 关联任务 | 路由文档 |
|-----------|---------|---------|
| `services/edm/src/plugin_manager.cpp` | 插件加载与执行 | `plugin-architecture.md` |
| `services/edm/src/query_policy/policy_query_config_table.cpp` | 策略查询配置 | `ipc-and-funccode.md` |
| `services/edm/src/event_management/` | 事件订阅/分发 | `event-management.md` |
| `services/edm_plugin/src/` | 策略插件实现 | `plugin-architecture.md` |
| 5 个 `BUILD.gn` | 构建配置 | `build-gn-rules.md` |

---

## 第二部分：核心类摘要

### services/edm 核心类

| 类 | 职责 | 核心方法 | 代码路径 |
|---|------|---------|---------|
| `AdminManager` | 管理员生命周期管理 | GetInstance, GetAdminByPkgName, EnableAdmin, DisableAdmin | `services/edm/src/admin_manager.cpp` |
| `PolicyManager` | 策略增删改查 | GetInstance, GetPolicy, SetPolicy | `services/edm/src/policy_manager.cpp` |
| `PluginManager` | 插件加载与执行 | GetPluginByFuncCode, UpdateDevicePolicy, LoadPlugin | `services/edm/src/plugin_manager.cpp` |
| `EnterpriseDeviceMgrAbility` | 主Ability，IPC服务入口 | HandleDevicePolicy, GetDevicePolicy | `services/edm/src/enterprise_device_mgr_ability.cpp` |
| `EnterpriseDeviceMgrStub` | IPC消息分发 | OnRemoteRequest | `services/edm/src/enterprise_device_mgr_stub.cpp` |

### services/edm query_policy 核心类（factory+config_table模式）

| 类 | 职责 | 核心方法 | 代码路径 |
|---|------|---------|---------|
| `PolicyQueryFactory` | 根据接口码创建query对象 | CreateQuery, CheckFeatureEnabled | `services/edm/src/query_policy/policy_query_factory.cpp` |
| `PolicyQueryConfigTable` | 配置表，集中定义所有策略元数据 | GetConfigTable, GetKnownPolicyCodes | `services/edm/src/query_policy/policy_query_config_table.cpp` |
| `PolicyQueryConfig` | 单个策略的配置数据结构 | policyName, dataType, permissionConfig | `services/edm/src/query_policy/policy_query_config.cpp` |
| `GenericPolicyQuery<DataType>` | 通用策略查询模板，根据配置自动处理 | GetPolicyName, GetPermission, QueryPolicy | `services/edm/src/query_policy/generic_policy_query.cpp` |
| `PluginPolicyReader` | 策略查询入口，调用Factory分发 | GetPolicyByCode, GetPolicyByCodeInner | `services/edm/src/query_policy/plugin_policy_reader.cpp` |

### services/edm event_management 核心类

| 类 | 职责 | 核心方法 | 代码路径 |
|---|------|---------|---------|
| `EventSubscriptionManager` | 事件订阅中心单例，refCount+延迟退订 | GetInstance, Subscribe, Unsubscribe, DispatchEvent | `services/edm/src/event_management/event_subscription_manager.cpp` |
| `MdmEventRelayer` | Admin事件桥接，工厂模式创建策略 | GetInstance, OnAdminSubscribe, OnAdminUnsubscribe, OnAdminRemoved | `services/edm/src/event_management/mdm_event_relayer.cpp` |
| `PluginEventRouter` | 插件事件路由，实现IPluginEventSubscribeManager | GetInstance, SubscribeEvent, UnsubscribeEvent, RestorePluginSubscriptions | `services/edm/src/event_management/plugin_event_router.cpp` |
| `AdapterFactory` | 适配器工厂，根据EventId创建对应adapter | CreateAdapter | `services/edm/src/event_management/adapter_factory.cpp` |
| `CommonEventAdapter` | CommonEvent子系统适配器 | SubscribeEvent, UnsubscribeEvent | `services/edm/src/event_management/common_event_adapter.cpp` |
| `AppLifecycleAdapter` | 应用生命周期适配器 | SubscribeEvent, UnsubscribeEvent | `services/edm/src/event_management/app_lifecycle_adapter.cpp` |
| `EdmCommonEventSubscriber` | CommonEvent接收者，分发到EventSubscriptionManager | OnReceiveEvent | `services/edm/src/event_management/edm_common_event_subscriber.cpp` |
| `EdmAppStateSubscriber` | 应用状态观察者，分发到EventSubscriptionManager | OnProcessCreated, OnProcessDied | `services/edm/src/event_management/edm_app_state_subscriber.cpp` |
| `SubscriptionHandle` | RAII订阅句柄，析构自动退订 | Release, GetHandleId | `services/edm/src/event_management/subscription_handle.cpp` |
| `DelayCancelTimer` | 延迟取消定时器，30秒宽限期 | Start, Cancel, IsRunning | `services/edm/src/event_management/delay_cancel_timer.cpp` |

### interfaces/inner_api/plugin_kits 核心接口

| 接口 | 职责 | 代码路径 |
|------|------|---------|
| `IPlugin` | 策略插件核心接口 | `interfaces/inner_api/plugin_kits/include/iplugin.h` |
| `IPluginTemplate<CT, DT>` | 策略处理模板类 | `interfaces/inner_api/plugin_kits/include/iplugin_template.h` |
| `IPolicySerializer<DT>` | 策略数据序列化接口 | `interfaces/inner_api/plugin_kits/include/ipolicy_serializer.h` |
| `IPluginExecuteStrategy` | 插件执行策略接口 | `interfaces/inner_api/plugin_kits/include/iplugin_execute_strategy.h` |

---

## 第三部分：架构知识路由

> 以下架构知识已提取到 `docs/knowledge/architecture/` 下独立文档，按任务场景查阅，避免在本文件内堆叠长篇架构说明。
>
> **编辑代码前须声明：任务类别 + 已读文档 + 发现的约束。**

| 任务场景 | 涉及路径 | 必读架构文档 |
|---------|---------|-------------|
| 改 FuncCode 编码 / IPC 路由 / 查询工厂 / ConfigTable / PermissionConfig / GenericPolicyQuery | `services/edm/src/enterprise_device_mgr_stub.cpp`、`enterprise_device_mgr_ability.cpp`、`plugin_manager.cpp`、`query_policy/` | `docs/knowledge/architecture/ipc-and-funccode.md` |
| 新增或修改策略插件、SO 加载机制、插件类型体系（5 种继承模式）、新策略开发流程（Type 1-6）、通用检查清单 | `services/edm_plugin/src/`、`services/edm/src/plugin_manager.cpp`、`query_policy/` | `docs/knowledge/architecture/plugin-architecture.md` |
| 改 Addon / Proxy 层（新旧写法）、序列化器、RDB 存储格式与数据库表 | `interfaces/kits/`、`interfaces/inner_api/`、`services/edm/src/database/` | `docs/knowledge/architecture/addon-and-storage.md` |
| 改 BUILD.gn 构建配置（5 个文件、5 个 SO 目标、条件编译规则） | 5 个 `BUILD.gn`（见路由文档） | `docs/knowledge/architecture/build-gn-rules.md` |
| 改事件订阅 / 分发 / Adapter / Subscriber / 回调策略 / 服务重启恢复 / 线程锁模型 / 新增事件 | `services/edm/src/event_management/`、`services/edm/include/event_management/` | `docs/knowledge/architecture/event-management.md` |

### 域术语速查

| 术语 | 含义 | 深入文档 |
|------|------|---------|
| FuncCode | 32位接口码（SystemFlag+OperateType+PolicyCode） | `ipc-and-funccode.md` |
| PluginSingleton | 双重检查锁单例插件基类，自动注册 | `plugin-architecture.md` |
| persistParam_ | BasicBoolPlugin 自动设置的 persist 系统参数 | `plugin-architecture.md` |
| feature gate | CheckFeatureEnabled 三层接口码可用性判断 | `ipc-and-funccode.md` |
| BYOD | Bring Your Own Device，受管个人设备 admin 类型 | `ipc-and-funccode.md` |
| SO | 策略插件动态库（device_core/communication/sys_service/need_extra/watermark） | `plugin-architecture.md` |
| SubscriberType | 事件订阅者类型（SA_CORE/MDM_RELAY/POLICY_BOUND） | `event-management.md` |
| AddonMethodAdapter | NAPI 异步调用适配器框架（推荐新写法） | `addon-and-storage.md` |

### 路径路由（按目录）

> 按修改目录快速定位必读文档，与上方任务场景路由互补。

| 修改目录 | 必读文档 |
|---------|---------|
| `services/edm/src/query_policy/` | `ipc-and-funccode.md` |
| `services/edm/src/enterprise_device_mgr_stub.cpp`、`enterprise_device_mgr_ability.cpp` | `ipc-and-funccode.md` |
| `services/edm/src/event_management/`、`include/event_management/` | `event-management.md` |
| `services/edm_plugin/src/` | `plugin-architecture.md` |
| `interfaces/kits/` | `addon-and-storage.md` |
| `interfaces/inner_api/` | `addon-and-storage.md`、`ipc-and-funccode.md` |
| `services/edm/src/database/` | `addon-and-storage.md` |
| 5 个 `BUILD.gn` | `build-gn-rules.md` |

---

## 第四部分：约束与边界（Do not / Ask before）

> 以下为不可破坏的红线。触及任一情形前须在回复中声明，并在适用时请求人工确认。

### Do not（禁止）

| 红线 | 说明 | 典型违反 → 正确做法 | 涉及路径 |
|------|------|---------------------|---------|
| 不得未评审改公开 API | NAPI/Addon/inner_api 的方法签名、参数语义、错误码变更须先做兼容性评审，禁止破坏跨版本兼容 | 直接改 Addon 方法签名 → 先兼容性评审，保持签名/错误码跨版本兼容 | `interfaces/kits/`、`interfaces/inner_api/` |
| 不得无迁移改 RDB schema | 数据库表结构变更须附带迁移脚本，禁止改表破坏存量策略数据 | 直接给表加字段 → 编写迁移脚本，保留存量数据 | `services/edm/src/database/`（见 `addon-and-storage.md` 策略存储组） |
| 不得削弱权限/信任边界 | 禁止绕过权限校验、削弱 admin 授权校验或 `PermissionConfig` 映射一致性 | 跳过 admin 授权校验 → 保持 `PermissionConfig` 与 Plugin `permissionConfig_` 一致 | `services/edm/src/admin_manager.cpp`、`policy_query_config_table.cpp`（见 `ipc-and-funccode.md`） |
| 不得移除 DFX 埋点 | 禁止删除日志/HiSysEvent/HiAppEvent 等可观测性与故障归因埋点 | 删 HiSysEvent 调用 → 保留日志/事件埋点 | 全局 |
| 不得违反模块分层依赖方向 | 禁止 services 反向依赖 interfaces/kits、edm_plugin 不得跨层直接调用非 inner_api 接口；依赖方向：common ← inner_api ← services | services 引用 interfaces/kits → 遵循 common ← inner_api ← services 分层 | 全局分层 |

### Ask before（须确认/升级评审）

| 情形 | 动作 | 关联文档 |
|------|------|---------|
| 变更公开 API 错误码或 `ErrcodeType`（STRING↔NUMBER） | 须兼容性评审；新接口 `AddonMethodSign.errcodeType` 必须为 `NUMBER` | `addon-and-storage.md`（Addon 层 → AddonMethodAdapter） |
| 修改 IPC 协议（MessageParcel 字段顺序 / FuncCode 编码） | 须确认前后版本兼容，避免破坏存量 Stub/Proxy | `ipc-and-funccode.md`（IPC 路由流程） |
| 引入或升级第三方依赖 | 须确认许可证合规与部件准入 | — |

---

## 第五部分：编码防错规则（按需加载）

> 完整规则文档位于 `docs/knowledge/coding-rules/`，每条规则包含错误根因、来源提交、错误/正确写法和检查清单。

### 加载时机

| 场景 | 必读文档 |
|------|---------|
| 编写或修改 NAPI/Addon/JS 互操作代码 | `docs/knowledge/coding-rules/03-napi-and-js-interop.md` |
| 编写或修改 IPC/MessageParcel 读写代码 | `docs/knowledge/coding-rules/04-ipc-and-parcel.md` |
| 新增策略（Plugin + Query）或修改权限配置 | `docs/knowledge/coding-rules/05-policy-and-permission-config.md` |
| 编写或修改 cJSON/JSON 序列化反序列化代码 | `docs/knowledge/coding-rules/06-data-parsing-and-validation.md` |
| 编写或修改涉及线程/锁/并发的代码 | `docs/knowledge/coding-rules/02-concurrency-and-threading.md` |
| 编写或修改涉及内存分配/指针的代码 | `docs/knowledge/coding-rules/01-memory-and-pointer-safety.md` |
| 新增或修改错误码 | `docs/knowledge/coding-rules/07-error-code-conventions.md` |
| 代码检视（通用） | `docs/knowledge/coding-rules/08-return-value-checking.md` |

### 高频错误 Top 5（代码检视重点）

| 排名 | 错误模式 | 检查方法 |
|------|---------|---------|
| 1 | 返回值未校验（napi/系统调用/文件操作） | 搜索 `napi_`、`LoadFromFile`、`->Get`/`->Set` 调用，确认返回值已校验 |
| 2 | 错误码类型不一致（STRING vs NUMBER） | 新接口 `AddonMethodSign.errcodeType` 必须为 `NUMBER` |
| 3 | 权限配置错误（策略码-权限映射） | Query 的 `GetPermission` 返回值须与 Plugin 的 `permissionConfig_` 一致 |
| 4 | 字段缺失/null 时强制要求导致失败 | cJSON 新增字段须选填，缺失时用默认值 |
| 5 | detached 线程捕获 this / 锁内初始化 | 检查 `std::thread(...).detach()` 和锁内 `GetInstance()` 调用 |

---

## 第六部分：验证流程

> 完整编译与测试验证流程见 `docs/knowledge/test-verify/ut-verification-guide.md`。
> 以下为快速参考。验证流程为四步顺序：**编译源码 → 推送 .so → 编译测试 → 执行 UT**。

### 6.1 快速命令

| 步骤 | 命令 | 成功标志 | 超时 |
|------|------|---------|------|
| 编译源码 | `./build.sh --product-name rk3568 --ccache --build-target enterprise_device_management` | `=====build  successful=====` | 30分钟 |
| 推送.so | `python3 base/customization/enterprise_device_management/docs/knowledge/test-verify/scripts/push_component_so.py <源码根目录> rk3568 enterprise_device_management` | `Summary: N/N succeeded, 0 failed` | 5分钟 |
| 重启设备 | `hdc shell reboot`（等待上线后再等60秒） | `hdc list targets` 显示设备 | 3分钟 |
| 编译测试 | `./build.sh --product-name rk3568 --ccache --build-target enterprise_device_management_test` | `=====build  successful=====` | 30分钟 |
| 执行UT | `bash test/testfwk/developer_test/start.sh run -t UT -tp enterprise_device_management` | `Test Summary` 行无 failed | 10分钟 |

> **跳步规则**：只改测试代码 → 跳到编译测试；测试已编译 → 跳到执行UT；源码未变 → 跳过编译源码。
> 每步依赖前一步成功，失败则停止。
> 以上命令需在 OpenHarmony 源码根目录执行。

### 6.2 执行 UT 前置检查

执行测试前必须确认 `test/testfwk/developer_test/config/user_config.xml` 的 `test_cases/dir` 为绝对路径：

```bash
python3 base/customization/enterprise_device_management/docs/knowledge/test-verify/scripts/fix_test_config.py <源码根目录> rk3568
```

路径为空或相对路径会导致 `tests is not exist` 报错。

### 6.3 完成定义（Done）

代码改动完成须满足以下全部条件：

- [ ] 所有修改的 BUILD.gn 文件已更新（见 `docs/knowledge/architecture/build-gn-rules.md`，5个文件）
- [ ] 源码编译通过（`=====build  successful=====`，无新增 error）
- [ ] 测试编译通过
- [ ] 相关 UT 用例通过（`Test Summary` 中 failed=0）
- [ ] 无编译告警新增（"can not find depended library"属正常告警）

### 6.4 无法运行验证时

当无法执行编译或测试时（如环境不可用），必须：
1. 在回复中明确说明"未执行编译/测试验证，请人工确认"
2. 列出预计影响的文件范围
3. 说明无法运行的原因（设备未连接/环境缺失等）

### 6.5 常见坑

| 问题 | 解决 |
|------|------|
| `tests is not exist` | `user_config.xml` 的 `test_cases/dir` 须为绝对路径，执行前置检查 |
| 编译超时 | 编译至少30分钟超时，测试执行至少10分钟超时 |
| 编译告警误判 | "can not find depended library"是正常告警，不是错误 |
| 设备未连接 | `hdc list targets` 确认设备在线，`user_config.xml` 的 SN 匹配 |
| 部件名错误 | `--build-target` 用 part name（`enterprise_device_management`），非二进制名 |

### 6.6 验证通过后报告

验证通过后，回复中应包含：

1. **Test Summary 行**：展示汇总数据（`modules: N, total: N, passed: N, failed: 0`）
2. **失败用例**（如有）：列出 `[ FAILED ]` 的测试名、源文件路径、行号、期望值与实际值
3. **报告路径**：告知 HTML 报告位置 `test/testfwk/developer_test/reports/<时间戳>/summary_report.html`

全部通过时确认 `failed=0` 即可，不需要逐条列出通过的用例。
