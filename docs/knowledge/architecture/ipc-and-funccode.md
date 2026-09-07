# FuncCode 编码与 IPC 路由

> FuncCode 编码机制与 IPC 路由流程的架构知识。日常工作流以 AGENTS.md 路由为准；需要深入细节时按任务场景查阅本文档对应章节。

## FuncCode 编码机制

### 位布局

32位FuncCode编码结构：
- **Bit 20**: SystemFlag（0=服务级，1=策略级）
- **Bit 16-19**: OperateType（0=GET，1=SET，2=REMOVE）
- **Bit 0-15**: PolicyCode（EdmInterfaceCode枚举值，范围1-3000）

### 核心宏定义

**代码路径**: `common/native/include/func_code.h`

| 宏 | 用途 |
|---|------|
| `CREATE_FUNC_CODE(FLAG, OPERATE_TYPE, POLICY)` | 组合FuncCode |
| `POLICY_FUNC_CODE(OPERATE_TYPE, POLICY)` | 策略级FuncCode快捷宏 |
| `SERVICE_FLAG(CODE)` | 判断是否服务级接口 |
| `POLICY_FLAG(CODE)` | 判断是否策略级接口 |
| `FUNC_TO_OPERATE(CODE)` | 提取操作类型 |
| `FUNC_TO_POLICY(CODE)` | 提取策略码 |

### 编码示例

| 操作 | 接口码 | OperateType | FuncCode |
|------|--------|-------------|----------|
| 设置禁止P2P | DISALLOWED_P2P=1148 | SET=1 | 0x00110474 |
| 查询禁止P2P | DISALLOWED_P2P=1148 | GET=0 | 0x00100474 |
| 添加管理员 | ADD_DEVICE_ADMIN=1 | - | 0x00000001 |

### 操作类型映射

| FuncOperateType | 插件执行方法 | 说明 |
|-----------------|-------------|------|
| GET (0) | IPlugin::OnGetPolicy() | 查询策略值 |
| SET (1) | IPluginExecuteStrategy::OnSetExecute() | 设置策略值 |
| REMOVE (2) | IPluginExecuteStrategy::OnAdminRemoveExecute() | 移除策略 |

---

## IPC 路由流程

### 整体架构

```
客户端 (NAPI) → IPC传输层 → Stub层 → Ability层 → PluginManager层 → Plugin层
```

### Stub 层分发

**代码路径**: `services/edm/src/enterprise_device_mgr_stub.cpp`

**路由逻辑**:
1. SERVICE_FLAG(code) → OnRemoteRequestIdl()（系统级接口，需特殊权限）
2. POLICY_FLAG(code) → 策略接口路由
   - FUNC_TO_OPERATE == GET → GetDevicePolicyInner()
   - FUNC_TO_OPERATE == SET/REMOVE → HandleDevicePolicyInner()

**系统级接口白名单**（14个）: ADD_DEVICE_ADMIN, REMOVE_DEVICE_ADMIN, GET_ENABLED_ADMIN, AUTHORIZE_ADMIN等

### Ability 层路由

**代码路径**: `services/edm/src/enterprise_device_mgr_ability.cpp`

| 方法 | 职责 | 调用链 |
|------|------|--------|
| HandleDevicePolicy | 设置策略 | 权限校验 → PluginManager::UpdateDevicePolicy → 安全审计 |
| GetDevicePolicy | 查询策略 | PluginPolicyReader::GetPolicyByCode → 回退到PluginManager::GetPolicy |

### PluginManager 层

**代码路径**: `services/edm/src/plugin_manager.cpp`

| 方法 | 职责 |
|------|------|
| GetPluginByFuncCode | 按需加载插件并返回实例 |
| UpdateDevicePolicy | 加锁 → 获取插件 → 执行策略 → 持久化 → 回调 |
| LoadPlugin | dlopen加载动态库，注册到pluginsCode_映射表 |

### PluginPolicyReader 查询路由

**代码路径**: `services/edm/src/query_policy/plugin_policy_reader.cpp`

**架构**: factory+config_table模式替代原来的13层链式switch-case分发

**查询流程**:
1. `GetPolicyByCodeInner` 先调用 `PolicyQueryFactory::CheckFeatureEnabled(code)` 检查feature gate
2. 检查通过后，调用 `PolicyQueryFactory::CreateQuery(code)` 创建query对象
3. 若query对象为nullptr（接口码完全未知），返回 `ERR_CANNOT_FIND_QUERY_FAILED`
4. 调用query对象的 `GetPolicy` 完成策略查询

**feature gate三层逻辑**（`CheckFeatureEnabled`）:

| 场景 | 判断条件 | 返回值 |
|------|---------|--------|
| feature已开启，策略可用 | 接口码在config table中 | `ERR_OK` |
| feature未开启，策略不可用 | 接口码不在config table中，但在known集合中 | `INTERFACE_UNSUPPORTED` |
| 接口码完全未知 | 接口码不在config table中，也不在known集合中 | `ERR_CANNOT_FIND_QUERY_FAILED` |

### PolicyQueryFactory 工厂模式

**代码路径**: `services/edm/src/query_policy/policy_query_factory.cpp`

**核心类关系**:
```
PluginPolicyReader → PolicyQueryFactory::CreateQuery(code)
                        ├── config table中dataType非CUSTOM → GenericPolicyQuery<DataType>
                        │       ├── BoolPolicyQuery (BOOL)
                        │       ├── ArrayStringPolicyQuery (ARRAY_STRING)
                        │       ├── IntPolicyQuery (INT)
                        │       └── StringPolicyQuery (STRING)
                        └── config table中dataType为CUSTOM → 保留的独立query类
                                ├── PasswordPolicyQuery, FingerprintAuthQuery (USERIAM)
                                ├── ClipboardPolicyQuery (PASTEBOARD)
                                ├── LocationPolicyQuery (LOCATION)
                                ├── TelephonyCallPolicyQuery (TELEPHONY)
                                ├── InstalledBundleInfoListQuery, GetWatermarkImageAppsQuery 等
```

**CreateQuery流程**:
1. 查询缓存 `queryCache_`（读写锁保护），命中则直接返回
2. 从 `PolicyQueryConfigTable::GetConfigTable()` 查找配置
3. dataType为CUSTOM → `CreateCustomQuery`（链式尝试4个分组switch-case）
4. dataType为BOOL/ARRAY_STRING/INT/STRING → `CreateGenericQuery`（根据dataType创建对应模板实例）
5. 创建成功后写入缓存

**CUSTOM类型保留的query类**: 这些query类因QueryPolicy逻辑无法通用化而保留独立实现，共约20个。

### PolicyQueryConfig 配置数据结构

**代码路径**: `services/edm/include/query_policy/policy_query_config.h`, `services/edm/src/query_policy/policy_query_config.cpp`

**PermissionConfig** — 权限配置，4种工厂方法:

| 工厂方法 | 适用场景 | 示例 |
|---------|---------|------|
| `RestrictionPermission(hasByod)` | 大多数bool禁用策略 | DISALLOWED_P2P, DISABLE_CAMERA |
| `SuperAdminOnlyPermission()` | 仅超级管理员权限的策略 | DISALLOW_CORE_DUMP |
| `SpecificPermission(permission)` | 固定权限的策略 | DISABLE_SET_BIOMETRICS_AND_SCREENLOCK → SET_USER_RESTRICTION |
| `TagPermission(tag, default, byod)` | 需要根据permissionTag返回不同权限的策略 | DISALLOWED_P2P(v11) → RESTRICT_POLICY |

**PermissionConfig::GetPermission 分发逻辑**:
1. `specificPermission`非空 → 直接返回（最高优先级）
2. `hasTagPermission`且SUPER_DEVICE_ADMIN且permissionTag非空 → 返回`tagPermission`
3. BYOD_DEVICE_ADMIN → 返回`byodAdminPermission`（无则回退到`superAdminPermission`）
4. 默认 → 返回`superAdminPermission`

**PolicyQueryConfig** — 单个策略完整配置:

| 字段 | 类型 | 说明 |
|------|------|------|
| `policyName` | string | 策略名称常量（如 `POLICY_DISALLOWED_P2P`） |
| `dataType` | PolicyDataType枚举 | BOOL/ARRAY_STRING/INT/STRING/CUSTOM |
| `permissionConfig` | PermissionConfig | 权限配置 |
| `isPolicySaved` | bool | 是否需要持久化到数据库 |
| `apiType` | IPlugin::ApiType | API类型（PUBLIC/INNER/SYSTEM） |
| `customHandler` | function | CUSTOM类型的自定义查询回调（可选） |

### PolicyQueryConfigTable 配置表

**代码路径**: `services/edm/src/query_policy/policy_query_config_table.cpp`

**结构**: `unordered_map<uint32_t, PolicyQueryConfig>`，key为EdmInterfaceCode值

**初始化**: 24个Init函数按策略类型分组初始化，每个函数内部使用`#ifdef`条件编译控制feature gate策略的条目是否存在。

**分组Init函数**:

| Init函数 | 覆盖策略类型 | 条件编译 |
|---------|-------------|---------|
| InitBoolCameraAndBluetoothConfigs | 摄像头、蓝牙、HDC等 | BLUETOOTH_EDM_ENABLE, CAMERA_FRAMEWORK_EDM_ENABLE, AUDIO_FRAMEWORK_EDM_ENABLE |
| InitBoolUsbAndMtpConfigs | USB、MTP等 | USB_SERVICE_EDM_ENABLE |
| InitBoolNetworkConfigs | VPN、飞行模式等 | NET_MANAGER_BASE_EDM_ENABLE, NETMANAGER_EXT_EDM_ENABLE |
| InitArrayStringBundleConfigs | 安装包列表等 | ABILITY_RUNTIME_EDM_ENABLE |
| InitCustomSecurityConfigs | 密码、指纹、水印等 | USERIAM_EDM_ENABLE |
| InitCustomAppPolicyConfigs | 剪贴板、位置等 | PASTEBOARD_EDM_ENABLE, LOCATION_EDM_ENABLE, TELEPHONY_EDM_ENABLE |

**GetKnownPolicyCodes**: 返回所有已知策略码集合（不受`#ifdef`过滤）。用于`CheckFeatureEnabled`区分"feature未开启"和"接口码未知"两种场景。新增策略时必须同步更新此集合。

### GenericPolicyQuery 通用查询模板

**代码路径**: `services/edm/include/query_policy/generic_policy_query.h`, `services/edm/src/query_policy/generic_policy_query.cpp`

**模板特化**: `GenericPolicyQuery<PolicyDataType>` 根据DataType特化QueryPolicy实现:

| 类型别名 | 模板参数 | QueryPolicy实现 |
|---------|---------|----------------|
| `BoolPolicyQuery` | `PolicyDataType::BOOL` | `GetBoolPolicy(policyData, reply)` |
| `ArrayStringPolicyQuery` | `PolicyDataType::ARRAY_STRING` | `GetArrayStringPolicy(policyData, reply)` |
| `IntPolicyQuery` | `PolicyDataType::INT` | `GetIntPolicy(policyData, reply)` |
| `StringPolicyQuery` | `PolicyDataType::STRING` | `reply.WriteInt32(ERR_OK); reply.WriteString(policyData)` |

**通用方法**（所有特化共享）: `GetPolicyName`、`GetPermission`、`IsPolicySaved`、`GetApiType` — 直接从`config_`字段返回，无需子类覆写
