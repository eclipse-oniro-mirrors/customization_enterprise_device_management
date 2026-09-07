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

## 第三部分：FuncCode 编码机制

### 3.1 位布局

32位FuncCode编码结构：
- **Bit 20**: SystemFlag（0=服务级，1=策略级）
- **Bit 16-19**: OperateType（0=GET，1=SET，2=REMOVE）
- **Bit 0-15**: PolicyCode（EdmInterfaceCode枚举值，范围1-3000）

### 3.2 核心宏定义

**代码路径**: `common/native/include/func_code.h`

| 宏 | 用途 |
|---|------|
| `CREATE_FUNC_CODE(FLAG, OPERATE_TYPE, POLICY)` | 组合FuncCode |
| `POLICY_FUNC_CODE(OPERATE_TYPE, POLICY)` | 策略级FuncCode快捷宏 |
| `SERVICE_FLAG(CODE)` | 判断是否服务级接口 |
| `POLICY_FLAG(CODE)` | 判断是否策略级接口 |
| `FUNC_TO_OPERATE(CODE)` | 提取操作类型 |
| `FUNC_TO_POLICY(CODE)` | 提取策略码 |

### 3.3 编码示例

| 操作 | 接口码 | OperateType | FuncCode |
|------|--------|-------------|----------|
| 设置禁止P2P | DISALLOWED_P2P=1148 | SET=1 | 0x00110474 |
| 查询禁止P2P | DISALLOWED_P2P=1148 | GET=0 | 0x00100474 |
| 添加管理员 | ADD_DEVICE_ADMIN=1 | - | 0x00000001 |

### 3.4 操作类型映射

| FuncOperateType | 插件执行方法 | 说明 |
|-----------------|-------------|------|
| GET (0) | IPlugin::OnGetPolicy() | 查询策略值 |
| SET (1) | IPluginExecuteStrategy::OnSetExecute() | 设置策略值 |
| REMOVE (2) | IPluginExecuteStrategy::OnAdminRemoveExecute() | 移除策略 |

---

## 第四部分：IPC 路由流程

### 4.1 整体架构

```
客户端 (NAPI) → IPC传输层 → Stub层 → Ability层 → PluginManager层 → Plugin层
```

### 4.2 Stub 层分发

**代码路径**: `services/edm/src/enterprise_device_mgr_stub.cpp`

**路由逻辑**:
1. SERVICE_FLAG(code) → OnRemoteRequestIdl()（系统级接口，需特殊权限）
2. POLICY_FLAG(code) → 策略接口路由
   - FUNC_TO_OPERATE == GET → GetDevicePolicyInner()
   - FUNC_TO_OPERATE == SET/REMOVE → HandleDevicePolicyInner()

**系统级接口白名单**（14个）: ADD_DEVICE_ADMIN, REMOVE_DEVICE_ADMIN, GET_ENABLED_ADMIN, AUTHORIZE_ADMIN等

### 4.3 Ability 层路由

**代码路径**: `services/edm/src/enterprise_device_mgr_ability.cpp`

| 方法 | 职责 | 调用链 |
|------|------|--------|
| HandleDevicePolicy | 设置策略 | 权限校验 → PluginManager::UpdateDevicePolicy → 安全审计 |
| GetDevicePolicy | 查询策略 | PluginPolicyReader::GetPolicyByCode → 回退到PluginManager::GetPolicy |

### 4.4 PluginManager 层

**代码路径**: `services/edm/src/plugin_manager.cpp`

| 方法 | 职责 |
|------|------|
| GetPluginByFuncCode | 按需加载插件并返回实例 |
| UpdateDevicePolicy | 加锁 → 获取插件 → 执行策略 → 持久化 → 回调 |
| LoadPlugin | dlopen加载动态库，注册到pluginsCode_映射表 |

### 4.5 PluginPolicyReader 查询路由

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

### 4.6 PolicyQueryFactory 工厂模式

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

### 4.7 PolicyQueryConfig 配置数据结构

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

### 4.8 PolicyQueryConfigTable 配置表

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

### 4.9 GenericPolicyQuery 通用查询模板

**代码路径**: `services/edm/include/query_policy/generic_policy_query.h`, `services/edm/src/query_policy/generic_policy_query.cpp`

**模板特化**: `GenericPolicyQuery<PolicyDataType>` 根据DataType特化QueryPolicy实现:

| 类型别名 | 模板参数 | QueryPolicy实现 |
|---------|---------|----------------|
| `BoolPolicyQuery` | `PolicyDataType::BOOL` | `GetBoolPolicy(policyData, reply)` |
| `ArrayStringPolicyQuery` | `PolicyDataType::ARRAY_STRING` | `GetArrayStringPolicy(policyData, reply)` |
| `IntPolicyQuery` | `PolicyDataType::INT` | `GetIntPolicy(policyData, reply)` |
| `StringPolicyQuery` | `PolicyDataType::STRING` | `reply.WriteInt32(ERR_OK); reply.WriteString(policyData)` |

**通用方法**（所有特化共享）: `GetPolicyName`、`GetPermission`、`IsPolicySaved`、`GetApiType` — 直接从`config_`字段返回，无需子类覆写

---

## 第五部分：插件分类和 SO 加载机制

### 5.1 插件 SO 分类

**代码路径**: `services/edm/src/plugin_manager.cpp`

| 分类 | SO 文件名 | 插件数量 | 典型策略 |
|------|-----------|----------|----------|
| 设备核心 | device_core_plugin.so | ~25 | DISABLE_CAMERA, LOCK_SCREEN |
| 通信 | communication_plugin.so | ~35 | DISALLOWED_P2P, DISABLE_WIFI |
| 系统服务 | sys_service_plugin.so | ~40 | PASSWORD_POLICY, CLIPBOARD_POLICY |
| 额外处理 | need_extra_plugin.so | ~20 | GET_DEVICE_INFO, INSTALL |
| 水印 | watermark_plugin.so | ~5 | WATERMARK_IMAGE |

### 5.2 按需加载机制

**流程**: GetPluginByFuncCode → LoadPluginByFuncCode → GetSoNameByCode → dlopen → 注册

**关键方法**:
- `GetSoNameByCode`: 根据接口码查找对应SO文件名
- `LoadPlugin`: dlopen加载，获取CreatePluginInstance符号，创建插件实例
- `LoadExtraPlugin`: 动态扫描插件目录，加载未注册的插件

### 5.3 自动卸载

- **超时**: 3分钟无调用
- **触发**: 定时器检查 + 引用计数
- **流程**: 检查引用计数 → 从映射表移除 → dlclose释放

### 5.4 注册模式

| 模式 | 特点 | 适用场景 |
|------|------|---------|
| PluginSingleton自动注册 | 双重检查锁单例，.cpp全局变量自动注册 | 简单策略，使用模板类 |
| 直接继承IPlugin | 构造函数手动设置属性，手动注册 | 复杂策略，不受模板限制 |

---

## 第六部分：插件类型体系

### 6.1 5种继承模式

| 模式 | 继承关系 | 数据类型 | 数量 | 典型场景 |
|------|---------|---------|------|----------|
| A. BasicBoolPlugin | PluginSingleton<T,bool> + BasicBoolPlugin | bool | 37 | 禁用摄像头、禁止P2P |
| B. BasicArrayStringPlugin | PluginSingleton<T,vector<string>> + BasicArrayStringPlugin | vector<string> | 12 | 允许安装包列表 |
| C. BasicArrayIntPlugin | PluginSingleton<T,vector<int>> + BasicArrayIntPlugin | vector<int32_t> | 1 | 隐藏设置菜单 |
| D. PluginSingleton仅继承 | PluginSingleton<T,DT> | 多种 | 40 | WiFi开关、设备信息 |
| E. 直接IPlugin | IPlugin | 自定义复杂类型 | 26 | 水印图片、密码策略 |

### 6.2 各模式关键方法

**代码路径参考**:
- BasicBoolPlugin: `interfaces/inner_api/plugin_kits/include/basic_bool_plugin.h`
- BasicArrayStringPlugin: `interfaces/inner_api/plugin_kits/include/basic_array_string_plugin.h`
- PluginSingleton: `interfaces/inner_api/plugin_kits/include/plugin_singleton.h`

| 模式 | 必须实现的方法 |
|------|---------------|
| A. BasicBoolPlugin | SetOtherModulePolicy(bool, userId), RemoveOtherModulePolicy(userId) |
| B. BasicArrayStringPlugin | SetOtherModulePolicy(vector<string>, userId, mergePolicy), RemoveOtherModulePolicy |
| D. PluginSingleton | 在InitPlugin中注册监听器 |
| E. IPlugin | OnHandlePolicy, OnGetPolicy, OnAdminRemove等纯虚函数 |

### 6.3 回调函数类型

**代码路径**: `interfaces/inner_api/plugin_kits/include/iplugin_template.h`

| 回调类型 | 参数 | 使用场景 |
|---------|------|---------|
| Supplier | 无 | 简单操作 |
| Function | DT &data | 只需新策略数据 |
| BiFunction | data, currentData, mergeData, userId | 需要比较新旧数据 |
| ReplyFunction | data, reply | 直接写入IPC回复 |
| BoolConsumer | isGlobalChanged | 策略完成后回调 |
| BiAdminFunction | adminName, data, mergeData, userId | 管理员移除时 |

### 6.4 序列化器

**代码路径**: `interfaces/inner_api/plugin_kits/include/utils/`

| 序列化器 | 数据类型 | 文件 |
|---------|---------|------|
| BoolSerializer | bool | bool_serializer.h |
| StringSerializer | string | string_serializer.h |
| IntSerializer | int32_t | int_serializer.h |
| LongSerializer | int64_t | long_serializer.h |
| ArrayStringSerializer | vector<string> | array_string_serializer.h |
| ArrayIntSerializer | vector<int32_t> | array_int_serializer.h |
| MapStringSerializer | map<string,string> | map_string_serializer.h |
| BitSerializer | uint32_t（位标志） | bit_serializer.h |

**自定义序列化器路径**: `services/edm_plugin/include/utils/`（20+个）

---

## 第七部分：Addon层和Proxy层实现

Addon层和Proxy层是JS层调用EDM服务的入口，位于Plugin和Query之上。有新旧两种写法，**推荐优先使用新写法**（基于AddonMethodAdapter框架）。

### 7.1 新写法（推荐）：基于AddonMethodAdapter框架

**核心文件**:
- 框架定义: `interfaces/kits/common/include/napi_edm_adapter.h`
- 框架实现: `interfaces/kits/common/src/napi_edm_adapter.cpp`
- 参考实现: `interfaces/kits/device_control/src/device_control_addon.cpp`（简单场景）
- 参考实现: `interfaces/kits/security_manager/src/security_manager_addon.cpp`（lambda场景）
- Proxy参考: `interfaces/inner_api/device_control/src/device_control_proxy.cpp`

**核心机制**:
- `EdmAddonCommonType` 枚举：定义参数类型（ELEMENT, BOOLEAN, STRING, INT32, CUSTOM等）
- `AddonMethodSign` 结构体：配置方法签名（参数类型列表、methodAttribute、policyCode等）
- `AddonMethodAdapter`：异步调用适配器，自动处理参数解析和异步工作队列
- `JsObjectToData`：同步调用辅助函数，解析参数到MessageParcel
- `CUSTOM`类型 + `argsConvert`：支持自定义lambda表达式处理复杂对象

**Addon层骨架代码**（异步模式）:
```cpp
// xxx_addon.cpp
#include "napi_edm_adapter.h"

// 1. 配置方法签名（可提取为Common函数）
void XxxAddon::SetPolicyCommon(AddonMethodSign &addonMethodSign, int policyCode)
{
    addonMethodSign.name = "setXxxPolicy";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.policyCode = policyCode;
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_11;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;  // 新接口使用NUMBER类型
}

// 2. NAPI入口函数
napi_value XxxAddon::SetXxxPolicy(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    SetPolicyCommon(addonMethodSign, EdmInterfaceCode::XXX_NEW_POLICY);
    // 调用适配器，传入异步执行函数和完成回调
    return AddonMethodAdapter(env, info, addonMethodSign, NativeSetXxxPolicy, NativeVoidCallbackComplete);
}

// 3. 异步执行函数（在线程池中执行）
void XxxAddon::NativeSetXxxPolicy(napi_env env, void *data)
{
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    asyncCallbackInfo->ret = XxxProxy::GetXxxProxy()->SetXxxPolicy(asyncCallbackInfo->data);
}
```

**Addon层骨架代码**（同步模式）:
```cpp
napi_value XxxAddon::GetXxxPolicy(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "getXxxPolicy";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};  // admin可为null
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;  // 新接口使用NUMBER类型
    
    AdapterAddonData adapterAddonData{};
    // 同步解析参数到MessageParcel
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    
    bool result = false;
    int32_t ret = XxxProxy::GetXxxProxy()->GetXxxPolicy(adapterAddonData.data, result);
    if (FAILED(ret)) {
        napi_throw(env, CreateErrorByType(env, ret, "", addonMethodSign.errcodeType));
        return nullptr;
    }
    napi_value jsResult = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &jsResult));
    return jsResult;
}
```

**Addon层骨架代码**（自定义Lambda处理复杂对象）:
```cpp
napi_value XxxAddon::SetComplexPolicy(napi_env env, napi_callback_info info)
{
    // 定义自定义lambda转换器
    auto convertComplexData = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) -> ErrCode {
            // 1. 从JS对象中提取字段
            XxxType policy;
            if (!JsObjectToString(env, argv, "field1", false, policy.field1)) {
                return EdmReturnErrCode::PARAM_ERROR;
            }
            if (!JsObjectToInt(env, argv, "field2", false, policy.field2)) {
                return EdmReturnErrCode::PARAM_ERROR;
            }
            // 2. 数据验证
            if (policy.field2 < 0 || policy.field2 > 100) {
                return EdmReturnErrCode::PARAM_ERROR;
            }
            // 3. 写入MessageParcel
            data.WriteString(policy.field1);
            data.WriteInt32(policy.field2);
            return ERR_OK;
    };
    
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "setComplexPolicy";
    // 第二个参数使用CUSTOM类型
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    // 绑定自定义lambda（第一个参数nullptr表示使用内置转换）
    addonMethodSign.argsConvert = {nullptr, convertComplexData};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;  // 新接口使用NUMBER类型
    
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) { return nullptr; }
    
    int32_t ret = XxxProxy::GetXxxProxy()->SetComplexPolicy(adapterAddonData.data);
    if (FAILED(ret)) { napi_throw(env, CreateErrorByType(env, ret, "", addonMethodSign.errcodeType)); }
    return nullptr;
}
```

**Proxy层骨架代码**（新写法）:
```cpp
// xxx_proxy.cpp
#include "enterprise_device_mgr_proxy.h"
#include "func_code.h"

int32_t XxxProxy::SetXxxPolicy(MessageParcel &data)
{
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::XXX_NEW_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t XxxProxy::GetXxxPolicy(MessageParcel &data, bool &result)
{
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::XXX_NEW_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    reply.ReadInt32(ret);
    if (ret != ERR_OK) {
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}
```

### 7.2 旧写法（补充）：直接解析参数

**参考实现**: `interfaces/kits/restrictions/src/restrictions_addon.cpp`（部分方法）
**Proxy参考**: `interfaces/inner_api/restrictions/src/restrictions_proxy.cpp`

旧写法特征：手动调用`napi_get_cb_info`、逐个校验参数类型、手动构建MessageParcel。

**Addon层骨架代码**（旧写法）:
```cpp
napi_value XxxAddon::SetXxxPolicy(napi_env env, napi_callback_info info)
{
    // 1. 手动获取参数
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    
    // 2. 手动校验参数
    ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, argc >= ARGS_SIZE_TWO, "parameter count error", ErrcodeType::NUMBER);
    ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, MatchValueType(env, argv[0], napi_object), "parameter admin error", ErrcodeType::NUMBER);
    ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, MatchValueType(env, argv[1], napi_boolean), "parameter value error", ErrcodeType::NUMBER);
    
    // 3. 手动解析参数
    AppExecFwk::ElementName elementName;
    ParseElementName(env, elementName, argv[0]);
    bool value = false;
    ParseBool(env, value, argv[1]);
    
    // 4. 调用Proxy
    ErrCode ret = XxxProxy::GetXxxProxy()->SetXxxPolicy(elementName, value);
    if (FAILED(ret)) { napi_throw(env, CreateErrorByType(env, ret, "", ErrcodeType::NUMBER)); }
    return nullptr;
}
```

**Proxy层骨架代码**（旧写法）:
```cpp
int32_t XxxProxy::SetXxxPolicy(const AppExecFwk::ElementName &admin, bool value)
{
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::XXX_NEW_POLICY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteBool(value);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
```

### 7.3 新旧写法对比

| 维度 | 新写法（推荐） | 旧写法 |
|------|--------------|--------|
| **参数配置** | 声明式：`argsType = {ELEMENT, BOOLEAN}` | 命令式：逐个`MatchValueType`+`ParseXxx` |
| **代码量** | 5-10行配置 + 1行调用 | 20-40行手动解析 |
| **异步支持** | `AddonMethodAdapter`一行搞定 | 手动创建AsyncCallbackInfo+HandleAsyncWork |
| **复杂对象** | `CUSTOM`类型+lambda转换器 | 手动遍历JS对象字段 |
| **错误处理** | 框架自动生成错误信息 | 手动编写每个错误字符串 |
| **Proxy签名** | `Method(MessageParcel &data)` | `Method(ElementName, bool, ...)` |
| **适用场景** | 标准CRUD操作、参数类型明确 | 特殊业务逻辑、需要精细控制 |

---

## 第八部分：策略存储方式和格式

### 7.1 存储介质

- **持久化**: RDB关系型数据库
- **内存缓存**: UserPolicyManager管理
- **管理类**: DevicePoliciesStorageRdb, AdminPoliciesStorageRdb

**代码路径**: `services/edm/src/database/`

### 7.2 数据库表

| 表名 | 字段 |
|------|------|
| device_admin_policies | userId, adminName, policyName, policyValue |
| device_combined_policies | userId, policyName, policyValue |
| admin_policies | userId, packageName, entInfo, managedEvents |

### 7.3 内存数据结构

```cpp
PolicyItemsMap = unordered_map<string, string>  // 策略名称 -> JSON字符串
AdminValueItemsMap = unordered_map<string, string>  // 管理员 -> 策略值
```

### 7.4 序列化格式

- **格式**: JSON字符串（cJSON库）
- **IPolicySerializer接口**: Deserialize, Serialize, GetPolicy, WritePolicy, MergePolicy

---

## 第九部分：BUILD.gn构建配置规则

### 9.1 添加新文件规则

添加一个新策略（Plugin + Query）需要更新以下5个BUILD.gn文件中的**指定目标**：

| # | BUILD.gn文件 | 目标名 | 添加内容 | 路径格式 |
|---|-------------|--------|---------|---------|
| 1 | `services/edm/BUILD.gn` | `edmservice` | Query源文件 | `"./src/query_policy/xxx_query.cpp"` |
| 2 | `services/edm_plugin/BUILD.gn` | 5个SO目标之一（见下表） | Plugin源文件 | `"./src/category/xxx_plugin.cpp"` |
| 3 | `test/unittest/services/edm/BUILD.gn` | `edmservice_static` | Query源文件 | `"../../../../services/edm/src/query_policy/xxx_query.cpp"` |
| 4 | `test/unittest/services/edm_plugin/BUILD.gn` | `edm_all_plugin_static` | Plugin源文件 | `"../../../../services/edm_plugin/src/category/xxx_plugin.cpp"` |
| 5 | `test/fuzztest/enterprisedevicemgrstubmock_fuzzer/BUILD.gn` | `edmservice_fuzz_static` | Query + Plugin源文件 | `"../../../services/edm/src/query_policy/xxx_query.cpp"` 和 `"../../../services/edm_plugin/src/category/xxx_plugin.cpp"` |

### 9.2 edm_plugin的5个SO目标

`services/edm_plugin/BUILD.gn` 包含5个独立的共享库目标，新插件必须添加到**功能匹配的那一个**：

| 目标名 | SO文件名 | 适用策略类型 |
|--------|---------|-------------|
| `device_core_plugin` | libdevice_core_plugin.z.so | 设备核心策略（摄像头、屏幕、管理员、蓝牙等） |
| `communication_plugin` | libcommunication_plugin.z.so | 通信策略（WiFi、电话、USB、网络、VPN等） |
| `sys_service_plugin` | libsys_service_plugin.z.so | 系统服务策略（剪贴板、密码、位置、权限等） |
| `need_extra_plugin` | libneed_extra_plugin.z.so | 额外处理策略（设备信息、OTA、壁纸等） |
| `watermark_plugin` | libwatermark_plugin.z.so | 水印策略 |

### 9.3 条件编译

如果用户明确声明新策略依赖某个条件编译标志（如 `wifi_edm_enable`、`bluetooth_edm_enable` 等），则在以上5个BUILD.gn中都需要用对应的 `if (xxx_edm_enable)` 块包裹。未声明条件编译的策略直接添加在 `enterprise_device_management_support_all` 无条件块中。

---

## 第十部分：新策略开发流程

### 10.1 策略分类决策树

| 判断条件 | 类型 | 特征 | 数量 |
|---------|------|------|------|
| 仅设置persist系统参数？ | Type 1 | 最简单，bool类型，设置persist参数 | ~22 |
| 需要调用外部系统API？ | Type 2 | bool类型，persist + 外部API调用 | ~14 |
| 即时操作，不需要持久化？ | Type 3 | int32_t/string类型，needSave=false | ~5 |
| 数组/列表类型策略？ | Type 4 | vector<string>，maxListSize限制，可能冲突检查 | ~7 |
| 需要服务重启后恢复策略？ | Type 5 | 在Type 1/2基础上增加OnOtherServiceStart | 9 |
| 复杂数据结构/自定义逻辑？ | Type 6 | 直接继承IPlugin，自定义序列化器 | ~28 |

### 10.2 Type 1: 仅设置persist参数（最简单）

**特征**: bool类型，仅设置系统persist参数，无外部API调用

**开发步骤**:
1. 定义接口码: `interfaces/inner_api/common/include/edm_ipc_interface_code.h`
2. 定义策略常量: `common/native/include/edm_constants.h`（PolicyName命名空间）
3. 创建插件类: `services/edm_plugin/src/restrictions/xxx_plugin.h/cpp`（继承BasicBoolPlugin）
4. 注册查询配置: `services/edm/src/query_policy/policy_query_config_table.cpp`（添加config条目 + 更新GetKnownPolicyCodes集合）
5. 更新BUILD.gn: 5个文件

**Plugin骨架代码**:
```cpp
// xxx_plugin.h
class XxxPlugin : public PluginSingleton<XxxPlugin, bool>, public BasicBoolPlugin {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<XxxPlugin, bool>> ptr) override;
    // 注意：不需要实现SetOtherModulePolicy和RemoveOtherModulePolicy
    // 父类BasicBoolPlugin会自动处理persistParam_的SetParameter调用
};

// xxx_plugin.cpp
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(XxxPlugin::GetPlugin());

void XxxPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<XxxPlugin, bool>> ptr) {
    // 1. ptr->InitAttribute(EdmInterfaceCode::XXX, PolicyName::POLICY_XXX,
    //        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
    //        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true)
    // 2. ptr->SetSerializer(BoolSerializer::GetInstance())
    // 3. ptr->SetOnHandlePolicyListener(&XxxPlugin::OnSetPolicy, FuncOperateType::SET)
    // 4. ptr->SetOnAdminRemoveListener(&XxxPlugin::OnAdminRemove)
    // 5. persistParam_ = "persist.edm.xxx_policy"  // 父类会自动调用system::SetParameter
}
```

**Query配置（替代独立query类）**:
通用类型（BOOL/ARRAY_STRING/INT/STRING）策略不再需要独立query类，只需在config table中添加配置条目：
```cpp
// policy_query_config_table.cpp — 在对应Init函数中添加
table.emplace(EdmInterfaceCode::XXX,
    PolicyQueryConfig{
        PolicyName::POLICY_XXX,                    // policyName
        PolicyDataType::BOOL,                      // dataType
        PermissionConfig::RestrictionPermission(), // permissionConfig
        true,                                      // isPolicySaved
        IPlugin::ApiType::PUBLIC                   // apiType
    });

// 同时在GetKnownPolicyCodes集合中添加策略码
knownCodes.insert(EdmInterfaceCode::XXX);
```

**CUSTOM类型query骨架**（仅自定义逻辑策略需要独立类）:
```cpp
// xxx_query.h
class XxxQuery : public IPolicyQuery {
public:
    std::string GetPolicyName() override;
    std::string GetPermission(IPlugin::PermissionType, const std::string &permissionTag) override;
    ErrCode QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
};

// xxx_query.cpp
std::string XxxQuery::GetPolicyName() { return PolicyName::POLICY_XXX; }

ErrCode XxxQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) {
    // 自定义反序列化和IPC回复逻辑
}
```

**参考实现**:
- `services/edm_plugin/src/restrictions/disallow_core_dump_plugin.cpp`
- `services/edm/src/query_policy/disallowed_p2p_query.cpp`

### 10.3 Type 2: persist + 外部API调用

**特征**: bool类型，设置persist参数 + 调用外部系统API（如PrivacyKit, WifiP2p等）

**开发步骤**: 同Type 1，但SetOtherModulePolicy中需调用外部API

**Plugin骨架代码**（与Type 1差异部分）:
```cpp
// 注意：system::SetParameter(persistParam_, ...) 由父类BasicBoolPlugin::OnSetPolicy自动调用
// 插件只需在SetOtherModulePolicy中调用外部API，不需要手动设置persist参数
ErrCode XxxPlugin::SetOtherModulePolicy(bool data, int32_t userId) {
    // 调用外部API，例如:
    // PrivacyKit::SetDisablePolicy("ohos.permission.CAMERA", data)
    // WifiP2p::RemoveGroup()
    // WifiHotspot::DisableHotspot()
    return ERR_OK;
}

ErrCode XxxPlugin::RemoveOtherModulePolicy(int32_t userId) {
    // 调用外部API恢复状态
    return ERR_OK;
}
```

**Query配置**: 同Type 1（在config table中添加BOOL类型配置条目）

**参考实现**:
- `services/edm_plugin/src/restrictions/disable_camera_plugin.cpp`
- `services/edm_plugin/src/restrictions/disallowed_p2p_plugin.cpp`
- `services/edm_plugin/src/restrictions/disallowed_tethering_plugin.cpp`
- `services/edm_plugin/src/restrictions/disallow_rs232_plugin.cpp`

### 10.4 Type 3: 即时操作（不持久化）

**特征**: int32_t/string类型，needSave=false，直接执行系统动作

**开发步骤**:
1. 定义接口码和策略常量
2. 创建插件类（继承PluginSingleton<T, int32_t/string>）
3. InitPlugin中设置needSave=false
4. 创建查询类
5. 注册并更新BUILD.gn

**Plugin骨架代码**:
```cpp
// xxx_plugin.h
class XxxPlugin : public PluginSingleton<XxxPlugin, int32_t> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<XxxPlugin, int32_t>> ptr) override;
};

// xxx_plugin.cpp
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(XxxPlugin::GetPlugin());

void XxxPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<XxxPlugin, int32_t>> ptr) {
    // 1. 配置权限
    // 2. ptr->InitAttribute(code, policyName, config, false)  // needSave=false
    // 3. ptr->SetSerializer(IntSerializer::GetInstance())
    // 4. ptr->SetOnHandlePolicyListener([](int32_t &data, ...) {
    //        // 直接调用系统API，例如:
    //        // ScreenLockManager::Lock(userId)
    //        // PowerMgrClient::RebootDevice("edm_Reboot")
    //        return ERR_OK;
    //    }, FuncOperateType::SET)
}
```

**Query配置**: 同Type 1（dataType为INT或STRING，在config table中添加配置条目）

**参考实现**:
- `services/edm_plugin/src/device_control/lock_screen_plugin.cpp`
- `services/edm_plugin/src/device_control/reboot_plugin.cpp`

### 10.5 Type 4: 数组/列表策略

**特征**: vector<string>类型，maxListSize限制，可能需冲突检查

**开发步骤**:
1. 定义接口码和策略常量
2. 创建插件类（继承BasicArrayStringPlugin）
3. 设置maxListSize限制
4. 创建查询类（使用GetArrayStringPolicy）
5. 注册并更新BUILD.gn

**Plugin骨架代码**:
```cpp
// xxx_plugin.h
class XxxPlugin : public PluginSingleton<XxxPlugin, std::vector<std::string>>, public BasicArrayStringPlugin {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<XxxPlugin, std::vector<std::string>>> ptr) override;
};

// xxx_plugin.cpp
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(XxxPlugin::GetPlugin());

void XxxPlugin::InitPlugin(...) {
    // 1. 配置权限
    // 2. ptr->InitAttribute(...)
    // 3. ptr->SetSerializer(ArrayStringSerializer::GetInstance())
    // 4. ptr->SetOnHandlePolicyListener(&XxxPlugin::OnBasicSetPolicy, FuncOperateType::SET)
    // 5. ptr->SetOnHandlePolicyListener(&XxxPlugin::OnBasicRemovePolicy, FuncOperateType::REMOVE)
    // 6. ptr->SetOnAdminRemoveListener(&XxxPlugin::OnBasicAdminRemove)
    // 7. maxListSize_ = EdmConstants::APPID_MAX_SIZE  // 设置列表上限
}
```

**Query配置**: 同Type 1（dataType为ARRAY_STRING，在config table中添加配置条目）

**参考实现**:
- `services/edm_plugin/src/bundle_manager/allowed_install_bundles_plugin.cpp`
- `services/edm_plugin/src/application_manager/disallowed_running_bundles_plugin.cpp`
- `services/edm/src/query_policy/allowed_install_bundles_query.cpp`

### 10.6 Type 5: 服务重启恢复

**特征**: 在Type 1/2基础上，注册SetOtherServiceStartListener，服务重启后从数据库恢复策略

**开发步骤**: 同Type 1/2，增加以下步骤：
1. 在Plugin的InitPlugin中注册SetOtherServiceStartListener
2. 在`enterprise_device_mgr_ability.cpp`的`AddOnAddSystemAbilityFuncMap`中注册系统服务启动回调
3. 实现OnOtherServiceStart从数据库恢复策略

**Plugin骨架代码**（在Type 1/2基础上增加）:
```cpp
void XxxPlugin::InitPlugin(...) {
    // ... Type 1/2的初始化
    // 增加: ptr->SetOtherServiceStartListener(&XxxPlugin::OnOtherServiceStart)
}

void XxxPlugin::OnOtherServiceStart(int32_t systemAbilityId) {
    // 1. 从数据库读取策略值
    // 2. 重新应用到系统（调用SetOtherModulePolicy）
}
```

**Ability注册监听**（`enterprise_device_mgr_ability.cpp`）:
```cpp
// 在AddOnAddSystemAbilityFuncMap或AddOnAddSystemAbilityFuncMapSecond中添加
addSystemAbilityFuncMap_[XXX_SERVICE_SYS_ABILITY_ID] =
    [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
        that->CallOnOtherServiceStart(EdmInterfaceCode::XXX_POLICY);
    };
```

**Query骨架代码**: 同Type 1

**参考实现**:
- `services/edm_plugin/src/restrictions/disable_usb_plugin.cpp`
- `services/edm_plugin/src/security_manager/password_policy_plugin.cpp`
- `services/edm_plugin/src/application_manager/clipboard_policy_plugin.cpp`
- `services/edm/src/enterprise_device_mgr_ability.cpp`（查看AddOnAddSystemAbilityFuncMap）

### 10.7 Type 6: 复杂自定义

**特征**: 直接继承IPlugin，自定义数据结构和序列化器，复杂业务逻辑

**开发步骤**:
1. 定义接口码和策略常量
2. 创建自定义数据结构（如XxxType）
3. 创建自定义序列化器: `services/edm_plugin/include/utils/xxx_serializer.h/cpp`
4. 创建插件类（直接继承IPlugin）
5. 创建查询类（自定义反序列化逻辑）
6. 注册并更新BUILD.gn

**Plugin骨架代码**:
```cpp
// xxx_plugin.h
class XxxPlugin : public IPlugin {
public:
    XxxPlugin();
    ErrCode OnHandlePolicy(uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(uint32_t funcCode, const std::string &adminName,
        bool isGlobalChanged, int32_t userId) override;
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeJsonData, int32_t userId) override;
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override;
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
        int32_t userId) override;
private:
    XxxType xxxData_;  // 自定义数据结构
};

// xxx_plugin.cpp
XxxPlugin::XxxPlugin() {
    // policyCode_ = EdmInterfaceCode::XXX
    // policyName_ = PolicyName::POLICY_XXX
    // permissionConfig_.typePermissions.emplace(...)
    // permissionConfig_.apiType = IPlugin::ApiType::PUBLIC
    // needSave_ = true
}

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<XxxPlugin>());

ErrCode XxxPlugin::OnHandlePolicy(...) {
    // 1. XxxSerializer::GetInstance()->GetPolicy(data, xxxData_)
    // 2. 数据验证
    // 3. 应用策略到系统
    // 4. XxxSerializer::GetInstance()->Serialize(xxxData_, policyData.policyData)
    // 5. policyData.isChanged = true
    return ERR_OK;
}

ErrCode XxxPlugin::OnGetPolicy(...) {
    // 1. 从数据库读取policyData
    // 2. XxxSerializer::GetInstance()->Deserialize(policyData, xxxData_)
    // 3. XxxSerializer::GetInstance()->WritePolicy(reply, xxxData_)
    return ERR_OK;
}
```

**自定义序列化器骨架**:
```cpp
// xxx_serializer.h
class XxxSerializer : public IPolicySerializer<XxxType>, public DelayedSingleton<XxxSerializer> {
public:
    bool Deserialize(const std::string &jsonString, XxxType &dataObj) override;
    bool Serialize(const XxxType &dataObj, std::string &jsonString) override;
    bool GetPolicy(MessageParcel &data, XxxType &result) override;
    bool WritePolicy(MessageParcel &reply, XxxType &result) override;
    bool MergePolicy(std::vector<XxxType> &adminValuesArray, XxxType &result) override;
};

// xxx_serializer.cpp
const bool REGISTER_RESULT = DelayedSingleton<XxxSerializer>::RegisterInstance();
```

**Query骨架代码**:
```cpp
// xxx_query.cpp
ErrCode XxxQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) {
    // 1. XxxType data
    // 2. XxxSerializer::GetInstance()->Deserialize(policyData, data)
    // 3. 业务逻辑处理
    // 4. XxxSerializer::GetInstance()->WritePolicy(reply, data)
    return ERR_OK;
}
```

**CUSTOM类型query注册**（config table + factory）:
```cpp
// policy_query_config_table.cpp — 在对应Init函数中添加CUSTOM类型配置
table.emplace(EdmInterfaceCode::XXX,
    PolicyQueryConfig{
        PolicyName::POLICY_XXX,       // policyName
        PolicyDataType::CUSTOM,       // dataType
        PermissionConfig::SuperAdminOnlyPermission(), // permissionConfig
        true,                         // isPolicySaved
        IPlugin::ApiType::PUBLIC      // apiType
    });
knownCodes.insert(EdmInterfaceCode::XXX);

// policy_query_factory.cpp — 在CreateCustomQuery对应分组中添加case
case EdmInterfaceCode::XXX:
    return std::make_shared<XxxQuery>();
```

**参考实现**:
- `services/edm_plugin/src/security_manager/set_watermark_image_plugin.cpp`
- `interfaces/inner_api/security_manager/include/watermark_image_serializer.h`

### 10.8 通用检查清单

| 步骤 | 文件路径 | 说明 |
|------|---------|------|
| 1. 定义接口码 | `interfaces/inner_api/common/include/edm_ipc_interface_code.h` | EdmInterfaceCode枚举中添加 |
| 2. 定义策略常量 | `common/native/include/edm_constants.h` | PolicyName命名空间中添加 |
| 3. 定义权限常量 | `common/native/include/edm_constants.h` | EdmPermission命名空间中选择 |
| 4. 实现插件类 | `services/edm_plugin/src/xxx/xxx_plugin.h/cpp` | 选择6种类型之一 |
| 5. 注册插件 | 在.cpp文件中添加 `const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(XxxPlugin::GetPlugin());` | PluginSingleton模式自动注册 |
| 6. 注册到SO列表 | `services/edm/src/plugin_manager.cpp` | 添加到对应的SoCodes列表（deviceCoreSoCodes_/communicationSoCodes_/sysServiceSoCodes_/needExtraSoCodes_/watermarkSoCodes_） |
| 7. 实现查询类 | 头文件: `services/edm/include/query_policy/xxx_query.h`，源文件: `services/edm/src/query_policy/xxx_query.cpp` | 继承IPolicyQuery（仅CUSTOM类型需要独立query类） |
| 8. 注册查询类 | `services/edm/src/query_policy/policy_query_config_table.cpp` | 在config table中添加配置条目（通用类型），或在PolicyQueryFactory::CreateCustomQuery中添加case（CUSTOM类型）；同时在GetKnownPolicyCodes集合中添加策略码 |
| 9. 添加Addon映射 | `interfaces/kits/xxx/src/xxx_addon.cpp` | 在labelCodeMap/itemCodeMap中添加映射（如适用） |
| 10. 确认条件编译 | 5个BUILD.gn | **用户未声明条件编译时，所有源文件添加到无条件块，禁止模仿参考文件的if块位置** |
| 11. 添加Proxy方法 | `interfaces/inner_api/xxx/src/xxx_proxy.cpp` | 封装HandleDevicePolicy/GetPolicy调用（如适用） |
| 12. 更新BUILD.gn | 见第九部分 | 5个文件添加源文件 |

**PluginManager SO列表注册**:

**代码路径**: `services/edm/src/plugin_manager.cpp`

| SO分类 | 变量名 | 典型策略 |
|--------|--------|----------|
| 设备核心 | `deviceCoreSoCodes_` | DISALLOW_ADD_LOCAL_ACCOUNT, DISABLE_CAMERA, SCREEN_OFF_TIME |
| 通信 | `communicationSoCodes_` | DISABLE_WIFI, DISALLOWED_P2P, TELEPHONY_CALL_POLICY |
| 系统服务 | `sysServiceSoCodes_` | PASSWORD_POLICY, CLIPBOARD_POLICY, LOCATION_POLICY |
| 额外处理 | `needExtraSoCodes_` | GET_DEVICE_INFO, SET_OTA_UPDATE_POLICY |
| 水印 | `watermarkSoCodes_` | WATERMARK_IMAGE, SCREEN_WATERMARK_IMAGE |

**示例**:
```cpp
// 在对应的列表中添加新的接口码
std::vector<uint32_t> PluginManager::deviceCoreSoCodes_ = {
    // ... 现有接口码
    EdmInterfaceCode::XXX_NEW_POLICY,  // 添加新策略
};
```

**BUILD.gn写法**: 详见第九部分。

---

## 第十一部分：事件管理与事件分发

### 11.1 整体架构

```
┌───────────────────────────────────────────────────────────────────┐
│                    EventSubscriptionManager                        │
│           (单例，refCount + 延迟退订 + 读写锁)                       │
│                                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │
│  │ SA_CORE 订阅 │  │MDM_RELAY订阅 │  │POLICY_BOUND │               │
│  │ (Ability自用)│  │(Admin事件)   │  │(插件事件)    │               │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘               │
│         │                │                │                       │
└─────────┼────────────────┼────────────────┼───────────────────────┘
          │                │                │
          ▼                ▼                ▼
  EnterpriseDevice   MdmEventRelayer   PluginEventRouter
  MgrAbility回调     (工厂创建策略)     (路由到Plugin)
  (内部处理)              │                │
                         ▼                ▼
                  EnterpriseConn   PluginManager::
                  Manager::        DispatchPluginEvent
                  ExecuteCallback       │
                  (IPC到Admin扩展)       ▼
                                    IPluginExecuteStrategy
                                    ::OnPluginEventExecute
```

**代码路径**: `services/edm/src/event_management/`、`services/edm/include/event_management/`

**三种订阅者类型**:

| SubscriberType | 值 | 使用者 | 说明 |
|----------------|---|--------|------|
| `SA_CORE` | 0 | EnterpriseDeviceMgrAbility | SA内部事件处理（如USER_SWITCHED触发内部逻辑） |
| `MDM_RELAY` | 1 | MdmEventRelayer | Admin扩展回调（如APP_START通知MDM应用） |
| `POLICY_BOUND` | 2 | PluginEventRouter | 插件策略事件（如剪贴板策略变化） |

### 11.2 核心数据类型

**代码路径**: `interfaces/inner_api/plugin_kits/include/edm_event_data.h`、`common/native/include/managed_event.h`

| 结构体 | 字段 | 说明 |
|--------|------|------|
| `EventId` | `uint32_t code` | 事件标识，有`operator==`/`operator!=` |
| `EventIdHash` | — | EventId的哈希函子 |
| `EdmEventData` | `EventId eventId`、`CommonEventData commonEventData`、`ProcessData appProcessData` | 传递给所有事件回调的负载 |

**ManagedEvent枚举** (`common/native/include/managed_event.h`):

| 枚举值 | 码值 | 适配器类型 | 事件来源 |
|--------|------|-----------|---------|
| `BUNDLE_ADDED` | 0 | COMMON_EVENT | COMMON_EVENT_PACKAGE_ADDED |
| `BUNDLE_REMOVED` | 1 | COMMON_EVENT | COMMON_EVENT_PACKAGE_REMOVED |
| `APP_START` | 2 | APP_LIFECYCLE | 应用进程创建 |
| `APP_STOP` | 3 | APP_LIFECYCLE | 应用进程退出 |
| `SYSTEM_UPDATE` | 4 | COMMON_EVENT(自定义) | DUE_SA_FIRMWARE_UPDATE_FOR_POLICY |
| `USER_ADDED` | 5 | COMMON_EVENT | COMMON_EVENT_USER_ADDED |
| `USER_SWITCHED` | 6 | COMMON_EVENT | COMMON_EVENT_USER_SWITCHED |
| `USER_REMOVED` | 7 | COMMON_EVENT | COMMON_EVENT_USER_REMOVED |
| `STARTUP_GUIDE_COMPLETED` | 8 | COMMON_EVENT(自定义) | OOBE.HWSTARTUPGUIDE.FINISHED |
| `BOOT_COMPLETED` | 9 | COMMON_EVENT | COMMON_EVENT_BOOT_COMPLETED |
| `BUNDLE_UPDATED` | 10 | COMMON_EVENT | COMMON_EVENT_PACKAGE_CHANGED |
| `POLICIES_CHANGED` | 11 | — | 策略变化通知（不走adapter） |
| `BMS_READY` | 101 | COMMON_EVENT | BMS内部就绪 |
| `KIOSK_MODE_ON` | 102 | COMMON_EVENT | Kiosk模式开启 |
| `KIOSK_MODE_OFF` | 103 | COMMON_EVENT | Kiosk模式关闭 |
| `SIM_STATE_CHANGED` | 104 | COMMON_EVENT | SIM卡状态变化 |
| `APP_MARKET_DOWNLOAD` | 105 | COMMON_EVENT(自定义) | 应用市场下载 |
| `APP_MARKET_INSTALL` | 106 | COMMON_EVENT(自定义) | 应用市场安装 |

### 11.3 EventSubscriptionManager（事件订阅中心）

**代码路径**: `services/edm/include/event_management/event_subscription_manager.h`、`services/edm/src/event_management/event_subscription_manager.cpp`

**设计**: 单例 + 引用计数事件组 + 延迟退订

**核心数据结构**:

```
subscriptions_: map<handleId, SubscriptionEntry{handleId, subscriberId, type, eventId, callback}>
eventGroupStates_: map<EventId, shared_ptr<EventGroupState{adapter, refCount, isSubscribed, timer}>>
```

**事件组分组** (`GetEventGroupId`): APP_START 和 APP_STOP 共享同一个事件组（APP_START），即共用一个 `AppLifecycleAdapter`。其他事件各自独立成组。

**Subscribe 流程**:
1. 计算 `groupId = GetEventGroupId(eventId)`
2. 加写锁
3. `EnsureGroupState` — 查找或创建 `EventGroupState`（首次创建 adapter）
4. 若有延迟退订定时器在运行，取消它（复用现有订阅）
5. 若 `!isSubscribed`，调用 `adapter->SubscribeEvent()`，成功则置 `isSubscribed=true`
6. `refCount++`
7. 创建 `SubscriptionEntry` 存入 `subscriptions_`
8. 返回 `SubscriptionHandle`（shared_ptr）

**Unsubscribe 流程**:
1. 加写锁，删除 `SubscriptionEntry`
2. `refCount--`
3. 若 `refCount` 降为 0：启动 30 秒延迟退订定时器（`DelayCancelTimer`）
4. 定时器到期后：若仍为 0 且已订阅，调用 `adapter->UnsubscribeEvent()`，重置 adapter

**DispatchEvent 流程**:
1. 加**读锁**
2. 收集所有 `entry.eventId == data.eventId` 的回调到临时列表
3. **释放锁**后逐个调用回调（避免死锁，允许回调内重新订阅/退订）

**服务重启恢复方法**:

| 方法 | 触发场景 | 行为 |
|------|---------|------|
| `ResetAdapterSubscribedState(groupId)` | AppMgr 重启 | 重置单个组的 `isSubscribed=false` |
| `ResetCommonEventAdapterStates()` | CES 重启 | 重置所有 COMMON_EVENT 类型组的 `isSubscribed` |
| `RetryFailedAdapters(type)` | 重启后重试 | 遍历未订阅的组，重新 `adapter->SubscribeEvent()` |

### 11.4 适配器层（Adapter层）

**代码路径**: `services/edm/include/event_management/i_event_source_adapter.h`、`adapter_factory.h`、`common_event_adapter.h`、`app_lifecycle_adapter.h`

**继承关系**:
```
IEventSourceAdapter (纯虚接口)
├── CommonEventAdapter  — 封装 EventFwk::CommonEventManager 订阅/退订
│   └── 持有 EdmCommonEventSubscriber
└── AppLifecycleAdapter — 封装 AppMgr 应用状态观察者
    └── 持有 EdmAppStateSubscriber
```

**AdapterFactory** (`adapter_factory.cpp`): 根据 `EventId` 创建对应适配器:
- APP_START → `AppLifecycleAdapter`
- BUNDLE_*/USER_*/BOOT_COMPLETED/BMS_READY/KIOSK_*/SIM_STATE_CHANGED → `CommonEventAdapter`（通过 `ConvertToCommonEvent` 映射到系统广播事件名）
- SYSTEM_UPDATE → `CommonEventAdapter`（自定义事件 + `ohos.permission.UPDATE_SYSTEM` 权限）
- STARTUP_GUIDE_COMPLETED → `CommonEventAdapter`（自定义事件 + `ohos.permission.ACCESS_STARTUPGUIDE` 权限）
- 其他自定义事件名非空 → `CommonEventAdapter`
- 未知 → `nullptr`

**ConvertToCommonEvent** 映射表（部分）:

| ManagedEvent | 系统广播事件名 |
|--------------|---------------|
| BUNDLE_ADDED | COMMON_EVENT_PACKAGE_ADDED |
| BUNDLE_REMOVED | COMMON_EVENT_PACKAGE_REMOVED |
| BUNDLE_UPDATED | COMMON_EVENT_PACKAGE_CHANGED |
| USER_ADDED | COMMON_EVENT_USER_ADDED |
| USER_SWITCHED | COMMON_EVENT_USER_SWITCHED |
| USER_REMOVED | COMMON_EVENT_USER_REMOVED |
| BOOT_COMPLETED | COMMON_EVENT_BOOT_COMPLETED |
| KIOSK_MODE_ON | COMMON_EVENT_KIOSK_MODE_ON |
| SIM_STATE_CHANGED | COMMON_EVENT_SIM_STATE_CHANGED |

**AppLifecycleAdapter 的可测试性**: `GetAppMgr()` 是 `protected virtual`，测试时可重写返回 mock。

### 11.5 接收者（Subscriber层）

**EdmCommonEventSubscriber** (`edm_common_event_subscriber.cpp`):
- 继承 `EventFwk::CommonEventSubscriber`
- `OnReceiveEvent(data)` → 构建 `EdmEventData{eventId_, data}` → `manager_.DispatchEvent(edmData)`

**EdmAppStateSubscriber** (`edm_app_state_subscriber.cpp`):
- 继承 `AppExecFwk::ApplicationStateObserverStub`（IPC stub）
- `OnProcessCreated(processData)` → `DispatchEvent(EdmEventData{APP_START, ..., appProcessData})`
- `OnProcessDied(processData)` → `DispatchEvent(EdmEventData{APP_STOP, ..., appProcessData})`

### 11.6 SubscriptionHandle（RAII订阅句柄）

**代码路径**: `services/edm/include/event_management/subscription_handle.h`、`services/edm/src/event_management/subscription_handle.cpp`

- 构造时关联 `EventSubscriptionManager` 和 `handleId`
- 析构或 `Release()` 时调用 `manager_->Unsubscribe(handleId_)`
- Move-only 语义（拷贝已删除），支持 `shared_ptr` 共享
- 建议用 `shared_ptr<SubscriptionHandle>` 管理，析构自动退订

### 11.7 DelayCancelTimer（延迟退订定时器）

**代码路径**: `services/edm/include/event_management/delay_cancel_timer.h`、`services/edm/src/event_management/delay_cancel_timer.cpp`

- `Start(task, delay)` — 先 Cancel 旧定时器，再起独立线程等待 delay 后执行 task
- `Cancel()` — 设置 `active_=false` 并通知条件变量，等待线程安全退出
- `IsRunning()` — 查询是否在等待中
- 析构自动 `Cancel()`
- 线程安全：`threadMutex_` 串行化 Start/Cancel，`mutex_`+`cv_` 实现等待
- **常量**: `DELAY_CANCEL_SECONDS = 30`（在 `event_subscription_manager.cpp` 中定义）

### 11.8 MdmEventRelayer（Admin事件桥接）

**代码路径**: `services/edm/include/event_management/mdm_event_relayer.h`、`services/edm/src/event_management/mdm_event_relayer.cpp`

**职责**: 将系统事件桥接到 MDM Admin 扩展能力的回调方法。

**StrategyFactory 类型**:
```cpp
using StrategyFactory = std::function<std::shared_ptr<ICallbackStrategy>(const EdmEventData &)>;
```
工厂仅创建策略（admin 无关），回调中捕获 admin 信息直接定向到该 admin。策略返回 `nullptr` 表示跳过（如 BUNDLE_UPDATED 类型不匹配时）。

**策略工厂注册**（构造函数中一次性注册）:

| 事件 | 策略类 | 策略构造参数来源 |
|------|--------|-----------------|
| APP_START | `AppStrategy` | `data.appProcessData.bundleName` |
| APP_STOP | `AppStrategy` | `data.appProcessData.bundleName` |
| BUNDLE_ADDED | `BundleStrategy` | `data.commonEventData.GetWant()` 的 bundleName+userId |
| BUNDLE_REMOVED | `BundleStrategy` | 同上 |
| BUNDLE_UPDATED | `BundleStrategy` | 同上（先检查 `type==2`，不匹配返回 nullptr） |
| USER_ADDED | `AccountStrategy` | `data.commonEventData.GetCode()` |
| USER_SWITCHED | `AccountStrategy` | 同上 |
| USER_REMOVED | `AccountStrategy` | 同上 |
| BOOT_COMPLETED | `DeviceBootCompletedStrategy` | 无参数 |
| STARTUP_GUIDE_COMPLETED | `StartupGuideCompletedStrategy` | 从 Want 提取 ota/firstBoot/subUserScene 组装 type 位标志，全为0则返回 nullptr |
| SYSTEM_UPDATE | `SystemUpdateStrategy` | 从 Want 提取 version/firstReceivedTime/packageType |

**OnAdminSubscribe 流程**:
1. `AdminManager::GetAdminByPkgName(adminName, userId)` 查询 `className_`
2. 加写锁，检查去重（同一 admin+event 不重复订阅）
3. 查找 `StrategyFactory`，创建回调 lambda
4. 回调逻辑: `factory(data)` → 若策略非空 → `EnterpriseConnManager::ExecuteCallback(adminName, className, userId, strategy)`
5. 调用 `EventSubscriptionManager::Subscribe(key, MDM_RELAY, EventId{event}, callback)`
6. 存储 `SubscriptionHandle` 到 `adminSubscriptionHandles_[key][event]`

**OnAdminUnsubscribe**: 从 map 移除 handle，handle 析构自动退订。

**OnAdminRemoved**: 批量移除该 admin 的所有 handle。

**恢复流程** (`RestoreSubscriptions`):
- `RestoreAdminSubscriptions()` — 恢复所有 admin 的非应用生命周期事件
- `RestoreAppLifecycleSubscriptions()` — 仅恢复 APP_START/APP_STOP 事件
- `RestoreAdminEvents(adminName, userId, appLifecycleOnly)` — 遍历 admin 的 `managedEvents_`，按 flag 过滤后调 `OnAdminSubscribe`

### 11.9 PluginEventRouter（插件事件路由）

**代码路径**: `services/edm/include/event_management/plugin_event_router.h`、`services/edm/src/event_management/plugin_event_router.cpp`

**职责**: 将系统事件路由到插件策略处理器。实现 `IPluginEventSubscribeManager` 接口，构造时注册为全局实例。

**核心数据结构**:
```
entries_: map<"policyName:eventCode", PluginEntry{policyCode, needAdminIteration, useEventUserId}>
eventGroupStates_: map<EventId, EventGroupState{handle, registeredKeys, eventFilter, permission}>
```

**SubscribeEvent 流程**:
1. 生成 key = `policyName + ":" + eventCode`
2. 加写锁，若 key 已存在返回 true（幂等）
3. 存入 `PluginEntry`
4. 查找/创建 EventGroupState，添加 key 到 `registeredKeys`
5. 若组内首次订阅（`handle==nullptr`），向 `EventSubscriptionManager` 注册（subscriberId="PLUGIN_ROUTER"，type=POLICY_BOUND）
6. 回调 = `OnEventDispatch(eventId, data)`

**OnEventDispatch 流程**:
1. 加读锁，`CollectDispatchEntries` 从两组 map 中收集匹配的 PluginEntry
2. 释放锁
3. 对每个 entry 调用 `PluginManager::DispatchPluginEvent(policyCode, data, needAdminIteration, useEventUserId)`

**RestorePluginSubscriptions**: 遍历 12 个预定义的 `{policyCode, policyName}` 对，查询 DB 中是否有策略值，有则调用 `PluginManager::SubscribePluginEvent`。

### 11.10 回调策略（ICallbackStrategy）

**代码路径**: `services/edm/include/connection/icallback_strategy.h`、`services/edm/include/connection/callback_strategies.h`

**继承关系**: `ICallbackStrategy` → `Execute(proxy)` 调用 `ExecuteImpl(proxy)`（子类实现）

**策略类列表**:

| 策略类 | 构造参数 | ExecuteImpl 调用 |
|--------|---------|-----------------|
| `AppStrategy` | code, bundleName | `proxy->OnApp(code, bundleName)` |
| `BundleStrategy` | code, bundleName, accountId | `proxy->OnBundle(code, bundleName, accountId)` |
| `AccountStrategy` | code, accountId | `proxy->OnAccount(code, accountId)` |
| `SystemUpdateStrategy` | UpdateInfo | `proxy->OnSystemUpdate(updateInfo)` |
| `StartupGuideCompletedStrategy` | type(int位标志) | `proxy->OnStartupGuideCompleted(type)` |
| `DeviceBootCompletedStrategy` | 无 | `proxy->OnDeviceBootCompleted()` |
| `KioskModeStrategy` | code, bundleName, accountId | `proxy->OnKioskMode(code, bundleName, accountId)` |
| `AdminStrategy` | code | `proxy->OnAdmin(code)` |
| `AdminPolicyChangedStrategy` | PolicyChangedEvent | `proxy->OnAdminPolicyChanged(event)` |
| `MarketAppsInstallStatusChangedStrategy` | bundleName, status | `proxy->OnMarketAppsInstallStatusChanged(...)` |
| `LogCollectedStrategy` | isSuccess | `proxy->OnLogCollected(isSuccess)` |
| `KeyEventStrategy` | keyEvent | `proxy->OnKeyEvent(keyEvent)` |

**EnterpriseConnManager::ExecuteCallback** (`enterprise_conn_manager.cpp:32-66`):
1. 检查连接状态（有proxy/需新建/有过期回调需清理）
2. 若有有效proxy → `strategy->Execute(proxy)`；失败则重连
3. 若需新建连接 → `EstablishConnection`（连接成功后通过 `SaveProxy` 执行 pending 策略）
4. 连接超时 = 10秒（可通过 `persist.sys.abilityms.timeout_unit_time_ratio` 系统参数调整）

### 11.11 三类事件流完整链路

**Admin管理事件流（如 APP_START）**:
```
AppMgr(进程创建)
  → EdmAppStateSubscriber::OnProcessCreated
    → EventSubscriptionManager::DispatchEvent(EdmEventData{APP_START, appProcessData})
      → MdmEventRelayer 回调 (SubscriberType::MDM_RELAY)
        → StrategyFactory 创建 AppStrategy(COMMAND_ON_APP_START, bundleName)
        → EnterpriseConnManager::ExecuteCallback(adminName, className, userId, strategy)
          → strategy->Execute(proxy)
            → proxy->OnApp(code, bundleName)  // IPC到Admin扩展
```

**SA核心事件流（如 USER_SWITCHED）**:
```
CommonEventService(用户切换广播)
  → EdmCommonEventSubscriber::OnReceiveEvent
    → EventSubscriptionManager::DispatchEvent
      → EnterpriseDeviceMgrAbility lambda (SubscriberType::SA_CORE)
        → 内部处理（如 OnCommonEventUserSwitched）
```

**插件策略事件流**:
```
CommonEventService(系统广播)
  → EdmCommonEventSubscriber::OnReceiveEvent
    → EventSubscriptionManager::DispatchEvent
      → PluginEventRouter::OnEventDispatch (SubscriberType::POLICY_BOUND)
        → CollectDispatchEntries → 对每个 PluginEntry:
          → PluginManager::DispatchPluginEvent(policyCode, data, needAdminIteration, useEventUserId)
            → plugin->GetExecuteStrategy()->OnPluginEventExecute(...)
```

### 11.12 服务重启恢复流程

**EnterpriseDeviceMgrAbility 中的回调** (`enterprise_device_mgr_ability.cpp`):

| 触发 | 调用链 |
|------|--------|
| AppMgr 启动 | `ResetAdapterSubscribedState(APP_START组)` → `RestoreAppLifecycleSubscriptions()` → `RetryFailedAdapters(APP_LIFECYCLE)` |
| CES 启动 | 清空 `saCoreHandles_` → `ResetCommonEventAdapterStates()` → 订阅 SA_CORE 事件 → `RestoreAdminSubscriptions()` → `RestorePluginSubscriptions()` → `RetryFailedAdapters(COMMON_EVENT)` |
| Admin 移除 | `MdmEventRelayer::OnAdminRemoved(adminName, userId)` |
| Admin 订阅事件 | `MdmEventRelayer::OnAdminSubscribe(bundleName, userId, event)` |
| Admin 退订事件 | `MdmEventRelayer::OnAdminUnsubscribe(bundleName, userId, event)` |

**saCoreHandles_**: `EnterpriseDeviceMgrAbility` 的成员，持有 SA 自身的 `SubscriptionHandle` 列表（USER_SWITCHED, USER_REMOVED, BUNDLE_*, BMS_READY, KIOSK_*, SIM_STATE_CHANGED, APP_MARKET_*）。

### 11.13 线程与锁模型

| 类 | 锁类型 | 保护范围 |
|----|--------|---------|
| `EventSubscriptionManager` | `shared_mutex` | 写锁: Subscribe/Unsubscribe/Reset/Retry；读锁: DispatchEvent |
| `MdmEventRelayer` | `shared_mutex` | 写锁: OnAdminSubscribe/Unsubscribe/Removed |
| `PluginEventRouter` | `shared_mutex` | 写锁: SubscribeEvent/UnsubscribeEvent；读锁: OnEventDispatch |
| `DelayCancelTimer` | `mutex` ×2 | `threadMutex_`: 串行化 Start/Cancel；`mutex_`+`cv_`: 定时等待 |
| `EnterpriseConnManager` | `mutex` | `connectionMap_` |

**关键线程安全设计**:
- `DispatchEvent` 在读锁下收集回调，释放锁后调用——避免回调内重新订阅/退订导致死锁
- `StartDelayedUnsubscribe` 在锁外启动定时器，定时器线程在到期后重新获取写锁
- 定时器 lambda 捕获 `shared_ptr<EventGroupState>`，确保延迟期间对象存活即使被移出 map

### 11.14 设计模式总结

| 模式 | 应用位置 | 用途 |
|------|---------|------|
| **Singleton** | EventSubscriptionManager, MdmEventRelayer, PluginEventRouter | 全局访问 |
| **Factory Method** | AdapterFactory | 根据 EventId 创建适配器 |
| **Strategy** | IEventSourceAdapter, ICallbackStrategy | 可插拔的事件源和回调 |
| **Observer** | EventSubscriptionManager + subscribers | 发布/订阅系统事件 |
| **RAII** | SubscriptionHandle | 析构自动退订 |
| **引用计数** | EventGroupState::refCount | 多订阅者共享适配器 |
| **延迟退订** | DelayCancelTimer + 30秒宽限期 | 避免频繁订阅/退订抖动 |
| **Mediator** | PluginEventRouter | 中介 EventSubscriptionManager 和 PluginManager |

### 11.15 新增事件开发指南

**场景**: 需要订阅一个新的系统广播事件并分发给 MDM Admin 扩展。

**步骤**:

1. **在 `managed_event.h` 中添加枚举值**（如 `MY_NEW_EVENT = 107`）

2. **在 `AdapterFactory::ConvertToCommonEvent` 中添加映射**（`adapter_factory.cpp`）:
   ```cpp
   case static_cast<uint32_t>(ManagedEvent::MY_NEW_EVENT):
       commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_MY_NEW_EVENT;
       return true;
   ```

3. **在 `MdmEventRelayer` 中注册策略工厂**（`mdm_event_relayer.cpp`）:
   ```cpp
   // 在 RegisterStrategyFactories() 中添加
   strategyFactories_[ManagedEvent::MY_NEW_EVENT] = [](const EdmEventData &data)
       -> std::shared_ptr<ICallbackStrategy> {
       // 从 data 中提取参数，创建策略
       return std::make_shared<XxxStrategy>(...);
   };
   ```
   若需过滤（如 BUNDLE_UPDATED 的 type 检查），返回 `nullptr` 表示跳过。

4. **若需要新的 ICallbackStrategy 子类**，在 `callback_strategies.h/cpp` 中添加:
   ```cpp
   class XxxStrategy : public ICallbackStrategy {
   public:
       explicit XxxStrategy(...) : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_XXX), ... {}
   private:
       bool ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override {
           return proxy->OnXxx(...);
       }
   };
   ```

5. **在 `IEnterpriseAdmin` 接口中添加对应的回调方法**（`interfaces/inner_api/common/include/ienterprise_admin.h`），并在 `EnterpriseAdminProxy` 中实现。

6. **若事件需要自定义事件名或权限**（非标准系统广播），在 `AdapterFactory::CreateAdapter` 中添加对应 case，传入 eventName 和 eventPermission。

7. **测试**: 在 `test/unittest/services/edm/src/mdm_event_relayer_test.cpp` 中添加策略工厂返回值验证测试。事件分发行为可通过 `EventSubscriptionManager::GetInstance().DispatchEvent(data)` 触发验证。

**参考实现**:
- 简单事件: `BOOT_COMPLETED` → `DeviceBootCompletedStrategy`（无参数）
- 带参数事件: `BUNDLE_ADDED` → `BundleStrategy`（从 Want 提取参数）
- 带过滤事件: `BUNDLE_UPDATED` → 先检查 type 再创建策略
- 带位标志事件: `STARTUP_GUIDE_COMPLETED` → 从 Want 组装 type 位标志

### 11.16 BUILD.gn 配置

**源文件**（`services/edm/BUILD.gn`，target `edmservice`）: 10 个 `.cpp` 文件在 `./src/event_management/` 下，无条件编译。

**测试文件**（`test/unittest/services/edm/BUILD.gn`，target `EdmServicesUnitTest`）: 10 个测试文件在 `if (common_event_service_edm_enable)` 块内。

**Include 路径**: `services/edm/include/event_management` 已在 BUILD.gn `config` 中配置。
