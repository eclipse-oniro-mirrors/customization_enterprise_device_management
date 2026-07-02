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

**架构**: 13层链式switch-case分发，避免单个巨大switch语句

| 函数 | 覆盖策略范围 |
|------|-------------|
| GetPolicyQuery | ALLOWED_BLUETOOTH_DEVICES, DISABLE_CAMERA等 |
| GetPolicyQueryFirst ~ Fourth | 各约7-9个策略 |
| GetPolicyQueryFifthPartOne ~ FifthPartTwo | 各约3-4个策略 |
| GetPolicyQuerySixth ~ Eleventh | 各约5-11个策略 |

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
4. 创建查询类: `services/edm/src/query_policy/xxx_query.h/cpp`（继承IPolicyQuery）
5. 注册查询类: `services/edm/src/query_policy/plugin_policy_reader.cpp`
6. 更新BUILD.gn: 5个文件

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

**Query骨架代码**:
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
    // return GetBoolPolicy(policyData, reply)
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

**Query骨架代码**: 同Type 1

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

**Query骨架代码**:
```cpp
// xxx_query.cpp
ErrCode XxxQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) {
    // return GetIntPolicy(policyData, reply)  // 或 GetStringPolicy
}
```

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

**Query骨架代码**:
```cpp
// xxx_query.cpp
ErrCode XxxQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) {
    // return GetArrayStringPolicy(policyData, reply)
}
```

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
| 7. 实现查询类 | 头文件: `services/edm/include/query_policy/xxx_query.h`，源文件: `services/edm/src/query_policy/xxx_query.cpp` | 继承IPolicyQuery |
| 8. 注册查询类 | `services/edm/src/query_policy/plugin_policy_reader.cpp` | GetPolicyQuery系列函数中添加case |
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
