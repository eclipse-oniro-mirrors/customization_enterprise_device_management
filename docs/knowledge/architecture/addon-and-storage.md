# Addon 层、Proxy 层与策略存储

> Addon/Proxy 层实现（新旧写法）与策略存储方式。编写或修改 NAPI/JS 互操作、序列化、数据库相关代码时查阅本文档。日常工作流以 AGENTS.md 路由为准。

## Addon 层和 Proxy 层实现

Addon层和Proxy层是JS层调用EDM服务的入口，位于Plugin和Query之上。有新旧两种写法，**推荐优先使用新写法**（基于AddonMethodAdapter框架）。

### 新写法（推荐）：基于AddonMethodAdapter框架

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

### 旧写法（补充）：直接解析参数

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

### 新旧写法对比

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

## 策略存储方式和格式

### 存储介质

- **持久化**: RDB关系型数据库
- **内存缓存**: UserPolicyManager管理
- **管理类**: DevicePoliciesStorageRdb, AdminPoliciesStorageRdb

**代码路径**: `services/edm/src/database/`

### 数据库表

| 表名 | 字段 |
|------|------|
| device_admin_policies | userId, adminName, policyName, policyValue |
| device_combined_policies | userId, policyName, policyValue |
| admin_policies | userId, packageName, entInfo, managedEvents |

### 内存数据结构

```cpp
PolicyItemsMap = unordered_map<string, string>  // 策略名称 -> JSON字符串
AdminValueItemsMap = unordered_map<string, string>  // 管理员 -> 策略值
```

### 序列化格式

- **格式**: JSON字符串（cJSON库）
- **IPolicySerializer接口**: Deserialize, Serialize, GetPolicy, WritePolicy, MergePolicy
