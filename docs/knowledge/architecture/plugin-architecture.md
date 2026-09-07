# 插件架构、类型体系与新策略开发流程

> 插件 SO 加载机制、插件类型体系（5 种继承模式、序列化器）、以及新策略开发的 6 种类型与通用检查清单。新增或修改策略插件时查阅本文档。BUILD.gn 修改规则见 `build-gn-rules.md`。日常工作流以 AGENTS.md 路由为准。

## 插件分类和 SO 加载机制

### 插件 SO 分类

**代码路径**: `services/edm/src/plugin_manager.cpp`

| 分类 | SO 文件名 | 插件数量 | 典型策略 |
|------|-----------|----------|----------|
| 设备核心 | device_core_plugin.so | ~25 | DISABLE_CAMERA, LOCK_SCREEN |
| 通信 | communication_plugin.so | ~35 | DISALLOWED_P2P, DISABLE_WIFI |
| 系统服务 | sys_service_plugin.so | ~40 | PASSWORD_POLICY, CLIPBOARD_POLICY |
| 额外处理 | need_extra_plugin.so | ~20 | GET_DEVICE_INFO, INSTALL |
| 水印 | watermark_plugin.so | ~5 | WATERMARK_IMAGE |

### 按需加载机制

**流程**: GetPluginByFuncCode → LoadPluginByFuncCode → GetSoNameByCode → dlopen → 注册

**关键方法**:
- `GetSoNameByCode`: 根据接口码查找对应SO文件名
- `LoadPlugin`: dlopen加载，获取CreatePluginInstance符号，创建插件实例
- `LoadExtraPlugin`: 动态扫描插件目录，加载未注册的插件

### 自动卸载

- **超时**: 3分钟无调用
- **触发**: 定时器检查 + 引用计数
- **流程**: 检查引用计数 → 从映射表移除 → dlclose释放

### 注册模式

| 模式 | 特点 | 适用场景 |
|------|------|---------|
| PluginSingleton自动注册 | 双重检查锁单例，.cpp全局变量自动注册 | 简单策略，使用模板类 |
| 直接继承IPlugin | 构造函数手动设置属性，手动注册 | 复杂策略，不受模板限制 |

---

## 插件类型体系

### 5种继承模式

| 模式 | 继承关系 | 数据类型 | 数量 | 典型场景 |
|------|---------|---------|------|----------|
| A. BasicBoolPlugin | PluginSingleton<T,bool> + BasicBoolPlugin | bool | 37 | 禁用摄像头、禁止P2P |
| B. BasicArrayStringPlugin | PluginSingleton<T,vector<string>> + BasicArrayStringPlugin | vector<string> | 12 | 允许安装包列表 |
| C. BasicArrayIntPlugin | PluginSingleton<T,vector<int>> + BasicArrayIntPlugin | vector<int32_t> | 1 | 隐藏设置菜单 |
| D. PluginSingleton仅继承 | PluginSingleton<T,DT> | 多种 | 40 | WiFi开关、设备信息 |
| E. 直接IPlugin | IPlugin | 自定义复杂类型 | 26 | 水印图片、密码策略 |

### 各模式关键方法

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

### 回调函数类型

**代码路径**: `interfaces/inner_api/plugin_kits/include/iplugin_template.h`

| 回调类型 | 参数 | 使用场景 |
|---------|------|---------|
| Supplier | 无 | 简单操作 |
| Function | DT &data | 只需新策略数据 |
| BiFunction | data, currentData, mergeData, userId | 需要比较新旧数据 |
| ReplyFunction | data, reply | 直接写入IPC回复 |
| BoolConsumer | isGlobalChanged | 策略完成后回调 |
| BiAdminFunction | adminName, data, mergeData, userId | 管理员移除时 |

### 序列化器

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

## 新策略开发流程

### 策略分类决策树

| 判断条件 | 类型 | 特征 | 数量 |
|---------|------|------|------|
| 仅设置persist系统参数？ | Type 1 | 最简单，bool类型，设置persist参数 | ~22 |
| 需要调用外部系统API？ | Type 2 | bool类型，persist + 外部API调用 | ~14 |
| 即时操作，不需要持久化？ | Type 3 | int32_t/string类型，needSave=false | ~5 |
| 数组/列表类型策略？ | Type 4 | vector<string>，maxListSize限制，可能冲突检查 | ~7 |
| 需要服务重启后恢复策略？ | Type 5 | 在Type 1/2基础上增加OnOtherServiceStart | 9 |
| 复杂数据结构/自定义逻辑？ | Type 6 | 直接继承IPlugin，自定义序列化器 | ~28 |

### Type 1: 仅设置persist参数（最简单）

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

### Type 2: persist + 外部API调用

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

### Type 3: 即时操作（不持久化）

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

### Type 4: 数组/列表策略

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

### Type 5: 服务重启恢复

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

### Type 6: 复杂自定义

**特征**: 直接继承IPlugin，自定义数据结构序列化器，复杂业务逻辑

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

### 通用检查清单

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
| 12. 更新BUILD.gn | 见 `build-gn-rules.md` | 5个文件添加源文件 |

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

**BUILD.gn写法**: 详见 `build-gn-rules.md`。
