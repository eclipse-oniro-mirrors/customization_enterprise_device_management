# 05 - 策略与权限配置规范

> 来源 Bug: 权限配置错误、config table 类型不匹配、null admin 兼容

## 规则 5.1：策略查询权限必须与设置权限匹配

**错误根因**: 查询策略时返回的权限与设置策略时的权限不一致，导致有权限设置的 admin 无法查询。

**来源**: `1bab465d` — `DisallowedAirplaneModeQuery`/`DisallowedMobileDataQuery` 查询权限返回 `PERMISSION_ENTERPRISE_MANAGE_NETWORK`，应为 `PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS`。

**错误写法**:
```cpp
// disallowed_airplane_mode_query.cpp
std::string GetPermission(IPlugin::PermissionType permissionType,
    const std::string &permissionTag) {
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK;  // 错误权限
}
```

**正确写法**:
```cpp
return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
```

**检查清单**:
- [ ] 新增策略时，Query 类的 `GetPermission` 返回值必须与 Plugin 的 `permissionConfig_` 一致
- [ ] 使用 config table 模式时，`PermissionConfig` 的工厂方法选择要正确
- [ ] 对比同类策略（如 restrictions 系列）的权限配置确保一致

---

## 规则 5.2：TagPermission 的 superAdmin 权限不能写错

**错误根因**: `TagPermission` 的 superAdmin 参数写成了不相关的权限，导致策略失效。

**来源**: `d63cad07` — `USB_READ_ONLY` 的 `TagPermission` superAdmin 权限误写为 `PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS`，应为 `PERMISSION_ENTERPRISE_MANAGE_USB`。

**错误写法**:
```cpp
// policy_query_config_table.cpp
{EdmInterfaceCode::USB_READ_ONLY, {PolicyName::POLICY_USB_READ_ONLY,
    PolicyDataType::INT,
    PermissionConfig::TagPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,  // 错误！
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS),
    true, IPlugin::ApiType::PUBLIC}}
```

**正确写法**:
```cpp
PermissionConfig::TagPermission(
    EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,  // tag permission
    EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,  // superAdmin 权限必须匹配
    EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS)
```

**检查清单**:
- [ ] `TagPermission(tagPermission, superAdminPermission, byodAdminPermission)` 三个参数的语义：
  - `tagPermission`: 当有 permissionTag 时的超级管理员权限
  - `superAdminPermission`: 无 tag 时的超级管理员权限
  - `byodAdminPermission`: BYOD 管理员权限
- [ ] superAdmin 权限应与策略领域匹配（USB 策略用 USB 权限）
- [ ] 新增策略后用对应 admin 类型测试 GET/SET 两个操作

---

## 规则 5.3：新策略必须加入 supportAdminNullPolicyCode_ 集合

**错误根因**: 支持 admin 传 null 的策略未加入 `supportAdminNullPolicyCode_` 集合，导致 null 调用被拒绝。

**来源**: `2ba0c29f` — 8 个策略接口未加入集合。

**正确做法**:
```cpp
// services/edm/src/permission_checker.cpp
std::vector<uint32_t> PermissionChecker::supportAdminNullPolicyCode_ = {
    ...
    EdmInterfaceCode::DISALLOWED_DEVICE_SUDO,      // 新增
    EdmInterfaceCode::DISALLOW_MODIFY_APN,
    EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS,
    EdmInterfaceCode::DISABLE_USER_MTP_CLIENT,
    EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE,
    EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY,
    EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION,
    EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN,
};
```

**检查清单**:
- [ ] 新增策略如果需要支持 admin 为 null（即 `argsType` 包含 `ELEMENT_NULL`），必须同时加入 `supportAdminNullPolicyCode_`
- [ ] admin 传 null 的策略，Addon 层使用 `EdmAddonCommonType::ELEMENT_NULL`
- [ ] 测试用例必须覆盖 admin 为 null 的场景

---

## 规则 5.4：config table 的 dataType 必须与实际数据结构匹配

**错误根因**: config table 中配置为 `INT` 类型，但实际数据需要自定义反序列化逻辑，应使用 `CUSTOM` 类型。

**来源**: `c3f50e2d` — `ALLOWED_INSTALL_APP_TYPE` 配置为 `INT`，应为 `CUSTOM`。

**错误写法**:
```cpp
// policy_query_config_table.cpp
{EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, {
    PolicyName::POLICY_ALLOWED_INSTALL_APP_TYPE,
    PolicyDataType::INT,  // 错误！实际数据非简单 int
    ...
}}
```

**正确写法**:
```cpp
{EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, {
    PolicyName::POLICY_ALLOWED_INSTALL_APP_TYPE,
    PolicyDataType::CUSTOM,  // 需要自定义反序列化
    ...
}}
// 同时在 PolicyQueryFactory::CreateCustomQuery 中添加 case
case EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE:
    return std::make_shared<AllowedInstallAppTypeQuery>();
```

**dataType 选择决策**:
| 数据类型 | dataType | 是否需要独立 query 类 |
|---------|----------|-------------------|
| bool | `BOOL` | 否，使用 `BoolPolicyQuery` |
| `vector<string>` | `ARRAY_STRING` | 否，使用 `ArrayStringPolicyQuery` |
| int32_t | `INT` | 否，使用 `IntPolicyQuery` |
| string | `STRING` | 否，使用 `StringPolicyQuery` |
| 自定义结构/需特殊逻辑 | `CUSTOM` | 是，需独立 query 类 |

**检查清单**:
- [ ] 新增策略在 config table 中配置 `dataType` 时，对照上表选择
- [ ] 如果策略数据不是简单的 bool/int/string/vector<string>，必须使用 `CUSTOM`
- [ ] 使用 `CUSTOM` 类型时，同时在 `PolicyQueryFactory::CreateCustomQuery` 中注册

---

## 规则 5.5：userId 判断不能简单按 admin 类型区分

**错误根因**: 根据 `IsSuperOrSubSuperAdmin` 判断 userId，但超级管理员的子用户订阅事件需要按当前用户存储。

**来源**: `187d1140` — `SubscribeManagedEvent`/`UnsubscribeManagedEvent` userId 判断错误。

**错误写法**:
```cpp
int32_t userId = AdminManager::GetInstance()->IsSuperOrSubSuperAdmin(
    admin.GetBundleName()) ? EdmConstants::DEFAULT_USER_ID : GetCurrentUserId();
```

**正确写法**: 通过 admin 对象的 `IsAllowedAcrossAccountSetPolicy` 判断
```cpp
int32_t userId = EdmConstants::DEFAULT_USER_ID;
std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(
    admin.GetBundleName(), GetCurrentUserId());
if (adminItem != nullptr && !adminItem->IsAllowedAcrossAccountSetPolicy()) {
    userId = GetCurrentUserId();
}
```

**检查清单**:
- [ ] 不要用 admin 类型（超级/普通）简单推导 userId
- [ ] 使用 `IsAllowedAcrossAccountSetPolicy()` 判断是否允许跨账户
- [ ] 多用户场景下，订阅事件必须按正确 userId 存储

---

## 规则 5.6：策略恢复必须处理 package added 事件

**错误根因**: 应用卸载重装后，`SET_ABILITY_ENABLED` 策略未恢复，因为 `OnCommonEventPackageAdded` 未处理。

**来源**: `b517a9ad` — package added 时未恢复 ability enabled 状态。

**正确做法**: 在 `OnCommonEventPackageAdded` 中调用策略恢复
```cpp
void OnCommonEventPackageAdded(...) {
    ...
    ConnectAbilityOnSystemEvent(bundleName, ManagedEvent::BUNDLE_ADDED, userId);
    int32_t appIndex = data.GetWant().GetIntParam(...);
    UpdateAbilityEnabled(bundleName, userId, appIndex);  // 新增恢复逻辑
}
```

**检查清单**:
- [ ] 所有涉及应用安装/卸载的策略，必须同时处理 `BUNDLE_ADDED` 和 `BUNDLE_REMOVED`
- [ ] 卸载重装场景测试：卸载应用 → 重装 → 验证策略是否恢复
- [ ] 恢复策略时遍历所有管理员
