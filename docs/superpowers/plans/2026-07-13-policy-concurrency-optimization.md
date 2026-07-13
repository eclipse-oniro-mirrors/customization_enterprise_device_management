# Policy Concurrency Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace PluginManager's single global exclusive lock with a three-layer locking scheme (global gate + plugin map + per-policy/conflict-group locks) to enable parallel policy SET/GET operations.

**Architecture:** Three lock layers: (1) `globalMutex_` reader-writer gate that blocks all policy ops during plugin load/unload and admin removal, (2) `pluginMapMutex_` for plugin map access with double-checked loading, (3) per-policy `shared_mutex` locks for same-policy SET/GET serialization plus per-conflict-group SET locks for conflicting policy serialization. GETs never touch conflict-group locks, ensuring SET A only blocks GET A (not GET B in the same conflict group).

**Tech Stack:** C++17 (`std::shared_mutex`, `std::shared_lock`, `std::unique_lock`), OpenHarmony GN build system, GTest (HWTEST_F)

## Global Constraints

- C++17 is available (`std::shared_mutex` already used in `EnterpriseDeviceMgrAbility::adminLock_`)
- Only `PluginManager` is modified — `adminLock_` and `PolicyManager::mutexLock_` are out of scope
- All existing unit tests must pass without modification
- Code follows existing style: no comments unless asked, uses `EDMLOGI`/`EDMLOGW`/`EDMLOGE` for logging
- Build target: `enterprise_device_management`
- Test runner: `test/testfwk/developer_test/start.sh -t edm`
- Repo root: `/srv/workspace/openharmony_master_default_20260712133706_huawei_cd2909430/code/base/customization/enterprise_device_management`

## File Structure

| File | Responsibility | Action |
|------|---------------|--------|
| `services/edm/include/plugin_manager.h` | PluginManager class declaration | Modify: add new lock members, helper methods; remove `mutexLock_` |
| `services/edm/src/plugin_manager.cpp` | PluginManager implementation | Modify: migrate all methods to new locking scheme |
| `test/unittest/services/edm/src/plugin_manager_concurrency_test.cpp` | Concurrency verification tests | Create: new test file |
| `test/unittest/services/edm/BUILD.gn` | Test build config | Modify: add new test source file |
| `test/unittest/services/edm/include/plugin_manager_test.h` | Test header (if needed for shared mocks) | Modify: add concurrency test class |

---

### Task 1: Add New Lock Members and Helper Methods

**Files:**
- Modify: `services/edm/include/plugin_manager.h`
- Modify: `services/edm/src/plugin_manager.cpp`

**Interfaces:**
- Produces: `GetPolicyLock(uint32_t) -> std::shared_ptr<std::shared_mutex>`, `GetConflictSetLock(uint32_t) -> std::shared_ptr<std::shared_mutex>`, `InitConflictGroupMap()` — used by Task 2
- Produces: new static members `globalMutex_`, `pluginMapMutex_`, `policyLocks_`, `conflictSetLocks_`, `conflictGroupMap_` — used by Task 2

- [ ] **Step 1: Add new includes to plugin_manager.h**

Add `<mutex>` and `<unordered_map>` to the includes if not already present. The header currently has `<shared_mutex>` and `<map>`.

```cpp
// In plugin_manager.h, update the include block (around line 19-24):
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
```

- [ ] **Step 2: Add new member declarations to plugin_manager.h**

In the `private` section of `PluginManager` (after `static std::shared_timed_mutex mutexLock_;` on line 92), add the new members. Do NOT remove `mutexLock_` yet — it will be removed in Task 2.

```cpp
private:
    // ... existing members ...
    static std::shared_timed_mutex mutexLock_;  // REMOVED in Task 2
    // New locking scheme (Task 1: add, Task 2: use)
    static std::shared_mutex globalMutex_;              // Layer 1: global gate
    static std::shared_mutex pluginMapMutex_;           // Layer 2: plugin map access
    static std::unordered_map<uint32_t, std::shared_ptr<std::shared_mutex>> policyLocks_;
    static std::mutex policyLocksMapMutex_;             // protects policyLocks_ map
    static std::unordered_map<uint32_t, std::shared_ptr<std::shared_mutex>> conflictSetLocks_;
    static std::mutex conflictSetLocksMapMutex_;        // protects conflictSetLocks_ map
    static std::unordered_map<uint32_t, uint32_t> conflictGroupMap_;  // policyCode -> groupId
```

Also add public/private helper method declarations:

```cpp
    std::shared_ptr<std::shared_mutex> GetPolicyLock(uint32_t policyCode);
    std::shared_ptr<std::shared_mutex> GetConflictSetLock(uint32_t policyCode);
    static void InitConflictGroupMap();
```

- [ ] **Step 3: Add static member definitions to plugin_manager.cpp**

After the existing `std::shared_timed_mutex PluginManager::mutexLock_;` (line 40), add:

```cpp
std::shared_mutex PluginManager::globalMutex_;
std::shared_mutex PluginManager::pluginMapMutex_;
std::unordered_map<uint32_t, std::shared_ptr<std::shared_mutex>> PluginManager::policyLocks_;
std::mutex PluginManager::policyLocksMapMutex_;
std::unordered_map<uint32_t, std::shared_ptr<std::shared_mutex>> PluginManager::conflictSetLocks_;
std::mutex PluginManager::conflictSetLocksMapMutex_;
std::unordered_map<uint32_t, uint32_t> PluginManager::conflictGroupMap_;
```

- [ ] **Step 4: Implement InitConflictGroupMap in plugin_manager.cpp**

Add this method after the static member definitions (before the `GetInstance` method). Uses `EdmInterfaceCode` enum values for conflict group mapping:

```cpp
void PluginManager::InitConflictGroupMap()
{
    static std::once_flag flag;
    std::call_once(flag, []() {
        // Group 1: USB cluster (7 policies)
        const uint32_t usbGroup = 1;
        conflictGroupMap_[EdmInterfaceCode::DISABLE_USB] = usbGroup;
        conflictGroupMap_[EdmInterfaceCode::ALLOWED_USB_DEVICES] = usbGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_USB_DEVICES] = usbGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES] = usbGroup;
        conflictGroupMap_[EdmInterfaceCode::USB_READ_ONLY] = usbGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE] = usbGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOW_USB_SERIAL] = usbGroup;

        // Group 2: Bluetooth cluster (3 policies)
        const uint32_t bluetoothGroup = 2;
        conflictGroupMap_[EdmInterfaceCode::DISABLE_BLUETOOTH] = bluetoothGroup;
        conflictGroupMap_[EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES] = bluetoothGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES] = bluetoothGroup;

        // Group 3: WiFi list cluster (3 policies)
        const uint32_t wifiGroup = 3;
        conflictGroupMap_[EdmInterfaceCode::DISABLE_WIFI] = wifiGroup;
        conflictGroupMap_[EdmInterfaceCode::ALLOWED_WIFI_LIST] = wifiGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_WIFI_LIST] = wifiGroup;

        // Group 4: MTP client pair (2 policies)
        const uint32_t mtpGroup = 4;
        conflictGroupMap_[EdmInterfaceCode::DISABLE_MTP_CLIENT] = mtpGroup;
        conflictGroupMap_[EdmInterfaceCode::DISABLE_USER_MTP_CLIENT] = mtpGroup;

        // Group 5: Distributed transmission pair (2 policies)
        const uint32_t distGroup = 5;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION] = distGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL] = distGroup;

        // Group 6: Sudo pair (2 policies)
        const uint32_t sudoGroup = 6;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_SUDO] = sudoGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DEVICE_SUDO] = sudoGroup;

        // Group 7: Notification pair (2 policies)
        const uint32_t notifGroup = 7;
        conflictGroupMap_[EdmInterfaceCode::DISALLOWED_NOTIFICATION] = notifGroup;
        conflictGroupMap_[EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES] = notifGroup;

        // Group 8: App running bundles cluster (3 policies)
        const uint32_t runningBundlesGroup = 8;
        conflictGroupMap_[EdmInterfaceCode::ALLOW_RUNNING_BUNDLES] = runningBundlesGroup;
        conflictGroupMap_[EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES] = runningBundlesGroup;
        conflictGroupMap_[EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS] = runningBundlesGroup;
    });
}
```

- [ ] **Step 5: Implement GetPolicyLock and GetConflictSetLock in plugin_manager.cpp**

Add these methods after `InitConflictGroupMap`:

```cpp
std::shared_ptr<std::shared_mutex> PluginManager::GetPolicyLock(uint32_t policyCode)
{
    std::lock_guard<std::mutex> lock(policyLocksMapMutex_);
    auto it = policyLocks_.find(policyCode);
    if (it != policyLocks_.end()) {
        return it->second;
    }
    auto newLock = std::make_shared<std::shared_mutex>();
    policyLocks_[policyCode] = newLock;
    return newLock;
}

std::shared_ptr<std::shared_mutex> PluginManager::GetConflictSetLock(uint32_t policyCode)
{
    auto groupIt = conflictGroupMap_.find(policyCode);
    if (groupIt == conflictGroupMap_.end()) {
        return nullptr;
    }
    uint32_t groupId = groupIt->second;
    std::lock_guard<std::mutex> lock(conflictSetLocksMapMutex_);
    auto it = conflictSetLocks_.find(groupId);
    if (it != conflictSetLocks_.end()) {
        return it->second;
    }
    auto newLock = std::make_shared<std::shared_mutex>();
    conflictSetLocks_[groupId] = newLock;
    return newLock;
}
```

- [ ] **Step 6: Build to verify compilation**

Run: `./build.sh --build-target enterprise_device_management`
Expected: Build succeeds (new members and methods are additive; old `mutexLock_` still exists)

- [ ] **Step 7: Commit**

```bash
git add services/edm/include/plugin_manager.h services/edm/src/plugin_manager.cpp
git commit -m "feat(edm): add new lock members and helper methods for concurrency optimization

Add globalMutex_, pluginMapMutex_, policyLocks_, conflictSetLocks_, and
conflictGroupMap_ as new static members. Implement GetPolicyLock,
GetConflictSetLock, and InitConflictGroupMap helpers. The old mutexLock_
is retained until all methods are migrated in the next task."
```

---

### Task 2: Migrate All PluginManager Methods to New Locking Scheme

**Files:**
- Modify: `services/edm/include/plugin_manager.h` (remove `mutexLock_`)
- Modify: `services/edm/src/plugin_manager.cpp` (migrate all methods)

**Interfaces:**
- Consumes: `GetPolicyLock`, `GetConflictSetLock`, `InitConflictGroupMap` from Task 1
- Produces: All PluginManager methods using the new three-layer locking scheme

**Note on `GetInstance()`:** The spec proposed `std::call_once`, but existing tests call `GetInstance().reset()` in TearDown, which would break `call_once` (the flag can only fire once). Instead, use double-checked locking with `globalMutex_`. `InitConflictGroupMap()` still uses `std::call_once` internally — it's safe because the conflict group map is static and never reset.

- [ ] **Step 1: Modify GetInstance() to use globalMutex_**

Replace the `GetInstance` method (line 154-165) with:

```cpp
std::shared_ptr<PluginManager> PluginManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::unique_lock<std::shared_mutex> autoLock(globalMutex_);
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) PluginManager());
            InitConflictGroupMap();
        }
    }
    IPluginManager::pluginManagerInstance_ = instance_.get();
    return instance_;
}
```

- [ ] **Step 2: Modify GetPluginByFuncCode to use double-checked locking**

Replace `GetPluginByFuncCode` (line 167-186) with:

```cpp
std::shared_ptr<IPlugin> PluginManager::GetPluginByFuncCode(std::uint32_t funcCode)
{
    EDMLOGD("PluginManager::GetPluginByFuncCode %{public}u", funcCode);
    std::uint32_t code = FuncCodeUtils::GetPolicyCode(funcCode);
    FuncCodeUtils::PrintFuncCode(funcCode);
    FuncFlag flag = FuncCodeUtils::GetSystemFlag(funcCode);
    if (flag == FuncFlag::POLICY_FLAG) {
        EDMLOGD("PluginManager::code %{public}u", code);
        // Fast path: shared lock for lookup
        {
            std::shared_lock<std::shared_mutex> lock(pluginMapMutex_);
            auto it = pluginsCode_.find(code);
            if (it != pluginsCode_.end()) {
                return it->second;
            }
        }
        // Slow path: exclusive lock for loading
        {
            std::unique_lock<std::shared_mutex> lock(pluginMapMutex_);
            auto it = pluginsCode_.find(code);
            if (it != pluginsCode_.end()) {
                return it->second;
            }
            auto loadRet = LoadPluginByFuncCode(funcCode);
            if (loadRet != ERR_OK) {
                EDMLOGD("GetPluginByFuncCode::load plugin failed");
                return nullptr;
            }
            it = pluginsCode_.find(code);
            if (it != pluginsCode_.end()) {
                return it->second;
            }
        }
    }
    EDMLOGD("GetPluginByFuncCode::return nullptr");
    return nullptr;
}
```

- [ ] **Step 3: Modify GetPluginByCode and GetPluginByPolicyName to use shared lock**

Replace `GetPluginByCode` (line 197-206) and `GetPluginByPolicyName` (line 188-195) with:

```cpp
std::shared_ptr<IPlugin> PluginManager::GetPluginByPolicyName(const std::string &policyName)
{
    std::shared_lock<std::shared_mutex> lock(pluginMapMutex_);
    auto it = pluginsName_.find(policyName);
    if (it != pluginsName_.end()) {
        return it->second;
    }
    EDMLOGI("GetPluginByPolicyName::return nullptr");
    return nullptr;
}

std::shared_ptr<IPlugin> PluginManager::GetPluginByCode(std::uint32_t code)
{
    EDMLOGD("PluginManager::code %{public}u", code);
    std::shared_lock<std::shared_mutex> lock(pluginMapMutex_);
    auto it = pluginsCode_.find(code);
    if (it != pluginsCode_.end()) {
        return it->second;
    }
    EDMLOGI("GetPluginByCode::return nullptr");
    return nullptr;
}
```

- [ ] **Step 4: Modify UpdateDevicePolicy to use new SET flow**

Replace `UpdateDevicePolicy` (line 608-638) with:

```cpp
ErrCode PluginManager::UpdateDevicePolicy(uint32_t code, const std::string &bundleName,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::shared_lock<std::shared_mutex> autoLock(globalMutex_);
    InitConflictGroupMap();
    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("UpdateDevicePolicy: get plugin by funcCode failed: %{public}d.", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    uint32_t policyCode = FuncCodeUtils::GetPolicyCode(code);
    auto conflictLock = GetConflictSetLock(policyCode);
    std::unique_ptr<std::unique_lock<std::shared_mutex>> conflictGuard;
    if (conflictLock != nullptr) {
        conflictGuard = std::make_unique<std::unique_lock<std::shared_mutex>>(*conflictLock);
    }
    auto policyLock = GetPolicyLock(policyCode);
    std::unique_lock<std::shared_mutex> policyGuard(*policyLock);

    std::string policyName = plugin->GetPolicyName();
    std::string oldCombinePolicy;
    PolicyManager::GetInstance()->GetPolicy("", policyName, oldCombinePolicy, userId);
    HandlePolicyData handlePolicyData{"", "", false};
    PolicyManager::GetInstance()->GetPolicy(bundleName, policyName, handlePolicyData.policyData, userId);
    plugin->GetOthersMergePolicyData(bundleName, userId, handlePolicyData.mergePolicyData);
    ErrCode ret = plugin->GetExecuteStrategy()->OnSetExecute(code, data, reply, handlePolicyData, userId);
    if (FAILED(ret)) {
        EDMLOGW("UpdateDevicePolicy: OnHandlePolicy failed");
        return ret;
    }
    EDMLOGD("UpdateDevicePolicy: isChanged:%{public}d, needSave:%{public}d", handlePolicyData.isChanged,
        plugin->NeedSavePolicy());
    bool isGlobalChanged = false;
    if (plugin->NeedSavePolicy() && handlePolicyData.isChanged) {
        PolicyManager::GetInstance()->SetPolicy(bundleName, policyName, handlePolicyData.policyData,
            handlePolicyData.mergePolicyData, userId);
        isGlobalChanged = (oldCombinePolicy != handlePolicyData.mergePolicyData);
    }
    plugin->OnHandlePolicyDone(code, bundleName, isGlobalChanged, userId);
    return ERR_OK;
}
```

- [ ] **Step 5: Modify GetPolicy to use new GET flow**

Replace `GetPolicy` (line 640-655) with:

```cpp
ErrCode PluginManager::GetPolicy(uint32_t funcCode, const std::string &bundleName, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    std::shared_lock<std::shared_mutex> autoLock(globalMutex_);
    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        EDMLOGE("PluginManager::GetPolicy get plugin by funcCode fail: %{public}u.", funcCode);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    uint32_t policyCode = FuncCodeUtils::GetPolicyCode(funcCode);
    auto policyLock = GetPolicyLock(policyCode);
    std::shared_lock<std::shared_mutex> policyGuard(*policyLock);

    std::string policyValue;
    if (plugin->NeedSavePolicy()) {
        PolicyManager::GetInstance()->GetPolicy(bundleName, plugin->GetPolicyName(), policyValue, userId);
    }
    auto ret = plugin->GetExecuteStrategy()->OnGetExecute(funcCode, policyValue, data, reply, userId);
    return ret;
}
```

- [ ] **Step 6: Modify RemoveAdminItem to use new admin removal flow**

Replace `RemoveAdminItem` (line 657-694) with:

```cpp
ErrCode PluginManager::RemoveAdminItem(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue, int32_t userId)
{
    std::unique_lock<std::shared_mutex> autoLock(globalMutex_);
    InitConflictGroupMap();
    {
        std::unique_lock<std::shared_mutex> mapLock(pluginMapMutex_);
        LoadAllPlugin();
    }
    std::shared_ptr<IPlugin> plugin = GetPluginByPolicyName(policyName);
    if (plugin == nullptr) {
        EDMLOGW("RemoveAdminItem: Get plugin by policyName failed: %{public}s", policyName.c_str());
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }
    auto funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, plugin->GetCode());
    auto conflictLock = GetConflictSetLock(plugin->GetCode());
    std::unique_ptr<std::unique_lock<std::shared_mutex>> conflictGuard;
    if (conflictLock != nullptr) {
        conflictGuard = std::make_unique<std::unique_lock<std::shared_mutex>>(*conflictLock);
    }
    auto policyLock = GetPolicyLock(plugin->GetCode());
    std::unique_lock<std::shared_mutex> policyGuard(*policyLock);

    std::string mergedPolicyData;
    plugin->GetOthersMergePolicyData(adminName, userId, mergedPolicyData);
    ErrCode ret = plugin->GetExecuteStrategy()->OnAdminRemoveExecute(funcCode, adminName, policyValue, mergedPolicyData,
        userId);
    if (ret != ERR_OK) {
        EDMLOGW("RemoveAdminItem: OnAdminRemove failed, admin:%{public}s, value:%{public}s, res:%{public}d.",
            adminName.c_str(), policyValue.c_str(), ret);
    }
    if (plugin->NeedSavePolicy()) {
        ErrCode setRet = ERR_OK;
        std::unordered_map<std::string, std::string> adminListMap;
        ret = PolicyManager::GetInstance()->GetAdminByPolicyName(policyName, adminListMap, userId);
        if ((ret == ERR_EDM_POLICY_NOT_FOUND) || adminListMap.empty()) {
            setRet = PolicyManager::GetInstance()->SetPolicy("", policyName, "", "", userId);
        } else {
            setRet = PolicyManager::GetInstance()->SetPolicy(adminName, policyName, "", mergedPolicyData, userId);
        }

        if (FAILED(setRet)) {
            EDMLOGW("RemoveAdminItem: DeleteAdminPolicy failed, admin:%{public}s, policy:%{public}s, res:%{public}d.",
                adminName.c_str(), policyValue.c_str(), ret);
            return ERR_EDM_DEL_ADMIN_FAILED;
        }
    }
    plugin->OnAdminRemoveDone(adminName, policyValue, userId);
    return ERR_OK;
}
```

- [ ] **Step 7: Modify CallOnOtherServiceStart and OnInitExecute**

Replace `CallOnOtherServiceStart` (line 696-710) with:

```cpp
void PluginManager::CallOnOtherServiceStart(uint32_t interfaceCode, int32_t systemAbilityId)
{
    EDMLOGI("PluginManager::CallOnOtherServiceStart %{public}d", interfaceCode);
    std::unique_lock<std::shared_mutex> autoLock(globalMutex_);
    {
        std::unique_lock<std::shared_mutex> mapLock(pluginMapMutex_);
        auto ret = LoadPluginByCode(interfaceCode);
        if (ret != ERR_OK) {
            return;
        }
    }
    auto plugin = GetPluginByCode(interfaceCode);
    if (plugin == nullptr) {
        EDMLOGE("CallOnOtherServiceStart get Plugin by code fail: %{public}u", interfaceCode);
        return;
    }
    plugin->OnOtherServiceStart(systemAbilityId);
}
```

Replace `OnInitExecute` (line 712-729) with:

```cpp
void PluginManager::OnInitExecute(uint32_t interfaceCode, const std::vector<std::string> &bundleNames, int32_t userId)
{
    EDMLOGI("PluginManager::OnInitExecute %{public}u", interfaceCode);
    std::unique_lock<std::shared_mutex> autoLock(globalMutex_);
    {
        std::unique_lock<std::shared_mutex> mapLock(pluginMapMutex_);
        auto ret = LoadPluginByCode(interfaceCode);
        if (ret != ERR_OK) {
            return;
        }
    }
    auto plugin = GetPluginByCode(interfaceCode);
    if (plugin == nullptr) {
        EDMLOGE("OnInitExecute get Plugin by code fail: %{public}u.", interfaceCode);
        return;
    }
    auto funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, interfaceCode);
    for (const std::string &bundleName : bundleNames) {
        plugin->GetExecuteStrategy()->OnInitExecute(funcCode, bundleName, userId);
    }
}
```

- [ ] **Step 8: Modify SetPluginUnloadFlag and UnloadCollectLogPlugin**

Replace `SetPluginUnloadFlag` (line 731-746) with:

```cpp
ErrCode PluginManager::SetPluginUnloadFlag(uint32_t code, bool unloadFlag)
{
    EDMLOGI("PluginManager::SetPluginUnloadFlag %{public}u", code);
    std::shared_lock<std::shared_mutex> autoLock(globalMutex_);
    auto funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, code);
    auto plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        EDMLOGE("SetPluginUnloadFlag get Plugin by code fail: %{public}u.", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    plugin->SetPluginUnloadFlag(unloadFlag);
    return ERR_OK;
}
```

Replace `UnloadCollectLogPlugin` (line 748-764) with:

```cpp
ErrCode PluginManager::UnloadCollectLogPlugin()
{
    EDMLOGI("PluginManager::UnloadCollectLogPlugin");
    std::shared_lock<std::shared_mutex> autoLock(globalMutex_);
    auto code = EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::START_COLLECT_LOG;
    auto funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, code);
    auto plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        EDMLOGE("UnloadCollectLogPlugin get Plugin by code fail: %{public}u.", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    plugin->SetPluginUnloadFlag(true);
    return ERR_OK;
}
```

- [ ] **Step 9: Modify metadata queries (GetPermission, GetPluginType, GetPolicyName, GetPluginPermissionByPolicyName)**

Replace `GetPermission` (line 766-776) with:

```cpp
std::string PluginManager::GetPermission(uint32_t funcCode, FuncOperateType operateType,
    IPlugin::PermissionType permissionType, const std::string &permissionTag)
{
    std::shared_lock<std::shared_mutex> autoLock(globalMutex_);
    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        EDMLOGE("PluginManager::GetPermission get plugin by funcCode fail: %{public}u.", funcCode);
        return NONE_PERMISSION_MATCH;
    }
    return plugin->GetPermission(operateType, permissionType, permissionTag);
}
```

Replace `GetPluginType` (line 778-787) with:

```cpp
IPlugin::ApiType PluginManager::GetPluginType(uint32_t funcCode, FuncOperateType operateType)
{
    std::shared_lock<std::shared_mutex> autoLock(globalMutex_);
    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        EDMLOGE("PluginManager::GetPluginType get plugin by funcCode fail: %{public}u.", funcCode);
        return IPlugin::ApiType::UNKNOWN;
    }
    return plugin->GetApiType(operateType);
}
```

Replace `GetPolicyName` (line 789-799) with:

```cpp
std::string PluginManager::GetPolicyName(uint32_t funcCode)
{
    std::shared_lock<std::shared_mutex> autoLock(globalMutex_);
    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        EDMLOGE("PluginManager::GetPolicyName get plugin by funcCode fail: %{public}u.", funcCode);
        return "";
    }
    auto ret = plugin->GetPolicyName();
    return ret;
}
```

Replace `GetPluginPermissionByPolicyName` (line 801-818) with:

```cpp
std::string PluginManager::GetPluginPermissionByPolicyName(const std::string &policyName,
    IPlugin::PermissionType permissionType)
{
    std::shared_lock<std::shared_mutex> autoLock(globalMutex_);
    {
        std::unique_lock<std::shared_mutex> mapLock(pluginMapMutex_);
        LoadAllPlugin();
    }
    std::shared_ptr<IPlugin> plugin = GetPluginByPolicyName(policyName);
    if (plugin == nullptr) {
        EDMLOGE("GetPluginPermissionByPolicyName get plugin by policy name fail: %{public}s.", policyName.c_str());
        return "";
    }
    auto permission = plugin->GetPermission(FuncOperateType::SET, permissionType);
    if (permission == NONE_PERMISSION_MATCH) {
        permission = plugin->GetPermission(FuncOperateType::SET, permissionType,
            EdmConstants::PERMISSION_TAG_VERSION_12);
    }
    EDMLOGD("GetPluginPermissionByPolicyName get permission %{public}s success", permission.c_str());
    return permission;
}
```

- [ ] **Step 10: Modify UnloadPluginTask to use new locks**

Replace the lock acquisition in `UnloadPluginTask` (line 362) with:

```cpp
void PluginManager::UnloadPluginTask(const std::string &soName, std::shared_ptr<SoLoadState> loadStatePtr)
{
    while (loadStatePtr->pluginHasInit) {
        {
            std::unique_lock<std::mutex> lock(loadStatePtr->waitMutex);
            loadStatePtr->notifySignal = false;
            loadStatePtr->waitSignal.wait_for(lock, std::chrono::milliseconds(TIMER_TIMEOUT), [=] {
                return loadStatePtr->notifySignal;
            });
        }
        std::unique_lock<std::shared_mutex> globalLock(globalMutex_);
        std::unique_lock<std::shared_mutex> mapLock(pluginMapMutex_);
        auto now = std::chrono::system_clock::now();
        auto diffTime = std::chrono::duration_cast<std::chrono::milliseconds>(now - loadStatePtr->lastCallTime).count();
        if (diffTime >= std::chrono::milliseconds(TIMER_TIMEOUT).count()) {
            if (UnloadPlugin(soName)) {
                loadStatePtr->pluginHasInit = false;
            }
        }
    }
}
```

- [ ] **Step 11: Remove old mutexLock_ declaration from header**

In `plugin_manager.h`, remove the line:
```cpp
static std::shared_timed_mutex mutexLock_;
```

- [ ] **Step 12: Remove old mutexLock_ definition from source**

In `plugin_manager.cpp`, remove the line:
```cpp
std::shared_timed_mutex PluginManager::mutexLock_;
```

- [ ] **Step 13: Build to verify compilation**

Run: `./build.sh --build-target enterprise_device_management`
Expected: Build succeeds with no references to `mutexLock_`

- [ ] **Step 14: Run existing unit tests**

Run:
```bash
cd test/testfwk/developer_test
./start.sh -t edm -s PluginManagerTest
./start.sh -t edm -s EnterpriseDeviceMgrAbilityTest
./start.sh -t edm -s UpdatePolicyConflictTest
```
Expected: All tests pass (locking changes are internal, no behavior change)

- [ ] **Step 15: Commit**

```bash
git add services/edm/include/plugin_manager.h services/edm/src/plugin_manager.cpp
git commit -m "refactor(edm): migrate PluginManager to three-layer locking scheme

Replace single global mutexLock_ (exclusive for all ops) with:
- globalMutex_ (shared for policy ops, exclusive for load/unload/admin removal)
- pluginMapMutex_ (shared for lookups, exclusive for load/unload, double-checked loading)
- Per-policy shared_mutex locks (exclusive for SET, shared for GET)
- Per-conflict-group SET locks (exclusive, only for SET — GETs never touch)

All existing unit tests pass without modification."
```

---

### Task 3: Add Concurrency Unit Tests

**Files:**
- Create: `test/unittest/services/edm/src/plugin_manager_concurrency_test.cpp`
- Modify: `test/unittest/services/edm/BUILD.gn` (add new test source)

**Interfaces:**
- Consumes: `PluginManager::GetInstance()`, `PluginManager::UpdateDevicePolicy()`, `PluginManager::GetPolicy()`, `PluginManager::GetPolicyLock()`, `PluginManager::GetConflictSetLock()` from Tasks 1-2

- [ ] **Step 1: Write concurrency test file**

Create `test/unittest/services/edm/src/plugin_manager_concurrency_test.cpp`:

```cpp
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define private public
#define protected public
#include "plugin_manager.h"
#undef protected
#undef private

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include "edm_ipc_interface_code.h"
#include "func_code_utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {

class PluginManagerConcurrencyTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ParallelSetDifferentPolicies
 * @tc.desc: Two threads SET different non-conflicting policies; both should proceed in parallel.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ParallelSetDifferentPolicies, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code1 = EdmInterfaceCode::DISABLE_CAMERA;
    uint32_t code2 = EdmInterfaceCode::SCREEN_OFF_TIME;
    auto lock1 = pm->GetPolicyLock(code1);
    auto lock2 = pm->GetPolicyLock(code2);
    ASSERT_NE(lock1, nullptr);
    ASSERT_NE(lock2, nullptr);
    ASSERT_NE(lock1.get(), lock2.get());

    std::atomic<int> runningCount(0);
    std::atomic<bool> bothConcurrent(false);

    auto setFunc = [&](std::shared_ptr<std::shared_mutex> lock) {
        std::unique_lock<std::shared_mutex> guard(*lock);
        runningCount++;
        if (runningCount.load() == 2) {
            bothConcurrent.store(true);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        runningCount--;
    };

    std::thread t1(setFunc, lock1);
    std::thread t2(setFunc, lock2);
    t1.join();
    t2.join();
    EXPECT_TRUE(bothConcurrent.load());
}

/**
 * @tc.name: ParallelSetSamePolicy
 * @tc.desc: Two threads SET the same policy; second must wait for first.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ParallelSetSamePolicy, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code = EdmInterfaceCode::DISABLE_CAMERA;
    auto lock = pm->GetPolicyLock(code);
    ASSERT_NE(lock, nullptr);

    std::atomic<bool> firstStarted(false);
    std::atomic<bool> secondStartedTooEarly(false);

    auto setFunc = [&](bool isFirst) {
        std::unique_lock<std::shared_mutex> guard(*lock);
        if (isFirst) {
            firstStarted.store(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        } else {
            if (!firstStarted.load()) {
                secondStartedTooEarly.store(true);
            }
        }
    };

    std::thread t1(setFunc, true);
    std::thread t2(setFunc, false);
    t1.join();
    t2.join();
    EXPECT_FALSE(secondStartedTooEarly.load());
}

/**
 * @tc.name: ParallelGetSamePolicy
 * @tc.desc: Multiple threads GET the same policy; all should proceed in parallel.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ParallelGetSamePolicy, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code = EdmInterfaceCode::DISABLE_CAMERA;
    auto lock = pm->GetPolicyLock(code);
    ASSERT_NE(lock, nullptr);

    std::atomic<int> runningCount(0);
    std::atomic<bool> allConcurrent(false);

    auto getFunc = [&]() {
        std::shared_lock<std::shared_mutex> guard(*lock);
        runningCount++;
        if (runningCount.load() == 3) {
            allConcurrent.store(true);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        runningCount--;
    };

    std::thread t1(getFunc);
    std::thread t2(getFunc);
    std::thread t3(getFunc);
    t1.join();
    t2.join();
    t3.join();
    EXPECT_TRUE(allConcurrent.load());
}

/**
 * @tc.name: SetBlocksGetSamePolicy
 * @tc.desc: SET blocks GET for the same policy.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, SetBlocksGetSamePolicy, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code = EdmInterfaceCode::DISABLE_CAMERA;
    auto lock = pm->GetPolicyLock(code);
    ASSERT_NE(lock, nullptr);

    std::atomic<bool> setStarted(false);
    std::atomic<bool> getStartedDuringSet(false);

    auto setFunc = [&]() {
        std::unique_lock<std::shared_mutex> guard(*lock);
        setStarted.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    };

    auto getFunc = [&]() {
        std::shared_lock<std::shared_mutex> guard(*lock);
        if (setStarted.load()) {
            getStartedDuringSet.store(true);
        }
    };

    std::thread setThread(setFunc);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::thread getThread(getFunc);
    setThread.join();
    getThread.join();
    EXPECT_FALSE(getStartedDuringSet.load());
}

/**
 * @tc.name: SetDoesNotBlockGetDifferentPolicy
 * @tc.desc: SET on policy X does NOT block GET on policy Y.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, SetDoesNotBlockGetDifferentPolicy, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code1 = EdmInterfaceCode::DISABLE_CAMERA;
    uint32_t code2 = EdmInterfaceCode::SCREEN_OFF_TIME;
    auto lock1 = pm->GetPolicyLock(code1);
    auto lock2 = pm->GetPolicyLock(code2);
    ASSERT_NE(lock1.get(), lock2.get());

    std::atomic<bool> setStarted(false);
    std::atomic<bool> getSucceededDuringSet(false);

    auto setFunc = [&]() {
        std::unique_lock<std::shared_mutex> guard(*lock1);
        setStarted.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    };

    auto getFunc = [&]() {
        std::shared_lock<std::shared_mutex> guard(*lock2);
        if (setStarted.load()) {
            getSucceededDuringSet.store(true);
        }
    };

    std::thread setThread(setFunc);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::thread getThread(getFunc);
    setThread.join();
    getThread.join();
    EXPECT_TRUE(getSucceededDuringSet.load());
}

/**
 * @tc.name: ConflictGroupSetSerialized
 * @tc.desc: SETs of conflicting policies (same conflict group) are serialized.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ConflictGroupSetSerialized, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    pm->InitConflictGroupMap();
    uint32_t code1 = EdmInterfaceCode::DISABLE_USB;
    uint32_t code2 = EdmInterfaceCode::ALLOWED_USB_DEVICES;
    auto conflictLock1 = pm->GetConflictSetLock(code1);
    auto conflictLock2 = pm->GetConflictSetLock(code2);
    ASSERT_NE(conflictLock1, nullptr);
    ASSERT_NE(conflictLock2, nullptr);
    ASSERT_EQ(conflictLock1.get(), conflictLock2.get());

    std::atomic<bool> firstStarted(false);
    std::atomic<bool> secondStartedTooEarly(false);

    auto setFunc = [&](bool isFirst) {
        std::unique_lock<std::shared_mutex> guard(*conflictLock1);
        if (isFirst) {
            firstStarted.store(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        } else {
            if (!firstStarted.load()) {
                secondStartedTooEarly.store(true);
            }
        }
    };

    std::thread t1(setFunc, true);
    std::thread t2(setFunc, false);
    t1.join();
    t2.join();
    EXPECT_FALSE(secondStartedTooEarly.load());
}

/**
 * @tc.name: ConflictGroupGetParallel
 * @tc.desc: GET of a conflict-group policy does NOT use the conflict SET lock.
 *          SET on policy X does not block GET on policy Y (same conflict group).
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ConflictGroupGetParallel, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    pm->InitConflictGroupMap();
    uint32_t code1 = EdmInterfaceCode::DISABLE_USB;
    uint32_t code2 = EdmInterfaceCode::ALLOWED_USB_DEVICES;
    auto conflictLock = pm->GetConflictSetLock(code1);
    auto policyLock2 = pm->GetPolicyLock(code2);
    ASSERT_NE(conflictLock, nullptr);
    ASSERT_NE(policyLock2, nullptr);
    ASSERT_NE(conflictLock.get(), policyLock2.get());

    std::atomic<bool> setStarted(false);
    std::atomic<bool> getSucceededDuringSet(false);

    auto setFunc = [&]() {
        std::unique_lock<std::shared_mutex> guard(*conflictLock);
        setStarted.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    };

    auto getFunc = [&]() {
        std::shared_lock<std::shared_mutex> guard(*policyLock2);
        if (setStarted.load()) {
            getSucceededDuringSet.store(true);
        }
    };

    std::thread setThread(setFunc);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::thread getThread(getFunc);
    setThread.join();
    getThread.join();
    EXPECT_TRUE(getSucceededDuringSet.load());
}

/**
 * @tc.name: ConflictGroupMapInitialized
 * @tc.desc: Verify conflict group map is correctly initialized.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ConflictGroupMapInitialized, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    pm->InitConflictGroupMap();
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_USB], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOWED_USB_DEVICES], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_USB_DEVICES], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::USB_READ_ONLY], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOW_USB_SERIAL], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_BLUETOOTH], 2u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES], 2u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES], 2u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_WIFI], 3u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOWED_WIFI_LIST], 3u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_WIFI_LIST], 3u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_MTP_CLIENT], 4u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_USER_MTP_CLIENT], 4u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION], 5u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL], 5u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_SUDO], 6u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DEVICE_SUDO], 6u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_NOTIFICATION], 7u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES], 7u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOW_RUNNING_BUNDLES], 8u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES], 8u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS], 8u);
    EXPECT_EQ(pm->conflictGroupMap_.count(EdmInterfaceCode::DISABLE_CAMERA), 0u);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
```

- [ ] **Step 2: Add test source to BUILD.gn**

In `test/unittest/services/edm/BUILD.gn`, add the new test file to the `sources` of the `PluginManagerUnitTest` target (line 472-474):

```gn
ohos_unittest("PluginManagerUnitTest") {
  # ...
  sources = [
    "./src/plugin_manager_test.cpp",
    "./src/plugin_manager_concurrency_test.cpp",  # ADD THIS LINE
  ]
  # ...
}
```

- [ ] **Step 3: Build the tests**

Run: `./build.sh --build-target enterprise_device_management`
Expected: Build succeeds, new test file compiles

- [ ] **Step 4: Run the concurrency tests**

Run:
```bash
cd test/testfwk/developer_test
./start.sh -t edm -s PluginManagerConcurrencyTest
```
Expected: All concurrency tests pass

- [ ] **Step 5: Commit**

```bash
git add test/unittest/services/edm/src/plugin_manager_concurrency_test.cpp test/unittest/services/edm/BUILD.gn
git commit -m "test(edm): add concurrency unit tests for PluginManager locking

Tests verify: parallel SET of different policies, serialized SET of same
policy, parallel GET of same policy, SET blocks GET same policy, SET does
not block GET different policy, conflict group SET serialized, conflict
group GET parallel, conflict group map initialization."
```

---

### Task 4: Run Full Test Suite and Verify

**Files:**
- No file changes — verification only

- [ ] **Step 1: Run all EDM unit tests**

Run:
```bash
cd test/testfwk/developer_test
./start.sh -t edm
```
Expected: All tests pass, including:
- PluginManagerTest
- PluginManagerConcurrencyTest
- EnterpriseDeviceMgrAbilityTest
- UpdatePolicyConflictTest
- All plugin tests in edm_plugin

- [ ] **Step 2: Verify no references to old mutexLock_ remain**

Run: `grep -r "mutexLock_" services/edm/`
Expected: No output (all references removed)

- [ ] **Step 3: Verify no references to shared_timed_mutex in PluginManager**

Run: `grep "shared_timed_mutex" services/edm/include/plugin_manager.h services/edm/src/plugin_manager.cpp`
Expected: No output (replaced with shared_mutex)

- [ ] **Step 4: Final commit (if any cleanup needed)**

If the verification in steps 1-3 passes with no issues, no additional commit is needed. If cleanup is required, commit the changes.
