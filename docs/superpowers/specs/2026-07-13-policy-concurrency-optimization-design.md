# Policy Concurrency Optimization Design

**Date:** 2026-07-13  
**Scope:** `PluginManager` lock optimization in `services/edm/`  
**Status:** Approved  

## Problem Statement

All policy operations in `EnterpriseDeviceMgrAbility` enter through `HandleDevicePolicy` and ultimately call `PluginManager::UpdateDevicePolicy`. The `PluginManager::mutexLock_` (a single `std::shared_timed_mutex`) is used as an **exclusive write lock** (`std::unique_lock`) for every operation — SET, GET, plugin load/unload, admin removal, and metadata queries.

This causes:

1. **All policy SETs are serialized** globally — even for unrelated policies.
2. **All policy GETs are serialized** globally — even for unrelated policies.
3. **A GET blocks during a SET** for any policy — even different policies.
4. **Plugin load/unload blocks everything** — necessary, but the granularity is correct.

## Requirements

1. **Same policy:** SETs serialized, GETs parallel; SET blocks GET for that policy.
2. **Different policies:** SETs parallel, GETs parallel.
3. **Plugin load/unload:** blocks all policy SETs and GETs.
4. **Admin removal:** blocks all policy SETs and GETs.
5. **Conflict policies:** conflicting SETs serialized; GETs still parallel; only same-policy writes block same-policy reads (not cross-policy).

## Design: Three-Layer Locking

Replace the single `mutexLock_` with three lock layers:

### Layer 1: `globalMutex_` (`std::shared_mutex`) — Global Gate

Replaces `mutexLock_` as the "block everything" mechanism. Reader-writer lock:

| Operation | Lock | Effect |
|-----------|------|--------|
| Plugin load/unload | exclusive | Blocks all policy ops |
| Admin removal (`RemoveAdminItem`) | exclusive | Blocks all policy ops |
| Policy SET (`UpdateDevicePolicy`) | shared | Allows parallel SETs; blocked during load/unload/admin removal |
| Policy GET (`GetPolicy`) | shared | Allows parallel GETs; blocked during load/unload/admin removal |
| Metadata queries (`GetPermission`, `GetPluginType`, `GetPolicyName`) | shared | Read-only; parallel |
| `CallOnOtherServiceStart`, `OnInitExecute` | exclusive | Infrequent; blocks all |

### Layer 2: `pluginMapMutex_` (`std::shared_mutex`) — Plugin Map Access

Separate from the gate to allow on-demand plugin loading while holding the gate's shared lock.

| Operation | Lock |
|-----------|------|
| `LoadPlugin` / `LoadAllPlugin` / `LoadExtraPlugin` | exclusive (modifies `pluginsCode_`, `pluginsName_`, `soLoadStateMap_`) |
| `UnloadPlugin` / `UnloadPluginTask` | exclusive (modifies same maps) |
| `GetPluginByFuncCode` (already loaded) | shared (read-only lookup) |
| `GetPluginByFuncCode` (not loaded) | exclusive via double-checked locking |
| `GetPluginByCode` / `GetPluginByPolicyName` | shared |
| `AddPlugin` / `RemovePlugin` | none (called within load/unload scope) |

**Double-checked `GetPluginByFuncCode`:**

```cpp
std::shared_ptr<IPlugin> PluginManager::GetPluginByFuncCode(uint32_t funcCode)
{
    uint32_t code = FuncCodeUtils::GetPolicyCode(funcCode);
    // Fast path: shared lock
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
        LoadPluginByFuncCode(funcCode);
        it = pluginsCode_.find(code);
        if (it != pluginsCode_.end()) {
            return it->second;
        }
    }
    return nullptr;
}
```

**Safety of the double-checked gap:** The gap between releasing shared and acquiring exclusive on `pluginMapMutex_` is safe because the caller holds shared on `globalMutex_`. Plugin unload needs exclusive on `globalMutex_`, so it cannot fire during this gap. Another thread might load the same plugin in the gap — the double-check handles this.

### Layer 3a: Per-Policy Locks (`std::shared_mutex` per policy)

For same-policy serialization:

| Operation | Lock | Effect |
|-----------|------|--------|
| Policy SET | exclusive on own policy's lock | Serializes same-policy SETs; blocks same-policy GETs |
| Policy GET | shared on own policy's lock | Allows parallel same-policy GETs; blocked by same-policy SET |
| `RemoveAdminItem` | exclusive on own policy's lock | Blocks same-policy GETs during removal |

Each policy has its own lock. Different policies have no lock contention.

Stored as `std::unordered_map<uint32_t, std::shared_ptr<std::shared_mutex>>` (since `std::shared_mutex` is non-movable). Created lazily on first access via `GetPolicyLock(policyCode)`.

### Layer 3b: Conflict Group SET Locks (`std::shared_mutex` per conflict group)

For conflict-group SET serialization (requirement #5):

| Operation | Lock | Effect |
|-----------|------|--------|
| Policy SET (in conflict group) | exclusive on conflict group's lock | Serializes SETs of conflicting policies |
| Policy GET | NOT used | GETs never touch conflict SET locks |

**Critical:** GETs do NOT acquire conflict SET locks. This ensures that SET A only blocks GET A (via the per-policy lock), not GET B (which is in the same conflict group but has a different per-policy lock).

Only policies in a conflict group have entries in `conflictGroupMap_`. Non-conflict policies skip the conflict SET lock entirely.

**Locking order for SET (conflict-group policy):**
1. `globalMutex_` (shared)
2. Conflict SET lock (exclusive)
3. Per-policy lock (exclusive)

**Locking order for SET (non-conflict policy):**
1. `globalMutex_` (shared)
2. Per-policy lock (exclusive)

**Locking order for GET (any policy):**
1. `globalMutex_` (shared)
2. Per-policy lock (shared)

**Overall locking order:** `globalMutex_` → `pluginMapMutex_` (brief, for lookup) → conflict SET lock → per-policy lock. No deadlock possible (strict DAG).

### Requirement Verification

| Requirement | How Satisfied |
|-------------|---------------|
| Same policy SETs serialized | Both take exclusive on per-policy lock |
| Same policy GETs parallel | Both take shared on per-policy lock |
| Same policy SET blocks GET | Exclusive blocks shared on per-policy lock |
| Different policies SETs parallel | Different per-policy locks; no conflict SET lock (non-conflict) or different conflict SET locks |
| Different policies GETs parallel | Different per-policy locks |
| Plugin load/unload blocks all | Exclusive on `globalMutex_`; policy ops need shared |
| Admin removal blocks all | Exclusive on `globalMutex_` in `RemoveAdminItem` |
| Conflict policies SETs serialized | Both take exclusive on same conflict SET lock |
| Conflict policies GETs parallel | GETs take shared on different per-policy locks (no conflict SET lock for GET) |
| SET A blocks GET A only (not GET B) | SET A takes exclusive on A's per-policy lock; doesn't touch B's |

## Conflict Group Map

### Static Map: `policyCode → groupId`

Initialized once via `std::call_once` in `InitConflictGroupMap()`.

### 10 Conflict Groups

| Group ID | Policies | Description |
|----------|----------|-------------|
| 1 | `DISABLE_USB`, `ALLOWED_USB_DEVICES`, `DISALLOWED_USB_DEVICES`, `DISALLOWED_PERMISSIVE_USB_DEVICES`, `USB_READ_ONLY`, `DISALLOWED_USB_STORAGE_DEVICE_WRITE`, `DISALLOW_USB_SERIAL` | USB cluster (7 policies) |
| 2 | `DISABLED_BLUETOOTH`, `ALLOWED_BLUETOOTH_DEVICES`, `DISALLOWED_BLUETOOTH_DEVICES` | Bluetooth cluster (3) |
| 3 | `DISABLE_WIFI`, `ALLOWED_WIFI_LIST`, `DISALLOWED_WIFI_LIST` | WiFi list cluster (3) |
| 4 | `DISABLED_MTP_CLIENT`, `DISABLED_USER_MTP_CLIENT` | MTP client pair (2) |
| 5 | `DISALLOWED_DISTRIBUTED_TRANSMISSION`, `DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL` | Distributed transmission pair (2) |
| 6 | `DISABLED_SUDO`, `DISALLOWED_DEVICE_SUDO` | Sudo pair (2) |
| 7 | `DISALLOWED_NOTIFICATION`, `ALLOWED_NOTIFICATION_BUNDLES` | Notification pair (2) |
| 8 | `ALLOW_RUNNING_BUNDLES`, `DISALLOW_RUNNING_BUNDLES`, `MANAGE_KEEP_ALIVE_APPS` | App running bundles cluster (3) |
| 9 | `MANAGE_USER_NON_STOP_APPS`, `DISABLED_SUPERHUB` | Non-stop apps vs SuperHub (2) |
| 10 | `OPERATE_DEVICE`, `DISALLOW_RESET_FACTORY` | Operate device disk-erase (2, latent) |

### Self-Conflict Policies (NOT in conflict groups)

These return `CONFIGURATION_CONFLICT_FAILED` for intra-policy conflicts (multi-admin or mutually exclusive sub-modes within the same policy). The per-policy lock already serializes same-policy SETs, which handles these cases. No conflict group lock needed:

- `TELEPHONY_CALL_POLICY` — trust-list vs block-list for same call type
- `FINGERPRINT_AUTH` — global disallow vs account-specific disallow
- `PERMISSION_MANAGED_STATE_POLICY` — same permission key already managed by another admin
- `DISABLE_RUNNING_BINARY_APP` — another admin has set the single-valued policy

## Implementation Details

### Header Changes (`plugin_manager.h`)

**Remove:**
```cpp
static std::shared_timed_mutex mutexLock_;
```

**Add:**
```cpp
static std::shared_mutex globalMutex_;
static std::shared_mutex pluginMapMutex_;
static std::unordered_map<uint32_t, std::shared_ptr<std::shared_mutex>> policyLocks_;
static std::mutex policyLocksMapMutex_;
static std::unordered_map<uint32_t, std::shared_ptr<std::shared_mutex>> conflictSetLocks_;
static std::mutex conflictSetLocksMapMutex_;
static std::unordered_map<uint32_t, uint32_t> conflictGroupMap_;

std::shared_ptr<std::shared_mutex> GetPolicyLock(uint32_t policyCode);
std::shared_ptr<std::shared_mutex> GetConflictSetLock(uint32_t policyCode);
bool IsInConflictGroup(uint32_t policyCode);
static void InitConflictGroupMap();
```

### Source Changes (`plugin_manager.cpp`)

#### `GetInstance()` — Use `std::call_once`

```cpp
std::shared_ptr<PluginManager> PluginManager::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, []() {
        instance_.reset(new (std::nothrow) PluginManager());
        InitConflictGroupMap();
    });
    IPluginManager::pluginManagerInstance_ = instance_.get();
    return instance_;
}
```

#### Helper Methods

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

#### `UpdateDevicePolicy` — SET Flow

```cpp
ErrCode PluginManager::UpdateDevicePolicy(uint32_t code, const std::string &bundleName,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::shared_lock<std::shared_mutex> globalLock(globalMutex_);
    InitConflictGroupMap();

    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(code);
    if (plugin == nullptr) {
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

    // ... existing policy execution logic unchanged ...
}
```

#### `GetPolicy` — GET Flow

```cpp
ErrCode PluginManager::GetPolicy(uint32_t funcCode, const std::string &bundleName,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::shared_lock<std::shared_mutex> globalLock(globalMutex_);

    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    uint32_t policyCode = FuncCodeUtils::GetPolicyCode(funcCode);

    auto policyLock = GetPolicyLock(policyCode);
    std::shared_lock<std::shared_mutex> policyGuard(*policyLock);

    // ... existing policy query logic unchanged ...
}
```

#### `RemoveAdminItem` — Admin Removal Flow

```cpp
ErrCode PluginManager::RemoveAdminItem(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue, int32_t userId)
{
    std::unique_lock<std::shared_mutex> globalLock(globalMutex_);
    InitConflictGroupMap();

    {
        std::unique_lock<std::shared_mutex> mapLock(pluginMapMutex_);
        LoadAllPlugin();
    }

    std::shared_ptr<IPlugin> plugin = GetPluginByPolicyName(policyName);
    if (plugin == nullptr) {
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }

    auto conflictLock = GetConflictSetLock(plugin->GetCode());
    std::unique_ptr<std::unique_lock<std::shared_mutex>> conflictGuard;
    if (conflictLock != nullptr) {
        conflictGuard = std::make_unique<std::unique_lock<std::shared_mutex>>(*conflictLock);
    }
    auto policyLock = GetPolicyLock(plugin->GetCode());
    std::unique_lock<std::shared_mutex> policyGuard(*policyLock);

    // ... existing removal logic (OnAdminRemoveExecute, SetPolicy, OnAdminRemoveDone) unchanged ...
}
```

#### `UnloadPluginTask` — Plugin Unload Flow

```cpp
void PluginManager::UnloadPluginTask(const std::string &soName, std::shared_ptr<SoLoadState> loadStatePtr)
{
    // ... wait loop unchanged ...
    std::unique_lock<std::shared_mutex> globalLock(globalMutex_);
    std::unique_lock<std::shared_mutex> mapLock(pluginMapMutex_);
    // ... check time, unload if expired ...
}
```

#### Metadata Queries — Shared Lock

```cpp
std::string PluginManager::GetPolicyName(uint32_t funcCode)
{
    std::shared_lock<std::shared_mutex> globalLock(globalMutex_);
    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        return "";
    }
    return plugin->GetPolicyName();
}
// Same pattern for GetPermission, GetPluginType, GetPluginPermissionByPolicyName
```

#### `SetPluginUnloadFlag` — Shared Lock

```cpp
ErrCode PluginManager::SetPluginUnloadFlag(uint32_t code, bool unloadFlag)
{
    std::shared_lock<std::shared_mutex> globalLock(globalMutex_);
    // Use GetPluginByFuncCode for double-checked loading on pluginMapMutex_
    auto funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, code);
    std::shared_ptr<IPlugin> plugin = GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    plugin->SetPluginUnloadFlag(unloadFlag);
    return ERR_OK;
}
```

**Note:** The current implementation calls `LoadPluginByCode(code)` then `GetPluginByCode(code)` separately. The new design refactors this to use `GetPluginByFuncCode(funcCode)` which handles both loading (double-checked on `pluginMapMutex_`) and lookup in one call.

## Error Handling & Edge Cases

### Plugin Not Found

`GetPluginByFuncCode` returns `nullptr` after double-checked loading attempt (e.g., `dlopen` fails). `UpdateDevicePolicy` / `GetPolicy` return `EdmReturnErrCode::INTERFACE_UNSUPPORTED` — same as current behavior. Gate shared lock is released; no per-policy lock acquired.

### Plugin Unload Race During On-Demand Loading

Thread A loads a plugin (holds exclusive on `pluginMapMutex_`, shared on `globalMutex_`). Unload timer fires and needs exclusive on `globalMutex_` — waits. No unload occurs during loading.

### Deadlock Prevention

Locking order is a strict DAG: `globalMutex_` → `pluginMapMutex_` → conflict SET lock → per-policy lock. `pluginMapMutex_` is always released before acquiring per-policy locks. No circular wait possible.

### Thread Safety of Lock Maps

`policyLocks_` and `conflictSetLocks_` are protected by their own `std::mutex`. Held only during lookup/creation. Once `shared_ptr<shared_mutex>` is obtained, lock/unlock happens without holding the map mutex. Entries are never deleted, so no use-after-free.

### Plugin SO Unloaded During Policy Execution

Policy ops hold shared on `globalMutex_`. Unload takes exclusive on `globalMutex_`. So unload waits for all policy ops to finish. The `shared_ptr<IPlugin>` obtained during a policy op is valid for the op's duration.

## Testing Strategy

### Existing Tests (Regression)

All existing unit tests must pass without modification:
- `test/unittest/services/edm/src/enterprise_device_mgr_ability_test.cpp`
- `test/unittest/services/edm/src/update_policy_conflict_test.cpp`
- All plugin tests in `test/unittest/services/edm_plugin/`

### New Concurrency Tests

| Test | Description | Expected Behavior |
|-----|-------------|-------------------|
| ParallelSetDifferentPolicies | Two threads SET different non-conflicting policies | Both succeed; execution overlaps |
| ParallelSetSamePolicy | Two threads SET the same policy | Second SET waits for first (serialized) |
| ParallelGetSamePolicy | Multiple threads GET the same policy | All succeed; execution overlaps |
| SetBlocksGetSamePolicy | Thread A SETs X; Thread B GETs X simultaneously | Thread B waits for Thread A |
| SetDoesNotBlockGetDifferentPolicy | Thread A SETs X; Thread B GETs Y simultaneously | Thread B does NOT wait |
| ConflictGroupSetSerialized | Thread A SETs X; Thread B SETs Y (same conflict group) | Thread B waits (conflict SET lock) |
| ConflictGroupGetParallel | Thread A SETs X; Thread B GETs Y (same conflict group) | Thread B does NOT wait |
| PluginUnloadBlocksAll | Unload timer fires while policy ops in progress | Unload waits for all ops to finish |
| AdminRemovalBlocksAll | RemoveAdminItem while policy ops in progress | Policy ops wait for removal to complete |

### Build Verification

```bash
./build.sh --build-target enterprise_device_management
cd test/testfwk/developer_test
./start.sh -t edm -s enterprise_device_mgr_ability_test
```

## Out of Scope

- `EnterpriseDeviceMgrAbility::adminLock_` — already uses `shared_lock` for GET and `unique_lock` for SET; not modified.
- `PolicyManager::mutexLock_` — storage layer lock; not modified.
- Plugin on-demand loading architecture — unchanged; only the locking around it changes.
- NAPI/Addon layer — no changes needed.
