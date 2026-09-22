# 并发锁模型

> PluginManager 三锁架构、UpdateDevicePolicy 三阶段、UAF 防护、ConflictGroupRegistry 冲突分组。修改并发锁或 `UpdateDevicePolicy`/`GetPolicy`/`UnloadPluginTask` 时查阅本文档。日常工作流以 AGENTS.md 路由为准。

## 三锁架构

**代码路径**: `services/edm/src/plugin_manager.cpp`、`services/edm/src/policy_manager.cpp`

| 锁 | 类型 | 保护对象 | 持有方式 |
|---|---|---|---|
| `mutexLock_` | `std::shared_timed_mutex` | `pluginsCode_`/`pluginsName_`/`soLoadStateMap_` 及 `SoLoadState` 成员 | 插件加载/卸载/查找用 `unique_lock` |
| `soPinMutex_` | `std::shared_mutex` | 防止 SO 被 `dlclose` 卸载（SO pinning） | `UpdateDevicePolicy`/`GetPolicy` Phase 2 用 `shared_lock`；`UnloadPluginTask` 用 `unique_lock` |
| `policyStripes_` | `std::mutex[ConflictGroupId::END]` | 按冲突组串行化同组 `OnSetExecute` | `NeedSavePolicy=true` 时按 `ConflictGroupId` 取条带 `unique_lock` |
| `PolicyManager::mutex_` | `std::recursive_mutex` | `policyMgrMap_`/`defaultPolicyMgr_` 及 `UserPolicyManager` map 访问 | 所有 `PolicyManager` 公共方法用 `lock_guard` |

### 职责分离

`mutexLock_` 与 `soPinMutex_` 分离的原因：SO 加载/卸载本质是对 `pluginsCode_` 的写操作，需要 `unique_lock`；而 SO pinning 需要 `shared_lock` 阻塞卸载。如果用同一把锁，`shared_lock` 会阻塞 `unique_lock`（加载/卸载），导致 `GetPolicyName` 等查询操作被阻塞。分离后，Phase 2+3 持 `shared_lock(soPinMutex_)` 仅阻塞卸载，不影响 `mutexLock_` 上的加载/查询。

## UpdateDevicePolicy 三阶段

```
Phase 1: unique_lock(mutexLock_) → GetPluginByFuncCode(加载+lastCallTime更新) → 释放
Phase 2: shared_lock(soPinMutex_) + unique_lock(policyStripes_[groupId]) → OnSetExecute
Phase 3: 同 Phase 2 锁 → SetPolicy(由 PolicyManager::mutex_ 保护) → OnHandlePolicyDone
```

### Phase 1：加载阶段

- `unique_lock(mutexLock_)` 独占
- `GetPluginByFuncCode` → `LoadPluginByFuncCode` → `LoadPlugin`
- `LoadPlugin` 更新 `lastCallTime`、唤醒 `UnloadPluginTask`（`notify_one`）
- 释放 `mutexLock_`

### Phase 2：执行阶段

- `shared_lock(soPinMutex_)`（防止 SO 卸载，允许多个 `OnSetExecute` 并发）
- `unique_lock(policyStripes_[groupId])`（仅 `NeedSavePolicy=true` 时，同冲突组串行）
- `OnSetExecute` → `GetPluginByFuncCode` → `LoadPlugin`（已加载路径：仅更新 `lastCallTime` + 通知）

### Phase 3：持久化阶段

- 同 Phase 2 锁（`soPinMutex_` + `policyStripes_`）
- `SetPolicy`（由 `PolicyManager::mutex_` 的 `lock_guard` 保护）
- `SubscribeEvent`/`UnsubscribeEvent`（由 `PluginEventRouter::mutex_` 保护）
- `OnHandlePolicyDone`（回调）

## GetPolicy 两阶段

```
Phase 1: unique_lock(mutexLock_) → GetPluginByFuncCode(加载) → 释放
Phase 2: shared_lock(soPinMutex_) → OnGetExecute(查询策略)
```

与 `UpdateDevicePolicy` 模式一致，Phase 2 不被 `mutexLock_` 阻塞。

## 锁顺序

```
soPinMutex_ (shared) → policyStripes_[i] (unique) → PolicyManager::mutex_ (lock_guard)
UnloadPluginTask: soPinMutex_ (unique) → mutexLock_ (unique)
```

无逆序，无死锁。

### 死锁分析

`UpdateDevicePolicy` 和 `UnloadPluginTask` 不会死锁：

- `UpdateDevicePolicy` Phase 2+3 持 `shared_lock(soPinMutex_)`，不持有 `mutexLock_`，不等待 `mutexLock_`
- `UnloadPluginTask` 持 `unique_lock(soPinMutex_)`，等待 `mutexLock_`
- 无循环等待

## UAF 防护

| 时间点 | 锁状态 | 风险 |
|---|---|---|
| Phase 1（`unique_lock(mutexLock_)`） | 独占 | 无 |
| Phase 1 释放 → Phase 2 获取（窗口） | 无锁 | `lastCallTime` 刚更新，`UnloadPluginTask` 检查 `diffTime < 3min` → 不卸载（timer 软保护） |
| Phase 2+3（`shared_lock(soPinMutex_)`） | 共享 | `UnloadPluginTask` 的 `unique_lock(soPinMutex_)` 被阻塞 → 不卸载 |

### Timer 软保护

Phase 1 的 `LoadPlugin` 更新 `lastCallTime = now`。`UnloadPluginTask` 在获取 `mutexLock_` 后读取 `lastCallTime`（`mutexLock_` 串行化保证写先于读），计算 `diffTime`。如果 `diffTime < 3min`（`TIMER_TIMEOUT = 180000ms`），不卸载。

如果 `UnloadPluginTask` 在 Phase 1 之前就拿到两把锁并检查 timer（`lastCallTime` 是旧值），则卸载。但之后 Phase 1 的 `LoadPlugin` 发现 `pluginHasInit == false` → 重新 dlopen 加载。无 UAF，只是重复卸载+加载。

## adminLock_ 改动

**代码路径**: `services/edm/src/enterprise_device_mgr_ability.cpp`

| 路径 | 原始 | 当前 |
|---|---|---|
| `HandleDevicePolicy` admin 查找 | `unique_lock` 全程 | `shared_lock` 仅 admin 查找分支 |
| `GetDevicePolicy` | `shared_lock` | 无 `adminLock_`（数据由 `PolicyManager::mutex_` 保护） |
| `GetDevicePolicyFromPlugin` admin 查找 | 继承调用方 `shared_lock` | 新增 `shared_lock` |

### TOCTOU

admin 查找（`shared_lock`）与 `UpdateDevicePolicy`（无 `adminLock_`）之间存在窗口，admin 可能被移除。但 `RemoveAdminItem` 需要 `unique_lock(mutexLock_)`，被 Phase 2+3 的 `shared_lock(soPinMutex_)` 间接阻塞（`UnloadPluginTask` 模式不适用，但 `RemoveAdminItem` 直接用 `unique_lock(mutexLock_)`，不被 `soPinMutex_` 阻塞）。语义不一致（策略设给已移除的 admin），非崩溃。

## ConflictGroupRegistry

**代码路径**: `services/edm/src/conflict_group_registry.cpp`、`services/edm/include/conflict_group_registry.h`

单例（C++11 `static` 局部变量），构造时注册 12 个冲突组：

| 组 | ConflictGroupId | 策略数 | 代表策略 |
|---|---|---|---|
| USB | GROUP_USB (1) | 7 | DISABLE_USB, ALLOWED_USB_DEVICES |
| 蓝牙 | GROUP_BLUETOOTH (2) | 3 | DISABLE_BLUETOOTH |
| Sudo | GROUP_SUDO (3) | 2 | DISALLOWED_SUDO |
| 通知 | GROUP_NOTIFICATION (4) | 2 | DISALLOWED_NOTIFICATION |
| 分布式 | GROUP_DISTRIBUTED (5) | 2 | DISALLOWED_DISTRIBUTED_TRANSMISSION |
| MTP | GROUP_MTP (6) | 2 | DISABLE_MTP_CLIENT |
| WiFi | GROUP_WIFI (7) | 3 | DISABLE_WIFI |
| 打印机 | GROUP_PRINTER (8) | 2 | ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE |
| 运行包 | GROUP_RUNNING_BUNDLES (9) | 3 | DISALLOW_RUNNING_BUNDLES |
| 恢复出厂 | GROUP_FACTORY_RESET (10) | 4 | OPERATE_DEVICE, RESET_FACTORY |
| SuperHub | GROUP_SUPERHUB (11) | 3 | MANAGE_USER_NON_STOP_APPS |
| 更新策略 | GROUP_UPDATE_POLICY (12) | 2 | SET_OTA_UPDATE_POLICY |

`GetConflictGroupId` 是 `const` 方法，`policyToGroup_` 构造后只读，线程安全。

未注册的策略返回 `NONE=0`，所有未分组 `NeedSavePolicy` 策略共享 `policyStripes_[0]`（保守串行）。

### 冲突组注册规则

插件抛出 `EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED` 有两种语义，需区分处理：

**类型 1：跨插件策略冲突 → 必须注册冲突组**

插件通过 `CheckConflictPolicy` 调用 `PolicyManager::GetPolicy` 查询**其他插件**的 policyName 来检测冲突。所有存在冲突关系的插件必须注册到 `ConflictGroupRegistry` 同一冲突组，设置策略时共享同一把 `policyStripes_` 锁。

示例：`DisableSudoPlugin::CheckConflictPolicy` 查询 `POLICY_DISALLOWED_DEVICE_SUDO`，两个插件互相检查对方策略 → 都注册到 Group C。

**类型 2：插件内部冲突 / 多 admin 冲突 → 不需要注册**

插件检查**自身**的 merge data 或内部参数状态，不涉及其他插件策略。此类冲突不需要注册冲突组。

| 插件 | 冲突原因 | 类型 | 注册? |
|---|---|---|---|
| `disable_running_binary_app_plugin` | "another admin has already set policy"（多 admin） | 2 | 否 |
| `fingerprint_auth_plugin` | `globalDisallow` vs per-account（内部参数互斥） | 2 | 否 |
| `set_permission_managed_state_plugin` | 同一 bundle 已被其他 admin 设置（多 admin） | 2 | 否 |
| `telephony_call_policy_plugin` | 黑/白名单互斥（内部模式冲突） | 2 | 否 |

**新增策略时检查清单**：
1. 插件是否通过 `CheckConflictPolicy` 检查其他插件的策略值？
2. 如果是，将所有冲突插件注册到 `ConflictGroupRegistry` 同一冲突组
3. 如果只是内部参数或多 admin 冲突，不需要注册

## 并发效果

| 场景 | 效果 |
|---|---|
| 不同冲突组的 `OnSetExecute` | 并行 |
| 同冲突组的 `OnSetExecute` | 串行 |
| 未分组 `NeedSavePolicy` 策略 | 串行（共享 `policyStripes_[0]`，保守） |
| `NeedSavePolicy=false` 策略 | 并行 |
| 主读路径 vs 写 | 不互斥（不同锁） |
| `GetPolicy` vs `UpdateDevicePolicy` | 不互斥（`soPinMutex_` 共享锁允许共存） |
| `GetPolicyName` 等查询 vs Phase 2+3 | 不阻塞（`mutexLock_` 与 `soPinMutex_` 不同锁） |

## 已知限制

| 限制 | 说明 |
|---|---|
| `lastCallTime` 技术性数据竞争 | `LoadPlugin` 在 `shared_lock(soPinMutex_)` 下写 `lastCallTime`（非原子），多 Phase 2 并发写。实践安全（64 位对齐写），C++ 标准下为 UB |
| `GetPolicyName` 等仍用 `unique_lock(mutexLock_)` | 未转换（收益极小），但不被 `soPinMutex_` 阻塞 |
| 未分组策略共享 `policyStripes_[0]` | 不相关的未分组策略互相串行（保守策略） |
| `pluginsCode_.find()` 在 Phase 2 无 `mutexLock_` 保护 | 与并发的不同 SO 加载（`insert`）有技术性数据竞争（实践安全，`std::map` 树遍历，加载罕见） |
