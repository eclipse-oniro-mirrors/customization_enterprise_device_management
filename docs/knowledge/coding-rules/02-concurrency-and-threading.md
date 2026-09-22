# 02 - 并发与线程规范

> 来源 Bug: 死锁、并发文件冲突、对象生命周期、多管理员策略清理

## 规则 2.1：锁作用域内禁止调用可能反向获取锁的初始化

**错误根因**: 在锁作用域内调用子系统初始化（单例构造），如果该单例内部也需要获取同一把锁，会导致死锁。

**来源**: `e92d6bcf` — `OnStart` 中 `WatermarkObserverManager`/`ExtInfoManager`/`EdmBluetoothManager` 初始化在锁内，自激活流程触发反向获取导致低概率死锁。

**错误写法**:
```cpp
{
    std::unique_lock lock(mutex_);
    // ... 受锁保护的初始化 ...
    WatermarkObserverManager::GetInstance();  // 单例构造可能反向获取锁
    ExtInfoManager::GetInstance()->GetSuperHubInfo();
    EdmBluetoothManagerImpl::GetInstance();
}
```

**正确写法**: 将子系统初始化移出锁作用域
```cpp
{
    std::unique_lock lock(mutex_);
    // ... 只做受锁保护的本地状态修改 ...
}
// 锁外初始化子系统
ExtInfoManager::GetInstance()->GetSuperHubInfo();
EdmBluetoothManagerImpl::GetInstance();
WatermarkObserverManager::GetInstance();
```

**检查清单**:
- [ ] 审查所有 `unique_lock`/`lock_guard` 作用域内的 `GetInstance()` 调用
- [ ] 单例构造链可能涉及的锁要梳理清楚，避免 A->B->A 循环
- [ ] 初始化代码尽量在锁外执行，锁内只做必要的共享状态修改

---

## 规则 2.2：并发清理必须只清理自身资源

**错误根因**: 清理函数删除整个目录下所有文件，并发场景下误删其他任务的文件。

**来源**: `5cb1b1b5` — `DeleteFiles()` 无参版本清理整个 HAP 目录，并发安装时互相误删。

**错误写法**:
```cpp
bool DeleteFiles() {
    std::vector<std::string> files;
    OHOS::GetDirFiles(HAP_DIRECTORY, files);  // 获取目录下所有文件
    for (auto &file : files) { RemoveFile(file); }  // 可能删掉别人的
}
```

**正确写法**: 只清理当前操作涉及的文件
```cpp
bool DeleteFiles(const std::vector<std::string> &files) {
    for (auto const &file : files) {  // 只删传入的文件
        if (!OHOS::RemoveFile(file)) { ... }
    }
}
// 调用处传入自己的文件列表
DeleteFiles(param.hapFilePaths);
```

**检查清单**:
- [ ] 所有清理/删除函数必须接收明确的资源列表参数，不要扫描整个目录
- [ ] 并发场景下，共享目录中的文件必须通过唯一命名区分（见规则 2.3）

---

## 规则 2.3：并发生成的文件名必须唯一

**错误根因**: 多个进程同时设置水印时，临时图片文件名冲突导致互相覆盖。

**来源**: `4c176f97` — 水印图片文件名生成不唯一，并发冲突。

**正确做法**:
- 文件名包含进程 PID + 时间戳 + 随机数，确保唯一
- `GenerateUniqueFileName()` 方法应为 public，确保各调用路径都能访问到唯一生成逻辑

**检查清单**:
- [ ] 所有生成的临时文件名必须包含足够熵（PID + 时间戳 + 随机数）
- [ ] 唯一性生成方法不要设为 private，确保所有调用路径统一使用

---

## 规则 2.4：多管理员去激活必须清理所有策略

**错误根因**: `OnAdminRemove` 只根据 `dataVec[0]` 清理对应参数，多管理员场景下其余策略失效。

**来源**: `4a10b86f` — `SetSwitchStatusPlugin::OnAdminRemove` 用 switch-case 只处理第一个开关。

**错误写法**:
```cpp
if (dataVec.size() <= 0) { return PARAM_ERROR; }
SwitchParam data = dataVec[0];
switch (data.key) {
    case SwitchKey::BLUETOOTH:
        system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
        break;
    case SwitchKey::WIFI:
        system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false");
        break;
    // 只处理了第一个，其余开关未清理
}
```

**正确写法**: 清理所有相关参数
```cpp
system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false");
#ifdef NFC_EDM_ENABLE
system::SetParameter(PARAM_FORCE_ENABLE_NFC, "false");
#endif
```

**检查清单**:
- [ ] 去激活/移除策略时，不要假设 `dataVec` 只有一个元素
- [ ] 如果策略涉及多个系统参数，去激活时必须全部恢复
- [ ] 不要用 switch-case 只处理第一个元素的方式做批量清理

---

## 规则 2.5：跨用户操作必须遍历所有活跃用户

**错误根因**: 只在全局设置了禁止卸载标志，未对各个活跃用户账号清理对应限制。

**来源**: `6bf2f27c` — `DelDisallowUninstallApp` 未遍历活跃用户清理 account 级限制。

**错误写法**:
```cpp
ErrCode DelDisallowUninstallApp(const std::string &bundleName) {
    if (!GetBundleMgr()->SetDisallowedUninstall(bundleName, false)) {
        return SYSTEM_ABNORMALLY;
    }
    return ERR_OK;  // 未清理各用户账号级别的限制
}
```

**正确写法**: 查询所有活跃用户并逐一清理
```cpp
ErrCode DelDisallowUninstallApp(const std::string &bundleName) {
    if (!GetBundleMgr()->SetDisallowedUninstall(bundleName, false)) {
        return SYSTEM_ABNORMALLY;
    }
    std::vector<int32_t> ids;
    GetOsAccountMgr()->QueryActiveOsAccountIds(ids);
    for (auto id : ids) {
        DelDisallowUninstallAppForAccount(bundleName, id);
    }
    return ERR_OK;
}
```

**检查清单**:
- [ ] 所有涉及"全局 + 用户级"的策略，恢复时必须同时清理两个层级
- [ ] 使用 `QueryActiveOsAccountIds` 获取所有活跃用户
- [ ] 升级场景（服务重启）尤其注意用户状态可能变化

---

## 规则 2.6：重启场景必须处理 userId 无效值

**错误根因**: `GetCurrentUserId()` 在服务重启、用户未登录时返回 -1，直接使用导致后续查询失败。

**来源**: `65f4dc1d` — 重启同步网络数据时 userId 为 -1 导致 admin 查询失败。

**正确写法**:
```cpp
int32_t userId = std::make_shared<EdmOsAccountManagerImpl>()->GetCurrentUserId();
if (userId == -1) {
    userId = EdmConstants::DEFAULT_USER_ID;  // 回退到默认用户
}
```

**检查清单**:
- [ ] 所有 `GetCurrentUserId()` 调用必须处理 -1（无效用户）
- [ ] 服务启动、服务重启回调场景尤其注意用户可能尚未登录
- [ ] 回退到 `DEFAULT_USER_ID` 而非直接使用 -1

---

## 规则 2.7：`shared_lock` 不能用于可能触发写操作的方法

**错误根因**: 方法在 `shared_lock` 下执行懒加载（dlopen + map 插入），这是写操作，与并发 `shared_lock` 读取同一 map 产生数据竞争。

**来源**: 并发优化开发过程 — `GetPluginByFuncCode` 在 `shared_lock` 下调用 `LoadPlugin`，首次加载时执行 dlopen + `AddPlugin`（写 `pluginsCode_` map），多线程并发时 UB。

**错误写法**:
```cpp
// 全部用 shared_lock，但 LoadPlugin 可能写 map
std::shared_lock<std::shared_timed_mutex> lock(mutexLock_);
auto plugin = GetPluginByFuncCode(code);  // 内部 LoadPlugin 可能 dlopen + map.insert()
```

**正确写法**: 可能触发加载（写 map）的方法用 `unique_lock`
```cpp
std::unique_lock<std::shared_timed_mutex> lock(mutexLock_);
auto plugin = GetPluginByFuncCode(code);  // 安全：独占访问
```

**检查清单**:
- [ ] 在 `shared_lock` 下调用的方法是否可能触发懒加载、插入、删除等写操作？
- [ ] 已加载路径（只读）和首次加载路径（写）是否在调用前可区分？不可区分则必须 `unique_lock`

---

## 规则 2.8：`std::shared_mutex` 不支持同线程重入

**错误根因**: 调用方持 `unique_lock(mutex)`，被调用方法内部尝试 `shared_lock(mutex)` → 同线程无法同时持有独占和共享锁 → 死锁。

**来源**: 并发优化开发过程 — `GetPluginByFuncCode` 两阶段方案（`shared_lock` 查找 → `unique_lock` 加载）在 `GetPolicy`/`GetPolicyName` 等（已持 `unique_lock`）调用时死锁。

**错误写法**:
```cpp
// 调用方
std::unique_lock<std::shared_mutex> lock(mutex_);
auto plugin = GetPluginByFuncCode(code);  // 内部尝试 shared_lock(mutex_) → 死锁

// 被调用方
std::shared_ptr<IPlugin> GetPluginByFuncCode(uint32_t code) {
    std::shared_lock<std::shared_mutex> slock(mutex_);  // ← 同线程已持 unique_lock → 死锁
    // ...
}
```

**正确写法**: 被调用方不自行加锁，依赖调用方持有的锁
```cpp
std::shared_ptr<IPlugin> GetPluginByFuncCode(uint32_t code) {
    // 无锁，依赖调用方已持有 unique_lock 或 shared_lock
    auto loadRet = LoadPluginByFuncCode(code);
    // ...
}
```

**检查清单**:
- [ ] 检查方法是否被持锁的调用方调用——如果是，被调用方不能在同一 mutex 上加锁
- [ ] `std::shared_mutex` 和 `std::shared_timed_mutex` 均不支持同线程重入（unique→shared 或 shared→unique）

---

## 规则 2.9：单一锁服务多个职责时需分离

**错误根因**: 一把锁同时保护 map 读写和 SO pinning（防止卸载）。`shared_lock` 用于 pinning 时阻塞了 `unique_lock` 用于 map 加载，导致查询方法被阻塞。

**来源**: 并发优化开发过程 — `mutexLock_` 同时服务 map 访问和 SO pinning，Phase 2+3 的 `shared_lock(mutexLock_)` 阻塞了 `GetPolicyName` 的 `unique_lock(mutexLock_)`。

**正确做法**: 按职责分离锁
```cpp
static std::shared_timed_mutex mutexLock_;    // map 读写（加载/卸载/查找）
static std::shared_mutex soPinMutex_;         // SO pinning（防止 dlclose 期间使用）
```

Phase 2+3 持 `shared_lock(soPinMutex_)` 仅阻塞卸载，不影响 `mutexLock_` 上的加载/查询。

**检查清单**:
- [ ] 一把锁是否服务多个不相关的职责？`shared_lock` 用于其中一个职责时是否阻塞了 `unique_lock` 用于另一个职责？
- [ ] 如果是，按职责拆分为不同的 mutex

---

## 规则 2.10：`std::recursive_mutex` 解决内部方法调用重入

**错误根因**: 公共方法 A 持 `unique_lock(mutex_)` 后调用公共方法 B，B 也尝试 `unique_lock(mutex_)` → 同线程重入 `std::shared_mutex` → 死锁。

**来源**: 并发优化开发过程 — `PolicyManager::Dump` 持锁后调用 `GetPolicyUserIds`（也加锁），`std::shared_mutex` 不支持重入 → 死锁。

**错误写法**:
```cpp
void Dump() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto mgr = GetUserPolicyMgr(userId);  // 无锁，OK
    GetPolicyUserIds(userIds);            // 内部 unique_lock(mutex_) → 死锁
}

void GetPolicyUserIds(std::vector<int32_t> &userIds) {
    std::unique_lock<std::shared_mutex> lock(mutex_);  // ← 同线程已持锁 → 死锁
    // ...
}
```

**正确写法**: 使用 `std::recursive_mutex` 允许同线程重入
```cpp
std::recursive_mutex mutex_;

void Dump() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);       // 计数=1
    GetPolicyUserIds(userIds);                                 // 内部 lock_guard → 计数=2 → OK
}

void GetPolicyUserIds(std::vector<int32_t> &userIds) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);        // 重入，安全
    // ...
}
```

**检查清单**:
- [ ] 公共方法是否调用其他公共方法（两者都加锁）？如果是，使用 `std::recursive_mutex`
- [ ] 不需要 `shared_lock`（读写分离）时优先用 `recursive_mutex` 而非 `shared_mutex`，避免重入死锁

---

## 规则 2.11：锁转换窗口的 timer 软保护

**错误根因**: 从 `unique_lock(mutexA)` 释放到 `shared_lock(mutexB)` 获取之间存在无锁窗口，卸载线程可能在窗口中获取 `unique_lock(mutexB)` 并执行卸载 → UAF。

**来源**: 并发优化开发过程 — `UpdateDevicePolicy` Phase 1 释放 `mutexLock_` 到 Phase 2 获取 `soPinMutex_` 之间，`UnloadPluginTask` 可能卸载 SO。

**正确做法**: 在 Phase 1 中更新 `lastCallTime`（时间戳），卸载线程在获取锁后检查 `diffTime < 3min` → 不卸载
```cpp
// Phase 1: unique_lock(mutexLock_)
LoadPlugin(soName);  // → lastCallTime = now; notify_one();
// 释放 mutexLock_

// [窗口：无锁] — UnloadPluginTask 可能获取锁，但检查 lastCallTime 刚更新 → 不卸载

// Phase 2: shared_lock(soPinMutex_) — UnloadPluginTask 被阻塞
plugin->OnSetExecute(...);
```

**限制**: 这是"软"保护（依赖 timer 检查），非"硬"锁保证。适用于卸载线程有 timer 检查的场景。如果 `LoadPlugin` 因任何原因未更新 `lastCallTime`（如 `soName` 为空提前返回），软保护失效。

**检查清单**:
- [ ] 锁转换窗口期间是否有线程可能执行危险操作（卸载/删除）？
- [ ] 该线程是否有可检查的"最近使用时间"或引用计数？在窗口前更新它
- [ ] 明确记录这是软保护，非硬保证——如果前置条件不满足（时间戳未更新），存在 UAF 风险
