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
