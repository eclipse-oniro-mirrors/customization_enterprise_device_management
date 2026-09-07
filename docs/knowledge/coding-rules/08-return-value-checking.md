# 08 - 返回值校验规范

> 来源 Bug: napi 函数、系统调用、文件操作返回值未校验（来自代码检视批量修复 6ba3dfd5）

## 规则 8.1：所有 napi 系统函数返回值必须校验为 napi_ok

**来源**: `6ba3dfd5` — 9 处 `napi_open_handle_scope` 只检查 scope == nullptr。

详见 [03-napi-and-js-interop.md 规则 3.4](./03-napi-and-js-interop.md#规则-34napi-系统函数返回值必须校验)。

**核心要求**:
```cpp
// 错误：只检查输出参数
napi_open_handle_scope(env, &scope);
if (scope == nullptr) { return; }

// 正确：同时检查 napi_status
auto status = napi_open_handle_scope(env, &scope);
if (status != napi_ok || scope == nullptr) {
    EDMLOGE("failed, status=%{public}d", status);
    return;
}
```

---

## 规则 8.2：文件操作返回值必须校验

**来源**: `6ba3dfd5` — `LoadFromFile` 返回值未校验。

**错误写法**:
```cpp
LoadFromFile(filePath, jsonString);  // 返回值被忽略
// jsonString 可能为空或无效
```

**正确写法**:
```cpp
if (!LoadFromFile(filePath, jsonString)) {
    EDMLOGE("LoadFromFile fail, path=%{public}s", filePath.c_str());
    return false;
}
```

**检查清单**:
- [ ] 所有 `LoadFromFile`/`SaveToFile`/`OpenFile`/`ReadFile` 返回值必须校验
- [ ] 文件操作失败时不要继续使用未初始化的数据
- [ ] `tellg()` 返回的 size 必须同时校验下限和上限

---

## 规则 8.3：系统服务调用返回值必须校验

**来源**: `6ba3dfd5` — `GetNameForUid` 返回值未校验。

**错误写法**:
```cpp
std::string name = bundleMgr->GetNameForUid(uid);  // 返回值未校验
// name 可能为空
```

**正确写法**:
```cpp
std::string name;
if (!bundleMgr->GetNameForUid(uid, name) || name.empty()) {
    EDMLOGE("GetNameForUid fail, uid=%{public}d", uid);
    return false;
}
```

**需校验的系统调用清单**:
- `BundleMgr` 系列：`GetBundleInfo`, `GetNameForUid`, `SetDisallowedUninstall`
- `OsAccountMgr` 系列：`QueryActiveOsAccountIds`
- `system::SetParameter` / `system::GetParameter`
- `DelayedSingleton<XXX>::GetInstance()` 后的方法调用

**检查清单**:
- [ ] 所有跨进程调用（IPC）的返回值必须校验
- [ ] 系统服务方法返回 bool 的，失败时返回错误码
- [ ] 系统服务方法返回 string 的，检查是否为空

---

## 规则 8.4：集合大小校验必须使用正确的比较

**来源**: `6ba3dfd5` — `permissionCount` 上限错误。

**错误写法**:
```cpp
if (permissionCount > 100) {  // 上限值不正确
    return false;
}
```

**正确写法**:
```cpp
if (permissionCount > EdmConstants::POLICIES_MAX_SIZE) {  // 200
    return false;
}
```

**检查清单**:
- [ ] 集合/列表大小上限使用 `EdmConstants` 中定义的常量，不要用魔数
- [ ] 上限值要与业务定义一致（如 `POLICIES_MAX_SIZE = 200`）
- [ ] 检查时使用 `> MAX` 还是 `>= MAX` 要明确

---

## 规则 8.5：streamsize 类型的零值校验

**来源**: `6ba3dfd5` — `device_control_addon.cpp` 中 streamsize 缺少 `== 0` 校验。

**注意**: `std::streamsize` 是有符号类型，可以做 `<= 0`，但要区分语义：
- `size < 0`：异常情况
- `size == 0`：空文件
- 两者都应该拒绝

**正确写法**:
```cpp
std::streamsize size = infile.tellg();
if (size <= 0 || size > MAX_SIZE) {  // 同时校验
    return nullptr;
}
```

---

## 规则 8.6：魔数必须替换为命名常量

**来源**: `453ef8bf` — 静态检查发现使用魔数 27。

**错误写法**:
```cpp
if (value == 27) {  // 27 是什么含义？
    ...
}
```

**正确写法**:
```cpp
constexpr int32_t SOME_MEANINGFUL_CONSTANT = 27;
if (value == SOME_MEANINGFUL_CONSTANT) {
    ...
}
```

**检查清单**:
- [ ] 代码中禁止出现裸数字常量（0, 1 除外，可用于布尔语义）
- [ ] 所有阈值、上限、索引值定义为命名常量
- [ ] 常量定义在 `EdmConstants` 命名空间或文件级 `constexpr`

---

## 总结：返回值校验检查清单（通用）

在提交代码前，搜索以下模式并确保都已校验返回值：

| 模式 | 搜索关键词 | 校验方式 |
|------|-----------|---------|
| napi 函数 | `napi_` 前缀 | 检查 `napi_status == napi_ok` |
| 文件操作 | `LoadFromFile`, `OpenFile`, `tellg`, `read` | 检查 bool 返回值 / size 范围 |
| 系统服务 | `->Get`, `->Set`, `->Query` | 检查返回值或输出参数非空 |
| IPC 调用 | `HandleDevicePolicy`, `GetPolicy` | 从 reply 读取错误码 |
| 内存分配 | `malloc`, `new`, `make_shared` | 检查返回值非 nullptr |
| cJSON | `cJSON_GetObjectItem` | 检查返回值非 nullptr + 类型校验 |
| 集合操作 | `size()`, `empty()` | 不要假设非空，先判空 |
