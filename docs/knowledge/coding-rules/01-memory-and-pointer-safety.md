# 01 - 内存安全与指针规范

> 来源 Bug: 悬垂指针、空指针解引用、VLA 栈溢出、内存泄漏

## 规则 1.1：detached 线程禁止捕获 this 裸指针

**错误根因**: detached 线程的执行时机不可控，捕获 `this` 时对象可能已销毁，导致 use-after-free。

**来源**: `27e9ebca` — `ScheduleRetry` 中 lambda 捕获 this，detached 线程延迟执行时 `WatermarkApplicationObserver` 可能已销毁。

**错误写法**:
```cpp
std::thread retryTask([this, retryParam]() {
    // ... 延迟等待 ...
    CallPluginSetWatermark(retryParam);  // this 可能已失效
});
retryTask.detach();
```

**正确写法**: 使用 `wptr` 弱引用，执行前 promote 检查
```cpp
wptr<WatermarkApplicationObserver> weakThis(this);
std::thread retryTask([weakThis, retryParam]() {
    // ... 延迟等待 ...
    sptr<WatermarkApplicationObserver> strongThis = weakThis.promote();
    if (strongThis != nullptr) {
        strongThis->CallPluginSetWatermark(retryParam);
    } else {
        EDMLOGI("object destroyed, skip retry");
    }
});
retryTask.detach();
```

**检查清单**:
- [ ] 所有 `std::thread(...).detach()` 调用，检查 lambda 是否捕获了 `this` 或裸指针
- [ ] 如果捕获对象，改用 `wptr` 弱引用 + `promote()` 提升
- [ ] 定时器回调、延迟重试、异步通知场景尤其注意

---

## 规则 1.2：禁止使用 VLA（变长数组）分配外部可控大小

**错误根因**: VLA 在栈上分配，大小由外部输入控制时可能导致栈溢出。

**来源**: `d6f22442` — `GetImageFromUrlUint8` 使用 `uint8_t data[size]`，size 来自文件大小。

**错误写法**:
```cpp
std::streamsize size = infile.tellg();
uint8_t data[size];  // VLA，栈溢出风险
```

**正确写法**: 堆分配 + 大小上限校验 + 使用后释放
```cpp
if (size <= 0 || size > MAX_IMAGE_SIZE) {  // 先校验上限
    return nullptr;
}
uint8_t* data = (uint8_t*)malloc(size);
if (data == nullptr) {
    EDMLOGE("malloc fail");
    return nullptr;
}
// ... 使用 data ...
free(data);
```

**检查清单**:
- [ ] 搜索所有 `type name[variable]` 形式的 VLA 用法
- [ ] 改为 `malloc`/`new` 堆分配，并配对 `free`/`delete`
- [ ] 外部输入的大小值必须设置合理上限

---

## 规则 1.3：cJSON_GetObjectItem 返回值必须判空

**错误根因**: `cJSON_GetObjectItem` 在字段缺失时返回 `nullptr`，直接调用 `cJSON_GetStringValue`/`cJSON_GetNumberValue` 会空指针解引用。

**来源**: `9fec601b` — `isDeviceTypeAllMatch` 字段缺失时崩溃。

**错误写法**:
```cpp
cJSON* field = cJSON_GetObjectItem(item, "field");
// 直接使用，未判空
value = cJSON_GetNumberValue(field);  // field 可能为 null
```

**正确写法**: 区分必填和选填字段
```cpp
cJSON* required = cJSON_GetObjectItem(item, "required_field");
if (required == nullptr) {
    cJSON_Delete(root);
    return false;
}
cJSON* optional = cJSON_GetObjectItem(item, "optional_field");
if (optional != nullptr && cJSON_IsBool(optional)) {
    value = cJSON_IsTrue(optional);
} else {
    value = false;  // 默认值
}
```

**检查清单**:
- [ ] 所有 `cJSON_GetObjectItem` 调用后必须判空
- [ ] 新增的 JSON 字段应为选填（向后兼容旧数据），缺失时使用默认值
- [ ] 对选填字段单独做类型校验，不要和必填字段混在同一个 if 中

---

## 规则 1.4：NAPI handle 必须包裹在 handle_scope 中

**错误根因**: 在 JS 回调中创建 `napi_value` 时未使用 `napi_open_handle_scope`/`napi_close_handle_scope`，导致 napi handle 泄露。

**来源**: `2b94ca43` — `OnDeviceAdminEnabled`/`OnBundleAdded` 等 9+ 回调方法泄露 handle。

**错误写法**:
```cpp
auto task = [bundleName, this]() {
    auto env = jsRuntime_.GetNapiEnv();
    napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName) };
    CallObjectMethod("onDeviceAdminEnabled", argv, 1);
    // handle 泄露
};
```

**正确写法**:
```cpp
auto task = [bundleName, this]() {
    auto env = jsRuntime_.GetNapiEnv();
    napi_handle_scope scope = nullptr;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        EDMLOGE("open handle scope failed, status=%{public}d", status);
        return;
    }
    napi_value argv[] = { AbilityRuntime::CreateJsValue(env, bundleName) };
    CallObjectMethod("onDeviceAdminEnabled", argv, 1);
    napi_close_handle_scope(env, scope);
};
```

**检查清单**:
- [ ] 所有创建 `napi_value` 的回调方法必须包裹 `napi_open/close_handle_scope`
- [ ] 校验 `napi_open_handle_scope` 的返回值 `napi_status`，不能只检查 `scope == nullptr`
- [ ] 确保 `napi_close_handle_scope` 在所有退出路径上都被调用

---

## 规则 1.5：malloc/new 后必须判空

**来源**: `d6f22442` — malloc 失败未判空。

**正确写法**:
```cpp
uint8_t* data = (uint8_t*)malloc(size);
if (data == nullptr) {
    EDMLOGE("malloc fail, size=%{public}d", (int32_t)size);
    infile.close();
    return nullptr;
}
```

**检查清单**:
- [ ] 所有 `malloc`/`calloc`/`new` 返回值必须判空
- [ ] 判空失败时释放已获取的资源（文件句柄等）再返回

---

## 规则 1.6：文件读取大小必须设上限

**错误根因**: 文件大小由外部输入控制，无上限可能导致后续缓冲区溢出。

**来源**: `735f67c7` — 水印图片文件大小无上限校验。

**正确写法**:
```cpp
std::streamsize size = infile.tellg();
if (size <= 0 || size > MAX_IMAGE_SIZE) {  // 同时校验下限和上限
    EDMLOGE("size invalid: %{public}d", (int32_t)size);
    infile.close();
    return nullptr;
}
```

**检查清单**:
- [ ] 所有 `tellg()`/`fseek` 获取的文件大小，必须同时校验 `> 0` 和 `<= 上限`
- [ ] 上限值定义在 `EdmConstants` 命名空间，不要分散在多处

---

## 规则 1.7：大小常量统一定义

**错误根因**: 同一限制值在多处分别定义，修改时容易遗漏导致不一致。

**来源**: `d6f22442` — `MAX_WATERMARK_IMAGE_SIZE` 在 addon 和 plugin 两处分别定义。

**正确写法**:
```cpp
// common/native/include/edm_constants.h
namespace EdmConstants {
    constexpr int32_t MAX_WATERMARK_IMAGE_SIZE = 512000; // 500 * 1024
}
```

**检查清单**:
- [ ] 所有策略相关的大小限制、数量限制统一定义在 `EdmConstants` 命名空间
- [ ] 不要在 addon、plugin、service 各处重复定义相同语义的常量
