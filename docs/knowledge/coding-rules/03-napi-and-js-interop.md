# 03 - NAPI 与 JS 互操作规范

> 来源 Bug: handle 泄露、返回值未校验、异步错误码类型传递

## 规则 3.1：所有 napi_value 创建必须包裹 handle_scope

**来源**: `2b94ca43` — 9+ 回调方法未包裹 handle_scope 导致泄露。

详见 [01-memory-and-pointer-safety.md 规则 1.4](./01-memory-and-pointer-safety.md#规则-14napi-handle-必须包裹在-handle_scope-中)。

**核心要求**:
```cpp
auto env = jsRuntime_.GetNapiEnv();
napi_handle_scope scope = nullptr;
auto status = napi_open_handle_scope(env, &scope);
if (status != napi_ok || scope == nullptr) {
    EDMLOGE("open handle scope failed, status=%{public}d", status);
    return;
}
// ... 创建并使用 napi_value ...
napi_close_handle_scope(env, scope);
```

---

## 规则 3.2：AddonMethodAdapter 必须传递 errcodeType

**错误根因**: 异步适配器未将 `methodSign.errcodeType` 传递给 `adapterAddonData`，导致错误码以 STRING 返回而非 NUMBER。

**来源**: `816bd975` — `openSession`/`addUserExtCredential`/`getUserExtCredential` 异步接口错误码类型错误。

**错误写法**:
```cpp
// napi_edm_adapter.cpp — AddonMethodAdapter
// 缺少 errcodeType 赋值
adapterAddonData->data = ...;
```

**正确写法**:
```cpp
adapterAddonData->errcodeType = methodSign.errcodeType;  // 必须传递
```

**检查清单**:
- [ ] 新增异步接口时，确认 `AddonMethodSign.errcodeType` 已正确配置
- [ ] 确认 `AddonMethodAdapter` 内部将 `errcodeType` 传递到了 `adapterAddonData`
- [ ] 新接口统一使用 `ErrcodeType::NUMBER`（见规则 07-01）

---

## 规则 3.3：JsObjectToU8Vector 等解析函数返回值必须校验

**错误根因**: `JsObjectToU8Vector` 返回 false（解析失败）时未中断，继续写入空数据。

**来源**: `816bd975` — `AddUserExtCredential`/`RemoveUserExtCredential` 中 `JsObjectToU8Vector` 返回值未校验。

**错误写法**:
```cpp
auto convertRemoveInfo = [](napi_env env, napi_value argv, MessageParcel &data,
    const AddonMethodSign &methodSign) -> ErrCode {
    std::vector<uint8_t> credentialId;
    JsObjectToU8Vector(env, argv, "credentialId", credentialId);  // 返回值忽略
    data.WriteUInt8Vector(credentialId);  // 解析失败也继续写
    ...
};
```

**正确写法**:
```cpp
std::vector<uint8_t> credentialId;
if (!JsObjectToU8Vector(env, argv, "credentialId", credentialId)) {
    EDMLOGE("Parameter credentialId error");
    return EdmReturnErrCode::PARAM_ERROR;  // 解析失败立即返回
}
data.WriteUInt8Vector(credentialId);
```

**检查清单**:
- [ ] 所有 `JsObjectToXxx` / `JsObjectToU8Vector` / `ParseInt` / `ParseBool` 等解析函数返回值必须校验
- [ ] 解析失败时返回 `PARAM_ERROR`，不要继续后续操作
- [ ] CUSTOM 类型的 lambda 转换器中，每个字段解析都要校验

---

## 规则 3.4：napi 系统函数返回值必须校验

**错误根因**: `napi_open_handle_scope`、`napi_get_undefined`、`napi_create_array` 等返回 `napi_status`，仅检查输出参数为 nullptr 不够。

**来源**: `6ba3dfd5` — 9 处 `napi_open_handle_scope` 只检查 scope == nullptr，未检查 napi_status。

**错误写法**:
```cpp
napi_open_handle_scope(env, &scope);
if (scope == nullptr) {  // 不够，napi_status 可能非 ok 但 scope 仍可能非空
    return;
}
```

**正确写法**:
```cpp
auto status = napi_open_handle_scope(env, &scope);
if (status != napi_ok || scope == nullptr) {
    EDMLOGE("failed, status=%{public}d", status);
    return;
}
```

**需校验的 napi 函数清单**:
- `napi_open_handle_scope` / `napi_close_handle_scope`
- `napi_get_undefined` / `napi_get_null` / `napi_get_boolean`
- `napi_create_array` / `napi_create_array_with_length`
- `napi_create_object` / `napi_create_function`
- `napi_get_cb_info` / `napi_get_reference_value`

**检查清单**:
- [ ] 所有 napi 函数调用的返回值 `napi_status` 必须校验为 `napi_ok`
- [ ] 不要只检查输出指针参数是否为 nullptr

---

## 规则 3.5：方法名映射字符串大小写必须与 JS 侧一致

**错误根因**: `removeAutoStartApps` 方法名映射字符串大小写拼写错误，导致 JS 侧调用不到。

**来源**: `6ba3dfd5` — `application_manager_addon.cpp` 中 `removeAutoStartApps` 大小写错误。

**检查清单**:
- [ ] addon 中 `itemCodeMap`/`labelCodeMap` 的字符串必须与 JS 接口定义完全一致（区分大小写）
- [ ] 新增接口映射后，确认 JS 侧能正确调用
