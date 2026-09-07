# 04 - IPC 与 MessageParcel 规范

> 来源 Bug: 读写不对齐、GetPolicy 返回值处理不一致、大小校验缺失

## 规则 4.1：MessageParcel 读写顺序必须严格对齐

**错误根因**: `OnRemovePolicy` 中 `ReadApplicationInstance` 前缺少一次 `ReadString`，导致后续读取偏移。

**来源**: `b517a9ad` — `SetAbilityDisablePlugin::OnHandlePolicy` 中 REMOVE 分支缺少 `data.ReadString()`。

**错误写法**:
```cpp
} else if (type == FuncOperateType::REMOVE) {
    ApplicationInstance userApp;
    // 缺少 data.ReadString()（permission tag）
    ApplicationInstanceHandle::ReadApplicationInstance(data, userApp);  // 读取偏移
    OnRemovePolicy(userApp, policyData);
}
```

**正确写法**:
```cpp
} else if (type == FuncOperateType::REMOVE) {
    ApplicationInstance userApp;
    data.ReadString();  // 先读取 permission tag（对齐 parcel 位置）
    ApplicationInstanceHandle::ReadApplicationInstance(data, userApp);
    OnRemovePolicy(userApp, policyData);
}
```

**检查清单**:
- [ ] Proxy 侧写入顺序和 Service 侧读取顺序必须严格一致
- [ ] 每次新增 parcel 字段，同时更新 Proxy 写入和 Service 读取
- [ ] 注意 `WITHOUT_PERMISSION_TAG` 等占位字段的读写对齐
- [ ] 使用 `WriteString`/`ReadString` 占位时，读取侧也要对应调用一次

---

## 规则 4.2：GetPolicy 返回值处理方式必须统一

**错误根因**: 不同接口对 `GetPolicy`（返回 bool）的返回值处理方式不一致，有的先判断 bool 再读错误码，有的直接读错误码。

**来源**: `816bd975` — `GetUserExtCredential`/`GetUnlockPolicy` 与 `GetWatermarkImageApps` 处理方式不一致。

**错误写法**（不一致方式 A）:
```cpp
if (!EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(code, data, reply)) {
    return PARAMETER_VERIFICATION_FAILED;  // GetPolicy 返回 false 就直接返回
}
int32_t ret = ERR_INVALID_VALUE;
reply.ReadInt32(ret);
if (ret != ERR_OK) { return ret; }
```

**正确写法**（统一方式 B — 直接从 reply 读错误码）:
```cpp
EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(code, data, reply);
int32_t ret = EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
if (!blRes) {
    EDMLOGE("fail. %{public}d", ret);
    return ret;
}
```

**检查清单**:
- [ ] 所有 `GetPolicy` 调用后，统一从 `reply.ReadInt32(ret)` 读取错误码，不要依赖 GetPolicy 的 bool 返回值
- [ ] 参考 `GetWatermarkImageApps` 的处理方式作为标准模式
- [ ] 新增 Proxy 的 Get 方法必须遵循统一模式

---

## 规则 4.3：IPC 数据大小必须校验上限

**错误根因**: 从 MessageParcel 读取的大小值未设上限，可能导致后续缓冲区溢出。

**来源**: `735f67c7`, `d6f22442` — 水印图片 size 从 parcel 读取后未校验上限。

**正确写法**:
```cpp
param.size = data.ReadInt32();
if (param.size <= 0 || param.size > EdmConstants::MAX_WATERMARK_IMAGE_SIZE) {
    EDMLOGE("size error: %{public}d", param.size);
    return false;
}
```

**检查清单**:
- [ ] 所有从 MessageParcel 读取的 size/length/count 值必须同时校验下限（>0）和上限（<= MAX_XXX）
- [ ] 不要用 `data.GetRawDataCapacity()` 作为上限（太大），应使用业务定义的合理上限
- [ ] 上限值统一定义在 `EdmConstants` 命名空间

---

## 规则 4.4：uint32_t 零值不能用 `!` 判断

**错误根因**: `uint32_t state` 的合法值 0 被 `!state` 误判为 false。

**来源**: `e0603405` — `WindowStateInfoHandle::ReadWindowStateInfo` 中 `!state` 导致 state=0 被拒绝。

**错误写法**:
```cpp
uint32_t state = data.ReadUint32();
if (!state || state > static_cast<uint32_t>(WindowState::BACKGROUND)) {
    return false;  // state=0 被误判
}
```

**正确写法**:
```cpp
uint32_t state = data.ReadUint32();
if (state > static_cast<uint32_t>(WindowState::BACKGROUND)) {
    return false;  // 只校验上限
}
```

**检查清单**:
- [ ] 所有 `uint32_t`/`uint64_t`/`size_t` 类型的值，禁止用 `!value` 判断是否为 0
- [ ] 使用 `value == 0` 或 `value > 0` 做显式判断
- [ ] 枚举值 0 通常是合法值（如 `FOREGROUND`、`NONE`），不要当作错误

---

## 规则 4.5：uint32_t size 不可能小于 0，不要做无意义判断

**错误根因**: 对 `uint32_t` 类型做 `< 0` 判断永远为 false，掩盖了真正的 `== 0` 检查意图。

**来源**: `6ba3dfd5` — `application_manager_proxy.cpp` 中 `uint32_t size` 判断 `< 0`。

**错误写法**:
```cpp
uint32_t size = data.ReadUint32();
if (size < 0) {  // 永远为 false
    return false;
}
```

**正确写法**:
```cpp
uint32_t size = data.ReadUint32();
if (size == 0) {
    return false;
}
```

**检查清单**:
- [ ] 审查所有无符号类型的比较，`< 0` 是无意义的
- [ ] 检查意图应该是 `== 0` 还是 `> MAX`，修正比较表达式
- [ ] `std::streamsize` 是有符号类型，可以做 `<= 0` 但要区分 `== 0` 和 `< 0`
