# 06 - 数据解析与校验规范

> 来源 Bug: cJSON 字段强制要求、uint32_t 零值判断、默认值缺失、局部引用临时对象

## 规则 6.1：JSON 字段新增时必须向后兼容（选填而非必填）

**错误根因**: 新增 JSON 字段后，旧数据缺少该字段时反序列化直接返回失败。

**来源**: `9fec601b`（isDeviceTypeAllMatch）、`7384557d`（complexityReg/validityPeriod）。

**错误写法**:
```cpp
cJSON* complexityReg = cJSON_GetObjectItem(root_, "complexityReg");
cJSON* validityPeriod = cJSON_GetObjectItem(root_, "validityPeriod");
if (!cJSON_IsString(complexityReg) || !cJSON_IsNumber(validityPeriod)) {
    return false;  // 旧数据缺少字段直接失败
}
policy.complexityReg = cJSON_GetStringValue(complexityReg);
```

**正确写法**: 逐字段可选解析
```cpp
cJSON* complexityReg = cJSON_GetObjectItem(root_, "complexityReg");
if (cJSON_IsString(complexityReg)) {
    policy.complexityReg = cJSON_GetStringValue(complexityReg);
}
// 缺失时使用结构体默认值（空字符串）

cJSON* validityPeriod = cJSON_GetObjectItem(root_, "validityPeriod");
if (cJSON_IsNumber(validityPeriod)) {
    policy.validityPeriod = cJSON_GetNumberValue(validityPeriod);
}
// 缺失时使用默认值 0
```

**检查清单**:
- [ ] 新增 JSON 字段时，必须设计为可选（缺失时用默认值）
- [ ] 不要将新增字段和已有必填字段放在同一个 `if` 中判断
- [ ] 序列化端写入了字段，反序列化端缺失该字段不应报错
- [ ] 为每个新增字段定义合理的默认值

---

## 规则 6.2：uint32_t 零值是合法值，禁止用 `!` 判断

**来源**: `e0603405` — `uint32_t state` 的 0 值被 `!state` 误判为 false。

详见 [04-ipc-and-parcel.md 规则 4.4](./04-ipc-and-parcel.md#规则-44uint32_t-零值不能用-判断)。

**核心要求**:
```cpp
// 错误
if (!state || state > MAX) { ... }

// 正确
if (state > MAX) { ... }  // 0 是合法值，只校验上限
```

**通用规则**:
- 无符号类型（`uint32_t`, `uint64_t`, `size_t`）的 0 值通常是合法的
- 禁止用 `!value` 判断无符号类型是否为 0
- 禁止对无符号类型做 `< 0` 判断（永远为 false）

---

## 规则 6.3：默认配置值缺失时必须显式设置

**错误根因**: 网络接口配置时未设置 `routeList_`，导致网关默认为 0.0.0.0。

**来源**: `31630975` — `SetNetworkInterfaceConfigPlugin::OnHandlePolicy` 未设置 routeList。

**错误写法**:
```cpp
StaticConfiguration::ExtractNetAddrBySeparator(gateway, cfg->ipStatic_.gatewayList_);
StaticConfiguration::ExtractNetAddrBySeparator(netMask, cfg->ipStatic_.netMaskList_);
StaticConfiguration::ExtractNetAddrBySeparator(dnsServers, cfg->ipStatic_.dnsServers_);
// routeList_ 未设置，默认为空，导致网关 0.0.0.0
```

**正确写法**: 显式设置默认值
```cpp
StaticConfiguration::ExtractNetAddrBySeparator(gateway, cfg->ipStatic_.gatewayList_);
StaticConfiguration::ExtractNetAddrBySeparator(netMask, cfg->ipStatic_.netMaskList_);
StaticConfiguration::ExtractNetAddrBySeparator(dnsServers, cfg->ipStatic_.dnsServers_);
StaticConfiguration::ExtractNetAddrBySeparator(DEFAULT_IPV4_ADDR,
    cfg->ipStatic_.routeList_);  // 显式设置默认路由
```

**检查清单**:
- [ ] 所有配置对象在设置前，检查是否需要显式初始化默认值
- [ ] 网络配置（IP、网关、路由、DNS）字段之间有依赖关系，必须全部设置
- [ ] 定义默认值常量（如 `DEFAULT_IPV4_ADDR = "0.0.0.0"`）

---

## 规则 6.4：禁止返回局部对象的引用

**错误根因**: `EdmJsonBuilder &jsonBuilder` 绑定到临时对象，`AddRawJson` 操作的是已销毁的临时对象。

**来源**: `15068b50` — `GlobalProxyPlugin::OnSetPolicy` 中局部引用临时对象。

**错误写法**:
```cpp
EdmJsonBuilder &jsonBuilder = EdmJsonBuilder()
    .Add("host", host)
    .Add("port", port)
    .Build();  // 临时对象，引用悬垂
jsonBuilder.AddRawJson("httpProxy", httpProxyJson);  // 操作已销毁对象
```

**正确写法**: 使用局部变量
```cpp
EdmJsonBuilder jsonBuilder;  // 局部变量，生命周期完整
jsonBuilder.AddRawJson("httpProxy", httpProxyJson);
if (userId != -1) {
    jsonBuilder.Add("accountId", userId);
}
```

**检查清单**:
- [ ] 禁止将 `const &` 或 `&` 绑定到临时对象（右值）
- [ ] 链式调用产生的临时对象不要保存引用，直接使用或用局部变量接收
- [ ] 特别注意 `Builder()` 模式返回临时对象的场景

---

## 规则 6.5：枚举值缺失（INVALID）分支必须显式处理

**错误根因**: `Direction` 枚举的 `INVALID` 值未被处理，direction 参数不传时默认拦截规则未设置。

**来源**: `7c817559` — `SetDefaultOutputDenyChain` 只处理 `OUTPUT`。

**错误写法**:
```cpp
bool SetDefaultOutputDenyChain(Direction direction, Family family) {
    if (direction == Direction::OUTPUT) {  // 未处理 INPUT 和 INVALID
        // 设置默认规则
    }
    ...
}
```

**正确写法**: 覆盖所有可能的值
```cpp
if (direction == Direction::OUTPUT || direction == Direction::INPUT ||
    direction == Direction::INVALID) {
    // 设置默认规则
}
```

**检查清单**:
- [ ] switch/if 分支必须覆盖所有枚举值，或使用 default 分支
- [ ] 特别注意 `INVALID`/`NONE`/`UNKNOWN` 等特殊枚举值的处理
- [ ] 参数可选（可能不传）时，确认默认值（通常映射为 INVALID）的处理逻辑
