# getCallLogs 接口需求设计实现文档

> PR: https://gitcode.com/openharmony/customization_enterprise_device_management/pull/2149
> SDK: https://gitcode.com/openharmony/interface_sdk-js/pull/36295
> Doc: https://gitcode.com/openharmony/docs/pull/166302
> @since 26.2.0

---

## 1. 需求概述

企业 MDM 应用需要读取设备通话记录进行审计，通过 MDM kit 提供读取通话记录的能力，支持按照时间范围和号码查询通话记录。

### 1.1 接口签名

```ts
function getCallLogs(admin: Want, queryConfig: TelephonyQueryConfig): Promise<Array<CallLogInfo>>;
```

### 1.2 数据结构

```ts
interface TelephonyQueryConfig {
    startTime: number;       // 秒级时间戳，按 create_time 匹配
    endTime: number;         // 秒级时间戳，按 create_time 匹配
    telephoneNumber?: string; // 可选，按号码过滤
}

interface CallLogInfo {
    createTime: number;       // 通话记录创建时间（秒）。来电=振铃时刻，去电=拨出时刻
    startTime: number;        // 通话接通时间（秒）。未接通时为 0
    endTime: number;          // 通话结束时间（秒）。未接通时为挂断时间
    isIncoming: boolean;      // true=呼入，false=呼出
    slotId: number;           // SIM 卡槽 ID
    telephoneNumber: string;  // 对方电话号码
}
```

### 1.3 权限与错误码

| 项 | 值 |
|---|---|
| 权限 | `ohos.permission.ENTERPRISE_READ_CALL_LOG` |
| 管理员类型 | SUPER_DEVICE_ADMIN（仅系统级管理员可调用） |
| 支持设备 | 手机、平板（不支持 PC） |
| 时间范围上限 | 31 天 |

| 错误码 | 说明 |
|--------|------|
| 201 | 权限校验失败 |
| 401 | 参数错误 |
| 9200001 | 非管理员应用 |
| 9200002 | 管理员权限不足 |
| 9200007 | 系统异常 |
| 9200012 | 参数校验失败 |
| 801 | 设备不支持 |

---

## 2. 数据库字段语义

通话记录数据库表 `calllog`，由 `contacts_data` 的 `CallLogAbility` 提供 DataShare 接口。时间字段均为**秒级 Unix 时间戳**（`time_t`）。

| 数据库字段 | 含义 | 设置时机 | 未接通时 |
|-----------|------|---------|---------|
| `create_time` | 通话记录创建时间 | 通话对象创建时（来电振铃/去电拨出） | 有值（所有记录都有） |
| `begin_time` | 通话接通时间 | `StateChangesToActive()` — 接听/连接成功 | **0** |
| `end_time` | 通话结束时间 | `StateChangesToDisconnected()` — 挂断 | 挂断时间 |
| `phone_number` | 对方号码 | 插入时 | 有值 |
| `call_direction` | 通话方向 | 0=呼入，1=呼出 | 有值 |
| `slot_id` | SIM 卡槽 | 0=卡槽1，1=卡槽2 | 有值 |

**关键设计决策：查询过滤用 `create_time` 而非 `begin_time`**。原因：未接/拒接/拦截的通话 `begin_time=0`，用 `begin_time >= startTime` 过滤会漏掉这些记录。`create_time` 是通话对象创建时写入的，所有记录都有。

---

## 3. 接口码与策略注册

### 3.1 接口码

```cpp
// edm_ipc_interface_code.h
GET_CALL_LOGS = 1194,  // 在 GET_PATCH_INFO(1193) 之后，POLICY_CODE_END(3000) 之前
```

### 3.2 策略注册（三处同步）

| 注册位置 | 文件 | 内容 |
|---------|------|------|
| CONFIG_TABLE | `policy_query_config_table.cpp` | CUSTOM + SpecificPermission(PERMISSION_ENTERPRISE_READ_CALL_LOG) + TELEPHONY_EDM_ENABLE 门控 |
| supportAdminNullPolicyCode_ | `permission_checker.cpp` | EdmInterfaceCode::GET_CALL_LOGS |
| communicationSoCodes_ | `plugin_manager.cpp` | EdmInterfaceCode::GET_CALL_LOGS |

CONFIG_TABLE 条目必须按接口码升序排列（`lower_bound` 二分查找）。GET_CALL_LOGS=1194 在 IS_ALLOWED_ODD_BURN=1188 之后、POLICY_CODE_END+X（3000+）之前，排序正确。

---

## 4. 数据大小控制与传输机制

### 4.1 需求规格

| 数据范围 | 传输方式 | 处理 |
|---------|---------|------|
| ≤ 128MB | raw data（IPC 通道） | 全量返回 |
| > 128MB | 截断到 ~128MB | 截断后走 raw data |

IPC raw data 通道最大支持 128MB，无需 ashmem 共享内存机制。

### 4.2 阈值常量

| 常量 | 值 | 用途 |
|------|------|------|
| `MAX_CALL_LOG_RETURN_SIZE` | 128MB | 返回数据截断上限 |
| `MAX_PARCEL_CAPACITY_OF_ASHMEM` | 1GB | tempParcel 容量上限 / proxy 校验上限 |

### 4.3 三层检查机制

```
数据库 N 条记录
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Layer 1：QueryCallLogs 查询循环（估算检查）       │
│                                                   │
│  检查: callLogs.size() × 64 >= 128MB?             │
│  作用: 用估算值提前停止从 DataShare 读行           │
│  目的: 防止 vector 撑爆内存                        │
│  触发点: ~209万条（128MB / 64 字节）               │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Layer 2：WriteCallLogsToReply 序列化循环（实际检查）│
│                                                   │
│  检查: tempParcel.GetDataSize() > 128MB?          │
│  作用: 用实际序列化大小精确截断                     │
│  目的: 防止 parcel 数据超限                         │
│  触发点: 实际 ~128MB（取决于号码长度）              │
│                                                   │
│  截断后: dataSize ≈ 128MB + 一条记录（~48-236字节） │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ 传输（统一走 raw data）                            │
│                                                   │
│  reply.WriteInt32(ERR_OK)                         │
│  reply.WriteInt32(dataSize)                       │
│  reply.WriteRawData(tempParcel.GetData(), dataSize)│
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Proxy 侧读取                                      │
│                                                   │
│  reply.ReadRawData(dataSize)                      │
│  → malloc + memcpy_s → ParseFrom(buffer)          │
└─────────────────────────────────────────────────┘
```

### 4.4 截断机制详解

**Layer 2 的检查在写入之前**，所以最后一条写入的记录可能把数据推过 128MB：

```
轮次 M：
  ① 检查: GetDataSize() = 127.99MB < 128MB → 通过
  ② 写入第 M 条记录（+236 字节）
  ③ actualCount++
     此时数据 = 127.99MB + 236 = 128.0002MB

轮次 M+1：
  ① 检查: GetDataSize() = 128.0002MB > 128MB → break
```

截断后 `dataSize ≈ 128MB + 一条记录`，远小于 1GB（tempParcel 容量上限）。

**count 占位符回填**：

```
tempParcel 内存布局：

写入时:  [count=0(4字节)] [记录1] [记录2] ... [记录M]
回填后:  [count=M(4字节)] [记录1] [记录2] ... [记录M]
```

先写 0 占位（循环前不知道最终条数），循环结束后用 `GetData()` 拿到缓冲区首地址，覆盖前 4 字节为实际 count。Proxy 按 count 读取，不会多读或少读。

### 4.5 每条记录序列化大小

| 字段 | 类型 | 字节数 |
|------|------|--------|
| createTime | int64 | 8 |
| startTime | int64 | 8 |
| endTime | int64 | 8 |
| isIncoming | bool | 4 |
| slotId | int32 | 4 |
| telephoneNumber | string | 4 + N + padding |
| **固定部分** | | **32** |
| **含 11 位号码** | | **~43** |
| **含 200 字符号码** | | **~236** |

### 4.6 raw data 传输流程

**插件端（WriteCallLogsToReply）**：

```
1. tempParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY_OF_ASHMEM)  → 设容量 1GB
2. tempParcel.WriteInt32(0)                     → 写 count 占位符
3. 循环写入记录（检查实际大小 > 128MB 则截断）
4. 回填 count 占位符
5. reply.WriteInt32(ERR_OK)                     → 写状态码
6. reply.WriteInt32(dataSize)                   → 写数据大小
7. reply.WriteRawData(tempParcel.GetData(), dataSize)  → 写原始数据
```

**Proxy 端（ReadBufferFromReply）**：

```
1. reply.ReadRawData(dataSize)                  → 读取原始数据指针
2. malloc(dataSize) + memcpy_s                  → 复制到本地 buffer
3. tempParcel.ParseFrom(buffer, dataSize)       → 解析为 parcel
```

**ParseFrom 所有权管理**：

`ParseFrom` 接管 buffer 所有权，parcel 析构时自动 free。`ParseFrom` 失败时手动 `free(buffer)` 防止泄漏。`GetCallLogs` 中不调用 `free(buffer)`，避免 double-free。

---

## 5. IPC 协议布局

### 5.1 GET 协议（Proxy → Stub → Plugin）

```
Proxy 写入:
  InterfaceToken → WITHOUT_USERID → permissionTag → HAS_ADMIN → admin → startTime → endTime → hasTel → [tel]

Stub 读取:
  InterfaceToken → hasUserId → [userId]

GetDevicePolicy 读取:
  permissionTag = ReadString()

GetDevicePolicyFromPlugin 读取:
  adminFlag = ReadInt32() (0=HAS_ADMIN)
  admin = ReadParcelable<ElementName>()

Plugin OnGetPolicy 读取:
  startTime → endTime → hasTelephoneNumber → [telephoneNumber]
```

### 5.2 返回数据格式

```
reply 布局:
  [ERR_OK(int32)] [dataSize(int32)] [data]

data 内部布局 (raw data):
  [count(int32)] [createTime(int64)] [startTime(int64)] [endTime(int64)]
  [isIncoming(bool)] [slotId(int32)] [telephoneNumber(string)]
  × count 条
```

插件序列化顺序与 Proxy 反序列化顺序严格对齐。

---

## 6. DataShare 查询实现

### 6.1 DataShareHelper 创建

参照 `call_manager` 的 `CallDataBaseHelper`：

```cpp
// Creator 用 base URI（authority only）
DataShareHelper::Creator(remote, "datashare:///com.ohos.calllogability", "", waitTime);

// Query 用 full URI（authority + path）
Uri uri("datashare:///com.ohos.calllogability/calls/calllog");
helper->Query(uri, predicates, columns);
```

token 为 `ENTERPRISE_DEVICE_MANAGER_SA_ID`（EDM 服务自身）。EDM 在 `edm.cfg` 中声明了 `ohos.permission.READ_CALL_LOG`，通过 calllog ability 的权限检查。

### 6.2 查询谓词

```cpp
predicates.GreaterThanOrEqualTo("create_time", std::to_string(config.startTime));
predicates.And()->LessThanOrEqualTo("create_time", std::to_string(config.endTime));
predicates.OrderByDesc("create_time");  // 按创建时间降序
```

时间戳为秒级，与数据库存储单位一致，无需转换。

### 6.3 结果集遍历

参照 call_manager 模式：

```cpp
resultSet->GetRowCount(rowCount);    // 空结果提前返回
resultSet->GoToFirstRow();           // 先到第一行
while (operationResult == 0) {
    // GetColumnIndex by name + GetLong/GetInt/GetString
    operationResult = resultSet->GoToNextRow();  // 末尾移动
}
resultSet->Close();                  // 释放结果集
helper->Release();                   // 释放 helper
```

---

## 7. 插件架构

### 7.1 插件类型

`PluginSingleton<GetCallLogsPlugin, int32_t>` — Type D 模式（直接继承 PluginSingleton），GET-only（needSave=false）。

### 7.2 查询路由

```
GetPolicy(GET_CALL_LOGS)
  → CheckFeatureEnabled(1194)  ← config table 中已注册，返回 ERR_OK
  → CreateQuery(1194)          ← CUSTOM 类型，CreateCustomQuery 返回 nullptr
  → ERR_CANNOT_FIND_QUERY_FAILED
  → GetDevicePolicyFromPlugin  ← fallback
      → CheckElementNullPermission(1194)  ← supportAdminNullPolicyCode_ 中已注册
      → PluginManager::GetPolicy
      → GetCallLogsPlugin::OnGetPolicy    ← 实际查询逻辑
```

### 7.3 条件编译

- 插件代码：`#ifdef TELEPHONY_EDM_ENABLE` 包裹 DataShare 相关代码
- Addon 代码：`#if defined(TELEPHONY_EDM_ENABLE)` 包裹 NAPI 方法
- 不支持时返回 `INTERFACE_UNSUPPORTED`（801）

---

## 8. Addon 层实现

### 8.1 异步调用

`getCallLogs` 为异步接口（Promise），使用 `HandleAsyncWork`：

```cpp
napi_value GetCallLogs(env, info) {
    // 参数校验：admin(Want) + queryConfig(object)
    // ParseQueryConfigFromJs: startTime, endTime, telephoneNumber?
    HandleAsyncWork(env, asyncCallbackInfo, "NativeGetCallLogs",
        NativeGetCallLogs, NativeGetCallLogsComplete);
}

void NativeGetCallLogs(env, data) {
    // 在线程池中执行：proxy->GetCallLogs(elementName, queryConfig, callLogs)
}

void NativeGetCallLogsComplete(env, status, data) {
    // 在主线程执行：ConvertVectorCallLogToJs → resolve deferred
}
```

### 8.2 错误码类型

所有 `CreateError` 调用使用 `ErrcodeType::NUMBER`（规则 7.1）。

### 8.3 JS 转换

```cpp
void ConvertVectorCallLogToJs(env, callLogs, result) {
    for (const auto &log : callLogs) {
        // napi_create_int64: createTime, startTime, endTime
        // napi_get_boolean: isIncoming (用 NAPI_CALL_RETURN_VOID 校验)
        // napi_create_int32: slotId
        // napi_create_string_utf8: telephoneNumber
    }
}
```

---

## 9. BUILD.gn

三个 BUILD.gn 文件均已添加 `get_call_logs_plugin.cpp`：

| 文件 | 用途 |
|------|------|
| `services/edm_plugin/BUILD.gn` | 编译插件到 communication_plugin.so |
| `test/fuzztest/enterprisedevicemgrstubmock_fuzzer/BUILD.gn` | Fuzz 测试 |
| `test/unittest/services/edm_plugin/BUILD.gn` | 单元测试 |

---

## 10. 完整数据流

```
JS: getCallLogs(admin, { startTime: 秒, endTime: 秒, telephoneNumber?: "..." })
  │
  ▼
Addon: ParseQueryConfigFromJs → TelephonyQueryConfig (秒)
  │  校验: 参数类型、时间范围 ≤ 31 天
  ▼
Proxy::GetCallLogs
  │  写 MessageParcel (GET 协议布局)
  │  IPC GetPolicy(GET_CALL_LOGS)
  ▼
Stub → GetDevicePolicy
  │  ReadString(permissionTag)
  │  CheckFeatureEnabled(1194) ✓
  │  CreateQuery(1194) → nullptr → ERR_CANNOT_FIND_QUERY_FAILED
  │  → GetDevicePolicyFromPlugin
  │    → ReadInt32(adminFlag=0=HAS_ADMIN) → ReadParcelable(admin)
  │    → CheckElementNullPermission(1194) ✓
  │    → PluginManager::GetPolicy
  ▼
GetCallLogsPlugin::OnGetPolicy
  │  校验: startTime≥0, endTime≥0, startTime≤endTime, 范围≤31天
  │  ReadInt64(startTime), ReadInt64(endTime), ReadBool(hasTel), [ReadString(tel)]
  │
  ├── TELEPHONY_EDM_ENABLE 未定义 → 返回 INTERFACE_UNSUPPORTED (801)
  │
  └── TELEPHONY_EDM_ENABLE 已定义:
       │
       ▼
     QueryCallLogs
       │  CreateCallLogHelper (base URI for Creator)
       │  BuildPredicates (create_time 过滤 + DESC 排序)
       │  helper->Query(full URI, predicates, columns)
       │  GetRowCount → 0 则提前返回空数组
       │  GoToFirstRow → while 循环:
       │    Layer 1: 估算 ≥ 128MB → break
       │    GetColumnIndex + GetLong/GetInt/GetString 读每列
       │    push 到 callLogs vector
       │    GoToNextRow
       │  resultSet->Close() + helper->Release()
       │
       ▼
     WriteCallLogsToReply
       │  tempParcel (容量 1GB)
       │  WriteInt32(0) — count 占位符
       │  循环:
       │    Layer 2: GetDataSize() > 128MB → break
       │    WriteInt64(createTime) + WriteInt64(startTime) + ...
       │    检查每个 Write 返回值
       │  回填 count 占位符
       │  WriteInt32(ERR_OK) + WriteInt32(dataSize) + WriteRawData(data)
       │
       ▼
     reply = [ERR_OK] [dataSize] [raw_data]
  │
  ▼
Proxy::GetCallLogs (读取 reply)
  │  ReadInt32(ret) → ERR_OK?
  │  ReadInt32(dataSize)
  │  校验: dataSize > 0 且 ≤ 1GB
  │  ReadRawData(dataSize) → src 指针
  │  AllocAndCopyBuffer: malloc + memcpy_s
  │  ParseCallLogsFromBuffer:
  │    ParseFrom(buffer) — parcel 接管所有权
  │    ReadInt32(count) + 安全校验 (count ≤ readableBytes)
  │    循环 count 次: ReadInt64(createTime) + ReadInt64(startTime) + ...
  │  (不 free(buffer) — ParseFrom 析构时自动释放)
  │
  ▼
Addon: ConvertVectorCallLogToJs
  │  napi_create_int64(createTime/startTime/endTime)
  │  NAPI_CALL_RETURN_VOID(napi_get_boolean(isIncoming))
  │  napi_create_int32(slotId)
  │  napi_create_string_utf8(telephoneNumber)
  │  → resolve deferred
  │
  ▼
JS: Array<CallLogInfo>
```

---

## 11. 代码检视合规检查

### 11.1 AGENTS.md 通用检查清单（12 步）

| # | 检查项 | 状态 |
|---|--------|------|
| 1 | 定义接口码 | ✅ GET_CALL_LOGS = 1194 |
| 2 | 定义策略常量 | ✅ POLICY_GET_CALL_LOGS |
| 3 | 定义权限常量 | ✅ PERMISSION_ENTERPRISE_READ_CALL_LOG |
| 4 | 实现插件类 | ✅ PluginSingleton, Type D |
| 5 | 注册插件 | ✅ AddPlugin(GetPlugin()) |
| 6 | 注册 SO 列表 | ✅ communicationSoCodes_ |
| 7 | 实现查询类 | ✅ N/A (CUSTOM, fallback to OnGetPolicy) |
| 8 | 注册查询配置 | ✅ CONFIG_TABLE (CUSTOM + SpecificPermission) |
| 9 | Addon 映射 | ✅ DECLARE_NAPI_FUNCTION("getCallLogs", GetCallLogs) |
| 10 | 条件编译 | ✅ TELEPHONY_EDM_ENABLE |
| 11 | Proxy 方法 | ✅ GET 协议布局 |
| 12 | BUILD.gn | ✅ 3 个文件 |

### 11.2 编码规则

| 规则 | 状态 | 说明 |
|------|------|------|
| 5.1 权限匹配 | ✅ | Plugin / config table / .d.ts 三层一致 |
| 5.3 supportAdminNullPolicyCode_ | ✅ | GET_CALL_LOGS 已加入 |
| 5.4 CUSTOM dataType | ✅ | 返回自定义 CallLogInfo 数组 |
| 7.1 NUMBER errcodeType | ✅ | 所有 CreateError 用 NUMBER |
| 4.1 Parcel 读写对齐 | ✅ | 序列化/反序列化字段顺序一致 |
| 4.2 GetPolicy 统一处理 | ✅ | ReadInt32(ret) && ret == ERR_OK |
| 4.3 IPC 大小校验 | ✅ | dataSize 上下限 + count 安全校验 |
| 8.1 napi 返回值校验 | ✅ | napi_get_boolean 用 NAPI_CALL_RETURN_VOID |
| 8.6 魔数替换 | ✅ | CALL_DIRECTION_OUT = 1 |

### 11.3 内存安全

| 检查项 | 状态 |
|--------|------|
| Write 返回值全部检查 | ✅ |
| reply.WriteInt32 返回值检查 | ✅ |
| ParseFrom double-free 已修复 | ✅ ParseFrom 接管所有权，GetCallLogs 不 free |
| ParseFrom 失败路径 free | ✅ |
| resultSet->Close() 释放 | ✅ |

---

## 12. 涉及文件清单

| 文件 | 改动类型 | 说明 |
|------|---------|------|
| `common/native/include/edm_constants.h` | 新增 | PERMISSION_ENTERPRISE_READ_CALL_LOG, POLICY_GET_CALL_LOGS |
| `interfaces/inner_api/common/include/call_log_info.h` | 新增 | CallLogInfo, TelephonyQueryConfig 结构体 |
| `interfaces/inner_api/common/include/edm_ipc_interface_code.h` | 新增 | GET_CALL_LOGS = 1194 |
| `interfaces/inner_api/telephony_manager/include/telephony_manager_proxy.h` | 新增 | GetCallLogs 声明 |
| `interfaces/inner_api/telephony_manager/src/telephony_manager_proxy.cpp` | 新增 | GetCallLogs + raw data 读取 + ParseFrom 安全 |
| `interfaces/kits/telephony_manager/include/telephony_manager_addon.h` | 新增 | GetCallLogs + AsyncCallLogCallbackInfo |
| `interfaces/kits/telephony_manager/src/telephony_manager_addon.cpp` | 新增 | NAPI 方法 + JS 转换 |
| `services/edm/include/telephony_manager/get_call_logs_plugin.h` | 新增 | 插件头文件 |
| `services/edm_plugin/src/telephony_manager/get_call_logs_plugin.cpp` | 新增 | DataShare 查询 + 序列化 + raw data 传输 |
| `services/edm/src/permission_checker.cpp` | 修改 | 加入 supportAdminNullPolicyCode_ |
| `services/edm/src/query_policy/policy_query_config_table.cpp` | 修改 | 加入 CONFIG_TABLE 条目 |
| `services/edm/src/plugin_manager.cpp` | 修改 | 加入 communicationSoCodes_ |
| `services/edm_plugin/BUILD.gn` | 修改 | 加入源文件 |
| `test/fuzztest/.../BUILD.gn` | 修改 | 加入源文件 |
| `test/unittest/.../BUILD.gn` | 修改 | 加入源文件 |
