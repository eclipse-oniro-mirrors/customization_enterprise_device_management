# getCallLogs 数据大小检查验证用例设计

> 针对 `get_call_logs_plugin.cpp` 中双层数据大小检查逻辑的数据库构造插桩验证方案。

## 1. 被测逻辑分析

### 1.1 两层防护

| 层 | 位置 | 检查条件 | 阈值 | 触发条件 |
|---|------|---------|------|---------|
| Layer 1 | `QueryCallLogs` 查询循环 | `callLogs.size() * ESTIMATED_RECORD_SIZE >= MAX_CALL_LOG_RETURN_SIZE` | 估算 ~209 万条（64 字节/条 × 128MB） | 估算大小超限，停止从 DataShare 读更多行 |
| Layer 2 | `WriteCallLogsToReply` 序列化循环 | `tempParcel.GetDataSize() > MAX_CALL_LOG_RETURN_SIZE` | 实际 128MB | 实际序列化大小超限，停止写入 parcel |

### 1.2 常量定义

```cpp
constexpr size_t ESTIMATED_RECORD_SIZE = 64;                              // 每条记录估算大小
constexpr int64_t MAX_CALL_LOG_RETURN_SIZE = 128LL * 1024 * 1024;       // 128MB，截断上限
// EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM = 1024 * 1024 * 1024;      // 1GB，tempParcel 容量上限
```

### 1.3 每条记录序列化大小

| 字段 | 类型 | 序列化字节数 |
|------|------|-------------|
| createTime | int64 | 8 |
| startTime | int64 | 8 |
| endTime | int64 | 8 |
| isIncoming | bool | 4 |
| slotId | int32 | 4 |
| telephoneNumber | string | 4（长度）+ N（内容）+ padding |
| **固定部分合计** | | **36 字节** |
| **含 11 位号码** | | ~43 字节 |
| **含 200 字符号码** | | ~236 字节 |

### 1.4 关键结论

- Layer 1 用 64 字节/条的保守估算，在查询阶段提前停止读取。
- Layer 2 用实际 `GetDataSize()` 精确检查，在序列化阶段停止写入。
- 所有数据统一走 `WriteRawData`（IPC raw data 通道），支持最大 128MB。
- 数据超过 128MB 时截断，截断后数据 ≈ 128MB + 一条记录。

### 1.5 代码位置

```
QueryCallLogs:
  Line 136: if (callLogs.size() * ESTIMATED_RECORD_SIZE >= MAX_CALL_LOG_RETURN_SIZE)
  → Layer 1: 估算截断（128MB），停止从 DataShare 读行

WriteCallLogsToReply:
  Line 221: if (tempParcel.GetDataSize() > MAX_CALL_LOG_RETURN_SIZE)
  → Layer 2: 实际截断（128MB），停止写入 tempParcel

  Line 207: reply.WriteRawData(tempParcel.GetData(), dataSize)
  → 统一走 IPC raw data 传输（最大 128MB）
```

---

## 2. 验证用例

### 用例 1：小数据量 — 正常全量返回

| 项 | 值 |
|---|---|
| 数据库构造 | 100 条记录，phone_number 长度 11 位 |
| 查询参数 | startTime=0, endTime=当前时间+1天, 无 phoneNumber 过滤 |
| 预期 | 返回 100 条，走 raw data 路径 |
| 验证点 | ① `callLogs.size() == 100` ② 每条记录字段完整且与数据库一致 ③ proxy 侧 `dataSize < 120MB`，走 `ReadRawData` 路径 |

### 用例 2：中数据量 — 仍全量返回

| 项 | 值 |
|---|---|
| 数据库构造 | 50,000 条记录，phone_number 长度 11 位 |
| 查询参数 | startTime=0, endTime=当前时间+1天 |
| 预期 | 返回 50,000 条，走 raw data 路径 |
| 验证点 | ① `callLogs.size() == 50000` ② Layer 1 不触发（50000 × 64 = 3.2MB < 100MB）③ Layer 2 不触发（实际 ~2.2MB < 100MB） |

### 用例 3：大数据量 — Layer 1 估算截断

| 项 | 值 |
|---|---|
| 数据库构造 | 200 万条记录，phone_number 长度 11 位（短号码） |
| 查询参数 | startTime=0, endTime=当前时间+1天 |
| 预期 Layer 1 触发 | `200万 × 64 = 128MB >= 100MB` → Layer 1 在约 163.84 万条时 break |
| 预期返回 | count ≈ 1,638,400，**小于** 200 万 |
| 验证点 | ① `callLogs.size() < 2,000,000` ② `callLogs.size() ≈ floor(100×1024×1024 / 64) = 1,638,400` ③ 日志出现 `"Estimated data size exceeds limit, stop at %{public}zu records."` ④ 返回的记录是 `create_time DESC` 排序的**最新**记录 ⑤ 无 crash、无 OOM |

### 用例 4：大数据量 + 长号码 — Layer 2 实际截断

| 项 | 值 |
|---|---|
| 数据库构造 | 150 万条记录，phone_number 长度 200 字符（超长号码） |
| 预期 Layer 1 不触发 | `150万 × 64 = 96MB < 100MB` → Layer 1 不 break |
| 预期 Layer 2 触发 | 每条实际序列化 ≈ 8+8+8+4+4+4+200 = ~236 字节，`150万 × 236 = 354MB > 100MB` |
| 预期返回 | count ≈ `floor(100MB / 236) ≈ 444,681`，**远小于** 150 万 |
| 验证点 | ① Layer 1 日志**不**出现 ② Layer 2 日志 `"Data size exceeds limit, truncated at %{public}d records."` **出现** ③ `callLogs.size() < 1,500,000` ④ `callLogs.size() ≈ floor(100×1024×1024 / 236)` ⑤ 无 crash |

### 用例 5：空数据库

| 项 | 值 |
|---|---|
| 数据库构造 | 0 条记录 |
| 查询参数 | startTime=0, endTime=当前时间+1天 |
| 预期 | `GetRowCount` 返回 0，提前返回 `ERR_OK` |
| 验证点 | ① `callLogs.empty() == true` ② 日志 `"Query success, but rowCount is 0."` ③ proxy 侧 `dataSize == 0`，直接返回 `ERR_OK` ④ 不进入序列化循环 |

### 用例 6：单条记录 — 最小可行

| 项 | 值 |
|---|---|
| 数据库构造 | 1 条记录 |
| 查询参数 | startTime=0, endTime=当前时间+1天 |
| 预期 | 返回 1 条，走 raw data 路径 |
| 验证点 | ① `callLogs.size() == 1` ② 记录字段与数据库一致 ③ `dataSize` 约 40-60 字节 |

### 用例 7：截断后数据完整性验证

| 项 | 值 |
|---|---|
| 数据库构造 | 200 万条记录，create_time 从 `T-200万秒` 到 `T`，每条递增 1 秒 |
| 查询参数 | startTime=0, endTime=T+1天 |
| 预期 | Layer 1 截断，返回约 163.84 万条 |
| 验证点 | ① 返回的第一条记录的 `createTime` 是**最大**的（最新通话） ② 返回的最后一条记录的 `createTime` 大于未返回的任意记录 ③ 返回记录的 `createTime` 严格递减 ④ count 占位符回填正确——proxy 解析出的 count == callLogs.size() ⑤ 每条记录的 `startTime`/`endTime`/`isIncoming`/`slotId`/`telephoneNumber` 与数据库对应行一致 |

### 用例 8：号码过滤 + 大数据量 — 过滤后不截断

| 项 | 值 |
|---|---|
| 数据库构造 | 200 万条记录，其中 50 条的 phone_number = "13800138000" |
| 查询参数 | startTime=0, endTime=T+1天, phoneNumber="13800138000" |
| 预期 | DataShare 层过滤后只有 50 条，Layer 1/2 都不触发 |
| 验证点 | ① `callLogs.size() == 50` ② 所有返回记录的 `telephoneNumber == "13800138000"` ③ 无截断日志 |

### 用例 9：时间范围过滤 — 缩小结果集避免截断

| 项 | 值 |
|---|---|
| 数据库构造 | 200 万条记录，create_time 从 `T-200万秒` 到 `T` |
| 查询参数 | startTime=T-3600, endTime=T（仅最近 1 小时） |
| 预期 | 最多 3600 条记录（1 小时内），远低于截断阈值 |
| 验证点 | ① `callLogs.size() <= 3600` ② 无截断 ③ 所有 `createTime` 在 [T-3600, T] 范围内 |

---

## 3. 用例与检查点对照表

| # | 场景 | 记录数 | 号码长度 | Layer 1 | Layer 2 | 返回数 |
|---|------|--------|---------|---------|---------|--------|
| 1 | 小数据 | 100 | 11 | 否 | 否 | 100 |
| 2 | 中数据 | 5万 | 11 | 否 | 否 | 5万 |
| 3 | Layer1 截断 | 200万 | 11 | 是 | 否 | ~209万 |
| 4 | Layer2 截断 | 150万 | 200 | 否 | 是 | ~55.7万 |
| 5 | 空数据库 | 0 | - | 否 | 否 | 0 |
| 6 | 单条 | 1 | 11 | 否 | 否 | 1 |
| 7 | 截断完整性 | 200万 | 11 | 是 | 否 | ~209万 |
| 8 | 号码过滤 | 200万(50匹配) | 11 | 否 | 否 | 50 |
| 9 | 时间过滤 | 200万 | 11 | 否 | 否 | ≤3600 |

---

## 4. 数据库构造要求

使用数据库构造工具创建通话记录时，需控制以下参数：

| 参数 | 说明 | 用例 3/7 | 用例 4 | 用例 8 |
|------|------|---------|--------|--------|
| 记录数量 | 总条数 | 200 万 | 150 万 | 200 万 |
| phone_number 长度 | 影响每条序列化大小 | 11 位（~43 字节/条） | 200 字符（~236 字节/条） | 11 位 |
| phone_number 分布 | 特定号码占比 | 随机 | 随机 | 50 条指定号码 |
| create_time 分布 | 时间戳递增 | T-200万 到 T，步长 1 秒 | 随机 | 随机 |
| begin_time | 接通时间 | create_time + 随机偏移 | 同左 | 同左 |
| end_time | 挂断时间 | begin_time + 随机时长 | 同左 | 同左 |
| call_direction | 通话方向 | 0/1 随机 | 0/1 随机 | 0/1 随机 |
| slot_id | 卡槽 | 0/1 随机 | 0/1 随机 | 0/1 随机 |

---

## 5. 关键验证点汇总

### 5.1 截断正确性

- [ ] Layer 1 触发时 `callLogs.size() < 数据库总条数`
- [ ] Layer 1 截断条数 ≈ `floor(MAX_CALL_LOG_RETURN_SIZE / ESTIMATED_RECORD_SIZE)`
- [ ] Layer 2 触发时 `callLogs.size() < 数据库总条数`
- [ ] Layer 2 截断条数 ≈ `floor(MAX_CALL_LOG_RETURN_SIZE / 实际单条大小)`
- [ ] Layer 1 和 Layer 2 不会同时触发（Layer 1 先触发则 Layer 2 数据量已可控）

### 5.2 数据完整性

- [ ] 截断后返回的 count（proxy 解析的 `tempParcel.ReadInt32()`）== 实际返回的记录数
- [ ] 返回记录按 `create_time DESC` 排序（最新通话在前）
- [ ] 每条记录的 `createTime`/`startTime`/`endTime`/`isIncoming`/`slotId`/`telephoneNumber` 与数据库对应行一致
- [ ] 未接通记录的 `startTime == 0`（begin_time 为 0）

### 5.3 传输路径

- [ ] 所有数据量走 `WriteRawData` 路径（proxy 侧 `ReadRawData`），统一 IPC 传输
- [ ] 截断后数据量 ≤ ~128MB，仍在 IPC raw data 支持范围内

### 5.4 稳定性

- [ ] 截断时不 crash、不 OOM
- [ ] 空数据库时正常返回空数组
- [ ] 截断后 proxy 解析不越界（count 安全校验 `count <= readableDataSize`）
