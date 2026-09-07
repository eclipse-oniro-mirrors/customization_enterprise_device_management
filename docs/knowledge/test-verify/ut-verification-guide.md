# EDM 部件编译与单元测试验证指南

> 适用范围：enterprise_device_management 部件的代码改动验证
> 验证流程：编译源码 → 推送 .so → 编译测试 → 执行 UT → 结果分析

## 1. 前置参数

| 参数 | 值 | 说明 |
|------|-----|------|
| 部件名 | `enterprise_device_management` | `--build-target` 的值，取自 `bundle.json` 的 `name` 字段 |
| 产品名 | `rk3568` | 默认产品；用户指定其他产品时用指定的 |
| 源码根目录 | 包含 `build.sh` 的目录 | 通常为当前工作目录的祖先目录 |

确认源码根目录：

```bash
# 从部件目录向上查找 build.sh
ls <源码根目录>/build.sh
```

## 2. 灵活跳步

并非所有场景都需要执行全部四步。根据改动范围选择：

| 改动场景 | 执行步骤 |
|---------|---------|
| 完整验证（改了源码+测试，需从头排查） | 步骤 3 + 4 + 5 + 6 |
| 只改了测试代码，源码未变 | 步骤 5 + 6 |
| 测试已编译，只需重新执行 | 仅步骤 6 |
| 只改了源码，需确认编译通过 | 仅步骤 3 |
| 只需推送 .so 到设备 | 仅步骤 4 |

**每一步依赖前一步成功**。步骤 3 失败则停止，不要继续后续步骤。

## 3. 步骤一：编译部件源码

```bash
./build.sh --product-name rk3568 --ccache --build-target enterprise_device_management [--fast-rebuild]
```

- 在**源码根目录**执行。
- `--ccache` 通过复用缓存加速增量编译。除非全量编译，否则始终加此参数。
- `--fast-rebuild` 可选：源码变更但不影响构建图拓扑时添加可跳过 GN 阶段加速。
- 编译通常需要 5–10 分钟。设置超时 1800000ms（30 分钟）。
- **成功标志**：输出中查找 `=====build  successful=====`。
- **注意**：编译输出包含大量"can not find depended library"告警，属正常现象，不代表编译失败。

### 编译跳过判断

执行前判断是否需要编译，比较产物时间戳与源码时间戳：

```bash
# 检查源码是否需要重新编译（比较 .so 产物与 .cpp/.h/.gn 源码时间戳）
# 产物目录：out/rk3568/<子系统>/enterprise_device_management/
# 如果产物比所有源码新 → 可跳过
# 如果 BUILD.gn 有变更 → 需正常编译（不能 --fast-rebuild）
```

| 判断结果 | 策略 |
|---------|------|
| 产物比所有源码和配置都新 | 跳过编译 |
| 源码变更但不影响构建图拓扑 | 加 `--fast-rebuild` |
| 产物不存在或 `BUILD.gn` 有变更 | 正常编译 |

## 4. 步骤二：推送 .so 到设备

源码编译成功后，将 .so 推送到设备系统目录，使 UT 测试加载最新代码。

### 4a. 推送 .so

```bash
# 遍历部件所有 BUILD.gn，解析 ohos_shared_library 的安装路径，通过 hdc 推送
python3 <技能目录>/scripts/push_component_so.py <源码根目录> rk3568 enterprise_device_management
```

脚本自动完成：
1. 从 `bundle.json` 获取子系统名，定位产物目录
2. 解析每个 `BUILD.gn` 的 `ohos_shared_library` 安装路径规则：
   - 默认：`/system/lib/`
   - `innerapi_tags = ["platformsdk"]`：`/system/lib/platformsdk/`
   - `relative_install_dir = "xxx"`：`/system/lib/xxx/`
3. 通过 hdc 将每个 .so 推送到设备对应目录
4. 推送前自动 remount `/system` 为读写模式

**成功标志**：输出 `Summary: N/N succeeded, 0 failed`。
**前置条件**：步骤一编译成功，设备已通过 hdc 连接。
**超时**：通常 1-2 分钟，使用 300000ms（5 分钟）。

### 4b. 重启设备

推送后**必须重启**，否则系统仍加载旧版本 .so：

```bash
hdc shell reboot
```

- 重启后等待 1-2 分钟设备完成启动。
- 使用 `hdc list targets` 确认设备重新上线后，**再额外等待 60 秒**让系统服务就绪。
- 过早执行测试会导致大量模块报"设备条件不满足"（unavailable）。
- 如果跳过了推送（设备未连接），则无需重启。

### 4c. 理解输出

- `[   OK  ]` — 推送成功
- `[ FAILED]` — 推送失败
- `[MISSING]` — 编译产物中未找到该 .so（可能未编译该目标）

## 5. 步骤三：编译测试用例

```bash
./build.sh --product-name rk3568 --ccache --build-target enterprise_device_management_test [--fast-rebuild]
```

- 测试目标始终是 `<部件名>_test`（部件名后追加 `_test`）。
- 编译时间与源码编译相近（5–10 分钟），使用 1800000ms 超时。
- **成功标志**：输出 `=====build  successful=====`。
- 验证测试二进制生成：

```bash
ls out/rk3568/tests/unittest/enterprise_device_management/enterprise_device_management/
# 应能看到可执行文件和 *_path.txt 文件
```

### 测试编译跳过判断

同源码编译，比较测试二进制时间戳与测试源码时间戳。

## 6. 步骤四：执行 UT 测试

### 6a. 检查并修复 user_config.xml（执行前必做）

开发者测试框架从以下文件读取配置：
`test/testfwk/developer_test/config/user_config.xml`

如果 `test_cases/dir` 为空或为相对路径，框架会报 `tests is not exist`。

执行测试前运行配置检查脚本：

```bash
python3 <技能目录>/scripts/fix_test_config.py <源码根目录> rk3568
```

脚本检查 `test_cases/dir` 是否为正确的绝对路径
（`<源码根目录>/out/rk3568/tests`），需要时修复。脚本是幂等的。

手动检查时，正确配置应为：
```xml
<test_cases>
  <dir>/绝对路径/out/rk3568/tests</dir>
</test_cases>
```

路径**必须是绝对路径**。相对路径无法工作。

### 6b. 执行测试

```bash
bash test/testfwk/developer_test/start.sh run -t UT -tp enterprise_device_management
```

- 在**源码根目录**执行。
- `start.sh` 是非交互式的：直接在命令行传参，不要管道输入。
- `-t UT` 指定单元测试，`-tp` 指定目标部件。
- 测试框架通过 hdc 连接设备，设备 SN 配置在 `user_config.xml` 中。
- 测试执行通常 1–5 分钟，使用 600000ms（10 分钟）超时。

### 6c. 理解输出

**测试汇总行**（接近末尾）：
```
Test Summary: modules: 10, repeat: 1, run modules: 10, total: 2833, passed: 2826, failed: 7, blocked: 0, ignored: 0, unavailable: 0
```

**单条用例结果**：
- `[       OK ]` — 通过
- `[  FAILED  ]` — 失败

**断言失败详情**：
```
[../../path/to/test_file.cpp:70: Failure]
Value of: ret == ERR_OK
Actual: false
Expected: true
```

**报告位置**：
`test/testfwk/developer_test/reports/<时间戳>/summary_report.html`

## 7. 结果分析

测试完成后，提取并向用户展示：

1. **总体统计**：从 Test Summary 行提取 总数/通过/失败/阻塞。
2. **失败用例列表**：提取所有 `[ FAILED ]` 的测试名。
3. **失败分析**：对每个失败项，提取断言详情（文件、行号、期望 vs 实际）。
4. **报告链接**：告知 HTML 报告位置。

全部通过时简单确认即可，不需要逐条列出通过的用例。

## 8. 常见坑

| # | 问题 | 解决 |
|---|------|------|
| 1 | `tests is not exist` 报错 | `user_config.xml` 的 `test_cases/dir` 为空或相对路径，执行步骤 6a 修复 |
| 2 | 交互式模式误解 | 不要管道输入 `start.sh`，直接命令行传参：`bash start.sh run -t UT -tp <部件名>` |
| 3 | 超时太短 | 编译至少 30 分钟超时，测试执行至少 10 分钟超时 |
| 4 | 编译告警误判 | "can not find depended library" 是正常告警，不是错误。只看 `=====build  successful=====` |
| 5 | 设备未连接 | 测试框架需要 hdc 连接设备。检查 `hdc list targets` 和 `user_config.xml` 的设备 SN |
| 6 | 部件名错误 | `--build-target` 用 part name（`enterprise_device_management`），不是二进制名或目录路径 |
