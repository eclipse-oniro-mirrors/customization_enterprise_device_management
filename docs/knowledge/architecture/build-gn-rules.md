# BUILD.gn 构建配置规则

> BUILD.gn 构建配置规则。新增策略或修改构建文件时查阅本文档。日常工作流以 AGENTS.md 路由为准。

## 添加新文件规则

添加一个新策略（Plugin + Query）需要更新以下5个BUILD.gn文件中的**指定目标**：

| # | BUILD.gn文件 | 目标名 | 添加内容 | 路径格式 |
|---|-------------|--------|---------|---------|
| 1 | `services/edm/BUILD.gn` | `edmservice` | Query源文件 | `"./src/query_policy/xxx_query.cpp"` |
| 2 | `services/edm_plugin/BUILD.gn` | 5个SO目标之一（见下表） | Plugin源文件 | `"./src/category/xxx_plugin.cpp"` |
| 3 | `test/unittest/services/edm/BUILD.gn` | `edmservice_static` | Query源文件 | `"../../../../services/edm/src/query_policy/xxx_query.cpp"` |
| 4 | `test/unittest/services/edm_plugin/BUILD.gn` | `edm_all_plugin_static` | Plugin源文件 | `"../../../../services/edm_plugin/src/category/xxx_plugin.cpp"` |
| 5 | `test/fuzztest/enterprisedevicemgrstubmock_fuzzer/BUILD.gn` | `edmservice_fuzz_static` | Query + Plugin源文件 | `"../../../services/edm/src/query_policy/xxx_query.cpp"` 和 `"../../../services/edm_plugin/src/category/xxx_plugin.cpp"` |

## edm_plugin的5个SO目标

`services/edm_plugin/BUILD.gn` 包含5个独立的共享库目标，新插件必须添加到**功能匹配的那一个**：

| 目标名 | SO文件名 | 适用策略类型 |
|--------|---------|-------------|
| `device_core_plugin` | libdevice_core_plugin.z.so | 设备核心策略（摄像头、屏幕、管理员、蓝牙等） |
| `communication_plugin` | libcommunication_plugin.z.so | 通信策略（WiFi、电话、USB、网络、VPN等） |
| `sys_service_plugin` | libsys_service_plugin.z.so | 系统服务策略（剪贴板、密码、位置、权限等） |
| `need_extra_plugin` | libneed_extra_plugin.z.so | 额外处理策略（设备信息、OTA、壁纸等） |
| `watermark_plugin` | libwatermark_plugin.z.so | 水印策略 |

## 条件编译

如果用户明确声明新策略依赖某个条件编译标志（如 `wifi_edm_enable`、`bluetooth_edm_enable` 等），则在以上5个BUILD.gn中都需要用对应的 `if (xxx_edm_enable)` 块包裹。未声明条件编译的策略直接添加在 `enterprise_device_management_support_all` 无条件块中。
