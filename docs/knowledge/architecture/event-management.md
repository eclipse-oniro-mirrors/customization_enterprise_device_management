# 事件管理与事件分发

> 事件订阅中心、适配器层、接收者、订阅句柄、定时器、Admin 事件桥接、插件事件路由、回调策略、三类事件流、服务重启恢复、线程锁模型与新增事件开发指南。新增或修改事件订阅/分发代码时查阅本文档。日常工作流以 AGENTS.md 路由为准。

## 整体架构

```
┌───────────────────────────────────────────────────────────────────┐
│                    EventSubscriptionManager                        │
│           (单例，refCount + 延迟退订 + 读写锁)                       │
│                                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │
│  │ SA_CORE 订阅 │  │MDM_RELAY订阅 │  │POLICY_BOUND │               │
│  │ (Ability自用)│  │(Admin事件)   │  │(插件事件)    │               │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘               │
│         │                │                │                       │
└─────────┼────────────────┼────────────────┼───────────────────────┘
          │                │                │
          ▼                ▼                ▼
  EnterpriseDevice   MdmEventRelayer   PluginEventRouter
  MgrAbility回调     (工厂创建策略)     (路由到Plugin)
  (内部处理)              │                │
                         ▼                ▼
                  EnterpriseConn   PluginManager::
                  Manager::        DispatchPluginEvent
                  ExecuteCallback       │
                  (IPC到Admin扩展)       ▼
                                    IPluginExecuteStrategy
                                    ::OnPluginEventExecute
```

**代码路径**: `services/edm/src/event_management/`、`services/edm/include/event_management/`

**三种订阅者类型**:

| SubscriberType | 值 | 使用者 | 说明 |
|----------------|---|--------|------|
| `SA_CORE` | 0 | EnterpriseDeviceMgrAbility | SA内部事件处理（如USER_SWITCHED触发内部逻辑） |
| `MDM_RELAY` | 1 | MdmEventRelayer | Admin扩展回调（如APP_START通知MDM应用） |
| `POLICY_BOUND` | 2 | PluginEventRouter | 插件策略事件（如剪贴板策略变化） |

## 核心数据类型

**代码路径**: `interfaces/inner_api/plugin_kits/include/edm_event_data.h`、`common/native/include/managed_event.h`

| 结构体 | 字段 | 说明 |
|--------|------|------|
| `EventId` | `uint32_t code` | 事件标识，有`operator==`/`operator!=` |
| `EventIdHash` | — | EventId的哈希函子 |
| `EdmEventData` | `EventId eventId`、`CommonEventData commonEventData`、`ProcessData appProcessData` | 传递给所有事件回调的负载 |

**ManagedEvent枚举** (`common/native/include/managed_event.h`):

| 枚举值 | 码值 | 适配器类型 | 事件来源 |
|--------|------|-----------|---------|
| `BUNDLE_ADDED` | 0 | COMMON_EVENT | COMMON_EVENT_PACKAGE_ADDED |
| `BUNDLE_REMOVED` | 1 | COMMON_EVENT | COMMON_EVENT_PACKAGE_REMOVED |
| `APP_START` | 2 | APP_LIFECYCLE | 应用进程创建 |
| `APP_STOP` | 3 | APP_LIFECYCLE | 应用进程退出 |
| `SYSTEM_UPDATE` | 4 | COMMON_EVENT(自定义) | DUE_SA_FIRMWARE_UPDATE_FOR_POLICY |
| `USER_ADDED` | 5 | COMMON_EVENT | COMMON_EVENT_USER_ADDED |
| `USER_SWITCHED` | 6 | COMMON_EVENT | COMMON_EVENT_USER_SWITCHED |
| `USER_REMOVED` | 7 | COMMON_EVENT | COMMON_EVENT_USER_REMOVED |
| `STARTUP_GUIDE_COMPLETED` | 8 | COMMON_EVENT(自定义) | OOBE.HWSTARTUPGUIDE.FINISHED |
| `BOOT_COMPLETED` | 9 | COMMON_EVENT | COMMON_EVENT_BOOT_COMPLETED |
| `BUNDLE_UPDATED` | 10 | COMMON_EVENT | COMMON_EVENT_PACKAGE_CHANGED |
| `POLICIES_CHANGED` | 11 | — | 策略变化通知（不走adapter） |
| `BMS_READY` | 101 | COMMON_EVENT | BMS内部就绪 |
| `KIOSK_MODE_ON` | 102 | COMMON_EVENT | Kiosk模式开启 |
| `KIOSK_MODE_OFF` | 103 | COMMON_EVENT | Kiosk模式关闭 |
| `SIM_STATE_CHANGED` | 104 | COMMON_EVENT | SIM卡状态变化 |
| `APP_MARKET_DOWNLOAD` | 105 | COMMON_EVENT(自定义) | 应用市场下载 |
| `APP_MARKET_INSTALL` | 106 | COMMON_EVENT(自定义) | 应用市场安装 |

## EventSubscriptionManager（事件订阅中心）

**代码路径**: `services/edm/include/event_management/event_subscription_manager.h`、`services/edm/src/event_management/event_subscription_manager.cpp`

**设计**: 单例 + 引用计数事件组 + 延迟退订

**核心数据结构**:

```
subscriptions_: map<handleId, SubscriptionEntry{handleId, subscriberId, type, eventId, callback}>
eventGroupStates_: map<EventId, shared_ptr<EventGroupState{adapter, refCount, isSubscribed, timer}>>
```

**事件组分组** (`GetEventGroupId`): APP_START 和 APP_STOP 共享同一个事件组（APP_START），即共用一个 `AppLifecycleAdapter`。其他事件各自独立成组。

**Subscribe 流程**:
1. 计算 `groupId = GetEventGroupId(eventId)`
2. 加写锁
3. `EnsureGroupState` — 查找或创建 `EventGroupState`（首次创建 adapter）
4. 若有延迟退订定时器在运行，取消它（复用现有订阅）
5. 若 `!isSubscribed`，调用 `adapter->SubscribeEvent()`，成功则置 `isSubscribed=true`
6. `refCount++`
7. 创建 `SubscriptionEntry` 存入 `subscriptions_`
8. 返回 `SubscriptionHandle`（shared_ptr）

**Unsubscribe 流程**:
1. 加写锁，删除 `SubscriptionEntry`
2. `refCount--`
3. 若 `refCount` 降为 0：启动 30 秒延迟退订定时器（`DelayCancelTimer`）
4. 定时器到期后：若仍为 0 且已订阅，调用 `adapter->UnsubscribeEvent()`，重置 adapter

**DispatchEvent 流程**:
1. 加**读锁**
2. 收集所有 `entry.eventId == data.eventId` 的回调到临时列表
3. **释放锁**后逐个调用回调（避免死锁，允许回调内重新订阅/退订）

**服务重启恢复方法**:

| 方法 | 触发场景 | 行为 |
|------|---------|------|
| `ResetAdapterSubscribedState(groupId)` | AppMgr 重启 | 重置单个组的 `isSubscribed=false` |
| `ResetCommonEventAdapterStates()` | CES 重启 | 重置所有 COMMON_EVENT 类型组的 `isSubscribed` |
| `RetryFailedAdapters(type)` | 重启后重试 | 遍历未订阅的组，重新 `adapter->SubscribeEvent()` |

## 适配器层（Adapter层）

**代码路径**: `services/edm/include/event_management/i_event_source_adapter.h`、`adapter_factory.h`、`common_event_adapter.h`、`app_lifecycle_adapter.h`

**继承关系**:
```
IEventSourceAdapter (纯虚接口)
├── CommonEventAdapter  — 封装 EventFwk::CommonEventManager 订阅/退订
│   └── 持有 EdmCommonEventSubscriber
└── AppLifecycleAdapter — 封装 AppMgr 应用状态观察者
    └── 持有 EdmAppStateSubscriber
```

**AdapterFactory** (`adapter_factory.cpp`): 根据 `EventId` 创建对应适配器:
- APP_START → `AppLifecycleAdapter`
- BUNDLE_*/USER_*/BOOT_COMPLETED/BMS_READY/KIOSK_*/SIM_STATE_CHANGED → `CommonEventAdapter`（通过 `ConvertToCommonEvent` 映射到系统广播事件名）
- SYSTEM_UPDATE → `CommonEventAdapter`（自定义事件 + `ohos.permission.UPDATE_SYSTEM` 权限）
- STARTUP_GUIDE_COMPLETED → `CommonEventAdapter`（自定义事件 + `ohos.permission.ACCESS_STARTUPGUIDE` 权限）
- 其他自定义事件名非空 → `CommonEventAdapter`
- 未知 → `nullptr`

**ConvertToCommonEvent** 映射表（部分）:

| ManagedEvent | 系统广播事件名 |
|--------------|---------------|
| BUNDLE_ADDED | COMMON_EVENT_PACKAGE_ADDED |
| BUNDLE_REMOVED | COMMON_EVENT_PACKAGE_REMOVED |
| BUNDLE_UPDATED | COMMON_EVENT_PACKAGE_CHANGED |
| USER_ADDED | COMMON_EVENT_USER_ADDED |
| USER_SWITCHED | COMMON_EVENT_USER_SWITCHED |
| USER_REMOVED | COMMON_EVENT_USER_REMOVED |
| BOOT_COMPLETED | COMMON_EVENT_BOOT_COMPLETED |
| KIOSK_MODE_ON | COMMON_EVENT_KIOSK_MODE_ON |
| SIM_STATE_CHANGED | COMMON_EVENT_SIM_STATE_CHANGED |

**AppLifecycleAdapter 的可测试性**: `GetAppMgr()` 是 `protected virtual`，测试时可重写返回 mock。

## 接收者（Subscriber层）

**EdmCommonEventSubscriber** (`edm_common_event_subscriber.cpp`):
- 继承 `EventFwk::CommonEventSubscriber`
- `OnReceiveEvent(data)` → 构建 `EdmEventData{eventId_, data}` → `manager_.DispatchEvent(edmData)`

**EdmAppStateSubscriber** (`edm_app_state_subscriber.cpp`):
- 继承 `AppExecFwk::ApplicationStateObserverStub`（IPC stub）
- `OnProcessCreated(processData)` → `DispatchEvent(EdmEventData{APP_START, ..., appProcessData})`
- `OnProcessDied(processData)` → `DispatchEvent(EdmEventData{APP_STOP, ..., appProcessData})`

## SubscriptionHandle（RAII订阅句柄）

**代码路径**: `services/edm/include/event_management/subscription_handle.h`、`services/edm/src/event_management/subscription_handle.cpp`

- 构造时关联 `EventSubscriptionManager` 和 `handleId`
- 析构或 `Release()` 时调用 `manager_->Unsubscribe(handleId_)`
- Move-only 语义（拷贝已删除），支持 `shared_ptr` 共享
- 建议用 `shared_ptr<SubscriptionHandle>` 管理，析构自动退订

## DelayCancelTimer（延迟退订定时器）

**代码路径**: `services/edm/include/event_management/delay_cancel_timer.h`、`services/edm/src/event_management/delay_cancel_timer.cpp`

- `Start(task, delay)` — 先 Cancel 旧定时器，再起独立线程等待 delay 后执行 task
- `Cancel()` — 设置 `active_=false` 并通知条件变量，等待线程安全退出
- `IsRunning()` — 查询是否在等待中
- 析构自动 `Cancel()`
- 线程安全：`threadMutex_` 串行化 Start/Cancel，`mutex_`+`cv_` 实现等待
- **常量**: `DELAY_CANCEL_SECONDS = 30`（在 `event_subscription_manager.cpp` 中定义）

## MdmEventRelayer（Admin事件桥接）

**代码路径**: `services/edm/include/event_management/mdm_event_relayer.h`、`services/edm/src/event_management/mdm_event_relayer.cpp`

**职责**: 将系统事件桥接到 MDM Admin 扩展能力的回调方法。

**StrategyFactory 类型**:
```cpp
using StrategyFactory = std::function<std::shared_ptr<ICallbackStrategy>(const EdmEventData &)>;
```
工厂仅创建策略（admin 无关），回调中捕获 admin 信息直接定向到该 admin。策略返回 `nullptr` 表示跳过（如 BUNDLE_UPDATED 类型不匹配时）。

**策略工厂注册**（构造函数中一次性注册）:

| 事件 | 策略类 | 策略构造参数来源 |
|------|--------|-----------------|
| APP_START | `AppStrategy` | `data.appProcessData.bundleName` |
| APP_STOP | `AppStrategy` | `data.appProcessData.bundleName` |
| BUNDLE_ADDED | `BundleStrategy` | `data.commonEventData.GetWant()` 的 bundleName+userId |
| BUNDLE_REMOVED | `BundleStrategy` | 同上 |
| BUNDLE_UPDATED | `BundleStrategy` | 同上（先检查 `type==2`，不匹配返回 nullptr） |
| USER_ADDED | `AccountStrategy` | `data.commonEventData.GetCode()` |
| USER_SWITCHED | `AccountStrategy` | 同上 |
| USER_REMOVED | `AccountStrategy` | 同上 |
| BOOT_COMPLETED | `DeviceBootCompletedStrategy` | 无参数 |
| STARTUP_GUIDE_COMPLETED | `StartupGuideCompletedStrategy` | 从 Want 提取 ota/firstBoot/subUserScene 组装 type 位标志，全为0则返回 nullptr |
| SYSTEM_UPDATE | `SystemUpdateStrategy` | 从 Want 提取 version/firstReceivedTime/packageType |

**OnAdminSubscribe 流程**:
1. `AdminManager::GetAdminByPkgName(adminName, userId)` 查询 `className_`
2. 加写锁，检查去重（同一 admin+event 不重复订阅）
3. 查找 `StrategyFactory`，创建回调 lambda
4. 回调逻辑: `factory(data)` → 若策略非空 → `EnterpriseConnManager::ExecuteCallback(adminName, className, userId, strategy)`
5. 调用 `EventSubscriptionManager::Subscribe(key, MDM_RELAY, EventId{event}, callback)`
6. 存储 `SubscriptionHandle` 到 `adminSubscriptionHandles_[key][event]`

**OnAdminUnsubscribe**: 从 map 移除 handle，handle 析构自动退订。

**OnAdminRemoved**: 批量移除该 admin 的所有 handle。

**恢复流程** (`RestoreSubscriptions`):
- `RestoreAdminSubscriptions()` — 恢复所有 admin 的非应用生命周期事件
- `RestoreAppLifecycleSubscriptions()` — 仅恢复 APP_START/APP_STOP 事件
- `RestoreAdminEvents(adminName, userId, appLifecycleOnly)` — 遍历 admin 的 `managedEvents_`，按 flag 过滤后调 `OnAdminSubscribe`

## PluginEventRouter（插件事件路由）

**代码路径**: `services/edm/include/event_management/plugin_event_router.h`、`services/edm/src/event_management/plugin_event_router.cpp`

**职责**: 将系统事件路由到插件策略处理器。实现 `IPluginEventSubscribeManager` 接口，构造时注册为全局实例。

**核心数据结构**:
```
entries_: map<"policyName:eventCode", PluginEntry{policyCode, needAdminIteration, useEventUserId}>
eventGroupStates_: map<EventId, EventGroupState{handle, registeredKeys, eventFilter, permission}>
```

**SubscribeEvent 流程**:
1. 生成 key = `policyName + ":" + eventCode`
2. 加写锁，若 key 已存在返回 true（幂等）
3. 存入 `PluginEntry`
4. 查找/创建 EventGroupState，添加 key 到 `registeredKeys`
5. 若组内首次订阅（`handle==nullptr`），向 `EventSubscriptionManager` 注册（subscriberId="PLUGIN_ROUTER"，type=POLICY_BOUND）
6. 回调 = `OnEventDispatch(eventId, data)`

**OnEventDispatch 流程**:
1. 加读锁，`CollectDispatchEntries` 从两组 map 中收集匹配的 PluginEntry
2. 释放锁
3. 对每个 entry 调用 `PluginManager::DispatchPluginEvent(policyCode, data, needAdminIteration, useEventUserId)`

**RestorePluginSubscriptions**: 遍历 12 个预定义的 `{policyCode, policyName}` 对，查询 DB 中是否有策略值，有则调用 `PluginManager::SubscribePluginEvent`。

## 回调策略（ICallbackStrategy）

**代码路径**: `services/edm/include/connection/icallback_strategy.h`、`services/edm/include/connection/callback_strategies.h`

**继承关系**: `ICallbackStrategy` → `Execute(proxy)` 调用 `ExecuteImpl(proxy)`（子类实现）

**策略类列表**:

| 策略类 | 构造参数 | ExecuteImpl 调用 |
|--------|---------|-----------------|
| `AppStrategy` | code, bundleName | `proxy->OnApp(code, bundleName)` |
| `BundleStrategy` | code, bundleName, accountId | `proxy->OnBundle(code, bundleName, accountId)` |
| `AccountStrategy` | code, accountId | `proxy->OnAccount(code, accountId)` |
| `SystemUpdateStrategy` | UpdateInfo | `proxy->OnSystemUpdate(updateInfo)` |
| `StartupGuideCompletedStrategy` | type(int位标志) | `proxy->OnStartupGuideCompleted(type)` |
| `DeviceBootCompletedStrategy` | 无 | `proxy->OnDeviceBootCompleted()` |
| `KioskModeStrategy` | code, bundleName, accountId | `proxy->OnKioskMode(code, bundleName, accountId)` |
| `AdminStrategy` | code | `proxy->OnAdmin(code)` |
| `AdminPolicyChangedStrategy` | PolicyChangedEvent | `proxy->OnAdminPolicyChanged(event)` |
| `MarketAppsInstallStatusChangedStrategy` | bundleName, status | `proxy->OnMarketAppsInstallStatusChanged(...)` |
| `LogCollectedStrategy` | isSuccess | `proxy->OnLogCollected(isSuccess)` |
| `KeyEventStrategy` | keyEvent | `proxy->OnKeyEvent(keyEvent)` |

**EnterpriseConnManager::ExecuteCallback** (`enterprise_conn_manager.cpp:32-66`):
1. 检查连接状态（有proxy/需新建/有过期回调需清理）
2. 若有有效proxy → `strategy->Execute(proxy)`；失败则重连
3. 若需新建连接 → `EstablishConnection`（连接成功后通过 `SaveProxy` 执行 pending 策略）
4. 连接超时 = 10秒（可通过 `persist.sys.abilityms.timeout_unit_time_ratio` 系统参数调整）

## 三类事件流完整链路

**Admin管理事件流（如 APP_START）**:
```
AppMgr(进程创建)
  → EdmAppStateSubscriber::OnProcessCreated
    → EventSubscriptionManager::DispatchEvent(EdmEventData{APP_START, appProcessData})
      → MdmEventRelayer 回调 (SubscriberType::MDM_RELAY)
        → StrategyFactory 创建 AppStrategy(COMMAND_ON_APP_START, bundleName)
        → EnterpriseConnManager::ExecuteCallback(adminName, className, userId, strategy)
          → strategy->Execute(proxy)
            → proxy->OnApp(code, bundleName)  // IPC到Admin扩展
```

**SA核心事件流（如 USER_SWITCHED）**:
```
CommonEventService(用户切换广播)
  → EdmCommonEventSubscriber::OnReceiveEvent
    → EventSubscriptionManager::DispatchEvent
      → EnterpriseDeviceMgrAbility lambda (SubscriberType::SA_CORE)
        → 内部处理（如 OnCommonEventUserSwitched）
```

**插件策略事件流**:
```
CommonEventService(系统广播)
  → EdmCommonEventSubscriber::OnReceiveEvent
    → EventSubscriptionManager::DispatchEvent
      → PluginEventRouter::OnEventDispatch (SubscriberType::POLICY_BOUND)
        → CollectDispatchEntries → 对每个 PluginEntry:
          → PluginManager::DispatchPluginEvent(policyCode, data, needAdminIteration, useEventUserId)
            → plugin->GetExecuteStrategy()->OnPluginEventExecute(...)
```

## 服务重启恢复流程

**EnterpriseDeviceMgrAbility 中的回调** (`enterprise_device_mgr_ability.cpp`):

| 触发 | 调用链 |
|------|--------|
| AppMgr 启动 | `ResetAdapterSubscribedState(APP_START组)` → `RestoreAppLifecycleSubscriptions()` → `RetryFailedAdapters(APP_LIFECYCLE)` |
| CES 启动 | 清空 `saCoreHandles_` → `ResetCommonEventAdapterStates()` → 订阅 SA_CORE 事件 → `RestoreAdminSubscriptions()` → `RestorePluginSubscriptions()` → `RetryFailedAdapters(COMMON_EVENT)` |
| Admin 移除 | `MdmEventRelayer::OnAdminRemoved(adminName, userId)` |
| Admin 订阅事件 | `MdmEventRelayer::OnAdminSubscribe(bundleName, userId, event)` |
| Admin 退订事件 | `MdmEventRelayer::OnAdminUnsubscribe(bundleName, userId, event)` |

**saCoreHandles_**: `EnterpriseDeviceMgrAbility` 的成员，持有 SA 自身的 `SubscriptionHandle` 列表（USER_SWITCHED, USER_REMOVED, BUNDLE_*, BMS_READY, KIOSK_*, SIM_STATE_CHANGED, APP_MARKET_*）。

## 线程与锁模型

| 类 | 锁类型 | 保护范围 |
|----|--------|---------|
| `EventSubscriptionManager` | `shared_mutex` | 写锁: Subscribe/Unsubscribe/Reset/Retry；读锁: DispatchEvent |
| `MdmEventRelayer` | `shared_mutex` | 写锁: OnAdminSubscribe/Unsubscribe/Removed |
| `PluginEventRouter` | `shared_mutex` | 写锁: SubscribeEvent/UnsubscribeEvent；读锁: OnEventDispatch |
| `DelayCancelTimer` | `mutex` ×2 | `threadMutex_`: 串行化 Start/Cancel；`mutex_`+`cv_`: 定时等待 |
| `EnterpriseConnManager` | `mutex` | `connectionMap_` |

**关键线程安全设计**:
- `DispatchEvent` 在读锁下收集回调，释放锁后调用——避免回调内重新订阅/退订导致死锁
- `StartDelayedUnsubscribe` 在锁外启动定时器，定时器线程在到期后重新获取写锁
- 定时器 lambda 捕获 `shared_ptr<EventGroupState>`，确保延迟期间对象存活即使被移出 map

## 设计模式总结

| 模式 | 应用位置 | 用途 |
|------|---------|------|
| **Singleton** | EventSubscriptionManager, MdmEventRelayer, PluginEventRouter | 全局访问 |
| **Factory Method** | AdapterFactory | 根据 EventId 创建适配器 |
| **Strategy** | IEventSourceAdapter, ICallbackStrategy | 可插拔的事件源和回调 |
| **Observer** | EventSubscriptionManager + subscribers | 发布/订阅系统事件 |
| **RAII** | SubscriptionHandle | 析构自动退订 |
| **引用计数** | EventGroupState::refCount | 多订阅者共享适配器 |
| **延迟退订** | DelayCancelTimer + 30秒宽限期 | 避免频繁订阅/退订抖动 |
| **Mediator** | PluginEventRouter | 中介 EventSubscriptionManager 和 PluginManager |

## 新增事件开发指南

**场景**: 需要订阅一个新的系统广播事件并分发给 MDM Admin 扩展。

**步骤**:

1. **在 `managed_event.h` 中添加枚举值**（如 `MY_NEW_EVENT = 107`）

2. **在 `AdapterFactory::ConvertToCommonEvent` 中添加映射**（`adapter_factory.cpp`）:
   ```cpp
   case static_cast<uint32_t>(ManagedEvent::MY_NEW_EVENT):
       commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_MY_NEW_EVENT;
       return true;
   ```

3. **在 `MdmEventRelayer` 中注册策略工厂**（`mdm_event_relayer.cpp`）:
   ```cpp
   // 在 RegisterStrategyFactories() 中添加
   strategyFactories_[ManagedEvent::MY_NEW_EVENT] = [](const EdmEventData &data)
       -> std::shared_ptr<ICallbackStrategy> {
       // 从 data 中提取参数，创建策略
       return std::make_shared<XxxStrategy>(...);
   };
   ```
   若需过滤（如 BUNDLE_UPDATED 的 type 检查），返回 `nullptr` 表示跳过。

4. **若需要新的 ICallbackStrategy 子类**，在 `callback_strategies.h/cpp` 中添加:
   ```cpp
   class XxxStrategy : public ICallbackStrategy {
   public:
       explicit XxxStrategy(...) : ICallbackStrategy(IEnterpriseAdmin::COMMAND_ON_XXX), ... {}
   private:
       bool ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) override {
           return proxy->OnXxx(...);
       }
   };
   ```

5. **在 `IEnterpriseAdmin` 接口中添加对应的回调方法**（`interfaces/inner_api/common/include/ienterprise_admin.h`），并在 `EnterpriseAdminProxy` 中实现。

6. **若事件需要自定义事件名或权限**（非标准系统广播），在 `AdapterFactory::CreateAdapter` 中添加对应 case，传入 eventName 和 eventPermission。

7. **测试**: 在 `test/unittest/services/edm/src/mdm_event_relayer_test.cpp` 中添加策略工厂返回值验证测试。事件分发行为可通过 `EventSubscriptionManager::GetInstance().DispatchEvent(data)` 触发验证。

**参考实现**:
- 简单事件: `BOOT_COMPLETED` → `DeviceBootCompletedStrategy`（无参数）
- 带参数事件: `BUNDLE_ADDED` → `BundleStrategy`（从 Want 提取参数）
- 带过滤事件: `BUNDLE_UPDATED` → 先检查 type 再创建策略
- 带位标志事件: `STARTUP_GUIDE_COMPLETED` → 从 Want 组装 type 位标志

## BUILD.gn 配置

**源文件**（`services/edm/BUILD.gn`，target `edmservice`）: 10 个 `.cpp` 文件在 `./src/event_management/` 下，无条件编译。

**测试文件**（`test/unittest/services/edm/BUILD.gn`，target `EdmServicesUnitTest`）: 10 个测试文件在 `if (common_event_service_edm_enable)` 块内。

**Include 路径**: `services/edm/include/event_management` 已在 BUILD.gn `config` 中配置。
