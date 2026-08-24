/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mdm_event_relayer.h"

#include "admin_manager.h"
#include "callback_strategies.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "enterprise_conn_manager.h"
#include "event_subscription_manager.h"
#include "icallback_strategy.h"
#include "ienterprise_admin.h"
#include "startup_scene.h"

namespace OHOS {
namespace EDM {
constexpr int32_t BUNDLE_UPDATE_EVENT = 2;


using AdminCallback = std::function<void(const std::string &, const std::string &, int32_t)>;

void DispatchToAdmins(ManagedEvent event, const EdmEventData &data, const AdminCallback &callback)
{
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subAdmins;
    AdminManager::GetInstance()->GetAdminBySubscribeEvent(event, subAdmins);
    for (auto &[uid, admins] : subAdmins) {
        for (auto &admin : admins) {
            callback(admin->adminInfo_.packageName_, admin->adminInfo_.className_, uid);
        }
    }
}

MdmEventRelayer::MdmEventRelayer()
{
    RegisterStrategyFactories();
}

MdmEventRelayer &MdmEventRelayer::GetInstance()
{
    static MdmEventRelayer instance;
    return instance;
}

void MdmEventRelayer::RegisterAppLifecycleStrategies()
{
    strategyFactories_[ManagedEvent::APP_START] = [](const EdmEventData &data) {
        DispatchToAdmins(ManagedEvent::APP_START, data,
            [&data](const std::string &pkg, const std::string &cls, int32_t uid) {
                auto strategy = std::make_shared<AppStrategy>(IEnterpriseAdmin::COMMAND_ON_APP_START,
                    data.appProcessData.bundleName);
                DelayedSingleton<EnterpriseConnManager>::GetInstance()->ExecuteCallback(pkg, cls, uid, strategy);
            });
    };
    strategyFactories_[ManagedEvent::APP_STOP] = [](const EdmEventData &data) {
        DispatchToAdmins(ManagedEvent::APP_STOP, data,
            [&data](const std::string &pkg, const std::string &cls, int32_t uid) {
                auto strategy = std::make_shared<AppStrategy>(IEnterpriseAdmin::COMMAND_ON_APP_STOP,
                    data.appProcessData.bundleName);
                DelayedSingleton<EnterpriseConnManager>::GetInstance()->ExecuteCallback(pkg, cls, uid, strategy);
            });
    };
}

void MdmEventRelayer::RegisterBundleStrategies()
{
    auto makeBundleFactory = [](ManagedEvent event, int32_t command) {
        return [event, command](const EdmEventData &data) {
            std::string bundleName = data.commonEventData.GetWant().GetElement().GetBundleName();
            int32_t userId = data.commonEventData.GetWant().GetIntParam(
                AppExecFwk::Constants::USER_ID, AppExecFwk::Constants::INVALID_USERID);
            DispatchToAdmins(event, data,
                [bundleName, userId, command](const std::string &pkg, const std::string &cls, int32_t uid) {
                    auto strategy = std::make_shared<BundleStrategy>(command, bundleName, userId);
                    DelayedSingleton<EnterpriseConnManager>::GetInstance()->ExecuteCallback(pkg, cls, uid, strategy);
                });
        };
    };
    strategyFactories_[ManagedEvent::BUNDLE_ADDED] =
        makeBundleFactory(ManagedEvent::BUNDLE_ADDED, IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED);
    strategyFactories_[ManagedEvent::BUNDLE_REMOVED] =
        makeBundleFactory(ManagedEvent::BUNDLE_REMOVED, IEnterpriseAdmin::COMMAND_ON_BUNDLE_REMOVED);
    strategyFactories_[ManagedEvent::BUNDLE_UPDATED] = [makeBundleFactory](const EdmEventData &data) {
        int32_t type = data.commonEventData.GetWant().GetIntParam("type", -1);
        if (type != BUNDLE_UPDATE_EVENT) {
            EDMLOGI("MdmEventRelayer BUNDLE_UPDATED skipped: type=%{public}d", type);
            return;
        }
        makeBundleFactory(ManagedEvent::BUNDLE_UPDATED, IEnterpriseAdmin::COMMAND_ON_BUNDLE_UPDATED)(data);
    };
}

void MdmEventRelayer::RegisterAccountStrategies()
{
    auto makeAccountFactory = [](ManagedEvent event, int32_t command) {
        return [event, command](const EdmEventData &data) {
            int32_t accountId = data.commonEventData.GetCode();
            DispatchToAdmins(event, data,
                [accountId, command](const std::string &pkg, const std::string &cls, int32_t uid) {
                    auto strategy = std::make_shared<AccountStrategy>(command, accountId);
                    DelayedSingleton<EnterpriseConnManager>::GetInstance()->ExecuteCallback(pkg, cls, uid, strategy);
                });
        };
    };
    strategyFactories_[ManagedEvent::USER_ADDED] =
        makeAccountFactory(ManagedEvent::USER_ADDED, IEnterpriseAdmin::COMMAND_ON_ACCOUNT_ADDED);
    strategyFactories_[ManagedEvent::USER_SWITCHED] =
        makeAccountFactory(ManagedEvent::USER_SWITCHED, IEnterpriseAdmin::COMMAND_ON_ACCOUNT_SWITCHED);
    strategyFactories_[ManagedEvent::USER_REMOVED] =
        makeAccountFactory(ManagedEvent::USER_REMOVED, IEnterpriseAdmin::COMMAND_ON_ACCOUNT_REMOVED);
}

void MdmEventRelayer::RegisterDeviceStrategies()
{
    strategyFactories_[ManagedEvent::BOOT_COMPLETED] = [](const EdmEventData &data) {
        DispatchToAdmins(ManagedEvent::BOOT_COMPLETED, data,
            [](const std::string &pkg, const std::string &cls, int32_t uid) {
                auto strategy = std::make_shared<DeviceBootCompletedStrategy>();
                DelayedSingleton<EnterpriseConnManager>::GetInstance()->ExecuteCallback(pkg, cls, uid, strategy);
            });
    };
    strategyFactories_[ManagedEvent::STARTUP_GUIDE_COMPLETED] = [](const EdmEventData &data) {
        bool isOtaFinish = data.commonEventData.GetWant().GetBoolParam("ota", false);
        bool isFirstBoot = data.commonEventData.GetWant().GetBoolParam("firstBoot", false);
        bool isSubUserScene = data.commonEventData.GetWant().GetBoolParam("subUserScene", false);
        uint32_t type = 0;
        if (isSubUserScene) {
            type |= 1 << static_cast<uint32_t>(StartupScene::USER_SETUP);
        }
        if (isOtaFinish) {
            type |= 1 << static_cast<uint32_t>(StartupScene::OTA);
        }
        if (isFirstBoot) {
            type |= 1 << static_cast<uint32_t>(StartupScene::DEVICE_PROVISION);
        }
        if (type == 0) {
            return;
        }
        DispatchToAdmins(ManagedEvent::STARTUP_GUIDE_COMPLETED, data,
            [type](const std::string &pkg, const std::string &cls, int32_t uid) {
                auto strategy = std::make_shared<StartupGuideCompletedStrategy>(type);
                DelayedSingleton<EnterpriseConnManager>::GetInstance()->ExecuteCallback(pkg, cls, uid, strategy);
            });
    };
    strategyFactories_[ManagedEvent::SYSTEM_UPDATE] = [](const EdmEventData &data) {
        UpdateInfo updateInfo;
        updateInfo.version = data.commonEventData.GetWant().GetStringParam("version");
        updateInfo.firstReceivedTime = data.commonEventData.GetWant().GetLongParam("firstReceivedTime", 0);
        updateInfo.packageType = data.commonEventData.GetWant().GetStringParam("packageType");
        DispatchToAdmins(ManagedEvent::SYSTEM_UPDATE, data,
            [updateInfo](const std::string &pkg, const std::string &cls, int32_t uid) {
                auto strategy = std::make_shared<SystemUpdateStrategy>(updateInfo);
                DelayedSingleton<EnterpriseConnManager>::GetInstance()->ExecuteCallback(pkg, cls, uid, strategy);
            });
    };
}

void MdmEventRelayer::RegisterStrategyFactories()
{
    RegisterAppLifecycleStrategies();
    RegisterBundleStrategies();
    RegisterAccountStrategies();
    RegisterDeviceStrategies();
}

void MdmEventRelayer::OnAdminSubscribe(const std::string &adminName, int32_t userId, ManagedEvent event)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    std::string key = MakeAdminKey(adminName, userId);
    if (adminSubscriptionHandles_.count(key) && adminSubscriptionHandles_[key].count(event)) {
        EDMLOGI("MdmEventRelayer::OnAdminSubscribe already subscribed admin=%{public}s event=%{public}u",
            adminName.c_str(), static_cast<uint32_t>(event));
        return;
    }

    auto it = strategyFactories_.find(event);
    if (it == strategyFactories_.end()) {
        EDMLOGE("MdmEventRelayer::OnAdminSubscribe no strategy factory for event=%{public}u",
            static_cast<uint32_t>(event));
        return;
    }

    auto &factory = it->second;
    auto callback = [factory](const EdmEventData &data) {
        factory(data);
    };

    auto handle = EventSubscriptionManager::GetInstance().Subscribe(
        key, SubscriberType::MDM_RELAY, EventId{static_cast<uint32_t>(event)}, callback);
    if (handle == nullptr) {
        EDMLOGE("MdmEventRelayer::OnAdminSubscribe Subscribe failed admin=%{public}s event=%{public}u",
            adminName.c_str(), static_cast<uint32_t>(event));
        return;
    }

    adminSubscriptionHandles_[key][event] = handle;
    EDMLOGI("MdmEventRelayer::OnAdminSubscribe success admin=%{public}s event=%{public}u",
        adminName.c_str(), static_cast<uint32_t>(event));
}

void MdmEventRelayer::OnAdminUnsubscribe(const std::string &adminName, int32_t userId, ManagedEvent event)
{
    std::shared_ptr<SubscriptionHandle> handle;
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        std::string key = MakeAdminKey(adminName, userId);
        auto adminIt = adminSubscriptionHandles_.find(key);
        if (adminIt == adminSubscriptionHandles_.end()) {
            return;
        }
        auto eventIt = adminIt->second.find(event);
        if (eventIt == adminIt->second.end()) {
            return;
        }
        handle = std::move(eventIt->second);
        adminIt->second.erase(eventIt);
        if (adminIt->second.empty()) {
            adminSubscriptionHandles_.erase(adminIt);
        }
    }
    EDMLOGI("MdmEventRelayer::OnAdminUnsubscribe success admin=%{public}s event=%{public}u",
        adminName.c_str(), static_cast<uint32_t>(event));
}

void MdmEventRelayer::OnAdminRemoved(const std::string &adminName, int32_t userId)
{
    std::unordered_map<ManagedEvent, std::shared_ptr<SubscriptionHandle>> handles;
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        std::string key = MakeAdminKey(adminName, userId);
        auto adminIt = adminSubscriptionHandles_.find(key);
        if (adminIt == adminSubscriptionHandles_.end()) {
            return;
        }
        handles = std::move(adminIt->second);
        adminSubscriptionHandles_.erase(adminIt);
    }
    EDMLOGI("MdmEventRelayer::OnAdminRemoved success admin=%{public}s eventCount=%{public}zu",
        adminName.c_str(), handles.size());
}

void MdmEventRelayer::RestoreAdminSubscriptions()
{
    RestoreSubscriptions(false);
}

void MdmEventRelayer::RestoreAppLifecycleSubscriptions()
{
    RestoreSubscriptions(true);
}

void MdmEventRelayer::RestoreAdminEvents(const std::string &adminName, int32_t userId, bool appLifecycleOnly)
{
    std::shared_ptr<Admin> admin = AdminManager::GetInstance()->GetAdminByPkgName(adminName, userId);
    if (admin == nullptr) {
        return;
    }
    for (auto event : admin->adminInfo_.managedEvents_) {
        bool isAppLifecycle = (event == ManagedEvent::APP_START || event == ManagedEvent::APP_STOP);
        if (isAppLifecycle != appLifecycleOnly) {
            continue;
        }
        OnAdminSubscribe(adminName, userId, event);
    }
}

void MdmEventRelayer::RestoreSubscriptions(bool appLifecycleOnly)
{
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> allAdmins;
    AdminManager::GetInstance()->GetAllAdmins(allAdmins);
    for (auto &[userId, admins] : allAdmins) {
        for (auto &admin : admins) {
            RestoreAdminEvents(admin->adminInfo_.packageName_, userId, appLifecycleOnly);
        }
    }
}

std::string MdmEventRelayer::MakeAdminKey(const std::string &adminName, int32_t userId)
{
    return adminName + "_" + std::to_string(userId);
}
} // namespace EDM
} // namespace OHOS
