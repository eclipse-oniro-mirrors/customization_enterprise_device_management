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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_MDM_EVENT_RELAYER_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_MDM_EVENT_RELAYER_H

#include <functional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "edm_event_data.h"
#include "managed_event.h"
#include "subscription_handle.h"

namespace OHOS {
namespace EDM {
class MdmEventRelayer {
public:
    static MdmEventRelayer &GetInstance();

    void OnAdminSubscribe(const std::string &adminName, int32_t userId, ManagedEvent event);
    void OnAdminUnsubscribe(const std::string &adminName, int32_t userId, ManagedEvent event);
    void OnAdminRemoved(const std::string &adminName, int32_t userId);
    void RestoreAdminSubscriptions();
    void RestoreAppLifecycleSubscriptions();

private:
    using StrategyFactory = std::function<void(const EdmEventData &)>;

    MdmEventRelayer();
    void RegisterStrategyFactories();
    void RegisterAppLifecycleStrategies();
    void RegisterBundleStrategies();
    void RegisterAccountStrategies();
    void RegisterDeviceStrategies();
    void RestoreSubscriptions(bool appLifecycleOnly);
    void RestoreAdminEvents(const std::string &adminName, int32_t userId, bool appLifecycleOnly);
    std::string MakeAdminKey(const std::string &adminName, int32_t userId);

    std::shared_mutex mutex_;
    std::unordered_map<ManagedEvent, StrategyFactory> strategyFactories_;

    std::unordered_map<std::string, std::unordered_map<ManagedEvent, std::shared_ptr<SubscriptionHandle>>>
        adminSubscriptionHandles_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_MDM_EVENT_RELAYER_H
