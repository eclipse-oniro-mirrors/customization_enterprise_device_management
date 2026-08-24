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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_PLUGIN_EVENT_ROUTER_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_PLUGIN_EVENT_ROUTER_H

#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "edm_event_data.h"
#include "iplugin_event_subscribe_manager.h"
#include "subscription_handle.h"

namespace OHOS {
namespace EDM {
class PluginEventRouter : public IPluginEventSubscribeManager {
public:
    static PluginEventRouter &GetInstance();

    void RestorePluginSubscriptions();

    bool SubscribeEvent(const std::string &policyName, uint32_t eventCode,
        uint32_t policyCode, bool needAdminIteration, bool useEventUserId) override;

    bool UnsubscribeEvent(const std::string &policyName, uint32_t eventCode) override;

    bool SubscribeCustomEvent(const std::string &policyName, uint32_t eventCode,
        uint32_t policyCode, const std::string &eventFilter, const std::string &permission) override;

    bool UnsubscribeCustomEvent(const std::string &policyName, uint32_t eventCode) override;

private:
    PluginEventRouter();

    struct PluginEntry {
        uint32_t policyCode;
        bool needAdminIteration = false;
        bool useEventUserId = false;
    };

    struct EventGroupState {
        std::shared_ptr<SubscriptionHandle> handle;
        std::vector<std::string> registeredKeys;
        std::string eventFilter;
        std::string permission;
    };

    void OnEventDispatch(EventId eventId, const EdmEventData &data);
    void CollectDispatchEntries(EventId eventId,
        std::unordered_map<EventId, std::unique_ptr<EventGroupState>, EventIdHash> &groupStates,
        std::vector<PluginEntry> &out);

    std::string MakeKey(const std::string &policyName, EventId eventId);

    std::shared_mutex mutex_;
    std::unordered_map<std::string, PluginEntry> entries_;
    std::unordered_map<EventId, std::unique_ptr<EventGroupState>, EventIdHash> eventGroupStates_;
    std::unordered_map<EventId, std::unique_ptr<EventGroupState>, EventIdHash> customEventGroupStates_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_PLUGIN_EVENT_ROUTER_H
