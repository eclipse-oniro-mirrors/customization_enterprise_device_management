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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_EVENT_SUBSCRIPTION_MANAGER_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_EVENT_SUBSCRIPTION_MANAGER_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "delay_cancel_timer.h"
#include "edm_event_data.h"
#include "i_event_source_adapter.h"
#include "managed_event.h"
#include "subscription_handle.h"

namespace OHOS {
namespace EDM {

class EventSubscriptionManager {
public:
    static EventSubscriptionManager &GetInstance();

    std::shared_ptr<SubscriptionHandle> Subscribe(const std::string &subscriberId, SubscriberType type,
        EventId eventId, std::function<void(const EdmEventData &)> callback,
        const std::string &eventName = "", const std::string &eventPermission = "");

    void Unsubscribe(uint32_t handleId);

    void DispatchEvent(const EdmEventData &data);

    void ResetAdapterSubscribedState(EventId groupId);

    void ResetCommonEventAdapterStates();

    void RetryFailedAdapters(AdapterType type);

    EventId GetEventGroupId(EventId eventId);

private:
    struct SubscriptionEntry {
        uint32_t handleId;
        std::string subscriberId;
        SubscriberType type;
        EventId eventId;
        std::function<void(const EdmEventData &)> callback;
    };

    struct EventGroupState : public std::enable_shared_from_this<EventGroupState> {
        std::shared_ptr<IEventSourceAdapter> adapter;
        std::atomic<int32_t> refCount{0};
        bool isSubscribed{false};
        std::shared_ptr<DelayCancelTimer> timer;
        std::string eventName;
        std::string eventPermission;
    };

    EventSubscriptionManager() = default;

    void StartDelayedUnsubscribe(EventId groupId, std::shared_ptr<EventGroupState> state);
    bool EnsureGroupState(EventId groupId, const std::string &eventName,
        const std::string &eventPermission, std::shared_ptr<EventGroupState> &outState);
    std::shared_ptr<IEventSourceAdapter> CreateAdapter(EventId groupId,
        const std::string &eventName, const std::string &eventPermission);

    std::shared_mutex mutex_;
    std::atomic<uint32_t> nextHandleId_{1};

    std::unordered_map<uint32_t, SubscriptionEntry> subscriptions_;
    std::unordered_map<EventId, std::shared_ptr<EventGroupState>, EventIdHash> eventGroupStates_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_EVENT_SUBSCRIPTION_MANAGER_H
