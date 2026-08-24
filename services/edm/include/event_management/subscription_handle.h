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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_SUBSCRIPTION_HANDLE_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_SUBSCRIPTION_HANDLE_H

#include <cstdint>
#include <string>

#include "edm_event_data.h"

namespace OHOS {
namespace EDM {
class EventSubscriptionManager;

enum class SubscriberType : uint32_t {
    SA_CORE = 0,
    MDM_RELAY = 1,
    POLICY_BOUND = 2,
};

class SubscriptionHandle {
public:
    SubscriptionHandle() = default;
    SubscriptionHandle(EventSubscriptionManager &manager, uint32_t handleId, EventId eventId,
        const std::string &subscriberId, SubscriberType type);
    SubscriptionHandle(SubscriptionHandle &&other) noexcept;
    SubscriptionHandle &operator=(SubscriptionHandle &&other) noexcept;
    SubscriptionHandle(const SubscriptionHandle &) = delete;
    SubscriptionHandle &operator=(const SubscriptionHandle &) = delete;
    ~SubscriptionHandle();

    void Release();
    uint32_t GetHandleId() const;
    EventId GetEventId() const;
    std::string GetSubscriberId() const;
    SubscriberType GetSubscriberType() const;

private:
    EventSubscriptionManager *manager_ = nullptr;
    uint32_t handleId_ = 0;
    EventId eventId_{};
    std::string subscriberId_;
    SubscriberType type_ = SubscriberType::SA_CORE;
    bool released_ = false;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_SUBSCRIPTION_HANDLE_H
