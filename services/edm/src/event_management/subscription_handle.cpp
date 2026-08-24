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

#include "subscription_handle.h"

#include "edm_log.h"
#include "event_subscription_manager.h"

namespace OHOS {
namespace EDM {
SubscriptionHandle::SubscriptionHandle(EventSubscriptionManager &manager, uint32_t handleId, EventId eventId,
    const std::string &subscriberId, SubscriberType type)
    : manager_(&manager), handleId_(handleId), eventId_(eventId), subscriberId_(subscriberId), type_(type)
{}

SubscriptionHandle::SubscriptionHandle(SubscriptionHandle &&other) noexcept
    : manager_(other.manager_), handleId_(other.handleId_), eventId_(other.eventId_),
      subscriberId_(std::move(other.subscriberId_)), type_(other.type_), released_(other.released_)
{
    other.manager_ = nullptr;
    other.handleId_ = 0;
    other.released_ = true;
}

SubscriptionHandle &SubscriptionHandle::operator=(SubscriptionHandle &&other) noexcept
{
    if (this != &other) {
        Release();
        manager_ = other.manager_;
        handleId_ = other.handleId_;
        eventId_ = other.eventId_;
        subscriberId_ = std::move(other.subscriberId_);
        type_ = other.type_;
        released_ = other.released_;
        other.manager_ = nullptr;
        other.handleId_ = 0;
        other.released_ = true;
    }
    return *this;
}

SubscriptionHandle::~SubscriptionHandle()
{
    Release();
}

void SubscriptionHandle::Release()
{
    if (!released_ && manager_ != nullptr && handleId_ != 0) {
        manager_->Unsubscribe(handleId_);
        released_ = true;
    }
}

uint32_t SubscriptionHandle::GetHandleId() const
{
    return handleId_;
}

EventId SubscriptionHandle::GetEventId() const
{
    return eventId_;
}

std::string SubscriptionHandle::GetSubscriberId() const
{
    return subscriberId_;
}

SubscriberType SubscriptionHandle::GetSubscriberType() const
{
    return type_;
}
} // namespace EDM
} // namespace OHOS
