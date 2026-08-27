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

#include "event_subscription_manager.h"

#include <vector>

#include "adapter_factory.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
constexpr int32_t DELAY_CANCEL_SECONDS = 30;

EventId EventSubscriptionManager::GetEventGroupId(EventId eventId)
{
    switch (eventId.code) {
        case static_cast<uint32_t>(ManagedEvent::APP_START):
        case static_cast<uint32_t>(ManagedEvent::APP_STOP):
            return EventId{static_cast<uint32_t>(ManagedEvent::APP_START)};
        default:
            return eventId;
    }
}

EventSubscriptionManager &EventSubscriptionManager::GetInstance()
{
    static EventSubscriptionManager instance;
    return instance;
}

std::shared_ptr<SubscriptionHandle> EventSubscriptionManager::Subscribe(const std::string &subscriberId,
    SubscriberType type, EventId eventId, std::function<void(const EdmEventData &)> callback,
    const std::string &eventName, const std::string &eventPermission)
{
    if (!callback) {
        EDMLOGE("EventSubscriptionManager::Subscribe callback is null");
        return nullptr;
    }

    EventId groupId = GetEventGroupId(eventId);
    EDMLOGI("EventSubscriptionManager::Subscribe subscriber=%{public}s event=%{public}u group=%{public}u",
        subscriberId.c_str(), eventId.code, groupId.code);

    std::shared_ptr<DelayCancelTimer> timerToCancel;
    std::shared_ptr<SubscriptionHandle> handleResult;
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);

        std::shared_ptr<EventGroupState> state;
        if (!EnsureGroupState(groupId, eventName, eventPermission, state)) {
            return nullptr;
        }

        if (state->timer && state->timer->IsRunning()) {
            timerToCancel = state->timer;
        }
        if (!state->isSubscribed) {
            if (state->adapter->SubscribeEvent()) {
                EDMLOGI("EventSubscriptionManager::Subscribe adapter subscribe suc, group=%{public}u", groupId.code);
                state->isSubscribed = true;
            } else {
                EDMLOGW("EventSubscriptionManager::Subscribe adapter subscribe failed, group=%{public}u", groupId.code);
            }
        }
        state->refCount.fetch_add(1);

        uint32_t handleId = nextHandleId_.fetch_add(1);
        subscriptions_[handleId] = SubscriptionEntry{handleId, subscriberId, type, eventId, std::move(callback)};

        handleResult = std::make_shared<SubscriptionHandle>(*this, handleId, eventId, subscriberId, type);
    }

    if (timerToCancel) {
        timerToCancel->Cancel();
    }
    return handleResult;
}

bool EventSubscriptionManager::EnsureGroupState(EventId groupId, const std::string &eventName,
    const std::string &eventPermission, std::shared_ptr<EventGroupState> &outState)
{
    auto groupIt = eventGroupStates_.find(groupId);
    if (groupIt == eventGroupStates_.end() || groupIt->second == nullptr) {
        auto adapter = CreateAdapter(groupId, eventName, eventPermission);
        if (adapter == nullptr) {
            EDMLOGE("EventSubscriptionManager::EnsureGroupState CreateAdapter failed for event=%{public}u",
                groupId.code);
            return false;
        }
        auto state = std::make_shared<EventGroupState>();
        state->adapter = adapter;
        state->eventName = eventName;
        state->eventPermission = eventPermission;
        eventGroupStates_[groupId] = state;
        groupIt = eventGroupStates_.find(groupId);
    }

    outState = groupIt->second;
    if (outState->adapter == nullptr) {
        auto adapter = CreateAdapter(groupId, outState->eventName, outState->eventPermission);
        if (adapter == nullptr) {
            EDMLOGE("EventSubscriptionManager::EnsureGroupState CreateAdapter failed (re-create) for event=%{public}u",
                groupId.code);
            return false;
        }
        outState->adapter = adapter;
        outState->isSubscribed = false;
    }
    return true;
}

void EventSubscriptionManager::StartDelayedUnsubscribe(EventId groupId,
    std::shared_ptr<EventGroupState> stateShared)
{
    if (!stateShared) {
        return;
    }
    stateShared->timer->Start(
        [this, groupId, stateShared]() {
            std::unique_lock<std::shared_mutex> innerLock(mutex_);
            auto it = eventGroupStates_.find(groupId);
            if (it == eventGroupStates_.end() || it->second.get() != stateShared.get()) {
                EDMLOGI("EventSubscriptionManager delayed unsubscribe: group state replaced, skip");
                return;
            }
            if (stateShared->refCount.load() == 0 && stateShared->isSubscribed) {
                if (stateShared->adapter && stateShared->adapter->UnsubscribeEvent()) {
                    EDMLOGI("EventSubscriptionManager delayed unsubscribe success, group=%{public}u", groupId.code);
                    stateShared->isSubscribed = false;
                    stateShared->adapter.reset();
                } else {
                    EDMLOGE("EventSubscriptionManager delayed unsubscribe failed, group=%{public}u", groupId.code);
                    stateShared->isSubscribed = false;
                }
            }
        },
        std::chrono::seconds(DELAY_CANCEL_SECONDS));
    EDMLOGI("EventSubscriptionManager::Unsubscribe delay cancel started, group=%{public}u", groupId.code);
}

void EventSubscriptionManager::Unsubscribe(uint32_t handleId)
{
    std::shared_ptr<DelayCancelTimer> timerToStart;
    std::shared_ptr<EventGroupState> stateShared;
    EventId groupId{};

    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = subscriptions_.find(handleId);
        if (it == subscriptions_.end()) {
            EDMLOGW("EventSubscriptionManager::Unsubscribe handleId=%{public}u not found", handleId);
            return;
        }
        EventId eventId = it->second.eventId;
        groupId = GetEventGroupId(eventId);
        subscriptions_.erase(it);

        auto groupIt = eventGroupStates_.find(groupId);
        if (groupIt == eventGroupStates_.end() || groupIt->second == nullptr) {
            return;
        }
        auto &state = groupIt->second;
        int32_t prevCount = state->refCount.fetch_sub(1);
        if (prevCount == 1) {
            if (!state->timer) {
                state->timer = std::make_shared<DelayCancelTimer>();
            }
            timerToStart = state->timer;
            stateShared = state;
        }
    }

    if (timerToStart) {
        StartDelayedUnsubscribe(groupId, stateShared);
    }
}

void EventSubscriptionManager::DispatchEvent(const EdmEventData &data)
{
    std::vector<std::function<void(const EdmEventData &)>> callbacks;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        for (auto &[handleId, entry] : subscriptions_) {
            if (entry.eventId == data.eventId) {
                callbacks.push_back(entry.callback);
            }
        }
    }
    for (const auto &cb : callbacks) {
        cb(data);
    }
}

void EventSubscriptionManager::ResetAdapterSubscribedState(EventId groupId)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = eventGroupStates_.find(groupId);
    if (it == eventGroupStates_.end() || it->second == nullptr) {
        return;
    }
    it->second->isSubscribed = false;
}

void EventSubscriptionManager::ResetCommonEventAdapterStates()
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    for (auto &[groupId, state] : eventGroupStates_) {
        if (state == nullptr || state->adapter == nullptr) {
            continue;
        }
        if (state->adapter->GetAdapterType() == AdapterType::COMMON_EVENT) {
            state->isSubscribed = false;
        }
    }
}

void EventSubscriptionManager::RetryFailedAdapters(AdapterType type)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    for (auto &[groupId, state] : eventGroupStates_) {
        if (state == nullptr || state->isSubscribed || state->adapter == nullptr) {
            continue;
        }
        if (state->adapter->GetAdapterType() != type) {
            continue;
        }
        if (state->adapter->SubscribeEvent()) {
            state->isSubscribed = true;
            EDMLOGI("EventSubscriptionManager::RetryFailedAdapters success, group=%{public}u", groupId.code);
        } else {
            EDMLOGE("EventSubscriptionManager::RetryFailedAdapters failed, group=%{public}u", groupId.code);
        }
    }
}

std::shared_ptr<IEventSourceAdapter> EventSubscriptionManager::CreateAdapter(EventId groupId,
    const std::string &eventName, const std::string &eventPermission)
{
    return AdapterFactory::CreateAdapter(*this, groupId, eventName, eventPermission);
}
} // namespace EDM
} // namespace OHOS
