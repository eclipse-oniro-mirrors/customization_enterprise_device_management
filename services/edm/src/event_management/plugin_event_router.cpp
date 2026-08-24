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

#include "plugin_event_router.h"

#include <algorithm>
#include <vector>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "event_subscription_manager.h"
#include "ipolicy_manager.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
PluginEventRouter::PluginEventRouter()
{
    IPluginEventSubscribeManager::SetInstance(this);
}

PluginEventRouter &PluginEventRouter::GetInstance()
{
    static PluginEventRouter instance;
    return instance;
}

void PluginEventRouter::RestorePluginSubscriptions()
{
    struct PluginSubInfo {
        uint32_t policyCode;
        std::string policyName;
    };
    static const std::vector<PluginSubInfo> subscribingPlugins = {
        { EdmInterfaceCode::DISALLOWED_UINPUT, PolicyName::POLICY_DISALLOW_UINPUT },
        { EdmInterfaceCode::HIDDEN_SETTINGS_MENU, PolicyName::POLICY_HIDDEN_SETTINGS_MENU },
        { EdmInterfaceCode::SET_KEY_CODE_POLICYS, PolicyName::POLICY_SET_KEY_CODE },
        { EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES, PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES },
        { EdmInterfaceCode::SET_ABILITY_ENABLED, PolicyName::POLICY_SET_ABILITY_ENABLED },
        { EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS, PolicyName::POLICY_MANAGE_USER_NON_STOP_APPS },
        { EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS, PolicyName::POLICY_MANAGE_KEEP_ALIVE_APPS },
        { EdmInterfaceCode::MANAGE_AUTO_START_APPS, PolicyName::POLICY_MANAGE_AUTO_START_APPS },
        { EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS, PolicyName::POLICY_MANAGE_FREEZE_EXEMPTED_APPS },
        { EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE, PolicyName::POLICY_ALLOWED_PERMISSION_BUNDLE },
        { EdmInterfaceCode::CLIPBOARD_POLICY, PolicyName::POLICY_CLIPBOARD_POLICY },
        { EdmInterfaceCode::WATERMARK_IMAGE, PolicyName::POLICY_WATERMARK_IMAGE_POLICY },
    };

    auto policyManager = IPolicyManager::GetInstance();
    if (policyManager == nullptr) {
        EDMLOGW("PluginEventRouter::RestorePluginSubscriptions policyManager is nullptr");
        return;
    }
    for (const auto &info : subscribingPlugins) {
        std::string policyValue;
        policyManager->GetPolicy("", info.policyName, policyValue, EdmConstants::DEFAULT_USER_ID);
        if (policyValue.empty()) {
            EDMLOGI("PluginEventRouter::RestorePluginSubscriptions skip %{public}u (no policy)", info.policyCode);
            continue;
        }
        auto pluginManager = PluginManager::GetInstance();
        if (pluginManager == nullptr) {
            EDMLOGW("PluginEventRouter::RestorePluginSubscriptions pluginManager is nullptr");
            continue;
        }
        pluginManager->SubscribePluginEvent(info.policyCode);
        EDMLOGI("PluginEventRouter::RestorePluginSubscriptions restored %{public}u", info.policyCode);
    }
}

std::string PluginEventRouter::MakeKey(const std::string &policyName, EventId eventId)
{
    return policyName + ":" + std::to_string(eventId.code);
}

bool PluginEventRouter::SubscribeEvent(const std::string &policyName, uint32_t eventCode,
    uint32_t policyCode, bool needAdminIteration, bool useEventUserId)
{
    EventId eventId{eventCode};
    std::string key = MakeKey(policyName, eventId);

    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (entries_.find(key) != entries_.end()) {
        EDMLOGD("PluginEventRouter::SubscribeEvent already registered key=%{public}s", key.c_str());
        return true;
    }

    entries_.emplace(key, PluginEntry{policyCode, needAdminIteration, useEventUserId});

    auto &groupState = eventGroupStates_[eventId];
    if (groupState == nullptr) {
        groupState = std::make_unique<EventGroupState>();
    }
    groupState->registeredKeys.push_back(key);

    if (groupState->handle == nullptr) {
        auto &manager = EventSubscriptionManager::GetInstance();
        groupState->handle = manager.Subscribe("PLUGIN_ROUTER", SubscriberType::POLICY_BOUND,
            eventId,
            [this, eventId](const EdmEventData &data) { OnEventDispatch(eventId, data); });
        if (groupState->handle == nullptr) {
            EDMLOGE("PluginEventRouter::SubscribeEvent failed to subscribe eventId=%{public}u", eventCode);
            entries_.erase(key);
            groupState->registeredKeys.pop_back();
            if (groupState->registeredKeys.empty()) {
                eventGroupStates_.erase(eventId);
            }
            return false;
        }
    }

    EDMLOGI("PluginEventRouter::SubscribeEvent success key=%{public}s", key.c_str());
    return true;
}

bool PluginEventRouter::UnsubscribeEvent(const std::string &policyName, uint32_t eventCode)
{
    EventId eventId{eventCode};
    std::string key = MakeKey(policyName, eventId);
    std::shared_ptr<SubscriptionHandle> handleToRelease;

    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto entryIt = entries_.find(key);
        if (entryIt == entries_.end()) {
            EDMLOGD("PluginEventRouter::UnsubscribeEvent not found key=%{public}s", key.c_str());
            return true;
        }
        entries_.erase(entryIt);

        auto groupIt = eventGroupStates_.find(eventId);
        if (groupIt != eventGroupStates_.end()) {
            auto &groupState = groupIt->second;
            auto &keys = groupState->registeredKeys;
            keys.erase(std::remove(keys.begin(), keys.end(), key), keys.end());

            if (keys.empty()) {
                handleToRelease = std::move(groupState->handle);
                eventGroupStates_.erase(groupIt);
            }
        }
    }

    EDMLOGI("PluginEventRouter::UnsubscribeEvent success key=%{public}s", key.c_str());
    return true;
}

bool PluginEventRouter::SubscribeCustomEvent(const std::string &policyName, uint32_t eventCode,
    uint32_t policyCode, const std::string &eventFilter, const std::string &permission)
{
    EventId eventId{eventCode};
    std::string key = policyName + ":custom:" + std::to_string(eventCode);

    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (entries_.find(key) != entries_.end()) {
        EDMLOGD("PluginEventRouter::SubscribeCustomEvent already registered key=%{public}s", key.c_str());
        return true;
    }

    entries_.emplace(key, PluginEntry{policyCode, false, false});

    auto &groupState = customEventGroupStates_[eventId];
    if (groupState == nullptr) {
        groupState = std::make_unique<EventGroupState>();
    }
    groupState->registeredKeys.push_back(key);
    groupState->eventFilter = eventFilter;
    groupState->permission = permission;

    if (groupState->handle == nullptr) {
        auto &manager = EventSubscriptionManager::GetInstance();
        groupState->handle = manager.Subscribe("PLUGIN_ROUTER", SubscriberType::POLICY_BOUND,
            eventId,
            [this, eventCode](const EdmEventData &data) { OnEventDispatch(EventId{eventCode}, data); },
            eventFilter, permission);
        if (groupState->handle == nullptr) {
            EDMLOGE("PluginEventRouter::SubscribeCustomEvent failed to subscribe eventCode=%{public}u", eventCode);
            entries_.erase(key);
            groupState->registeredKeys.pop_back();
            if (groupState->registeredKeys.empty()) {
                customEventGroupStates_.erase(eventId);
            }
            return false;
        }
    }

    EDMLOGI("PluginEventRouter::SubscribeCustomEvent success key=%{public}s", key.c_str());
    return true;
}

bool PluginEventRouter::UnsubscribeCustomEvent(const std::string &policyName, uint32_t eventCode)
{
    EventId eventId{eventCode};
    std::string key = policyName + ":custom:" + std::to_string(eventCode);
    std::shared_ptr<SubscriptionHandle> handleToRelease;

    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto entryIt = entries_.find(key);
        if (entryIt == entries_.end()) {
            EDMLOGD("PluginEventRouter::UnsubscribeCustomEvent not found key=%{public}s", key.c_str());
            return true;
        }
        entries_.erase(entryIt);

        auto groupIt = customEventGroupStates_.find(eventId);
        if (groupIt != customEventGroupStates_.end()) {
            auto &groupState = groupIt->second;
            auto &keys = groupState->registeredKeys;
            keys.erase(std::remove(keys.begin(), keys.end(), key), keys.end());

            if (keys.empty()) {
                handleToRelease = std::move(groupState->handle);
                customEventGroupStates_.erase(groupIt);
            }
        }
    }

    EDMLOGI("PluginEventRouter::UnsubscribeCustomEvent success key=%{public}s", key.c_str());
    return true;
}

void PluginEventRouter::CollectDispatchEntries(EventId eventId,
    std::unordered_map<EventId, std::unique_ptr<EventGroupState>, EventIdHash> &groupStates,
    std::vector<PluginEntry> &out)
{
    for (auto &[groupKey, groupState] : groupStates) {
        if (groupKey != eventId) {
            continue;
        }
        for (const auto &key : groupState->registeredKeys) {
            auto entryIt = entries_.find(key);
            if (entryIt == entries_.end()) {
                continue;
            }
            out.push_back(entryIt->second);
        }
    }
}

void PluginEventRouter::OnEventDispatch(EventId eventId, const EdmEventData &data)
{
    std::vector<PluginEntry> dispatchList;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CollectDispatchEntries(eventId, eventGroupStates_, dispatchList);
        CollectDispatchEntries(eventId, customEventGroupStates_, dispatchList);
    }
    for (const auto &entry : dispatchList) {
        PluginManager::GetInstance()->DispatchPluginEvent(
            entry.policyCode, data, entry.needAdminIteration, entry.useEventUserId);
    }
}
} // namespace EDM
} // namespace OHOS
