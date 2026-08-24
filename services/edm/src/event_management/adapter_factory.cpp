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

#include "adapter_factory.h"

#include "app_lifecycle_adapter.h"
#include "common_event_adapter.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<IEventSourceAdapter> AdapterFactory::CreateAdapter(EventSubscriptionManager &manager,
    EventId groupId, const std::string &eventName, const std::string &eventPermission)
{
    switch (static_cast<ManagedEvent>(groupId.code)) {
        case ManagedEvent::BUNDLE_ADDED:
        case ManagedEvent::BUNDLE_REMOVED:
        case ManagedEvent::BUNDLE_UPDATED:
        case ManagedEvent::USER_ADDED:
        case ManagedEvent::USER_SWITCHED:
        case ManagedEvent::USER_REMOVED:
        case ManagedEvent::BOOT_COMPLETED:
        case ManagedEvent::BMS_READY:
        case ManagedEvent::KIOSK_MODE_ON:
        case ManagedEvent::KIOSK_MODE_OFF:
        case ManagedEvent::SIM_STATE_CHANGED:
            return CreateCommonEventAdapter(manager, groupId, "", "");
        case ManagedEvent::APP_START:
            return CreateAppLifecycleAdapter(manager);
        case ManagedEvent::SYSTEM_UPDATE:
            return CreateCommonEventAdapter(manager, groupId,
                EDM_SYSTEM_UPDATE_FOR_POLICY, EDM_SYSTEM_UPDATE_PERMISSION);
        case ManagedEvent::STARTUP_GUIDE_COMPLETED:
            return CreateCommonEventAdapter(manager, groupId,
                EDM_OOBE_FINISHED_EVENT, EDM_OOBE_FINISHED_PERMISSION);
        default:
            break;
    }

    if (!eventName.empty()) {
        return CreateCommonEventAdapter(manager, groupId, eventName, eventPermission);
    }

    EDMLOGE("AdapterFactory::CreateAdapter unknown groupId=%{public}u", groupId.code);
    return nullptr;
}

std::shared_ptr<IEventSourceAdapter> AdapterFactory::CreateAppLifecycleAdapter(EventSubscriptionManager &manager)
{
    return std::make_shared<AppLifecycleAdapter>(manager);
}

std::shared_ptr<IEventSourceAdapter> AdapterFactory::CreateCommonEventAdapter(EventSubscriptionManager &manager,
    EventId groupId, const std::string &commonEvent, const std::string &publisherPermission)
{
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    if (commonEvent.empty()) {
        std::string eventName;
        if (!ConvertToCommonEvent(groupId, eventName)) {
            EDMLOGE("AdapterFactory::CreateCommonEventAdapter cannot convert groupId=%{public}u", groupId.code);
            return nullptr;
        }
        skill.AddEvent(eventName);
    } else {
        skill.AddEvent(commonEvent);
    }
    EventFwk::CommonEventSubscribeInfo info(skill);
    if (!publisherPermission.empty()) {
        info.SetPermission(publisherPermission);
    }
    return std::make_shared<CommonEventAdapter>(info, manager, groupId);
}

bool AdapterFactory::ConvertToCommonEvent(EventId eventId, std::string &commonEvent)
{
    switch (static_cast<ManagedEvent>(eventId.code)) {
        case ManagedEvent::BUNDLE_ADDED:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED;
            break;
        case ManagedEvent::BUNDLE_REMOVED:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED;
            break;
        case ManagedEvent::USER_ADDED:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED;
            break;
        case ManagedEvent::USER_SWITCHED:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED;
            break;
        case ManagedEvent::USER_REMOVED:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
            break;
        case ManagedEvent::BOOT_COMPLETED:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED;
            break;
        case ManagedEvent::BUNDLE_UPDATED:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED;
            break;
        case ManagedEvent::BMS_READY:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED;
            break;
        case ManagedEvent::KIOSK_MODE_ON:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_ON;
            break;
        case ManagedEvent::KIOSK_MODE_OFF:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_OFF;
            break;
        case ManagedEvent::SIM_STATE_CHANGED:
            commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED;
            break;
        default:
            return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS
