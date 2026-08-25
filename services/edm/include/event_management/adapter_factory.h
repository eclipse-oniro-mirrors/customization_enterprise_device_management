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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_ADAPTER_FACTORY_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_ADAPTER_FACTORY_H

#include <string>

#include "common_event_support.h"
#include "event_subscription_manager.h"
#include "i_event_source_adapter.h"
#include "managed_event.h"
#include "subscription_handle.h"

namespace OHOS {
namespace EDM {
const std::string EDM_SYSTEM_UPDATE_FOR_POLICY = "usual.event.DUE_SA_FIRMWARE_UPDATE_FOR_POLICY";
const std::string EDM_SYSTEM_UPDATE_PERMISSION = "ohos.permission.UPDATE_SYSTEM";
const std::string EDM_OOBE_FINISHED_EVENT = "custom.event.OOBE.HWSTARTUPGUIDE.FINISHED";
const std::string EDM_OOBE_FINISHED_PERMISSION = "ohos.permission.ACCESS_STARTUPGUIDE";

class AdapterFactory {
public:
    static std::shared_ptr<IEventSourceAdapter> CreateAdapter(EventSubscriptionManager &manager,
        EventId groupId, const std::string &eventName = "", const std::string &eventPermission = "");

private:
    static std::shared_ptr<IEventSourceAdapter> CreateCommonEventAdapter(EventSubscriptionManager &manager,
        EventId groupId, const std::string &commonEvent, const std::string &publisherPermission);
    static std::shared_ptr<IEventSourceAdapter> CreateAppLifecycleAdapter(EventSubscriptionManager &manager);
    static bool ConvertToCommonEvent(EventId eventId, std::string &commonEvent);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_ADAPTER_FACTORY_H
