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

#ifndef INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_EDM_EVENT_DATA_H
#define INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_EDM_EVENT_DATA_H

#include <cstdint>
#include <functional>

#include "application_state_observer_stub.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace EDM {

struct EventId {
    uint32_t code;

    bool operator==(const EventId &other) const
    {
        return code == other.code;
    }

    bool operator!=(const EventId &other) const
    {
        return !(*this == other);
    }
};

struct EventIdHash {
    size_t operator()(const EventId &id) const
    {
        return std::hash<uint32_t>()(id.code);
    }
};

struct EdmEventData {
    EventId eventId{};
    EventFwk::CommonEventData commonEventData;
    AppExecFwk::ProcessData appProcessData;
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_EDM_EVENT_DATA_H
