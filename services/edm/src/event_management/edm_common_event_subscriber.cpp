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

#include "edm_common_event_subscriber.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
EdmCommonEventSubscriber::EdmCommonEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
    EventSubscriptionManager &manager, EventId eventId)
    : EventFwk::CommonEventSubscriber(subscribeInfo), manager_(manager), eventId_(eventId)
{}

void EdmCommonEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    EDMLOGI("EdmCommonEventSubscriber::OnReceiveEvent eventId=%{public}u", eventId_.code);
    EdmEventData edmData;
    edmData.eventId = eventId_;
    edmData.commonEventData = data;
    manager_.DispatchEvent(edmData);
}
} // namespace EDM
} // namespace OHOS
