/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_USER_AUTH_EVENT_ADAPTER_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_USER_AUTH_EVENT_ADAPTER_H

#include <memory>

#include "edm_event_data.h"
#include "event_subscription_manager.h"
#include "i_event_source_adapter.h"

namespace OHOS {
namespace EDM {
class EdmUserAuthListener;

class UserAuthEventAdapter : public IEventSourceAdapter {
public:
    explicit UserAuthEventAdapter(EventSubscriptionManager &manager);

    ~UserAuthEventAdapter() override;

    bool SubscribeEvent() override;

    bool UnsubscribeEvent() override;

    AdapterType GetAdapterType() const override { return AdapterType::USER_AUTH; }

private:
    bool RegisterIamListener();

    bool UnregisterIamListener();

protected:
    virtual int32_t DoRegisterIamListener();

    virtual int32_t DoUnregisterIamListener();

    EventSubscriptionManager &manager_;
    std::shared_ptr<EdmUserAuthListener> listener_;
    bool isListenerRegistered_{false};
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_USER_AUTH_EVENT_ADAPTER_H
