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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_APP_LIFECYCLE_ADAPTER_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_APP_LIFECYCLE_ADAPTER_H

#include "edm_app_state_subscriber.h"
#include "i_event_source_adapter.h"
#include "iedm_app_manager.h"

namespace OHOS {
namespace EDM {
class AppLifecycleAdapter : public IEventSourceAdapter {
public:
    explicit AppLifecycleAdapter(EventSubscriptionManager &manager);
    bool SubscribeEvent() override;
    bool UnsubscribeEvent() override;
    AdapterType GetAdapterType() const override { return AdapterType::APP_LIFECYCLE; }

protected:
    virtual std::shared_ptr<IEdmAppManager> GetAppMgr();

private:
    sptr<AppExecFwk::IApplicationStateObserver> subscriber_;
    std::shared_ptr<IEdmAppManager> edmAppManager_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_APP_LIFECYCLE_ADAPTER_H
