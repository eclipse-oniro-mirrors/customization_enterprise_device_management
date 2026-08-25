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

#include "app_lifecycle_adapter.h"

#include "edm_app_manager_impl.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
AppLifecycleAdapter::AppLifecycleAdapter(EventSubscriptionManager &manager)
{
    subscriber_ = new (std::nothrow) EdmAppStateSubscriber(manager);
}

bool AppLifecycleAdapter::SubscribeEvent()
{
    if (subscriber_ == nullptr) {
        EDMLOGE("AppLifecycleAdapter::SubscribeEvent subscriber is null");
        return false;
    }
    if (GetAppMgr()->RegisterApplicationStateObserver(subscriber_)) {
        EDMLOGE("AppLifecycleAdapter::SubscribeEvent RegisterApplicationStateObserver failed");
        return false;
    }
    return true;
}

bool AppLifecycleAdapter::UnsubscribeEvent()
{
    if (subscriber_ == nullptr) {
        EDMLOGE("AppLifecycleAdapter::UnsubscribeEvent subscriber is null");
        return false;
    }
    if (GetAppMgr()->UnregisterApplicationStateObserver(subscriber_)) {
        EDMLOGE("AppLifecycleAdapter::UnsubscribeEvent UnregisterApplicationStateObserver failed");
        return false;
    }
    return true;
}

std::shared_ptr<IEdmAppManager> AppLifecycleAdapter::GetAppMgr()
{
    if (edmAppManager_ == nullptr) {
        edmAppManager_ = std::make_shared<EdmAppManagerImpl>();
    }
    return edmAppManager_;
}
} // namespace EDM
} // namespace OHOS
