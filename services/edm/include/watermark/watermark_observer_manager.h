/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_UTILS_WATERMARK_OBSERVER_MANAGER_H
#define SERVICES_EDM_INCLUDE_UTILS_WATERMARK_OBSERVER_MANAGER_H

#include "app_mgr_interface.h"
#include "edm_sys_manager.h"
#include "watermark_application_observer.h"
#include "iwatermark_observer_manager.h"

namespace OHOS {
namespace EDM {
class WatermarkObserverManager : public IWatermarkObserverManager {
public:
    bool SubscribeAppStateObserver() override;
    bool UnSubscribeAppStateObserver() override;
    static WatermarkObserverManager* GetInstance();
private:
    sptr<AppExecFwk::IAppMgr> GetAppManager();
    sptr<AppExecFwk::IApplicationStateObserver> observer_;
    static WatermarkObserverManager* instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_UTILS_WATERMARK_OBSERVER_MANAGER_H