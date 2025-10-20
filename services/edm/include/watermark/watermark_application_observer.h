/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_UTILS_WATERMARK_APPLICATION_OBSERVER_H
#define SERVICES_EDM_INCLUDE_UTILS_WATERMARK_APPLICATION_OBSERVER_H

#include "application_state_observer_stub.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "watermark_image_type.h"
#include "watermark_image_serializer.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
class WatermarkApplicationObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    void OnProcessCreated(const AppExecFwk::ProcessData &processData) override;
    void OnProcessDied(const AppExecFwk::ProcessData &processData) override;
    void HandleWatermark(const AppExecFwk::ProcessData &processData, bool enabled);
    void SetProcessWatermarkOnAppStart(const std::string &bundleName, int32_t accountId,
        int32_t pid, bool enabled);
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_UTILS_WATERMARK_APPLICATION_OBSERVER_H