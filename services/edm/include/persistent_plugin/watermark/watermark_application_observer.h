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

#ifndef SERVICES_EDM_INCLUDE_PERSISTENT_PLUGIN_WATERMARK_APPLICATION_OBSERVER_H
#define SERVICES_EDM_INCLUDE_PERSISTENT_PLUGIN_WATERMARK_APPLICATION_OBSERVER_H

#include "application_state_observer_stub.h"
#include "set_watermark_image_plugin.h"

namespace OHOS {
namespace EDM {
class SetWatermarkImagePlugin;
class WatermarkApplicationObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    WatermarkApplicationObserver(SetWatermarkImagePlugin &listener) : listener_(listener) {}

    void OnProcessCreated(const AppExecFwk::ProcessData &processData) override;
    void OnProcessDied(const AppExecFwk::ProcessData &processData) override {};

private:
    SetWatermarkImagePlugin &listener_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_PERSISTENT_PLUGIN_WATERMARK_APPLICATION_OBSERVER_H