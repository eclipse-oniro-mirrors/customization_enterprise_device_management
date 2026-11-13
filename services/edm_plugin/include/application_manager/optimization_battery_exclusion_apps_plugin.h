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

#ifndef SERVICES_EDM_PLUGIN_OPTIMIZATION_BATTERY_EXCLUSION_APPS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_OPTIMIZATION_BATTERY_EXCLUSION_APPS_PLUGIN_H

#include <string>
#include <vector>

#include "basic_array_string_plugin.h"
#include "external_manager_factory.h"
#include "iexternal_manager_factory.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {
class OptimizationBatteryExclusionAppsPlugin : public BasicArrayStringPlugin, public IPlugin {
public:
    OptimizationBatteryExclusionAppsPlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
        std::string &othersMergePolicyData) override;
    bool SubscribeEvent() override;
    bool UnsubscribeEvent() override;
    void OnPluginEvent(const std::string &adminName, HandlePolicyData &policyData,
        const EdmEventData &data, int32_t userId) override;

protected:
    ErrCode SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
        std::vector<std::string> &failedData) override;
    std::shared_ptr<IExternalManagerFactory> externalManagerFactory_ = std::make_shared<ExternalManagerFactory>();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_OPTIMIZATION_BATTERY_EXCLUSION_APPS_PLUGIN_H
