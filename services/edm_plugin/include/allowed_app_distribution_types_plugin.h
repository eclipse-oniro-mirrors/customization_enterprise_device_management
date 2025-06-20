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

#ifndef CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ALLOWED_APP_DISTRIBUTION_TYPES_PLUGIN_H
#define CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ALLOWED_APP_DISTRIBUTION_TYPES_PLUGIN_H

#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
class AllowedAppDistributionTypesPlugin : public
    PluginSingleton<AllowedAppDistributionTypesPlugin, std::vector<int32_t>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<AllowedAppDistributionTypesPlugin,
        std::vector<int32_t>>> ptr) override;

    ErrCode OnSetPolicy(std::vector<int32_t> &data, std::vector<int32_t> &currentData,
        std::vector<int32_t> &mergeData, int32_t userId);
    ErrCode OnRemovePolicy(std::vector<int32_t> &data, std::vector<int32_t> &currentData,
        std::vector<int32_t> &mergeData, int32_t userId);
    ErrCode OnAdminRemove(const std::string &adminName, std::vector<int32_t> &data,
        std::vector<int32_t> &mergeData, int32_t userId);
};
} // namespace EDM
} // namespace OHOS

#endif //CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ALLOWED_APP_DISTRIBUTION_TYPES_PLUGIN_H
