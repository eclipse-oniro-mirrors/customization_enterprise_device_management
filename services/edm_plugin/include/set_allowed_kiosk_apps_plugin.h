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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_SET_ALLOWED_KIOSK_APPS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_SET_ALLOWED_KIOSK_APPS_PLUGIN_H

#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
class SetAllowedKioskAppsPlugin : public PluginSingleton<SetAllowedKioskAppsPlugin, std::vector<std::string>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<SetAllowedKioskAppsPlugin, std::vector<std::string>>> ptr) override;
    ErrCode OnSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
        std::vector<std::string> &mergePolicyData, int32_t userId);
    ErrCode OnAdminRemove(const std::string &adminName, std::vector<std::string> &data,
        std::vector<std::string> &mergeData, int32_t userId);
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    void OnOtherServiceStart(int32_t systemAbilityId);
private:
    int32_t SetKioskAppsToAms(const std::vector<std::string> &bundleNames);
    int32_t SetKioskAppsToWms(const std::vector<std::string> &bundleNames);
    int32_t SetKioskAppsToNotification(const std::vector<std::string> &bundleNames);
    int32_t convertAppIdentifierToBundleNames(
        const std::vector<std::string> &appIdentifiers, std::vector<std::string> &bundleNames);
};
} // namespace EDM
} // namespace OHOS

#endif /* SERVICES_EDM_PLUGIN_INCLUDE_CLEAR_UP_APPLICATION_DATA_PLUGIN_H */
