/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_AUTO_START_APPS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_AUTO_START_APPS_PLUGIN_H

#include "plugin_singleton.h"
#include "iremote_stub.h"

namespace OHOS {
namespace EDM {
class ManageAutoStartAppsPlugin : public PluginSingleton<ManageAutoStartAppsPlugin, std::vector<std::string>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<ManageAutoStartAppsPlugin,
        std::vector<std::string>>> ptr) override;

    ErrCode OnSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData, int32_t userId);
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    ErrCode OnRemovePolicy(std::vector<std::string> &data, std::vector<std::string> &currentData, int32_t userId);
    void OnAdminRemoveDone(const std::string &adminName, std::vector<std::string> &data, int32_t userId);
private:
    bool ParseAutoStartAppWant(std::string appWant, std::string &bundleName, std::string &abilityName);
    bool CheckBundleAndAbilityExited (std::vector<std::string> data);
};
} // namespace EDM
} // namespace OHOS

#endif /* SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_AUTO_START_APPS_PLUGIN_H */