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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_DISABLED_NETWORK_INTERFACE_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_DISABLED_NETWORK_INTERFACE_PLUGIN_H

#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
class DisabledNetworkInterfacePlugin : public PluginSingleton<DisabledNetworkInterfacePlugin,
    std::map<std::string, std::string>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<DisabledNetworkInterfacePlugin,
        std::map<std::string, std::string>>> ptr) override;

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

    ErrCode OnSetPolicy(std::map<std::string, std::string> &data, std::map<std::string, std::string> &currentData,
        std::map<std::string, std::string> &mergeData, int32_t userId);

    ErrCode OnAdminRemove(const std::string &adminName, std::map<std::string, std::string> &data,
        std::map<std::string, std::string> &mergeData, int32_t userId);

    void OnOtherServiceStart(int32_t systemAbilityId);

private:
    ErrCode IsNetInterfaceExist(const std::string &netInterface);
    bool SetInterfaceDisabled(const std::string &ifaceName, bool status);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_DISABLED_NETWORK_INTERFACE_PLUGIN_H
