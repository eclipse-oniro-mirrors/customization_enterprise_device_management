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

#ifndef ENTERPRISE_DEVICE_MANAGEMENT_DISALLOWED_WIFI_LIST_PLUGIN_H
#define ENTERPRISE_DEVICE_MANAGEMENT_DISALLOWED_WIFI_LIST_PLUGIN_H

#include "plugin_singleton.h"
#include "wifi_id.h"

namespace OHOS {
namespace EDM {
class DisallowWifiListPlugin : public PluginSingleton<DisallowWifiListPlugin, std::vector<WifiId>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<DisallowWifiListPlugin, std::vector<WifiId>>> ptr) override;

    ErrCode OnSetPolicy(std::vector<WifiId> &data, std::vector<WifiId> &currentData,
        std::vector<WifiId> &mergeData, int32_t userId);
    ErrCode OnRemovePolicy(std::vector<WifiId> &data, std::vector<WifiId> &currentData,
        std::vector<WifiId> &mergeData, int32_t userId);
    ErrCode OnAdminRemove(const std::string &adminName, std::vector<WifiId> &data,
        std::vector<WifiId> &mergeData, int32_t userId);
};
} // namespace EDM
} // namespace OHOS

#endif //ENTERPRISE_DEVICE_MANAGEMENT_DISALLOWED_WIFI_LIST_PLUGIN_H
