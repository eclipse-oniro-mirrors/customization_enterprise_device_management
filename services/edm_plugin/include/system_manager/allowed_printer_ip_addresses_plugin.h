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
 
#ifndef SERVICES_EDM_PLUGIN_ALLOWED_PRINTER_IP_ADDRESSES_PLUGIN_H
#define SERVICES_EDM_PLUGIN_ALLOWED_PRINTER_IP_ADDRESSES_PLUGIN_H
 
#include <string>
#include <vector>
 
#include "basic_array_string_plugin.h"
#include "plugin_singleton.h"
 
namespace OHOS {
namespace EDM {
class AllowedPrinterIPAddressesPlugin : public PluginSingleton<AllowedPrinterIPAddressesPlugin,
    std::vector<std::string>>, public BasicArrayStringPlugin {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<AllowedPrinterIPAddressesPlugin,
        std::vector<std::string>>> ptr) override;
 
    ErrCode OnBasicSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
        std::vector<std::string> &mergeData, int32_t userId) override;
 
    ErrCode OnBasicRemovePolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
        std::vector<std::string> &mergeData, int32_t userId) override;
 
    void OnChangedPolicyDone(bool isGlobalChanged);
    void OnAdminRemoveDone();
};
} // namespace EDM
} // namespace OHOS
 
#endif // SERVICES_EDM_PLUGIN_ALLOWED_PRINTER_IP_ADDRESSES_PLUGIN_H