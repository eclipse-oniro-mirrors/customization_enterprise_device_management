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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_HIDDEN_SETTINGS_MENU_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_HIDDEN_SETTINGS_MENU_PLUGIN_H

#include <message_parcel.h>
#include <vector>
#include <string>
#include <cstdint>

#include "basic_array_int_plugin.h"
#include "settings_menu_policy.h"

#include "cJSON.h"
#include "iplugin.h"
#include "plugin_singleton.h"
#include "key_code.h"

namespace OHOS {
namespace EDM {
class HiddenSettingsMenuPlugin : public BasicArrayIntPlugin, public IPlugin {
public:
    HiddenSettingsMenuPlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override {};
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
        const std::string &mergeJsonData, int32_t userId) override;
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override {};
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
        std::string &othersMergePolicyData) override;
    ErrCode SetOtherModulePolicy(const std::vector<int32_t> &data, int32_t userId,
        std::vector<int32_t> &failedData) override;
    ErrCode RemoveOtherModulePolicy(const std::vector<int32_t> &data, int32_t userId,
        std::vector<int32_t> &failedData) override;
    void OnOtherServiceStartForAdmin(const std::string &adminName, int32_t userId) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_HIDDEN_SETTINGS_MENU_PLUGIN_H
