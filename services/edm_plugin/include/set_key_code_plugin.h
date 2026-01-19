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

#ifndef ENTERPRISE_DEVICE_MANAGEMENT_SET_KEY_CODE_PLUGIN_H
#define ENTERPRISE_DEVICE_MANAGEMENT_SET_KEY_CODE_PLUGIN_H

#include "iplugin.h"
#include "key_code.h"

namespace OHOS {
namespace EDM {

class SetKeyCodePlugin : public IPlugin {
public:
    SetKeyCodePlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    ErrCode OnSetPolicy(std::vector<KeyCustomization> &keyCustomizations, std::vector<KeyCustomization> &currentData,
        std::vector<KeyCustomization> &mergeData);
    ErrCode OnRemovePolicy(std::vector<int> &keyCodes,
        std::vector<KeyCustomization> &currentData, std::vector<KeyCustomization> &mergeData);
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override{};
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
        const std::string &mergeJsonData, int32_t userId) override;
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override {};
    ErrCode SetOtherModulePolicy(std::vector<KeyCustomization> &keyCustomization);
    void OnOtherServiceStartForAdmin(const std::string &adminName, int32_t userId) override;
};
} // namespace EDM
} // namespace OHOS

#endif //ENTERPRISE_DEVICE_MANAGEMENT_SET_KEY_CODE_PLUGIN_H