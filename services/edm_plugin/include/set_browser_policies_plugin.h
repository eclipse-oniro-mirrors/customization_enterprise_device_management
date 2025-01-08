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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_SET_BROWSER_POLICIES_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_SET_BROWSER_POLICIES_PLUGIN_H

#include "iplugin.h"
#include "ipolicy_manager.h"
#include "cJSON.h"

namespace OHOS {
namespace EDM {
class SetBrowserPoliciesPlugin : public IPlugin {
public:
    SetBrowserPoliciesPlugin();

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override;

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeData, int32_t userId) override
    {
        return ERR_OK;
    };

    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData, int32_t userId) override{};

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

    ErrCode GetOthersMergePolicyData(const std::string &adminName, std::string &othersMergePolicyData) override;

    bool AddBrowserPoliciesToRoot(cJSON* root, const std::string &policiesString);
private:
    void NotifyBrowserPolicyChanged();
    ErrCode SetRootPolicy(cJSON* currentPolicies, cJSON* mergePolicies, const std::string &appid,
        const std::string &policyValue);
    ErrCode SetPolicy(cJSON* currentPolicies, cJSON* mergePolicies, const std::string &appid,
        const std::string &policyName, const std::string &policyValue);
    ErrCode SetPolicyValue(cJSON* policy, std::string policyName, std::string policyValue);
    ErrCode MergeBrowserPolicy(const AdminValueItemsMap &adminValues, std::string &policyData);
    bool AddBrowserPolicyToRoot(cJSON* root, const cJSON* adminPolicy);
    ErrCode UpdateCurrentAndMergePolicy(cJSON* currentPolicies, cJSON* mergePolicies, HandlePolicyData &policyData);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_SET_BROWSER_POLICIES_PLUGIN_H
