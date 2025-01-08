/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_MANAGED_BROWSER_POLICY_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_MANAGED_BROWSER_POLICY_PLUGIN_H

#include "iplugin.h"
#include "ipolicy_manager.h"
#include "managed_browser_policy_type.h"

namespace OHOS {
namespace EDM {
class ManagedBrowserPolicyPlugin : public IPlugin {
public:
    ManagedBrowserPolicyPlugin();

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override;

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, const std::string &mergeData,
        int32_t userId) override;

    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData, int32_t userId) override{};

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

private:
    ErrCode ModifyOrRemoveManagedBrowserPolicy(std::map<std::string, ManagedBrowserPolicyType> &policies,
        const std::string &bundleName, const std::string &policyName, const std::string &policyValue);

    ErrCode AddManagedBrowserPolicy(std::map<std::string, ManagedBrowserPolicyType> &policies,
        const std::string &bundleName, const std::string &policyName, const std::string &policyValue);

    ErrCode GetManagedBrowserPolicyFileData(const std::string &bundleName, MessageParcel &reply);

    ErrCode GetManagedBrowserPolicyVersion(const std::string &policyData,
        const std::string &bundleName, MessageParcel &reply);

    bool FindPolicyNameInLine(const std::string &line, std::string &policyNameInLine);

    bool GetCallingBundleName(std::string &bundleName);

    bool UpdatePolicyFile(std::map<std::string, ManagedBrowserPolicyType> &policies, const std::string &bundleName,
        std::string &url, std::string &tempUrl);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_MANAGED_BROWSER_POLICY_PLUGIN_H
