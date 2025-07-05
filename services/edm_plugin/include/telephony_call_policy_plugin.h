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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_TELEPHONY_CALL_POLICY_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_TELEPHONY_CALL_POLICY_PLUGIN_H

#include "telephony_call_policy_serializer.h"
#include "iplugin.h"
#include "ipolicy_manager.h"

namespace OHOS {
    namespace EDM {
    class TelephonyCallPolicyPlugin : public IPlugin {
    public:
        TelephonyCallPolicyPlugin();
    
        ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
            HandlePolicyData &policyData, int32_t userId) override;
        void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
            int32_t userId) override{};
        ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, const std::string &mergeData,
            int32_t userId) override;
        void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
            int32_t userId) override{};
        ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
            int32_t userId) override
        {
            return ERR_OK;
        };
        ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
            std::string &othersMergePolicyData) override;
        void OnOtherServiceStart(int32_t systemAbilityId) override;
    
    private:
        std::vector<std::string> MergeAndRemoveDuplicates(const std::vector<std::string> &v1,
            const std::vector<std::string> &v2);
        bool IsTrustBlockConflict(const std::string &policyTye, const int32_t flag,
            std::map<std::string, TelephonyCallPolicyType> &mergePolicies);
        bool CheckIsLimit(const std::string &policyTye, const int32_t flag,
            const std::vector<std::string> &addList, std::map<std::string, TelephonyCallPolicyType> &mergePolicies);
        ErrCode AddCurrentAndMergePolicy(std::map<std::string, TelephonyCallPolicyType> &policies,
            std::map<std::string, TelephonyCallPolicyType> &mergePolicies, const std::string &polictType,
            const int32_t flag, const std::vector<std::string> &policyName);
        ErrCode RemoveCurrentAndMergePolicy(std::map<std::string, TelephonyCallPolicyType> &policies,
            std::map<std::string, TelephonyCallPolicyType> &mergePolicies, const std::string &polictType,
            const int32_t flag, const std::vector<std::string> &policyName);
    };
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_TELEPHONY_CALL_POLICY_PLUGIN_H
