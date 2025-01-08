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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_FINGERPRINT_AUTH_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_FINGERPRINT_AUTH_PLUGIN_H

#include "plugin_singleton.h"
#include "fingerprint_policy.h"

namespace OHOS {
namespace EDM {
class FingerprintAuthPlugin : public IPlugin {
public:
    FingerprintAuthPlugin();

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override{};

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeData, int32_t userId) override;

    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData, int32_t userId) override{};

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

    ErrCode GetOthersMergePolicyData(const std::string &adminName, std::string &othersMergePolicyData) override;

private:
    ErrCode HandleFingerprintAuthPolicy(bool disallow, FingerprintPolicy &currentPolicy,
        FingerprintPolicy &mergePolicy);

    ErrCode HandleFingerprintForAccountPolicy(bool disallow, int32_t accountId, FingerprintPolicy &currentPolicy,
        FingerprintPolicy &mergePolicy);

    ErrCode SetGlobalConfigParam(FingerprintPolicy policy);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_FINGERPRINT_AUTH_PLUGIN_H
