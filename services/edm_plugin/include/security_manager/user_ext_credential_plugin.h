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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_SECURITY_MANAGER_USER_EXT_CREDENTIAL_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_SECURITY_MANAGER_USER_EXT_CREDENTIAL_PLUGIN_H

#include <vector>
#include <memory>
#include "account_iam_client.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {
class UserExtCredentialPlugin : public IPlugin {
public:
    UserExtCredentialPlugin();
    virtual ~UserExtCredentialPlugin() = default;
    ErrCode OnHandlePolicy(uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(uint32_t funcCode, const std::string &adminName,
        bool isGlobalChanged, int32_t userId) override {}
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeJsonData, int32_t userId) override { return ERR_OK; }
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override {}
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
        int32_t userId) override;

protected:
    virtual void CallAddCredential(int32_t accountId, const AccountSA::CredentialParameters &credInfo,
        const std::shared_ptr<AccountSA::IDMCallback> &callback);
    virtual void CallDelCred(int32_t accountId, uint64_t credentialId,
        const std::vector<uint8_t> &authToken, const std::shared_ptr<AccountSA::IDMCallback> &callback);
    virtual int32_t CallGetCredentialInfo(int32_t accountId, int32_t authType,
        const std::shared_ptr<AccountSA::GetCredInfoCallback> &callback);

private:
    ErrCode HandleAddCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveCredential(MessageParcel &data, MessageParcel &reply);
};
} // namespace EDM
} // namespace OHOS

#endif
