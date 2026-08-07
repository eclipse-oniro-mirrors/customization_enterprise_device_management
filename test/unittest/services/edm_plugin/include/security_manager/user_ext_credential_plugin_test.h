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

#ifndef EDM_UNIT_TEST_USER_EXT_CREDENTIAL_PLUGIN_TEST_H
#define EDM_UNIT_TEST_USER_EXT_CREDENTIAL_PLUGIN_TEST_H

#include <gtest/gtest.h>
#include "iplugin_manager.h"
#include "user_ext_credential_plugin.h"

namespace OHOS {
namespace EDM {
namespace TEST {

class UserExtCredentialPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

class UserExtCredentialPluginMock : public UserExtCredentialPlugin {
public:
    int32_t addCredentialResult = 0;
    uint64_t addCredentialId = 0;
    int32_t delCredResult = 0;
    int32_t getCredInfoResult = 0;
    std::vector<AccountSA::CredentialInfo> credInfoList;
    int32_t lastAccountId = -1;

protected:
    void CallAddCredential(int32_t accountId, const AccountSA::CredentialParameters &credInfo,
        const std::shared_ptr<AccountSA::IDMCallback> &callback) override
    {
        lastAccountId = accountId;
        AccountSA::Attributes extraInfo;
        extraInfo.SetUint64Value(AccountSA::Attributes::ATTR_CREDENTIAL_ID, addCredentialId);
        callback->OnResult(addCredentialResult, extraInfo);
    }

    void CallDelCred(int32_t accountId, uint64_t credentialId,
        const std::vector<uint8_t> &authToken,
        const std::shared_ptr<AccountSA::IDMCallback> &callback) override
    {
        lastAccountId = accountId;
        AccountSA::Attributes extraInfo;
        callback->OnResult(delCredResult, extraInfo);
    }

    int32_t CallGetCredentialInfo(int32_t accountId, int32_t authType,
        const std::shared_ptr<AccountSA::GetCredInfoCallback> &callback) override
    {
        lastAccountId = accountId;
        callback->OnCredentialInfo(getCredInfoResult, credInfoList);
        return getCredInfoResult;
    }
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_USER_EXT_CREDENTIAL_PLUGIN_TEST_H
