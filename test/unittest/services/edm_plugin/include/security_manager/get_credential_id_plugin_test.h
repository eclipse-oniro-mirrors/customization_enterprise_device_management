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

#ifndef EDM_UNIT_TEST_GET_CREDENTIAL_ID_PLUGIN_TEST_H
#define EDM_UNIT_TEST_GET_CREDENTIAL_ID_PLUGIN_TEST_H

#include <gtest/gtest.h>
#include <vector>

#include "get_credential_id_plugin.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
namespace TEST {

class GetCredentialIdPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

class GetCredentialIdPluginMock : public GetCredentialIdPlugin {
public:
    ErrCode verifyResult = ERR_OK;
    uint64_t mockedCredentialId = 0;
    int verifyCallCount = 0;
    std::vector<uint8_t> lastAuthToken;
    uint64_t lastAllowableDuration = 0;

protected:
    ErrCode CallVerifyAuthToken(const std::vector<uint8_t> &authToken, uint64_t allowableDuration,
        uint64_t &credentialId) override
    {
        verifyCallCount++;
        lastAuthToken = authToken;
        lastAllowableDuration = allowableDuration;
        if (verifyResult != ERR_OK) {
            return verifyResult;
        }
        credentialId = mockedCredentialId;
        return ERR_OK;
    }
};

class GetCredentialIdPluginRealMock : public GetCredentialIdPlugin {
public:
    ErrCode InvokeCallVerifyAuthToken(const std::vector<uint8_t> &authToken, uint64_t allowableDuration,
        uint64_t &credentialId)
    {
        return CallVerifyAuthToken(authToken, allowableDuration, credentialId);
    }
};

class GetCredentialIdPluginPureMock : public GetCredentialIdPlugin {
public:
    ErrCode InvokeCallVerifyAuthToken(const std::vector<uint8_t> &authToken, uint64_t allowableDuration,
        uint64_t &credentialId)
    {
        return CallVerifyAuthToken(authToken, allowableDuration, credentialId);
    }
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_GET_CREDENTIAL_ID_PLUGIN_TEST_H
