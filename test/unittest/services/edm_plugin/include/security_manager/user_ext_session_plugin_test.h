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

#ifndef EDM_UNIT_TEST_USER_EXT_SESSION_PLUGIN_TEST_H
#define EDM_UNIT_TEST_USER_EXT_SESSION_PLUGIN_TEST_H

#include <gtest/gtest.h>
#include "iplugin_manager.h"
#include "user_ext_session_plugin.h"

namespace OHOS {
namespace EDM {
namespace TEST {

class UserExtSessionPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

class UserExtSessionPluginMock : public UserExtSessionPlugin {
public:
    int32_t openSessionResult = 0;
    int32_t closeSessionResult = 0;
    std::vector<uint8_t> challengeToReturn = {0xAA, 0xBB, 0xCC};

protected:
    int32_t CallOpenSession(int32_t accountId, std::vector<uint8_t> &challenge) override
    {
        lastAccountId = accountId;
        if (openSessionResult == 0) {
            challenge = challengeToReturn;
        }
        return openSessionResult;
    }

    int32_t CallCloseSession(int32_t accountId) override
    {
        lastAccountId = accountId;
        return closeSessionResult;
    }

public:
    int32_t lastAccountId = -1;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_USER_EXT_SESSION_PLUGIN_TEST_H
