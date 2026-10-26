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

#ifndef EDM_UNIT_TEST_PASSWORD_LAST_CHANGED_TIME_PLUGIN_TEST_H
#define EDM_UNIT_TEST_PASSWORD_LAST_CHANGED_TIME_PLUGIN_TEST_H

#include <gtest/gtest.h>
#include "iplugin_manager.h"
#include "password_last_changed_time_plugin.h"

namespace OHOS {
namespace EDM {
namespace TEST {

class PasswordLastChangedTimePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

class PasswordLastChangedTimePluginMock : public PasswordLastChangedTimePlugin {
public:
    int32_t getLatestEnrollmentResult = 0;
    uint64_t latestEnrollmentTime = 0;
    int32_t lastAccountId = -1;
    int32_t lastAuthType = -1;
    int callCount = 0;

protected:
    int32_t CallGetLatestEnrollmentTime(int32_t accountId, int32_t authType, uint64_t &latestTime) override
    {
        callCount++;
        lastAccountId = accountId;
        lastAuthType = authType;
        latestTime = latestEnrollmentTime;
        return getLatestEnrollmentResult;
    }
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_PASSWORD_LAST_CHANGED_TIME_PLUGIN_TEST_H
