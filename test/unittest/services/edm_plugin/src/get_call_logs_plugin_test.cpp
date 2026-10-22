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

#include <gtest/gtest.h>
#include <string>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "func_code.h"
#include "get_call_logs_plugin.h"
#include "message_parcel.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class GetCallLogsPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void GetCallLogsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetCallLogsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicy_StartGreaterThanEnd_Fail
 * @tc.desc: Test OnGetPolicy when startTime is greater than endTime.
 * @tc.type: FUNC
 */
HWTEST_F(GetCallLogsPluginTest, TestOnGetPolicy_StartGreaterThanEnd_Fail, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt64(100);
    data.WriteInt64(50);
    data.WriteBool(false);
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<GetCallLogsPlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_NegativeStartTime_Fail
 * @tc.desc: Test OnGetPolicy when startTime is negative.
 * @tc.type: FUNC
 */
HWTEST_F(GetCallLogsPluginTest, TestOnGetPolicy_NegativeStartTime_Fail, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt64(-1);
    data.WriteInt64(100);
    data.WriteBool(false);
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<GetCallLogsPlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_NegativeEndTime_Fail
 * @tc.desc: Test OnGetPolicy when endTime is negative.
 * @tc.type: FUNC
 */
HWTEST_F(GetCallLogsPluginTest, TestOnGetPolicy_NegativeEndTime_Fail, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt64(100);
    data.WriteInt64(-1);
    data.WriteBool(false);
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<GetCallLogsPlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_TimeRangeExceeds31Days_Fail
 * @tc.desc: Test OnGetPolicy when time range exceeds 31 days.
 * @tc.type: FUNC
 */
HWTEST_F(GetCallLogsPluginTest, TestOnGetPolicy_TimeRangeExceeds31Days_Fail, TestSize.Level1)
{
    int64_t endTime = 2000000000;
    int64_t startTime = endTime - (32LL * 24 * 60 * 60);
    MessageParcel data;
    data.WriteInt64(startTime);
    data.WriteInt64(endTime);
    data.WriteBool(false);
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<GetCallLogsPlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_EmptyTelephoneNumber_Fail
 * @tc.desc: Test OnGetPolicy when hasTelephoneNumber is true but telephoneNumber is empty.
 * @tc.type: FUNC
 */
HWTEST_F(GetCallLogsPluginTest, TestOnGetPolicy_EmptyTelephoneNumber_Fail, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt64(100);
    data.WriteInt64(200);
    data.WriteBool(true);
    data.WriteString("");
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<GetCallLogsPlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_Exactly31Days_PassValidation
 * @tc.desc: Test OnGetPolicy when time range is exactly 31 days (boundary, passes validation).
 *           Validates that the boundary is inclusive — 31 days should NOT trigger the range check.
 * @tc.type: FUNC
 */
HWTEST_F(GetCallLogsPluginTest, TestOnGetPolicy_Exactly31Days_PassValidation, TestSize.Level1)
{
    int64_t endTime = 2000000000;
    int64_t startTime = endTime - (31LL * 24 * 60 * 60);
    MessageParcel data;
    data.WriteInt64(startTime);
    data.WriteInt64(endTime);
    data.WriteBool(false);
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<GetCallLogsPlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_NE(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_ValidTimeNoTelephoneNumber_PassValidation
 * @tc.desc: Test OnGetPolicy with valid time range and no telephoneNumber filter.
 *           Passes parameter validation (does not return PARAMETER_VERIFICATION_FAILED).
 * @tc.type: FUNC
 */
HWTEST_F(GetCallLogsPluginTest, TestOnGetPolicy_ValidTimeNoTelephoneNumber_PassValidation, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt64(100);
    data.WriteInt64(200);
    data.WriteBool(false);
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<GetCallLogsPlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_NE(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_ValidTimeWithTelephoneNumber_PassValidation
 * @tc.desc: Test OnGetPolicy with valid time range and a non-empty telephoneNumber.
 *           Passes parameter validation (does not return PARAMETER_VERIFICATION_FAILED).
 * @tc.type: FUNC
 */
HWTEST_F(GetCallLogsPluginTest, TestOnGetPolicy_ValidTimeWithTelephoneNumber_PassValidation, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt64(100);
    data.WriteInt64(200);
    data.WriteBool(true);
    data.WriteString("13800138000");
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<GetCallLogsPlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_NE(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
