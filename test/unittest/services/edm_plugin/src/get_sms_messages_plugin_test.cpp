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

#define protected public
#define private public
#include "get_sms_messages_plugin.h"
#undef private
#undef protected

#include <gtest/gtest.h>
#include <limits>
#include <vector>

#include "edm_constants.h"
#include "edm_data_ability_utils_mock.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "sms_message_info.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int64_t START_TIME = 1000;
constexpr int64_t END_TIME = 2000;
const std::string TELEPHONE_NUMBER = "13800000000";

class GetSmsMessagesPluginTest : public testing::Test {
protected:
    void SetUp() override;
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void GetSmsMessagesPluginTest::SetUp()
{
    EdmDataAbilityUtils::ResetSmsMessagesResult();
}

void GetSmsMessagesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetSmsMessagesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicyInvalidStartTimeNegative
 * @tc.desc: Test OnGetPolicy with negative startTime.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestOnGetPolicyInvalidStartTimeNegative, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt64(-1);
    data.WriteInt64(END_TIME);
    data.WriteString(TELEPHONE_NUMBER);

    std::shared_ptr<IPlugin> plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyInvalidEndTimeNegative
 * @tc.desc: Test OnGetPolicy with negative endTime.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestOnGetPolicyInvalidEndTimeNegative, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt64(START_TIME);
    data.WriteInt64(-1);
    data.WriteString(TELEPHONE_NUMBER);

    std::shared_ptr<IPlugin> plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyInvalidRange
 * @tc.desc: Test OnGetPolicy with startTime greater than endTime.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestOnGetPolicyInvalidRange, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt64(END_TIME);
    data.WriteInt64(START_TIME);
    data.WriteString(TELEPHONE_NUMBER);

    std::shared_ptr<IPlugin> plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestPluginConstruction
 * @tc.desc: Test GetSmsMessagesPlugin construction and policy code.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestPluginConstruction, TestSize.Level1)
{
    auto plugin = std::make_shared<GetSmsMessagesPlugin>();
    ASSERT_TRUE(plugin != nullptr);
    ASSERT_TRUE(plugin->policyCode_ == static_cast<uint32_t>(EdmInterfaceCode::GET_SMS_MESSAGES));
    ASSERT_FALSE(plugin->permissionConfig_.typePermissions.empty());
    for (const auto &item : plugin->permissionConfig_.typePermissions) {
        ASSERT_TRUE(item.second == EdmPermission::PERMISSION_ENTERPRISE_READ_MESSAGES);
    }
}

/**
 * @tc.name: TestOnGetPolicyEndTimeOverflow
 * @tc.desc: Test OnGetPolicy with endTime that would overflow when converted to milliseconds.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestOnGetPolicyEndTimeOverflow, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt64(0);
    data.WriteInt64(std::numeric_limits<int64_t>::max());
    data.WriteString(TELEPHONE_NUMBER);

    std::shared_ptr<IPlugin> plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQuerySmsMessagesConvertSecondsToMilliseconds
 * @tc.desc: Test QuerySmsMessages converts the seconds time range to milliseconds for the database
 *           and converts the returned timer back to seconds.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestQuerySmsMessagesConvertSecondsToMilliseconds, TestSize.Level1)
{
    SmsQueryResult mockResult;
    mockResult.slotId = 1;
    mockResult.telephoneNumber = "13800000000";
    mockResult.content = "hello";
    mockResult.timer = 1500999;
    mockResult.isSender = true;
    EdmDataAbilityUtils::SetSmsMessagesResult(ERR_OK, {mockResult});

    auto plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::vector<SmsMessageInfo> messages;
    ErrCode ret = plugin->QuerySmsMessages(START_TIME, END_TIME, TELEPHONE_NUMBER, messages);

    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(EdmDataAbilityUtils::GetLastSmsStartTime(), START_TIME * 1000);
    EXPECT_EQ(EdmDataAbilityUtils::GetLastSmsEndTime(), END_TIME * 1000);
    EXPECT_EQ(EdmDataAbilityUtils::GetLastSmsTelephoneNumber(), TELEPHONE_NUMBER);
    ASSERT_EQ(messages.size(), 1);
    EXPECT_EQ(messages[0].slotId, 1);
    EXPECT_EQ(messages[0].telephoneNumber, "13800000000");
    EXPECT_EQ(messages[0].content, "hello");
    EXPECT_EQ(messages[0].timer, 1500);
    EXPECT_TRUE(messages[0].isSender);
}

/**
 * @tc.name: TestQuerySmsMessagesEmptyResult
 * @tc.desc: Test QuerySmsMessages returns success with empty messages when database has no matched record.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestQuerySmsMessagesEmptyResult, TestSize.Level1)
{
    EdmDataAbilityUtils::SetSmsMessagesResult(ERR_OK, {});

    auto plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::vector<SmsMessageInfo> messages;
    ErrCode ret = plugin->QuerySmsMessages(START_TIME, END_TIME, TELEPHONE_NUMBER, messages);

    ASSERT_EQ(ret, ERR_OK);
    EXPECT_TRUE(messages.empty());
    EXPECT_EQ(EdmDataAbilityUtils::GetLastSmsStartTime(), START_TIME * 1000);
    EXPECT_EQ(EdmDataAbilityUtils::GetLastSmsEndTime(), END_TIME * 1000);
}

/**
 * @tc.name: TestQuerySmsMessagesQueryFailed
 * @tc.desc: Test QuerySmsMessages returns the database error code when the query fails.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestQuerySmsMessagesQueryFailed, TestSize.Level1)
{
    EdmDataAbilityUtils::SetSmsMessagesResult(EdmReturnErrCode::EXECUTE_TIME_OUT, {});

    auto plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::vector<SmsMessageInfo> messages;
    ErrCode ret = plugin->QuerySmsMessages(START_TIME, END_TIME, TELEPHONE_NUMBER, messages);

    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_TRUE(messages.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
