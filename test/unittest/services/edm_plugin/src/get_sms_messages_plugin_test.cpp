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

#include "edm_constants.h"
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
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

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
 * @tc.name: TestOnGetPolicySuc
 * @tc.desc: Test GetSmsMessagesPlugin::OnGetPolicy with valid time range.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestOnGetPolicySuc, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt64(START_TIME);
    data.WriteInt64(END_TIME);
    data.WriteString(TELEPHONE_NUMBER);

    std::shared_ptr<IPlugin> plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    int32_t dataSize = reply.ReadInt32();
    ASSERT_TRUE(dataSize > 0);
    const void *buffer = reply.ReadRawData(dataSize);
    ASSERT_TRUE(buffer != nullptr);
    MessageParcel tempParcel;
    ASSERT_TRUE(tempParcel.WriteUnpadBuffer(buffer, dataSize));
    tempParcel.RewindRead(0);
    ASSERT_TRUE(tempParcel.ReadInt32() == 0);
}

/**
 * @tc.name: TestOnGetPolicyEmptyNumber
 * @tc.desc: Test OnGetPolicy with empty telephone number.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestOnGetPolicyEmptyNumber, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt64(START_TIME);
    data.WriteInt64(END_TIME);
    data.WriteString("");

    std::shared_ptr<IPlugin> plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    int32_t dataSize = reply.ReadInt32();
    ASSERT_TRUE(dataSize > 0);
    const void *buffer = reply.ReadRawData(dataSize);
    ASSERT_TRUE(buffer != nullptr);
    MessageParcel tempParcel;
    ASSERT_TRUE(tempParcel.WriteUnpadBuffer(buffer, dataSize));
    tempParcel.RewindRead(0);
    ASSERT_TRUE(tempParcel.ReadInt32() == 0);
}

/**
 * @tc.name: TestOnGetPolicyEqualTime
 * @tc.desc: Test OnGetPolicy with startTime equal to endTime.
 * @tc.type: FUNC
 */
HWTEST_F(GetSmsMessagesPluginTest, TestOnGetPolicyEqualTime, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt64(START_TIME);
    data.WriteInt64(START_TIME);
    data.WriteString(TELEPHONE_NUMBER);

    std::shared_ptr<IPlugin> plugin = std::make_shared<GetSmsMessagesPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    int32_t dataSize = reply.ReadInt32();
    ASSERT_TRUE(dataSize > 0);
    const void *buffer = reply.ReadRawData(dataSize);
    ASSERT_TRUE(buffer != nullptr);
    MessageParcel tempParcel;
    ASSERT_TRUE(tempParcel.WriteUnpadBuffer(buffer, dataSize));
    tempParcel.RewindRead(0);
    ASSERT_TRUE(tempParcel.ReadInt32() == 0);
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
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAM_ERROR);
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
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAM_ERROR);
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
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAM_ERROR);
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
} // namespace TEST
} // namespace EDM
} // namespace OHOS
