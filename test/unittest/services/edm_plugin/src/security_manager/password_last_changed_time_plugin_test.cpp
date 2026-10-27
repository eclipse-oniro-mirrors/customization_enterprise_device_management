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

#include "security_manager/password_last_changed_time_plugin_test.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "iam_common_defines.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

constexpr uint64_t LATEST_ENROLLMENT_TIME = 1729000000000;

void PasswordLastChangedTimePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void PasswordLastChangedTimePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestPluginInit
 * @tc.desc: Test PasswordLastChangedTimePlugin init, policy code, policy name and needSave are set correctly.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestPluginInit, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = std::make_shared<PasswordLastChangedTimePlugin>();
    ASSERT_NE(plugin, nullptr);
    ASSERT_TRUE(plugin->GetCode() == (std::uint32_t)EdmInterfaceCode::PASSWORD_LAST_CHANGED_TIME);
    ASSERT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_PASSWORD_LAST_CHANGED_TIME);
    ASSERT_FALSE(plugin->NeedSavePolicy());
}

/**
 * @tc.name: TestOnHandlePolicyInvalidValue
 * @tc.desc: Test OnHandlePolicy always returns ERR_INVALID_VALUE for set operation.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestOnHandlePolicyInvalidValue, TestSize.Level1)
{
    PasswordLastChangedTimePluginMock plugin;
    uint32_t code = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::PASSWORD_LAST_CHANGED_TIME);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: TestOnGetPolicySuccess
 * @tc.desc: Test OnGetPolicy returns ERR_OK and replies latest enrollment time when IAM call succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestOnGetPolicySuccess, TestSize.Level1)
{
    PasswordLastChangedTimePluginMock plugin;
    plugin.getLatestEnrollmentResult = 0;
    plugin.latestEnrollmentTime = LATEST_ENROLLMENT_TIME;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(DEFAULT_USER_ID);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.callCount, 1);
    ASSERT_EQ(plugin.lastAccountId, DEFAULT_USER_ID);
    ASSERT_EQ(plugin.lastAuthType, static_cast<int32_t>(UserIam::UserAuth::AuthType::PIN));
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, ERR_OK);
    uint64_t latestTime = reply.ReadUint64();
    ASSERT_EQ(latestTime, LATEST_ENROLLMENT_TIME);
}

/**
 * @tc.name: TestOnGetPolicyAccountIdZeroSuccess
 * @tc.desc: Test OnGetPolicy accepts boundary accountId 0 and passes it to the IAM seam.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestOnGetPolicyAccountIdZeroSuccess, TestSize.Level1)
{
    PasswordLastChangedTimePluginMock plugin;
    plugin.getLatestEnrollmentResult = 0;
    plugin.latestEnrollmentTime = LATEST_ENROLLMENT_TIME;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(0);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.callCount, 1);
    ASSERT_EQ(plugin.lastAccountId, 0);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, ERR_OK);
    uint64_t latestTime = reply.ReadUint64();
    ASSERT_EQ(latestTime, LATEST_ENROLLMENT_TIME);
}

/**
 * @tc.name: TestOnGetPolicyCapabilityNotSupportedReturnsZero
 * @tc.desc: Test OnGetPolicy replies ERR_OK with time 0 when IAM reports CAPABILITY_NOT_SUPPORTED,
 *     meaning the user has no PIN credential.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestOnGetPolicyCapabilityNotSupportedReturnsZero, TestSize.Level1)
{
    PasswordLastChangedTimePluginMock plugin;
    plugin.getLatestEnrollmentResult = UserIam::UserAuth::CAPABILITY_NOT_SUPPORTED;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(DEFAULT_USER_ID);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.callCount, 1);
    ASSERT_EQ(plugin.lastAccountId, DEFAULT_USER_ID);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, ERR_OK);
    uint64_t latestTime = reply.ReadUint64();
    ASSERT_EQ(latestTime, 0);
}

/**
 * @tc.name: TestOnGetPolicyIamServiceError
 * @tc.desc: Test OnGetPolicy returns EXECUTE_TIME_OUT(9200016) and replies without errMsg when IAM
 *     reports GENERAL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestOnGetPolicyIamServiceError, TestSize.Level1)
{
    PasswordLastChangedTimePluginMock plugin;
    plugin.getLatestEnrollmentResult = UserIam::UserAuth::GENERAL_ERROR;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(DEFAULT_USER_ID);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    ASSERT_EQ(plugin.callCount, 1);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestOnGetPolicyUnknownError
 * @tc.desc: Test OnGetPolicy returns EXECUTE_TIME_OUT(9200016) and replies without errMsg for an
 *     unknown IAM error code.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestOnGetPolicyUnknownError, TestSize.Level1)
{
    PasswordLastChangedTimePluginMock plugin;
    plugin.getLatestEnrollmentResult = 123;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(DEFAULT_USER_ID);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    ASSERT_EQ(plugin.callCount, 1);
    ASSERT_EQ(plugin.lastAccountId, DEFAULT_USER_ID);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestOnGetPolicyInvalidAccountIdError
 * @tc.desc: Test OnGetPolicy returns UID_INVALID(9200006) and skips the IAM call when
 * accountId is negative.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestOnGetPolicyInvalidAccountIdError, TestSize.Level1)
{
    PasswordLastChangedTimePluginMock plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(-1);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::UID_INVALID);
    ASSERT_EQ(plugin.callCount, 0);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::UID_INVALID);
}

/**
 * @tc.name: TestOnGetPolicyAccountNotExists
 * @tc.desc: Test OnGetPolicy returns UID_INVALID(9200006) and skips the IAM call when
 *     the accountId does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordLastChangedTimePluginTest, TestOnGetPolicyAccountNotExists, TestSize.Level1)
{
    PasswordLastChangedTimePluginMock plugin;
    plugin.isAccountExist = false;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(DEFAULT_USER_ID);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::UID_INVALID);
    ASSERT_EQ(plugin.existsCallCount, 1);
    ASSERT_EQ(plugin.lastExistsAccountId, DEFAULT_USER_ID);
    ASSERT_EQ(plugin.callCount, 0);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::UID_INVALID);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
