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

#include "security_manager/user_ext_session_plugin_test.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ukey_iam_error_converter.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

void UserExtSessionPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void UserExtSessionPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

HWTEST_F(UserExtSessionPluginTest, TestPluginInit, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = std::make_shared<UserExtSessionPlugin>();
    ASSERT_NE(plugin, nullptr);
}

HWTEST_F(UserExtSessionPluginTest, TestOnHandlePolicyInvalidOperateType, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_INVALID_VALUE);
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionSuccess, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = 0;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.lastAccountId, 100);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, 0);
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionSuccessChallengeInReply, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = 0;
    plugin.challengeToReturn = {0x01, 0x02, 0x03, 0x04};
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    reply.ReadInt32();
    std::vector<uint8_t> challenge;
    reply.ReadUInt8Vector(&challenge);
    ASSERT_EQ(challenge.size(), static_cast<size_t>(4));
    ASSERT_EQ(challenge[0], 0x01);
    ASSERT_EQ(challenge[3], 0x04);
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionInvalidParameterError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = UKEY_ERR_IAM_INVALID_PARAMETERS;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionAccountNotExistError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = UKEY_ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(999);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_EQ(plugin.lastAccountId, 999);
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionTimeoutError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = UKEY_ERR_IAM_TIMEOUT;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionTokenTimeoutError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = UKEY_ERR_IAM_TOKEN_TIMEOUT;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT));
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionSessionTimeoutError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = UKEY_ERR_IAM_SESSION_TIMEOUT;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT);
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionServiceBusyError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = UKEY_ERR_IAM_BUSY;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionIpcError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = UKEY_ERR_IAM_IPC_ERROR;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionRemoteDiedError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = UKEY_ERR_ACCOUNT_COMMON_REMOTE_DIED;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(UserExtSessionPluginTest, TestOpenSessionUnknownError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.openSessionResult = 99999;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(UserExtSessionPluginTest, TestCloseSessionSuccess, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.closeSessionResult = 0;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.lastAccountId, 100);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, 0);
}

HWTEST_F(UserExtSessionPluginTest, TestCloseSessionInvalidParameterError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.closeSessionResult = UKEY_ERR_IAM_INVALID_PARAMETERS;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtSessionPluginTest, TestCloseSessionTimeoutError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.closeSessionResult = UKEY_ERR_IAM_TIMEOUT;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(UserExtSessionPluginTest, TestCloseSessionTokenExpiredError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.closeSessionResult = UKEY_ERR_IAM_AUTH_TOKEN_EXPIRED;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT);
}

HWTEST_F(UserExtSessionPluginTest, TestCloseSessionLockedError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.closeSessionResult = UKEY_ERR_IAM_LOCKED;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(UserExtSessionPluginTest, TestCloseSessionHardwareNotSupportedError, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    plugin.closeSessionResult = UKEY_ERR_IAM_HARDWARE_NOT_SUPPORTED;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_SESSION);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(UserExtSessionPluginTest, TestOnGetPolicyAlwaysReturnsOk, TestSize.Level1)
{
    UserExtSessionPluginMock plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
